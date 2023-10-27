#!/usr/bin/env python
#
"""
Test the various functions in the `deliver` module
"""
# system imports
#

# 3rd party imports
#
import factory
import pytest

# Project imports
#
from ..deliver import (
    apply_message_filter_rules,
    deliver_message,
    deliver_message_locally,
    make_delivery_status_notification,
    make_encapsulated_fwd_msg,
    report_failed_message,
)
from ..models import EmailAccount, MessageFilterRule
from .conftest import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
def test_apply_message_filter_rules(
    email_account_factory,
    message_filter_rule_factory,
    email_factory,
):
    ea = email_account_factory()
    ea.save()
    msg = email_factory()
    folder = "test"
    mfr = message_filter_rule_factory(
        email_account=ea,
        header=MessageFilterRule.FROM,
        pattern=msg["from"],
        destination=folder,
    )
    mfr.save()

    deliver_to = apply_message_filter_rules(ea, msg)
    assert deliver_to == [folder]

    # Make a new email, since the from is guaranteed to be different this will
    # NOT atch our rule.
    #
    msg = email_factory()
    deliver_to = apply_message_filter_rules(ea, msg)
    assert len(deliver_to) == 0


####################################################################
#
def test_deliver_message_locally(
    email_account_factory, message_filter_rule_factory, email_factory
):
    ea = email_account_factory()
    ea.save()
    msg = email_factory()

    deliver_message_locally(ea, msg)

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)

    # Now create a mfr and make sure the message is delivered to the proper
    # folder.
    #
    msg = email_factory()
    folder_name = "test"
    folder = mh.add_folder(folder_name)
    mfr = message_filter_rule_factory(
        email_account=ea,
        header=MessageFilterRule.FROM,
        pattern=msg["from"],
        destination=folder_name,
    )
    mfr.save()
    deliver_message_locally(ea, msg)
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_spam_locally(email_account_factory, email_factory):
    ea = email_account_factory()
    ea.save()

    # Low spam score. Should be delivered to inbox
    #
    msg = email_factory()
    msg["X-Spam-Score"] = "-0.0"

    deliver_message_locally(ea, msg)

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)

    # Set the spam score over the limit in the email account.
    #
    msg.replace_header("X-Spam-Score", str(ea.spam_score_threshold))
    deliver_message_locally(ea, msg)

    # The message should have been delivered to Junk since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder(ea.spam_delivery_folder)
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_alias(email_account_factory, email_factory):
    ea_1 = email_account_factory(delivery_method=EmailAccount.ALIAS)
    ea_1.save()
    ea_2 = email_account_factory()
    ea_2.save()
    ea_1.alias_for.add(ea_2)

    # Messages being delivered to ea1 will be delivered to ea2.
    #
    msg = email_factory()
    deliver_message(ea_1, msg)

    # The message should have been delivered to the inbox of ea_2.
    #
    mh = ea_2.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)

    # Create another level of aliasing.
    ea_3 = email_account_factory()
    ea_3.save()
    ea_2.alias_for.add(ea_3)
    ea_2.delivery_method = EmailAccount.ALIAS
    ea_2.save()

    # message sent to ea_1 will be delivered to ea_3
    #
    msg = email_factory()
    deliver_message(ea_1, msg)
    mh = ea_3.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_to_multiple_aliases(email_account_factory, email_factory):
    ea_1 = email_account_factory(delivery_method=EmailAccount.ALIAS)
    ea_1.save()
    ea_2 = email_account_factory()
    ea_2.save()
    ea_3 = email_account_factory()
    ea_3.save()

    ea_1.alias_for.add(ea_2)
    ea_1.alias_for.add(ea_3)

    msg = email_factory()
    deliver_message(ea_1, msg)

    mh_2 = ea_2.MH()
    folder = mh_2.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)

    mh_3 = ea_3.MH()
    folder = mh_3.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_email_account_alias_depth(
    email_account_factory, email_factory, caplog
):
    """
    we only let an alias go three deep. if we try to alias more than that
    it will be delivered at a higher level. also a warning will be logged.
    """
    # Make a list of email accounts, aliasing them to the next account.
    email_accounts = []
    prev_ea = None
    for i in range(EmailAccount.MAX_ALIAS_DEPTH + 2):
        ea = email_account_factory(delivery_method=EmailAccount.ALIAS)
        ea.save()
        email_accounts.append(ea)

        if prev_ea:
            prev_ea.alias_for.add(ea)
        prev_ea = ea

    # The message should be delivered to the max alias depth email
    # account. Also a message should have been logged about this.
    #
    msg = email_factory()
    deliver_message(email_accounts[0], msg)

    assert "Deliver recursion too deep for message" in caplog.text

    ea = email_accounts[EmailAccount.MAX_ALIAS_DEPTH]
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_forwarding(email_account_factory, email_factory, smtp):
    """
    Test forwarding of the message by having the original message attached
    as an rfc822 attachment, the original content text being in the new
    message.
    """
    ea_1 = email_account_factory(
        delivery_method=EmailAccount.FORWARDING,
        forward_to=factory.Faker("email"),
    )
    ea_1.save()

    msg = email_factory()
    original_from = msg["From"]
    original_subj = msg["Subject"]

    deliver_message(ea_1, msg)

    # NOTE: in the models object we create a smtp_client. On the smtp_client
    #       the only thing we care about is that the `send_message` method was
    #       called with the appropriate values.
    #
    send_message = smtp.return_value.send_message
    assert send_message.call_count == 1
    assert send_message.call_args.kwargs == {
        "from_addr": ea_1.email_address,
        "to_addrs": [ea_1.forward_to],
    }

    sent_message = send_message.call_args.args[0]
    assert sent_message["Original-From"] == original_from
    assert sent_message["Original-Recipient"] == ea_1.email_address
    assert sent_message["Resent-From"] == ea_1.email_address
    assert sent_message["Resent-To"] == ea_1.forward_to
    assert sent_message["From"] == ea_1.email_address
    assert sent_message["To"] == ea_1.forward_to
    assert sent_message["Subject"] == f"Fwd: {original_subj}"


####################################################################
#
def test_deactivated_forward(email_account_factory, email_factory):
    """
    Deactivated email accounts can receive email, can alias email, but can
    not forward email. The account that tries to forward the email has it
    delivered locally.
    """
    ea_1 = email_account_factory(
        delivery_method=EmailAccount.FORWARDING,
        forward_to=factory.Faker("email"),
        deactivated=True,
    )
    ea_1.save()

    msg = email_factory()

    # Since this account is forwarding, but it is deactivated the message will
    # be locally delivered.
    #
    deliver_message(ea_1, msg)
    mh = ea_1.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_generate_dsn(email_account_factory, email_factory):
    ea = email_account_factory()
    ea.save()
    msg = email_factory()

    from_addr = f"mailer-daemon@{ea.server.domain_name}"
    action = "failed"
    status = "5.1.1"
    subject = "DSN Message!"
    report_text = "Hey there"
    diagnostic = "smtp; email bad!"

    dsn = make_delivery_status_notification(
        ea,
        report_text=report_text,
        subject=subject,
        from_addr=from_addr,
        action=action,
        status=status,
        diagnostic=diagnostic,
        reported_msg=msg,
    )

    assert dsn["From"] == from_addr
    assert dsn["To"] == ea.email_address
    assert dsn["Subject"] == subject
    assert dsn.is_multipart()

    # And not going to really look at the parts.. just make sure they match
    # what we expect.
    #
    expected = [
        "multipart/report",
        "text/plain",
        "message/delivery-status",
        "text/plain",
        "message/rfc822",
        "multipart/alternative",
        "text/plain",
        "text/html",
    ]
    results = [part.get_content_type() for part in dsn.walk()]
    assert expected == results


####################################################################
#
def test_generate_forwarded_message(
    email_account_factory,
    email_factory,
    faker,
):
    """
    Do a cursory test of our function that generates a forwarded email
    """
    forward_to = faker.email()
    ea = email_account_factory(
        delivery_method=EmailAccount.FORWARDING, forward_to=forward_to
    )
    ea.save()
    msg = email_factory(msg_from=ea.email_address)

    forwarded_msg = make_encapsulated_fwd_msg(ea, msg)

    assert forwarded_msg["From"] == ea.email_address
    assert forwarded_msg["To"] == ea.forward_to
    assert forwarded_msg["Reply-To"] == msg["From"]
    assert forwarded_msg["Original-From"] == msg["From"]
    assert forwarded_msg["Original-Recipient"] == ea.email_address
    assert forwarded_msg["Resent-From"] == ea.email_address
    assert forwarded_msg["Resent-To"] == ea.forward_to

    expected = [
        "multipart/mixed",
        "text/plain",
        "message/rfc822",
        "multipart/alternative",
        "text/plain",
        "text/html",
    ]
    results = [part.get_content_type() for part in forwarded_msg.walk()]
    assert expected == results

    # Look for the first message/rfc822 part. That should be our
    # forwarded message. It should be the third part of our message.
    #
    for part in forwarded_msg.walk():
        if part.get_content_type == "message/rfc822":
            assert part.get_content().as_bytes() == msg.as_bytes()
            break


####################################################################
#
def test_report_failed_message(
    email_account_factory, email_factory, caplog, faker
):
    ea = email_account_factory()
    ea.save()
    msg = email_factory(msg_from=ea.email_address)

    report_failed_message(
        ea,
        msg,
        report_text="Unable to send email",
        subject=f"Failed to send: {msg['Subject']}",
        action="failed",
        status="5.1.1",
        diagnostic="smtp; yo buddy",
    )

    # Should now be a message in ea's local mail inbox. Note, we have other
    # tests for the contents of the DSN so we do not quibble much here except
    # to make sure that the message was delivered locally.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert stored_msg["From"] == f"mailer-daemon@{ea.server.domain_name}"

    # if we try to send email address being a string should also work.
    #
    report_failed_message(
        ea.email_address,
        msg,
        report_text="Unable to send email",
        subject=f"Failed to send: {msg['Subject']}",
        action="failed",
        status="5.1.1",
        diagnostic="smtp; yo buddy",
    )

    # Should now be a message in ea's local mail inbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(2)
    assert stored_msg["From"] == f"mailer-daemon@{ea.server.domain_name}"

    # And we if try to send to an invalid email address we get a log message.
    #
    caplog.clear()
    bad_email = faker.email()
    report_failed_message(
        bad_email,
        msg,
        report_text="Unable to send email",
        subject=f"Failed to send: {msg['Subject']}",
        action="failed",
        status="5.1.1",
        diagnostic="smtp; yo buddy",
    )
    assert f"Failed to lookup EmailAccount for '{bad_email}'" in caplog.text
