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
)
from ..models import EmailAccount, MessageFilterRule

pytestmark = pytest.mark.django_db


####################################################################
#
def assert_email_equal(msg1, msg2, ignore_headers=False):
    """
    Because we can not directly compare a Message and EmailMessage object
    we need to compare their parts. Since an EmailMessage is a sub-class of
    Message it will have all the same methods necessary for comparison.
    """
    # Compare all headers, unless we are ignoring them.
    #
    if ignore_headers is False:
        assert msg1.items() == msg2.items()

    # If we are ignoring only some headers, then skip those.
    #
    if isinstance(ignore_headers, list):
        ignore_headers = [x.lower() for x in ignore_headers]
        for header, value in msg1.items():
            if header.lower() in ignore_headers:
                continue
            assert msg2[header] != value

    assert msg1.is_multipart() == msg2.is_multipart()

    # If not multipart, the payload should be the same.
    #
    if not msg1.is_multipart():
        assert msg1.get_payload() == msg2.get_payload()

    # Otherwise, compare each part.
    #
    parts1 = msg1.get_payload()
    parts2 = msg2.get_payload()
    assert len(parts1) == len(parts2)

    for part1, part2 in zip(parts1, parts2):
        assert part1.get_payload() == part2.get_payload()


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
def test_deliver_alias(email_account_factory, email_factory):
    ea_1 = email_account_factory(account_type=EmailAccount.ALIAS)
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
    ea_2.account_type = EmailAccount.ALIAS
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
    ea_1 = email_account_factory(account_type=EmailAccount.ALIAS)
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
        ea = email_account_factory(account_type=EmailAccount.ALIAS)
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
def test_resent_forwarding(email_account_factory, email_factory, smtp):
    """
    Test forwarding of the message by having some headers re-written, the
    subject modified but the message otherwise sent on as it is.
    """
    ea_1 = email_account_factory(
        account_type=EmailAccount.FORWARDING,
        forward_style=EmailAccount.FORWARD_RESEND,
        forward_to=factory.Faker("email"),
    )
    ea_1.save()

    msg = email_factory()
    original_to = msg["To"]
    original_from = msg["From"]
    original_subj = msg["Subject"]

    deliver_message(ea_1, msg)

    # The message should have been delivered to our smtp mock using the
    # `send_message` call.
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
    assert sent_message["To"] == original_to
    assert sent_message["Subject"] == f"Fwd: {original_subj}"

    assert_email_equal(msg, sent_message, ignore_headers=True)


####################################################################
#
def test_encapsulate_forwarding(email_account_factory, email_factory, smtp):
    """
    Test forwarding of the message by having the original message attached
    as an rfc822 attachment, the original content text being in the new
    message.
    """
    ea_1 = email_account_factory(
        account_type=EmailAccount.FORWARDING,
        forward_style=EmailAccount.FORWARD_ENCAPSULTE,
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

    # Look for the first message/rfc822 attachement. That should be our
    # forwarded message.
    #
    for attachment in sent_message.iter_attachments():
        if attachment.get_content_type() == "message/rfc822":
            print(attachment.get_payload(decode=True))
            assert attachment.get_payload(decode=True) == msg.as_bytes()


####################################################################
#
def test_deactivated_forward(email_account_factory, email_factory):
    """
    Deactivated email accounts can receive email, can alias email, but can
    not forward email. The account that tries to forward the email has it
    delivered locally.
    """
    ea_1 = email_account_factory(
        account_type=EmailAccount.FORWARDING,
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
