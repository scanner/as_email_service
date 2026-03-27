#!/usr/bin/env python
#
"""
Test the various functions in the `deliver` module
"""

# system imports
#
from collections.abc import Callable
from email.message import EmailMessage
from typing import cast

# 3rd party imports
#
import pytest
from faker import Faker
from pytest_mock import MockerFixture

# Project imports
#
from ..deliver import (
    apply_message_filter_rules,
    deliver_message_locally,
    make_delivery_status_notification,
    report_failed_message,
)
from ..models import (
    AliasToDelivery,
    EmailAccount,
    LocalDelivery,
    MessageFilterRule,
)
from .conftest import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
def test_apply_message_filter_rules(
    email_account_factory: Callable[..., EmailAccount],
    message_filter_rule_factory: Callable[..., MessageFilterRule],
    email_factory: Callable[..., EmailMessage],
) -> None:
    ea = email_account_factory()
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

    # Make a new email — the from is guaranteed to be different, so this will
    # NOT match our rule.
    #
    msg = email_factory()
    deliver_to = apply_message_filter_rules(ea, msg)
    assert len(deliver_to) == 0


####################################################################
#
def test_deliver_message_locally(
    email_account_factory: Callable[..., EmailAccount],
    message_filter_rule_factory: Callable[..., MessageFilterRule],
    email_factory: Callable[..., EmailMessage],
) -> None:
    ea = email_account_factory()
    ld = LocalDelivery.objects.get(email_account=ea)
    msg = email_factory()

    deliver_message_locally(ld, msg)

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ld.MH()
    folder = mh.get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
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
    deliver_message_locally(ld, msg)
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_spam_locally(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
) -> None:
    ea = email_account_factory()
    ld = LocalDelivery.objects.get(email_account=ea)

    # Low spam score — should be delivered to inbox.
    #
    msg = email_factory()
    msg["X-Spam-Status"] = "No, score=-0.0 required=5.0 tests=NONE"

    deliver_message_locally(ld, msg)

    mh = ld.MH()
    folder = mh.get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)

    # Set the spam score over the limit configured on the LocalDelivery.
    #
    msg.replace_header(
        "X-Spam-Status",
        f"Yes, score={ld.spam_score_threshold}.0 required=5.0 tests=NONE",
    )
    deliver_message_locally(ld, msg)

    # The message should land in the spam folder.
    #
    folder = mh.get_folder(ld.spam_delivery_folder)
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_alias(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
) -> None:
    """
    Messages delivered to an alias-only account are forwarded to the target.
    """
    # ea_1 has no local delivery — it only has an alias to ea_2.
    #
    ea_1 = email_account_factory(local_delivery=False)
    ea_2 = email_account_factory()
    AliasToDelivery.objects.create(email_account=ea_1, target_account=ea_2)

    msg = email_factory()
    ea_1.deliver(msg)

    # The message should have landed in ea_2's inbox.
    #
    ld_2 = LocalDelivery.objects.get(email_account=ea_2)
    mh = ld_2.MH()
    folder = mh.get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)

    # Create another level of aliasing: ea_2 (alias-only) → ea_3 (local).
    #
    ld_2.delete()  # remove ea_2's local delivery to make it alias-only
    ea_3 = email_account_factory()
    AliasToDelivery.objects.create(email_account=ea_2, target_account=ea_3)

    msg = email_factory()
    ea_1.deliver(msg)

    # Message sent to ea_1 should now land in ea_3's inbox.
    #
    ld_3 = LocalDelivery.objects.get(email_account=ea_3)
    mh = ld_3.MH()
    folder = mh.get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_to_multiple_aliases(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
) -> None:
    """
    An account with multiple AliasToDelivery entries delivers to all targets.
    """
    ea_1 = email_account_factory(local_delivery=False)
    ea_2 = email_account_factory()
    ea_3 = email_account_factory()
    AliasToDelivery.objects.create(email_account=ea_1, target_account=ea_2)
    AliasToDelivery.objects.create(email_account=ea_1, target_account=ea_3)

    msg = email_factory()
    ea_1.deliver(msg)

    ld_2 = LocalDelivery.objects.get(email_account=ea_2)
    folder = ld_2.MH().get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)

    ld_3 = LocalDelivery.objects.get(email_account=ea_3)
    folder = ld_3.MH().get_folder("inbox")
    stored_msg = cast(EmailMessage, folder.get(str(1)))
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_deliver_alias_loop_detection(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    GIVEN a cycle in alias targets (A → B → A)
    WHEN  a message is delivered to A
    THEN  the loop is detected, a warning is logged, and delivery stops
          cleanly (no infinite recursion).
    """
    ea_a = email_account_factory(local_delivery=False)
    ea_b = email_account_factory(local_delivery=False)
    AliasToDelivery.objects.create(email_account=ea_a, target_account=ea_b)
    AliasToDelivery.objects.create(email_account=ea_b, target_account=ea_a)

    msg = email_factory()
    ea_a.deliver(msg)

    assert "Alias loop detected" in caplog.text


####################################################################
#
def test_deliver_alias_hop_limit(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    caplog: pytest.LogCaptureFixture,
    mocker: MockerFixture,
) -> None:
    """
    GIVEN a chain of alias accounts longer than MAX_HOPS
    WHEN  a message is delivered to the first account
    THEN  the hop limit fires, a warning is logged, and delivery stops.
    """
    # Patch MAX_HOPS to 2 so we only need a small chain.
    #
    mocker.patch.object(AliasToDelivery, "MAX_HOPS", 2)

    # Chain: ea_0 → ea_1 → ea_2 → ea_3 (all alias-only; ea_3 never reached).
    #
    accounts = [email_account_factory(local_delivery=False) for _ in range(4)]
    for i in range(3):
        AliasToDelivery.objects.create(
            email_account=accounts[i], target_account=accounts[i + 1]
        )

    msg = email_factory()
    accounts[0].deliver(msg)

    assert "Alias hop limit" in caplog.text


####################################################################
#
def test_generate_dsn(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
) -> None:
    ea = email_account_factory()
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
def test_report_failed_message(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    caplog: pytest.LogCaptureFixture,
    faker: Faker,
) -> None:
    ea = email_account_factory()
    ld = LocalDelivery.objects.get(email_account=ea)
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

    # Should now be a message in ea's local mail inbox.
    #
    mh = ld.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(str(1))
    assert stored_msg is not None
    assert stored_msg["From"] == f"mailer-daemon@{ea.server.domain_name}"

    # Passing the email address as a string should also work.
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

    folder = mh.get_folder("inbox")
    stored_msg = folder.get(str(2))
    assert stored_msg is not None
    assert stored_msg["From"] == f"mailer-daemon@{ea.server.domain_name}"

    # An invalid email address should log an error and not raise.
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
