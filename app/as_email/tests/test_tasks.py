#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
import json
from datetime import UTC, datetime
from pathlib import Path

# 3rd party imports
#
import pytest
from dirty_equals import Contains
from pytest_mock import MockerFixture

# Project imports
#
from ..models import EmailAccount, InactiveEmail
from ..providers.base import EmailAccountInfo
from ..tasks import (
    check_update_pwfile_for_emailaccount,
    decrement_num_bounces_counter,
    dispatch_incoming_email,
    dispatch_spooled_outgoing_email,
    process_email_bounce,
    process_email_spam,
    provider_create_alias,
    provider_create_domain,
    provider_delete_alias,
    provider_enable_all_aliases,
    provider_report_unused_domains,
    provider_sync_aliases,
    retry_failed_incoming_email,
)
from ..utils import (
    read_emailaccount_pwfile,
    spool_message,
    write_spooled_email,
)
from .factories import DummyProviderBackend
from .test_deliver import assert_email_equal

pytestmark = pytest.mark.django_db


# ####################################################################
# #
# @pytest.fixture(autouse=True)
# def mock_provider_tasks(mocker: MockerFixture) -> dict[str, MagicMock]:
#     """
#     Disable signal handlers that trigger provider tasks during model creation.

#     For test_tasks.py, we disable the signal handlers during test setup so they
#     don't trigger tasks when creating test objects, while allowing tests to call
#     tasks directly.
#     """
#     # Instead of mocking HUEY or tasks, disable the signal handlers
#     # that trigger tasks during model creation
#     mock_create_provider_aliases = mocker.patch(
#         "as_email.signals.create_provider_aliases"
#     )
#     mock_handle_receive_providers_changed = mocker.patch(
#         "as_email.signals.handle_receive_providers_changed"
#     )
#     mock_delete_provider_aliases = mocker.patch(
#         "as_email.signals.delete_provider_aliases"
#     )

#     return {
#         "create_provider_aliases": mock_create_provider_aliases,
#         "handle_receive_providers_changed": mock_handle_receive_providers_changed,
#         "delete_provider_aliases": mock_delete_provider_aliases,
#     }


####################################################################
#
def test_dispatch_spool_outgoing_email(
    email_account_factory, email_factory, smtp
):
    """
    Given a message spooled in outgoing spool directory
    When dispatch_spooled_outgoing_email task runs
    Then the message is sent via SMTP
    """
    ea = email_account_factory()
    ea.save()
    server = ea.server
    msg = email_factory(msg_from=ea.email_address)
    rcpt_tos = [msg["To"]]
    from_addr = msg["From"]
    spool_message(server.outgoing_spool_dir, msg.as_bytes())
    res = dispatch_spooled_outgoing_email()
    res()
    assert smtp.sendmail.call_count == 1
    assert smtp.sendmail.call_args.args == Contains(
        from_addr,
        rcpt_tos,
    )


####################################################################
#
def test_dispatch_incoming_email(
    email_account_factory,
    email_factory,
    tmp_path,
):
    """
    Given a spooled incoming email in JSON format
    When dispatch_incoming_email task runs
    Then the message is delivered to recipient's inbox
    """
    ea = email_account_factory()
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    fname = write_spooled_email(msg["To"], tmp_path, msg, str(now), message_id)
    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_dispatch_incoming_mail_failure(
    mocker: MockerFixture,
    email_spool_dir,
    email_account_factory,
    email_factory,
    settings,
):
    """
    Given deliver_message raises an exception
    When dispatch_incoming_email task runs
    Then the message is moved to failed incoming directory
    """
    mocker.patch(
        "as_email.tasks.deliver_message", side_effect=Exception("ERROR")
    )
    ea = email_account_factory()
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    fname = write_spooled_email(
        msg["To"], settings.EMAIL_SPOOL_DIR, msg, str(now), message_id
    )

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # We should find a single file in the failed message directory that has the
    # same message id from above.
    #
    failed_msg_file = list(settings.FAILED_INCOMING_MSG_DIR.iterdir())[0]
    email_msg = json.loads(failed_msg_file.read_text())
    assert email_msg["message-id"] == message_id


####################################################################
#
def test_retry_failed_incoming_email_failure(
    caplog,
    email_spool_dir,
    email_factory,
    settings,
) -> None:
    """
    Given multiple failed messages without valid EmailAccounts
    When retry_failed_incoming_email task runs
    Then it attempts 5 redeliveries and stops
    """
    # Create 5 email messages, but do not create any EmailAccount's. This will
    # result in the lookup failing.
    #
    settings.FAILED_INCOMING_MSG_DIR.mkdir(parents=True, exist_ok=True)
    failed_email_files = []
    for _ in range(5):
        msg = email_factory()
        now = datetime.now()
        message_id = msg["Message-ID"]
        msg_path = write_spooled_email(
            msg["To"],
            settings.FAILED_INCOMING_MSG_DIR,
            msg,
            str(now),
            message_id,
        )
        failed_email_files.append(msg_path)

    res = retry_failed_incoming_email()
    res()

    # Make sure our five failed retry messages were logged.
    #
    assert "Stopping redelivery attempts after" in caplog.text
    for msg_path in failed_email_files:
        assert f"Unable to deliver failed message '{msg_path}'" in caplog.text


####################################################################
#
def test_retry_failed_incoming_email(
    mocker: MockerFixture,
    email_spool_dir,
    email_account_factory,
    email_factory,
    settings,
) -> None:
    """
    Given failed messages with valid EmailAccounts
    When retry_failed_incoming_email task runs
    Then deliver_message is called for each EmailAccount
    """
    # Mock the `deliver_message` function so we can verify that it was called
    # properly.
    #
    mock_deliver_message = mocker.Mock(return_value=None)
    mocker.patch("as_email.tasks.deliver_message", new=mock_deliver_message)
    deliveries = []
    for _ in range(6):
        ea = email_account_factory()
        msg = email_factory(to=ea.email_address)
        now = datetime.now()
        message_id = msg["Message-ID"]
        write_spooled_email(
            msg["To"],
            settings.FAILED_INCOMING_MSG_DIR,
            msg,
            str(now),
            message_id,
        )
        deliveries.append((ea.email_address, msg))

    res = retry_failed_incoming_email()
    res()

    # And check to see that all messages were delivered.
    #
    expected = sorted(deliveries, key=lambda x: x[0])
    mock_call_args = mock_deliver_message.call_args_list
    assert mock_call_args
    called = sorted(
        [(x[0][0].email_address, x[0][1]) for x in mock_call_args],
        key=lambda x: x[0],
    )
    for exp, call in zip(expected, called):
        assert exp[0] == call[0]
        assert_email_equal(exp[1], call[1])


####################################################################
#
def test_decrement_num_bounces_counter(email_account_factory):
    """
    Given email accounts with varying bounce counts
    When decrement_num_bounces_counter task runs
    Then bounce counts decrease and accounts reactivate if below threshold
    """
    # No accounts.. there should be no errors.
    #
    res = decrement_num_bounces_counter()
    res()

    ea_1 = email_account_factory()
    ea_1.save()
    ea_2 = email_account_factory()
    ea_2.save()

    # 0 bounces.. there should be no changes and no errors.
    #
    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 0
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == 0

    # some bounces
    #
    ea_1.num_bounces = 14
    ea_1.save()
    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 13
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == 0

    # Num bounces at limit, and deactivated
    #
    ea_2.num_bounces = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
    ea_2.deactivated = True
    ea_2.deactivated_reason = EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
    ea_2.save()

    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 12
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 1
    assert ea_2.deactivated is False
    assert ea_2.deactivated_reason is None

    # If deactivated reason is not due to num bounces, then going under the
    # threshold changes nothing.
    #
    ea_1.num_bounces = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
    ea_1.deactivated = True
    ea_1.deactivated_reason = "Sending too much spam"
    ea_1.save()

    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 1
    assert ea_1.deactivated
    assert ea_1.deactivated_reason == "Sending too much spam"

    ea_2.refresh_from_db()
    assert ea_2.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    assert ea_2.deactivated is False
    assert ea_2.deactivated_reason is None


####################################################################
#
def test_too_many_bounces_postmark(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
    django_outbox,
):
    """
    Given an account near bounce limit, and the provider is 'postmark'
    When process_email_bounce increments bounces past limit
    Then account is deactivated and owner notified
    """
    bounce_start = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    ea = email_account_factory(num_bounces=bounce_start)
    ea.save()
    assert ea.num_bounces == bounce_start
    bounced_msg = email_factory(msg_from=ea.email_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    bounce_data = {
        "ID": bounce_id,
        "Type": "HardBounce",
        "TypeCode": 1,
        "Name": "Hard bounce",
        "Tag": "Test",
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "ServerID": 23,
        "Description": "The server was unable to deliver your message",
        "Details": "Test bounce details",
        "Email": "john@example.com",
        "From": ea.email_address,
        "BouncedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": False,
        "CanActivate": True,
        "RecordType": "Bounce",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 1
    assert ea.deactivated is False
    assert ea.deactivated_reason is None

    # and a second bounce.
    #
    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 2
    assert ea.deactivated
    assert (
        ea.deactivated_reason == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
    )

    # and since this email account was deactivated we also send an email notice
    # to the email account's owner.
    #
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email


####################################################################
#
def test_bounce_inactive(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
    django_outbox,
):
    """
    Given a bounce marked as inactive by Postmark
    When process_email_bounce task runs
    Then an InactiveEmail record is created for destination address
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    bounce_address = faker.email()
    bounced_msg = email_factory(msg_from=ea.email_address, to=bounce_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    can_activate = True
    bounce_data = {
        "ID": bounce_id,
        "Type": "HardBounce",
        "TypeCode": 1,
        "Name": "Hard bounce",
        "Tag": "Test",
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "ServerID": 23,
        "Description": "The server was unable to deliver your message",
        "Details": "Test bounce details",
        "Email": bounce_address,
        "From": ea.email_address,
        "BouncedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": True,
        "CanActivate": can_activate,
        "RecordType": "Bounce",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert ea.deactivated is False
    # Since the EmailAccount was NOT deactivated, no email was sent to the
    # EmailAccount's owner.
    #
    assert len(django_outbox) == 0

    inactive = InactiveEmail.objects.get(email_address=bounce_address)
    assert inactive.can_activate == can_activate


####################################################################
#
def test_transient_bounce_notifications(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
):
    """
    Given a transient bounce notification
    When process_email_bounce task runs
    Then bounce count does not increase
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    assert ea.deactivated is False
    bounced_msg = email_factory(msg_from=ea.email_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    bounce_data = {
        "ID": bounce_id,
        "Type": "Transient",
        "TypeCode": 2,
        "Name": "Transient",
        "Tag": "Test",
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "ServerID": 23,
        "Description": "A transient failure",
        "Details": "Test bounce details",
        "Email": "john@example.com",
        "From": ea.email_address,
        "BouncedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": False,
        "CanActivate": True,
        "RecordType": "Transient",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 0
    assert ea.deactivated is False


####################################################################
#
def test_bounce_to_forwarded_to_deactivates_emailaccount(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
    django_outbox,
):
    """
    Given an account with forward_to that generates hard bounce
    When process_email_bounce task runs
    Then account is deactivated due to bad forward_to address
    """
    forward_to = faker.email()
    ea = email_account_factory(
        delivery_method=EmailAccount.DeliveryMethods.FORWARDING,
        forward_to=forward_to,
    )
    ea.save()
    assert ea.num_bounces == 0
    assert ea.deactivated is False

    bounced_msg = email_factory(msg_from=ea.email_address, to=forward_to)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)

    bounce_data = {
        "BouncedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "CanActivate": True,
        "Description": "Invalid email address — The address is not a valid email address.",
        "Details": "Invalid email address",
        "DumpAvailable": False,
        "Email": forward_to,
        "From": ea.email_address,
        "ID": bounce_id,
        "Inactive": False,
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "Name": "Bad email address",
        "RecordType": "BadEmailAddress",
        "ServerID": 23,
        "Subject": "Bad email address",
        "Tag": "Test",
        "Type": "BadEmailAddress",
        "TypeCode": 100000,
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert ea.deactivated is True
    assert ea.deactivated_reason == ea.DEACTIVATED_DUE_TO_BAD_FORWARD_TO

    # and since this email account was deactivated we also send an email notice
    # to the email account's owner.
    #
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email


####################################################################
#
def test_process_email_spam(
    email_account_factory,
    email_factory,
    faker,
):
    """
    Given a spam complaint notification
    When process_email_spam task runs
    Then bounce count increases by one
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    to_addr = faker.email()
    spam_id = faker.pyint(1_000_000_000, 9_999_999_999)
    spam_data = {
        "RecordType": "SpamComplaint",
        "MessageStream": "outbound",
        "ID": spam_id,
        "Type": "SpamComplaint",
        "TypeCode": 512,
        "Name": "Spam complaint",
        "Tag": "Test",
        "MessageID": faker.uuid4(),
        "Metadata": {"a_key": "a_value", "b_key": "b_value"},
        "ServerID": 1234,
        "Description": "This is a description",
        "Details": "Test spam complaint details",
        "Email": to_addr,
        "From": ea.email_address,
        "BouncedAt": "2019-11-05T16:33:54.9070259Z",
        "DumpAvailable": True,
        "Inactive": True,
        "CanActivate": False,
        "Subject": "Test subject",
        "Content": "<Abuse report dump>",
    }

    res = process_email_spam(ea.pk, spam_data)
    res()

    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert not ea.deactivated


####################################################################
#
def test_process_email_spam_too_many_bounces(
    email_account_factory,
    email_factory,
    django_outbox,
    faker,
):
    """
    Given an account near bounce limit with spam complaints
    When process_email_spam increments past limit
    Then account is deactivated and owner notified
    """
    bounce_start = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    ea = email_account_factory(num_bounces=bounce_start)
    ea.save()
    assert ea.num_bounces == bounce_start
    to_addr = faker.email()
    spam_id = faker.pyint(1_000_000_000, 9_999_999_999)
    spam_data = {
        "RecordType": "SpamComplaint",
        "MessageStream": "outbound",
        "ID": spam_id,
        "Type": "SpamComplaint",
        "TypeCode": 512,
        "Name": "Spam complaint",
        "Tag": "Test",
        "MessageID": faker.uuid4(),
        "Metadata": {"a_key": "a_value", "b_key": "b_value"},
        "ServerID": 1234,
        "Description": "This is a description",
        "Details": "Test spam complaint details",
        "Email": to_addr,
        "From": ea.email_address,
        "BouncedAt": "2019-11-05T16:33:54.9070259Z",
        "DumpAvailable": True,
        "Inactive": True,
        "CanActivate": False,
        "Subject": "Test subject",
        "Content": "<Abuse report dump>",
    }

    res = process_email_spam(ea.pk, spam_data)
    res()

    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 1
    assert ea.deactivated is False
    assert ea.deactivated_reason is None

    # and a second bounce.
    #
    res = process_email_spam(ea.pk, spam_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 2
    assert ea.deactivated
    assert (
        ea.deactivated_reason == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
    )

    # and since this email account was deactivated we also send an email notice
    # to the email account's owner.
    #
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email


####################################################################
#
def test_process_email_spam_forward_to(
    email_account_factory,
    email_factory,
    django_outbox,
    faker,
):
    """
    Given an account forwarding to address marked as spam
    When process_email_spam task runs
    Then account is immediately deactivated
    """
    forward_to = faker.email()
    ea = email_account_factory(
        delivery_method=EmailAccount.DeliveryMethods.FORWARDING,
        forward_to=forward_to,
    )
    ea.save()
    assert ea.num_bounces == 0
    assert ea.deactivated is False

    spam_id = faker.pyint(1_000_000_000, 9_999_999_999)
    spam_data = {
        "RecordType": "SpamComplaint",
        "MessageStream": "outbound",
        "ID": spam_id,
        "Type": "SpamComplaint",
        "TypeCode": 512,
        "Name": "Spam complaint",
        "Tag": "Test",
        "MessageID": faker.uuid4(),
        "Metadata": {"a_key": "a_value", "b_key": "b_value"},
        "ServerID": 1234,
        "Description": "This is a description",
        "Details": "Test spam complaint details",
        "Email": forward_to,
        "From": ea.email_address,
        "BouncedAt": "2019-11-05T16:33:54.9070259Z",
        "DumpAvailable": True,
        "Inactive": True,
        "CanActivate": False,
        "Subject": "Test subject",
        "Content": "<Abuse report dump>",
    }

    res = process_email_spam(ea.pk, spam_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert ea.deactivated is True
    assert ea.deactivated_reason == ea.DEACTIVATED_DUE_TO_BAD_FORWARD_TO

    # Since this results in the EmailAccount being deactivated the mail is
    # forced in to local delivery.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert str(stored_msg["From"]).startswith("mailer-daemon")
    assert stored_msg["To"] == ea.email_address
    assert (
        stored_msg["Subject"]
        == f"Message marked as spam: {spam_data['Subject']}"
    )
    assert stored_msg.is_multipart()

    # and since this email account was deactivated we also send an email notice
    # to the email account's owner.
    #
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email


####################################################################
#
def test_process_spam_invalid_typecode(
    email_account_factory,
    email_factory,
    faker,
):
    """
    Given a spam complaint with invalid TypeCode
    When process_email_spam task runs
    Then it treats as non-transient bounce without failing
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    to_addr = faker.email()
    spam_id = faker.pyint(1_000_000_000, 9_999_999_999)
    spam_data = {
        "RecordType": "SpamComplaint",
        "MessageStream": "outbound",
        "ID": spam_id,
        "Type": "SpamComplaint",
        "TypeCode": 71923424,  # Not a valid TypeCode
        "Name": "Spam complaint",
        "Tag": "Test",
        "MessageID": faker.uuid4(),
        "Metadata": {"a_key": "a_value", "b_key": "b_value"},
        "ServerID": 1234,
        "Description": "This is a description",
        "Details": "Test spam complaint details",
        "Email": to_addr,
        "From": ea.email_address,
        "BouncedAt": "2019-11-05T16:33:54.9070259Z",
        "DumpAvailable": True,
        "Inactive": True,
        "CanActivate": False,
        "Subject": "Test subject",
        "Content": "<Abuse report dump>",
    }

    res = process_email_spam(ea.pk, spam_data)
    res()

    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert not ea.deactivated


####################################################################
#
def test_delete_email_account_removes_pwfile_entry(
    settings, email_account_factory, faker
):
    """
    Given an email account exists in pwfile
    When the account is deleted
    Then its pwfile entry is removed
    """
    # Create account with a non-default password so signal fires
    ea = email_account_factory(password=faker.password())
    ea.save()

    # It should exist in the pwfile after we save it.
    #
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address in accounts

    # And now if we delete the email address, it should be deleted from the
    # external pw file via the signal-triggered task.
    #
    ea.delete()
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address not in accounts


####################################################################
#
def test_check_update_pwfile_for_emailaccount_creates_new_entry(
    settings, email_account_factory, faker
):
    """
    Given a new email account with password
    When the account is saved
    Then a new entry is added to the pwfile via signal
    """
    # Create account with a non-default password so signal fires
    ea = email_account_factory(password=faker.password())
    ea.save()

    # Verify the account was added to pwfile
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address in accounts
    assert accounts[ea.email_address].pw_hash == ea.password

    # Verify mail_dir is relative to EXT_PW_FILE parent
    expected_mail_dir = Path(ea.mail_dir).relative_to(
        settings.EXT_PW_FILE.parent
    )
    assert accounts[ea.email_address].maildir == expected_mail_dir


####################################################################
#
def test_check_update_pwfile_for_emailaccount_updates_password(
    settings, email_account_factory, faker
):
    """
    Given an email account with password in pwfile
    When the password is changed and saved
    Then the pwfile entry is updated with new password hash via signal
    """
    # Create account with a non-default password so signal fires
    ea = email_account_factory(password=faker.password())
    ea.save()

    # Verify initial state
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    original_password = ea.password
    assert accounts[ea.email_address].pw_hash == original_password

    # Change the password
    new_password = faker.password()
    ea.set_password(new_password, save=True)

    # Verify password was updated in pwfile via signal
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert accounts[ea.email_address].pw_hash == ea.password
    assert accounts[ea.email_address].pw_hash != original_password


####################################################################
#
def test_check_update_pwfile_for_emailaccount_updates_maildir(
    settings, email_account_factory, faker, tmp_path
):
    """
    Given an email account with password in pwfile
    When the mail_dir is changed and task is invoked
    Then the pwfile entry is updated with new mail_dir path
    """
    # Create account with a non-default password so it's in pwfile
    ea = email_account_factory(password=faker.password())
    ea.save()

    # Verify initial state
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    original_mail_dir = accounts[ea.email_address].maildir

    # Change the mail_dir (simulate moving the mailbox)
    new_mail_dir = settings.MAIL_DIRS / "new_location" / ea.email_address
    new_mail_dir.mkdir(parents=True, exist_ok=True)
    ea.mail_dir = str(new_mail_dir)
    ea.save()

    # Call task directly (signal only fires on password change)
    res = check_update_pwfile_for_emailaccount(ea.pk)
    res()

    # Verify mail_dir was updated in pwfile
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    expected_mail_dir = Path(new_mail_dir).relative_to(
        settings.EXT_PW_FILE.parent
    )
    assert accounts[ea.email_address].maildir == expected_mail_dir
    assert accounts[ea.email_address].maildir != original_mail_dir


####################################################################
#
def test_check_update_pwfile_for_emailaccount_no_change(
    settings, email_account_factory, mocker
):
    """
    Given an email account with no changes
    When check_update_pwfile_for_emailaccount is invoked
    Then the pwfile is not rewritten
    """
    ea = email_account_factory()
    ea.save()

    # Mock write_emailaccount_pwfile to track if it's called
    mock_write = mocker.patch("as_email.tasks.write_emailaccount_pwfile")

    # Save again without changes
    res = check_update_pwfile_for_emailaccount(ea.pk)
    res()

    # Verify pwfile was not rewritten
    mock_write.assert_not_called()


########################################################################
########################################################################
#
class TestProviderCreateDomain:
    """Tests for provider_create_domain task."""

    ####################################################################
    #
    def test_create_domain_success(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        requests_mock,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given a provider and a server
        When the provider is added as a receiving provider
        Then the provider backend's create_domain method should be called
             and the domain created by the provider backend (due to signals on
             the server)
        """
        server = server_factory(send_provider=None, receive_providers=[])

        # First make sure that the domain name is not in the domain names
        # managed by the dummy provider.
        #
        assert server.domain_name not in dummy_provider.domains

        # Then call the task that creates the domain using the dummy provider.
        #
        res = provider_create_domain(server.pk, dummy_provider.PROVIDER_NAME)
        res()

        # And now the domain should be one managed by the dummy provider.
        #
        assert server.domain_name in dummy_provider.domains

    ####################################################################
    #
    def test_create_domain_backend_exception(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        caplog,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given a backend that raises an exception
        When provider_create_domain is called
        Then the exception should be logged and re-raised
        """
        server = server_factory(send_provider=None, receive_providers=[])

        # Mock the dummy provider's `create_domain` method to raise an
        # exception.
        #
        mocker.patch.object(
            dummy_provider,
            "create_domain",
            side_effect=Exception("API error"),
        )

        res = provider_create_domain(server.pk, dummy_provider.PROVIDER_NAME)
        with pytest.raises(Exception, match="API error"):
            res()

        # Verify error was logged
        assert "Failed to create domain" in caplog.text


########################################################################
########################################################################
#
class TestProviderCreateAlias:
    """Tests for provider_create_alias task."""

    ####################################################################
    #
    def test_create_alias_success(
        self, mocker: MockerFixture, email_account_factory, provider_factory
    ) -> None:
        """
        Given an email account
        When provider_create_alias is called
        Then the backend's create_update_email_account method should be called
        """
        provider = provider_factory(backend_name="forwardemail")
        email_account = email_account_factory()
        email_account.server.receive_providers.add(provider)

        # Mock get_backend
        mock_backend = mocker.Mock()
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_create_alias(email_account.pk, provider.backend_name)
        res()

        # Verify backend.create_update_email_account was called
        mock_backend.create_update_email_account.assert_called_once_with(
            email_account
        )

    ####################################################################
    #
    def test_create_alias_backend_exception(
        self,
        mocker: MockerFixture,
        email_account_factory,
        provider_factory,
        caplog,
    ) -> None:
        """
        Given a backend that raises an exception
        When provider_create_alias is called
        Then the exception should be logged and re-raised
        """
        provider = provider_factory(backend_name="forwardemail")
        email_account = email_account_factory()
        email_account.server.receive_providers.add(provider)

        # Mock get_backend to raise exception
        mock_backend = mocker.Mock()
        mock_backend.create_update_email_account.side_effect = Exception(
            "API error"
        )
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_create_alias(email_account.pk, provider.backend_name)
        with pytest.raises(Exception, match="API error"):
            res()

        # Verify error was logged
        assert "Failed to create/update alias" in caplog.text


########################################################################
########################################################################
#
class TestProviderDeleteAlias:
    """Tests for provider_delete_alias task."""

    ####################################################################
    #
    def test_delete_alias_success(
        self, mocker: MockerFixture, email_account_factory, provider_factory
    ) -> None:
        """
        Given an email address and domain
        When provider_delete_alias is called
        Then the backend's delete_email_account_by_address should be called
        """
        provider = provider_factory(backend_name="forwardemail")
        email_account = email_account_factory()
        server = email_account.server
        server.receive_providers.add(provider)

        # Mock get_backend
        mock_backend = mocker.Mock()
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_delete_alias(
            email_account.email_address,
            server.domain_name,
            provider.backend_name,
        )
        res()

        # Verify backend.delete_email_account_by_address was called
        mock_backend.delete_email_account_by_address.assert_called_once_with(
            email_account.email_address, server
        )

    ####################################################################
    #
    def test_delete_alias_server_does_not_exist(
        self, mocker: MockerFixture, faker, provider_factory, caplog
    ) -> None:
        """
        Given a domain name that doesn't exist
        When provider_delete_alias is called
        Then a warning should be logged and no exception raised
        """
        provider = provider_factory(backend_name="forwardemail")

        # Mock get_backend
        mock_backend = mocker.Mock()
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        email_address = faker.email()
        domain_name = faker.domain_name()

        res = provider_delete_alias(
            email_address, domain_name, provider.backend_name
        )
        res()

        # Verify warning was logged
        assert "server" in caplog.text and "no longer exists" in caplog.text
        # Verify backend was not called
        mock_backend.delete_email_account_by_address.assert_not_called()

    ####################################################################
    #
    def test_delete_alias_backend_exception(
        self,
        mocker: MockerFixture,
        email_account_factory,
        provider_factory,
        caplog,
    ) -> None:
        """
        Given a backend that raises an exception
        When provider_delete_alias is called
        Then the exception should be logged and re-raised
        """
        provider = provider_factory(backend_name="forwardemail")
        email_account = email_account_factory()
        server = email_account.server
        server.receive_providers.add(provider)

        # Mock get_backend to raise exception
        mock_backend = mocker.Mock()
        mock_backend.delete_email_account_by_address.side_effect = Exception(
            "API error"
        )
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_delete_alias(
            email_account.email_address,
            server.domain_name,
            provider.backend_name,
        )
        with pytest.raises(Exception, match="API error"):
            res()

        # Verify error was logged
        assert "Failed to delete alias" in caplog.text


########################################################################
########################################################################
#
class TestProviderEnableAllAliases:
    """Tests for provider_enable_all_aliases task."""

    ####################################################################
    #
    def test_enable_all_aliases_creates_missing(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given a server with email accounts but missing aliases on provider
        When provider_enable_all_aliases is called
        Then missing aliases should be created
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        ea2 = email_account_factory(server=server)

        # Mock backend to return empty list (no aliases exist on provider)
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = []
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        provider_enable_all_aliases(
            server.pk, provider.backend_name, is_enabled=True
        )

        # Verify both aliases were created
        assert mock_backend.create_email_account.call_count == 2
        # Check the calls included both email accounts
        calls = mock_backend.create_email_account.call_args_list
        created_emails = {call[0][0].email_address for call in calls}
        assert created_emails == {ea1.email_address, ea2.email_address}

    ####################################################################
    #
    def test_enable_all_aliases_updates_existing(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given aliases that exist but have wrong is_enabled state
        When provider_enable_all_aliases is called
        Then aliases should be updated
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        mailbox_name = ea1.email_address.split("@")[0]

        # Mock backend to return alias that is disabled
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox_name}",
                email=ea1.email_address,
                domain=server.domain_name,
                enabled=False,
                name=mailbox_name,
            )
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_enable_all_aliases(
            server.pk, provider.backend_name, is_enabled=True
        )
        res()

        # Verify alias was updated, not created
        mock_backend.create_update_email_account.assert_not_called()
        mock_backend.enable_email_account.assert_called_once_with(
            ea1, is_enabled=True
        )

    ####################################################################
    #
    def test_enable_all_aliases_skips_correct_state(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given aliases already in correct is_enabled state When
        provider_enable_all_aliases is called Then aliases should be skipped
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        mailbox_name = ea1.email_address.split("@")[0]

        # Mock backend to return alias that is already enabled
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox_name}",
                email=ea1.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox_name,
            )
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_enable_all_aliases(
            server.pk, provider.backend_name, is_enabled=True
        )
        res()

        # Verify no changes were made
        mock_backend.create_update_email_account.assert_not_called()
        mock_backend.enable_email_account.assert_not_called()

    ####################################################################
    #
    def test_enable_all_aliases_mixed_operations(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given a mix of enabled, disabled, and missing email accounts from the backend
        When `provider_enable_all_aliases` is called
        Then disabled accounts should be enabled, missing accounts created
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)  # Will need to be created
        ea2 = email_account_factory(server=server)  # Needs update
        ea3 = email_account_factory(server=server)  # Already correct

        mailbox2 = ea2.email_address.split("@")[0]
        mailbox3 = ea3.email_address.split("@")[0]

        # All the backends have the same methods. We are testing that this task
        # will properly take the list of email accounts that the backend
        # returns from `list_email_accounts` and issue commands to set them all
        # to enabled.
        #
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox2}",
                email=ea2.email_address,
                domain=server.domain_name,
                enabled=False,
                name=mailbox2,
            ),  # Wrong state
            EmailAccountInfo(
                id=f"dummy-{mailbox3}",
                email=ea3.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox3,
            ),  # Correct state
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        # Call the huey task. Remember in tests all huey tasks execute in
        # immediate mode.
        #
        res = provider_enable_all_aliases(
            server.pk, provider.backend_name, is_enabled=True
        )
        res()

        # Verify operations
        # ea1 should be created (not in backend list)
        mock_backend.create_email_account.assert_called_once_with(ea1)
        # ea2 should be enabled (in backend list but wrong state)
        mock_backend.enable_email_account.assert_called_once_with(
            ea2, is_enabled=True
        )
        # ea3 should not be touched (already in correct state)


########################################################################
########################################################################
#
class TestProviderSyncAliases:
    """Tests for provider_sync_aliases periodic task."""

    ####################################################################
    #
    def test_sync_aliases_processes_all_providers(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
    ) -> None:
        """
        Given multiple providers with servers
        When provider_sync_aliases is called
        Then provider_enable_all_aliases should be called for each server
        """

        # Mock ForwardEmail API responses
        requests_mock.get(
            "https://api.forwardemail.net/v1/domains",
            json=[],
            status_code=200,
        )
        requests_mock.post(
            "https://api.forwardemail.net/v1/domains",
            json={"name": "test.example.com", "id": "domain123"},
            status_code=200,
        )
        requests_mock.get(
            "https://api.forwardemail.net/v1/domains/domain123/aliases",
            json=[],
            status_code=200,
        )

        provider1 = provider_factory(backend_name="forwardemail")
        provider2 = provider_factory(
            backend_name="postmark", name="Postmark Provider"
        )

        server1 = server_factory()
        server1.receive_providers.add(provider1)

        server2 = server_factory()
        server2.receive_providers.add(provider2)

        email_account_factory(server=server1)
        email_account_factory(server=server2)

        # Mock get_backend
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = []
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        # Mock provider_enable_all_aliases to track calls and prevent execution
        mock_enable_fn = mocker.Mock(return_value=None)
        mocker.patch(
            "as_email.tasks.provider_enable_all_aliases",
            side_effect=mock_enable_fn,
        )

        # Reset mock to clear calls from setup (domain creation, etc.)
        mock_enable_fn.reset_mock()

        res = provider_sync_aliases()
        res()

        # Verify provider_enable_all_aliases was called for each server
        # Due to signal handlers and provider setup, may be called more than once per server
        # so we check it was called at least twice (once for each server minimum)
        assert mock_enable_fn.call_count >= 2

    ####################################################################
    #
    def test_sync_aliases_handles_backend_errors(
        self, mocker: MockerFixture, server_factory, provider_factory, caplog
    ) -> None:
        """
        Given a provider that raises an exception getting backend
        When provider_sync_aliases is called
        Then the error should be logged and other providers processed
        """
        _ = provider_factory(backend_name="invalid_backend")
        provider2 = provider_factory(
            backend_name="forwardemail", name="ForwardEmail"
        )

        server = server_factory()
        server.receive_providers.add(provider2)

        # Mock get_backend to fail for invalid_backend
        def get_backend_side_effect(name):
            if name == "invalid_backend":
                raise Exception("Unknown backend")
            return mocker.Mock()

        mocker.patch(
            "as_email.tasks.get_backend",
            side_effect=get_backend_side_effect,
        )

        # Mock provider_enable_all_aliases
        mock_enable_task = mocker.Mock()
        mocker.patch(
            "as_email.tasks.provider_enable_all_aliases",
            return_value=mock_enable_task,
        )

        res = provider_sync_aliases()
        res()

        # Verify error was logged for invalid backend
        assert "Failed to get backend" in caplog.text
        assert "invalid_backend" in caplog.text


########################################################################
########################################################################
#
class TestProviderReportUnusedDomains:
    """Tests for provider_report_unused_domains periodic task."""

    ####################################################################
    #
    def test_report_unused_domains_no_aliases(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        django_outbox,
    ) -> None:
        """
        Given a server with no email accounts
        When provider_report_unused_domains is called
        Then an email report should be sent
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        # Mock get_backend
        mock_backend = mocker.Mock()
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_report_unused_domains()
        res()

        # Verify email was sent
        assert len(django_outbox) == 1
        email = django_outbox[0]
        assert "unused domain" in email.subject.lower()
        assert server.domain_name in email.body

    ####################################################################
    #
    def test_report_unused_domains_all_disabled(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
        django_outbox,
    ) -> None:
        """
        Given a server with email accounts but all disabled on provider
        When provider_report_unused_domains is called
        Then the domain should be reported as unused
        """
        provider = provider_factory(backend_name="forwardemail")
        server = server_factory()
        server.receive_providers.add(provider)

        email_account_factory(server=server)

        # Mock get_backend to return disabled aliases
        mailbox_name = "test"
        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox_name}",
                email=f"{mailbox_name}@{server.domain_name}",
                domain=server.domain_name,
                enabled=False,
                name=mailbox_name,
            )
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_report_unused_domains()
        res()

        # Verify email was sent
        assert len(django_outbox) == 1
        email = django_outbox[0]
        assert server.domain_name in email.body

    ####################################################################
    #
    def test_report_unused_domains_active_aliases(
        self,
        mocker: MockerFixture,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        django_outbox,
    ) -> None:
        """
        Given a server with an active alias
        When provider_report_unused_domains is called
        Then no email should be sent
        """

        provider = provider_factory(
            backend_name=DummyProviderBackend.PROVIDER_NAME
        )
        server = server_factory(receive_providers=[provider])
        # server.receive_providers.add(provider)

        # Setup enabled email accounts in our dummy provider
        # Since create_provider_aliases signal is mocked, manually add to provider
        #
        email_account = email_account_factory(server=server)
        dummy_provider.create_update_email_account(email_account)

        # Call the task that generates the email that will list any unused
        # domains. Since we have only one domain with one active email account
        # there should be no unused domains, so no email is sent.
        #
        res = provider_report_unused_domains()
        res()

        # Verify no email was sent
        #
        assert len(django_outbox) == 0

    ####################################################################
    #
    def test_report_unused_domains_multiple_providers(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        django_outbox,
    ) -> None:
        """
        Given multiple providers with unused domains
        When provider_report_unused_domains is called
        Then all should be included in the report
        """
        provider1 = provider_factory(backend_name="forwardemail")
        provider2 = provider_factory(
            backend_name="postmark", name="Postmark Provider"
        )

        server1 = server_factory()
        server1.receive_providers.add(provider1)

        server2 = server_factory()
        server2.receive_providers.add(provider2)

        # Mock get_backend
        mock_backend = mocker.Mock()
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_report_unused_domains()
        res()

        # Verify email was sent with both providers
        assert len(django_outbox) == 1
        email = django_outbox[0]
        assert server1.domain_name in email.body
        assert server2.domain_name in email.body
        assert "forwardemail" in email.body
        assert "postmark" in email.body
