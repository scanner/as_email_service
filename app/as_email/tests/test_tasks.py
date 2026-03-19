#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

# 3rd party imports
#
import pytest
import requests.exceptions
from _pytest.logging import LogCaptureFixture
from dirty_equals import Contains
from django.conf import LazySettings
from faker import Faker
from pytest_mock import MockerFixture

# Project imports
#
from ..models import EmailAccount, InactiveEmail, LocalDelivery
from ..providers.base import (
    BounceEvent,
    BounceType,
    Capability,
    EmailAccountInfo,
)
from ..tasks import (
    ALIAS_SYNC_INTERVAL_SECONDS,
    ALIAS_SYNC_MAX_PER_RUN,
    ALIAS_SYNC_STALE_THRESHOLD_SECONDS,
    _alias_sync_last_ok,
    check_update_pwfile_for_emailaccount,
    decrement_num_bounces_counter,
    dispatch_incoming_email,
    dispatch_spooled_outgoing_email,
    process_bounce,
    provider_create_or_update_email_account,
    provider_create_update_server,
    provider_delete_email_account,
    provider_report_unused_servers,
    provider_sync_all_email_accounts,
    provider_sync_server_email_accounts,
    retry_failed_incoming_email,
    scan_message_for_spam,
)
from ..utils import (
    read_emailaccount_pwfile,
    redis_client,
    spool_message,
    write_spooled_email,
)
from .factories import DummyProviderBackend
from .test_deliver import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
def test_dispatch_spool_outgoing_email(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    smtp: MagicMock,
) -> None:
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
    assert server.outgoing_spool_dir is not None
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
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    tmp_path: Path,
) -> None:
    """
    Given a spooled incoming email in JSON format
    When dispatch_incoming_email task runs
    Then the message is delivered to recipient's inbox
    """
    ea = email_account_factory()
    ea.scan_incoming_spam = False
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
    ld = LocalDelivery.objects.get(email_account=ea)
    mh = ld.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get("1")
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_dispatch_incoming_mail_failure(
    mocker: MockerFixture,
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN a delivery method that raises a transient exception
    WHEN dispatch_incoming_email task runs
    THEN the message is moved to FAILED_INCOMING_MSG_DIR and a Redis retry
         record is created containing the failing method's PK
    """
    ea = email_account_factory()
    ea.scan_incoming_spam = False
    ea.save()
    mocker.patch(
        "as_email.models.LocalDelivery.deliver",
        side_effect=Exception("connection refused"),
    )
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    fname = write_spooled_email(
        msg["To"], settings.EMAIL_SPOOL_DIR, msg, str(now), message_id
    )

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # Message should be in the failed directory.
    #
    failed_files = list(settings.FAILED_INCOMING_MSG_DIR.iterdir())
    assert len(failed_files) == 1
    email_msg = json.loads(failed_files[0].read_text())
    assert email_msg["message-id"] == message_id

    # A Redis retry record should exist with the failing method's PK.
    #
    r = redis_client()
    ld = LocalDelivery.objects.get(email_account=ea)
    redis_key = f"delivery_retry:{failed_files[0].stem}"
    retry_data = r.hgetall(redis_key)
    assert retry_data, "Expected Redis retry record"
    assert json.loads(retry_data[b"failed_method_pks"].decode()) == [ld.pk]
    assert retry_data[b"attempt_count"].decode() == "1"


####################################################################
#
def test_dispatch_incoming_email_auth_failure_auto_disables(
    mocker: MockerFixture,
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN a delivery method that raises an IMAP authentication error
    WHEN dispatch_incoming_email task runs
    THEN the method is immediately auto-disabled, no retry record is created,
         and the spool file is removed (not queued for retry)
    """
    ea = email_account_factory()
    ea.scan_incoming_spam = False
    ea.save()
    mocker.patch(
        "as_email.models.LocalDelivery.deliver",
        side_effect=Exception("AUTHENTICATIONFAILED Invalid credentials"),
    )
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    fname = write_spooled_email(
        msg["To"], settings.EMAIL_SPOOL_DIR, msg, str(now), msg["Message-ID"]
    )

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # Delivery method must be disabled.
    #
    ld = LocalDelivery.objects.get(email_account=ea)
    ld.refresh_from_db()
    assert not ld.enabled

    # Auth failures are not queued for retry.
    #
    assert not list(settings.FAILED_INCOMING_MSG_DIR.iterdir())
    r = redis_client()
    assert not list(r.scan_iter(b"delivery_retry:*"))


####################################################################
#
def test_scan_message_for_spam_success(
    mocker: MockerFixture,
    email_factory: Callable[..., EmailMessage],
    caplog: LogCaptureFixture,
) -> None:
    """
    GIVEN a valid message and aiospamc.process returning spam headers
    WHEN scan_message_for_spam is called
    THEN the returned message contains X-Spam-* headers
    """
    original = email_factory()
    scanned_bytes = (
        b"X-Spam-Status: No, score=2.0\r\n"
        b"X-Spam-Score: 2.0\r\n"
        b"\r\n"
        b"body text"
    )
    mock_result = mocker.MagicMock()
    mock_result.body = scanned_bytes
    mock_process = mocker.patch(
        "as_email.tasks.aiospamc.process",
        new_callable=AsyncMock,
        return_value=mock_result,
    )

    result = scan_message_for_spam(original)

    assert mock_process.call_count == 1
    assert result["X-Spam-Score"] == "2.0"
    assert result["X-Spam-Status"] is not None
    assert "Spam scan failed" not in caplog.text


####################################################################
#
def test_scan_message_for_spam_failure(
    mocker: MockerFixture,
    email_factory: Callable[..., EmailMessage],
    caplog: LogCaptureFixture,
) -> None:
    """
    GIVEN aiospamc.process raises a connection error
    WHEN scan_message_for_spam is called
    THEN the original message is returned unmodified and a warning is logged
    """
    original = email_factory()
    mocker.patch(
        "as_email.tasks.aiospamc.process",
        new_callable=AsyncMock,
        side_effect=ConnectionError("spamd unreachable"),
    )

    result = scan_message_for_spam(original)

    assert result is original
    assert "Spam scan failed" in caplog.text


####################################################################
#
def test_scan_message_for_spam_non_ascii(
    mocker: MockerFixture,
    malformed_non_ascii_email: EmailMessage,
    caplog: LogCaptureFixture,
) -> None:
    """
    GIVEN a malformed message with non-ASCII content but no charset
          declaration (common in spam)
    WHEN  scan_message_for_spam is called
    THEN  the message is serialized to spamd without UnicodeEncodeError
    """
    scanned_bytes = (
        b"X-Spam-Status: Yes, score=9.0\r\n"
        b"X-Spam-Score: 9.0\r\n"
        b"\r\n"
        b"body text"
    )
    mock_result = mocker.MagicMock()
    mock_result.body = scanned_bytes
    mocker.patch(
        "as_email.tasks.aiospamc.process",
        new_callable=AsyncMock,
        return_value=mock_result,
    )

    result = scan_message_for_spam(malformed_non_ascii_email)

    assert result["X-Spam-Score"] == "9.0"
    assert "Spam scan failed" not in caplog.text


####################################################################
#
def test_dispatch_incoming_email_scan_enabled(
    mocker: MockerFixture,
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    tmp_path: Path,
) -> None:
    """
    GIVEN an account with scan_incoming_spam=True
    WHEN dispatch_incoming_email task runs
    THEN scan_message_for_spam is called before delivery
    """
    mock_scan = mocker.patch(
        "as_email.tasks.scan_message_for_spam", side_effect=lambda m: m
    )
    ea = email_account_factory()
    ea.scan_incoming_spam = True
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    fname = write_spooled_email(msg["To"], tmp_path, msg, str(now), message_id)

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    assert mock_scan.call_count == 1


####################################################################
#
def test_dispatch_incoming_email_scan_disabled(
    mocker: MockerFixture,
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    tmp_path: Path,
) -> None:
    """
    GIVEN an account with scan_incoming_spam=False
    WHEN dispatch_incoming_email task runs
    THEN scan_message_for_spam is not called and delivery still succeeds
    """
    mock_scan = mocker.patch("as_email.tasks.scan_message_for_spam")
    ea = email_account_factory()
    ea.scan_incoming_spam = False
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    fname = write_spooled_email(msg["To"], tmp_path, msg, str(now), message_id)

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    assert mock_scan.call_count == 0
    ld = LocalDelivery.objects.get(email_account=ea)
    mh = ld.MH()
    folder = mh.get_folder("inbox")
    assert folder.get("1") is not None


####################################################################
#
def test_retry_failed_incoming_email_failure(
    caplog: LogCaptureFixture,
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN multiple failed messages whose recipients have no EmailAccount
    WHEN retry_failed_incoming_email task runs
    THEN it logs a warning for each unreadable file and stops after
         NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN consecutive failures
    """
    # Create 6 files with addresses that have no matching EmailAccount so the
    # lookup raises DoesNotExist and the file is counted as a failure.
    # NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN = 5: the guard fires at the start
    # of the 6th iteration (when count == 5), logging the "Stopping" message
    # and breaking before processing that file.
    #
    failed_email_files = []
    for _ in range(6):
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

    assert "Stopping redelivery attempts after" in caplog.text
    # Exactly 5 of the 6 files are processed; one is skipped when the loop
    # breaks after reaching NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN.
    assert caplog.text.count("Unable to read failed message") == 5


####################################################################
#
def test_retry_failed_incoming_email(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN failed messages in FAILED_INCOMING_MSG_DIR with Redis retry records
         whose next_retry_at is in the past
    WHEN retry_failed_incoming_email task runs
    THEN each message is delivered successfully, its file is deleted, and its
         Redis record is removed
    """
    r = redis_client()
    pending = []
    for _ in range(3):
        ea = email_account_factory()
        msg = email_factory(to=ea.email_address)
        now = datetime.now()
        fname = write_spooled_email(
            msg["To"],
            settings.FAILED_INCOMING_MSG_DIR,
            msg,
            str(now),
            msg["Message-ID"],
        )
        ld = LocalDelivery.objects.get(email_account=ea)
        redis_key = f"delivery_retry:{fname.stem}"
        r.hset(
            redis_key,
            mapping={
                "first_failure": datetime.now(UTC).isoformat(),
                "attempt_count": "1",
                "failed_method_pks": json.dumps([ld.pk]),
                # next_retry_at in the past so the file is processed now.
                "next_retry_at": (
                    datetime.now(UTC) - timedelta(seconds=60)
                ).isoformat(),
            },
        )
        pending.append((fname, redis_key))

    res = retry_failed_incoming_email()
    res()

    # All files and Redis records should be cleaned up after successful retry.
    #
    for fname, redis_key in pending:
        assert not fname.exists(), f"{fname} should have been deleted"
        assert not r.exists(redis_key), f"{redis_key} should have been deleted"


####################################################################
#
def test_retry_respects_backoff(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN a failed message whose Redis record has next_retry_at in the future
    WHEN retry_failed_incoming_email task runs
    THEN the file is skipped and attempt_count is unchanged
    """
    r = redis_client()
    ea = email_account_factory()
    msg = email_factory(to=ea.email_address)
    fname = write_spooled_email(
        msg["To"],
        settings.FAILED_INCOMING_MSG_DIR,
        msg,
        str(datetime.now()),
        msg["Message-ID"],
    )
    ld = LocalDelivery.objects.get(email_account=ea)
    redis_key = f"delivery_retry:{fname.stem}"
    r.hset(
        redis_key,
        mapping={
            "first_failure": datetime.now(UTC).isoformat(),
            "attempt_count": "1",
            "failed_method_pks": json.dumps([ld.pk]),
            # next_retry_at is one hour in the future.
            "next_retry_at": (
                datetime.now(UTC) + timedelta(hours=1)
            ).isoformat(),
        },
    )

    res = retry_failed_incoming_email()
    res()

    # File must still be present (skipped due to backoff).
    #
    assert fname.exists()
    data = r.hgetall(redis_key)
    assert data[b"attempt_count"].decode() == "1"


####################################################################
#
def test_retry_auto_disable_after_window(
    email_account_factory: Callable[..., EmailAccount],
    email_factory: Callable[..., EmailMessage],
    settings: LazySettings,
) -> None:
    """
    GIVEN a failed message whose first_failure is older than DELIVERY_RETRY_DAYS
    WHEN retry_failed_incoming_email task runs
    THEN the still-failing method is auto-disabled, the file is deleted, and
         the Redis record is removed
    """
    r = redis_client()
    ea = email_account_factory()
    msg = email_factory(to=ea.email_address)
    fname = write_spooled_email(
        msg["To"],
        settings.FAILED_INCOMING_MSG_DIR,
        msg,
        str(datetime.now()),
        msg["Message-ID"],
    )
    ld = LocalDelivery.objects.get(email_account=ea)
    redis_key = f"delivery_retry:{fname.stem}"
    # first_failure is 8 days ago; default DELIVERY_RETRY_DAYS is 7.
    #
    stale = datetime.now(UTC) - timedelta(days=8)
    r.hset(
        redis_key,
        mapping={
            "first_failure": stale.isoformat(),
            "attempt_count": "5",
            "failed_method_pks": json.dumps([ld.pk]),
            "next_retry_at": (
                datetime.now(UTC) - timedelta(seconds=1)
            ).isoformat(),
        },
    )

    res = retry_failed_incoming_email()
    res()

    # Method must be auto-disabled.
    #
    ld.refresh_from_db()
    assert not ld.enabled

    # File and Redis record must be cleaned up.
    #
    assert not fname.exists()
    assert not r.exists(redis_key)


####################################################################
#
def test_decrement_num_bounces_counter(
    email_account_factory: Callable[..., EmailAccount],
) -> None:
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


########################################################################
########################################################################
#
class TestProcessBounce:
    """Tests for the provider-agnostic process_bounce Huey task."""

    ####################################################################
    #
    def _make_event(self, **overrides) -> BounceEvent:
        """Return a minimal BounceEvent suitable for most tests."""
        defaults = BounceEvent(
            email_from="sender@example.com",
            email_to="recipient@example.com",
            subject="Test subject",
            transient=False,
            bounce_type=BounceType.BOUNCE,
            description="550 No such user",
            details="5.1.1",
        )
        for k, v in overrides.items():
            setattr(defaults, k, v)
        return defaults

    ####################################################################
    #
    @pytest.mark.parametrize(
        "transient,expected_bounce_delta",
        [
            pytest.param(False, 1, id="permanent-increments"),
            pytest.param(True, 0, id="transient-no-increment"),
        ],
    )
    def test_process_bounce_bounce_count(
        self,
        email_account_factory: Callable[..., EmailAccount],
        transient: bool,
        expected_bounce_delta: int,
    ) -> None:
        """
        GIVEN: a BounceEvent that is either transient or permanent
        WHEN:  process_bounce runs
        THEN:  permanent events increment num_bounces; transient events do not
        """
        ea = email_account_factory(
            email_address="sender@example.com", num_bounces=0
        )
        event = self._make_event(transient=transient)

        res = process_bounce(ea.pk, event)
        res()

        ea.refresh_from_db()
        assert ea.num_bounces == expected_bounce_delta

    ####################################################################
    #
    def test_process_bounce_deactivates_at_limit(
        self,
        email_account_factory: Callable[..., EmailAccount],
        django_outbox: list[Any],
    ) -> None:
        """
        GIVEN: an account whose num_bounces is one below the limit
        WHEN:  process_bounce runs with a permanent bounce
        THEN:  the account is deactivated, the owner is notified by email,
               and a DSN is sent to the EmailAccount
        """
        start = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 1
        ea = email_account_factory(
            email_address="sender@example.com", num_bounces=start
        )
        event = self._make_event()

        res = process_bounce(ea.pk, event)
        res()

        ea.refresh_from_db()
        assert ea.deactivated is True
        assert (
            ea.deactivated_reason
            == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
        )
        # Owner notified via send_mail (DSN goes through ea.deliver(), not outbox)
        assert len(django_outbox) == 1
        assert django_outbox[0].to[0] == ea.owner.email

    ####################################################################
    #
    def test_process_bounce_transient_no_deactivation(
        self,
        email_account_factory: Callable[..., EmailAccount],
        django_outbox: list[Any],
    ) -> None:
        """
        GIVEN: an account at the bounce limit
        WHEN:  process_bounce runs with a transient event
        THEN:  the account is NOT deactivated and no owner email is sent
        """
        ea = email_account_factory(
            email_address="sender@example.com",
            num_bounces=EmailAccount.NUM_EMAIL_BOUNCE_LIMIT,
        )
        event = self._make_event(transient=True)

        res = process_bounce(ea.pk, event)
        res()

        ea.refresh_from_db()
        assert ea.deactivated is False
        # Only DSN; no owner notification
        assert all(ea.owner.email not in m.to for m in django_outbox)

    ####################################################################
    #
    def test_process_bounce_inactive_recipient_creates_record(
        self,
        email_account_factory: Callable[..., EmailAccount],
    ) -> None:
        """
        GIVEN: a BounceEvent with inactive=True and can_activate=True
        WHEN:  process_bounce runs
        THEN:  an InactiveEmail record is created for the recipient address
        """
        ea = email_account_factory(email_address="sender@example.com")
        event = self._make_event(inactive=True, can_activate=True)

        res = process_bounce(ea.pk, event)
        res()

        assert InactiveEmail.objects.filter(
            email_address=event.email_to
        ).exists()
        inactive = InactiveEmail.objects.get(email_address=event.email_to)
        assert inactive.can_activate is True

    ####################################################################
    #
    @pytest.mark.parametrize(
        "bounce_type,expected_prefix",
        [
            pytest.param(
                BounceType.BOUNCE, "Bounced email", id="bounce-subject"
            ),
            pytest.param(BounceType.SPAM, "Spam complaint", id="spam-subject"),
        ],
    )
    def test_process_bounce_dsn_subject(
        self,
        email_account_factory: Callable[..., EmailAccount],
        mocker: MockerFixture,
        bounce_type: BounceType,
        expected_prefix: str,
    ) -> None:
        """
        GIVEN: a BounceEvent that is either a bounce or spam complaint
        WHEN:  process_bounce runs
        THEN:  the DSN subject line reflects the correct event type

        NOTE: report_failed_message delivers via ea.deliver(), not Django's
        mail backend, so we mock it and inspect the subject kwarg directly.
        """
        ea = email_account_factory(email_address="sender@example.com")
        event = self._make_event(bounce_type=bounce_type)
        mock_rfm = mocker.patch("as_email.tasks.report_failed_message")

        res = process_bounce(ea.pk, event)
        res()

        mock_rfm.assert_called_once()
        assert expected_prefix in mock_rfm.call_args.kwargs["subject"]


####################################################################
#
def test_delete_email_account_removes_pwfile_entry(
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    faker: Faker,
) -> None:
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
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    faker: Faker,
) -> None:
    """
    Given a new email account with password
    When the account is saved
    Then a new entry is added to the pwfile via signal
    """
    # Create account with a non-default password so signal fires
    ea = email_account_factory(password=faker.password())
    ea.save()

    ld = LocalDelivery.objects.get(email_account=ea)

    # Verify the account was added to pwfile
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address in accounts
    assert accounts[ea.email_address].pw_hash == ea.password

    # Verify mail_dir is relative to EXT_PW_FILE parent
    assert ld.maildir_path is not None
    expected_mail_dir = Path(ld.maildir_path).relative_to(
        settings.EXT_PW_FILE.parent
    )
    assert accounts[ea.email_address].maildir == expected_mail_dir


####################################################################
#
def test_check_update_pwfile_for_emailaccount_updates_password(
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    faker: Faker,
) -> None:
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
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    faker: Faker,
) -> None:
    """
    Given an email account with password in pwfile
    When the maildir_path on LocalDelivery is changed and task is invoked
    Then the pwfile entry is updated with new maildir path
    """
    # Create account with a non-default password so it's in pwfile
    ea = email_account_factory(password=faker.password())
    ea.save()

    ld = LocalDelivery.objects.get(email_account=ea)

    # Verify initial state
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    original_mail_dir = accounts[ea.email_address].maildir

    # Change the maildir_path on LocalDelivery (simulate moving the mailbox)
    new_mail_dir = settings.MAIL_DIRS / "new_location" / ea.email_address
    new_mail_dir.mkdir(parents=True, exist_ok=True)
    ld.maildir_path = str(new_mail_dir)
    ld.save()

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
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    mocker: MockerFixture,
) -> None:
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
    """Tests for provider_create_update_server task."""

    ####################################################################
    #
    def test_create_update_domain_success(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        requests_mock,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        GIVEN: a provider and a server whose domain does not yet exist
        WHEN:  provider_create_update_server is called
        THEN:  the domain is registered on the provider backend
        """
        server = server_factory(send_provider=None, receive_providers=[])

        # First make sure that the domain name is not in the domain names
        # managed by the dummy provider.
        #
        assert server.domain_name not in dummy_provider.domains

        # Then call the task that creates the domain using the dummy provider.
        #
        res = provider_create_update_server(
            server.pk, dummy_provider.PROVIDER_NAME
        )
        res()

        # And now the domain should be one managed by the dummy provider.
        #
        assert server.domain_name in dummy_provider.domains

    ####################################################################
    #
    def test_create_update_domain_backend_exception(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        caplog,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        GIVEN: a backend whose create_update_domain raises an exception
        WHEN:  provider_create_update_server is called
        THEN:  the exception is logged and re-raised
        """
        server = server_factory(send_provider=None, receive_providers=[])

        # Mock the dummy provider's `create_update_domain` method to raise an
        # exception.
        #
        mocker.patch.object(
            dummy_provider,
            "create_update_domain",
            side_effect=Exception("API error"),
        )

        res = provider_create_update_server(
            server.pk, dummy_provider.PROVIDER_NAME
        )
        with pytest.raises(Exception, match="API error"):
            res()

        # Verify error was logged
        assert "Failed to register server" in caplog.text


########################################################################
########################################################################
#
class TestProviderCreateAlias:
    """Tests for provider_create_or_update_email_account task."""

    ####################################################################
    #
    def test_create_alias_success(
        self,
        mocker: MockerFixture,
        email_account_factory,
        server_factory,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given an email account and the dummy provider
        When provider_create_or_update_email_account is called
        Then the backend's create_update_email_account method should be called
        """
        server = server_factory(send_provider=None, receive_providers=[])
        email_account = email_account_factory(server=server)

        res = provider_create_or_update_email_account(
            email_account.pk, dummy_provider.PROVIDER_NAME
        )
        res()

        # Verify backend.create_update_email_account was called
        #
        assert email_account.email_address in dummy_provider.email_accounts

    ####################################################################
    #
    def test_create_alias_backend_exception(
        self,
        mocker: MockerFixture,
        email_account_factory,
        server_factory,
        provider_factory,
        dummy_provider: DummyProviderBackend,
        caplog,
    ) -> None:
        """
        Given a backend that raises an exception
        When provider_create_or_update_email_account is called
        Then the exception should be logged and re-raised
        """
        server = server_factory(send_provider=None, receive_providers=[])
        email_account = email_account_factory(server=server)

        # Mock the dummy provider's `create_update_email_account` method
        # to raise an exception.
        #
        mocker.patch.object(
            dummy_provider,
            "create_update_email_account",
            side_effect=Exception("API error"),
        )

        res = provider_create_or_update_email_account(
            email_account.pk, dummy_provider.PROVIDER_NAME
        )
        with pytest.raises(Exception, match="API error"):
            res()

        assert "Failed to create/update email account" in caplog.text


########################################################################
########################################################################
#
class TestProviderDeleteAlias:
    """Tests for provider_delete_email_account task."""

    ####################################################################
    #
    def test_delete_alias_success(
        self,
        mocker: MockerFixture,
        email_account_factory,
        server_factory,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given an email address and domain
        When provider_delete_email_account is called
        Then the backend's delete_email_account_by_address should be called
        """
        # By creating a default server it will have the dummy provider as its
        # receiver and sender methods.  When creating the email account this
        # will cause it to call the dummy provider backend and create the email
        # account on the dummy provider backend. This way, when we delete the
        # email account by address it should no longer exist in the dummy
        # provider backend.
        #
        server = server_factory()
        email_account = email_account_factory(server=server)
        assert email_account.email_address in dummy_provider.email_accounts

        res = provider_delete_email_account(
            email_account.email_address,
            server.domain_name,
            dummy_provider.PROVIDER_NAME,
        )
        res()

        # and the email account should no longer exist in the dummy provider
        # backend.
        #
        assert email_account.email_address not in dummy_provider.email_accounts

    ####################################################################
    #
    def test_delete_alias_server_does_not_exist(
        self, mocker: MockerFixture, faker, provider_factory, caplog
    ) -> None:
        """
        Given a domain name that doesn't exist
        When provider_delete_email_account is called
        Then a warning should be logged and no exception raised
        """
        provider = provider_factory()
        email_address = faker.email()
        domain_name = faker.domain_name()

        res = provider_delete_email_account(
            email_address, domain_name, provider.backend_name
        )
        res()

        # Verify warning was logged
        assert "server" in caplog.text and "no longer exists" in caplog.text

    ####################################################################
    #
    def test_delete_alias_backend_exception(
        self,
        mocker: MockerFixture,
        email_account_factory,
        provider_factory,
        server_factory,
        dummy_provider: DummyProviderBackend,
        caplog,
    ) -> None:
        """
        Given a backend that raises an exception
        When provider_delete_email_account is called
        Then the exception should be logged and re-raised
        """
        server = server_factory(send_provider=None, receive_providers=[])
        email_account = email_account_factory(server=server)

        # Mock the dummy provider's `delete_email_account_by_address`
        # method to raise an exception.
        #
        mocker.patch.object(
            dummy_provider,
            "delete_email_account_by_address",
            side_effect=Exception("API error"),
        )

        res = provider_delete_email_account(
            email_account.email_address,
            server.domain_name,
            dummy_provider.PROVIDER_NAME,
        )
        with pytest.raises(Exception, match="API error"):
            res()

        assert "Failed to delete email account" in caplog.text


########################################################################
########################################################################
#
class TestProviderSyncServerEmailAccounts:
    """Tests for provider_sync_server_email_accounts task."""

    ####################################################################
    #
    def test_creates_missing_email_accounts(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given a server with email accounts missing on the provider
        When provider_sync_server_email_accounts is called with enabled=True
        Then missing email accounts should be created on the provider
        """
        server = server_factory(send_provider=None, receive_providers=[])
        ea1 = email_account_factory(server=server)
        ea2 = email_account_factory(server=server)
        email_accounts = sorted((ea1, ea2), key=lambda x: x.email_address)

        res = provider_sync_server_email_accounts(
            server.pk,
            dummy_provider.PROVIDER_NAME,
            enabled=True,
        )
        res()

        backend_email_accounts = dummy_provider.list_email_accounts(server)
        assert len(backend_email_accounts) == 2
        backend_email_accounts.sort(key=lambda x: x.email)

        for a, b in zip(email_accounts, backend_email_accounts):
            assert a.email_address == b.email

    ####################################################################
    #
    def test_enables_disabled_email_accounts(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        Given email accounts that exist but are disabled on the provider
        When provider_sync_server_email_accounts is called with enabled=True
        Then they should be re-enabled
        """
        server = server_factory()
        email_accounts = [
            email_account_factory(server=server) for _ in range(3)
        ]
        for ea in email_accounts:
            dummy_provider.email_accounts[ea.email_address]["enabled"] = False

        for ea in dummy_provider.list_email_accounts(server):
            assert ea.enabled is False

        res = provider_sync_server_email_accounts(
            server.pk, dummy_provider.PROVIDER_NAME, enabled=True
        )
        res()

        for ea in dummy_provider.list_email_accounts(server):
            assert ea.enabled is True

    ####################################################################
    #
    def test_skips_already_correct_email_accounts(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given email accounts already correct on the provider
        When provider_sync_server_email_accounts is called with enabled=True
        Then create_update_email_account is called (returns False = no change),
             no create or delete calls are made
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        mailbox_name = ea1.email_address.split("@")[0]

        mock_backend = mocker.Mock()
        mock_backend.create_update_email_account.return_value = False
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

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=True
        )
        res()

        mock_backend.create_email_account.assert_not_called()
        mock_backend.delete_email_account_by_address.assert_not_called()
        mock_backend.create_update_email_account.assert_called_once_with(ea1)

    ####################################################################
    #
    def test_deletes_orphaned_email_accounts(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given email accounts on the provider with no corresponding local EmailAccount
        (e.g. catch-all "*", or leftovers from deleted accounts)
        When provider_sync_server_email_accounts is called with enabled=True
        Then orphaned email accounts should be deleted
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        mailbox1 = ea1.email_address.split("@")[0]

        # Provider has ea1 plus a stray catch-all with no local counterpart
        catchall_email = f"*@{server.domain_name}"
        mock_backend = mocker.Mock()
        mock_backend.create_update_email_account.return_value = False
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox1}",
                email=ea1.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox1,
            ),
            EmailAccountInfo(
                id="dummy-catchall",
                email=catchall_email,
                domain=server.domain_name,
                enabled=True,
                name="*",
            ),
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=True
        )
        res()

        mock_backend.delete_email_account_by_address.assert_called_once_with(
            catchall_email, server
        )
        mock_backend.create_email_account.assert_not_called()

    ####################################################################
    #
    def test_mixed_operations(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given a mix of missing, needing-update, correct, and orphaned email accounts
        When provider_sync_server_email_accounts is called with enabled=True
        Then: missing are created, drifted are updated, orphans are deleted,
              correct are skipped
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)  # missing from provider
        ea2 = email_account_factory(server=server)  # needs update (disabled)
        ea3 = email_account_factory(server=server)  # already correct

        mailbox2 = ea2.email_address.split("@")[0]
        mailbox3 = ea3.email_address.split("@")[0]
        catchall_email = f"*@{server.domain_name}"

        mock_backend = mocker.Mock()
        # ea2 needs update (returns True), ea3 is correct (returns False)
        mock_backend.create_update_email_account.side_effect = (
            lambda ea: ea == ea2
        )
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox2}",
                email=ea2.email_address,
                domain=server.domain_name,
                enabled=False,
                name=mailbox2,
            ),
            EmailAccountInfo(
                id=f"dummy-{mailbox3}",
                email=ea3.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox3,
            ),
            EmailAccountInfo(
                id="dummy-catchall",
                email=catchall_email,
                domain=server.domain_name,
                enabled=True,
                name="*",
            ),
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=True
        )
        res()

        mock_backend.create_email_account.assert_called_once_with(ea1)
        mock_backend.delete_email_account_by_address.assert_called_once_with(
            catchall_email, server
        )
        assert mock_backend.create_update_email_account.call_count == 2
        called_with = {
            call.args[0]
            for call in mock_backend.create_update_email_account.call_args_list
        }
        assert called_with == {ea2, ea3}

    ####################################################################
    #
    def test_enabled_false_deletes_all_email_accounts(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        Given a server with email accounts on the provider
        When provider_sync_server_email_accounts is called with enabled=False
        Then all remote email accounts should be deleted (provider removed from server)
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        ea2 = email_account_factory(server=server)
        mailbox1 = ea1.email_address.split("@")[0]
        mailbox2 = ea2.email_address.split("@")[0]

        mock_backend = mocker.Mock()
        mock_backend.CAPABILITIES = frozenset(
            {Capability.MANAGES_EMAIL_ACCOUNTS}
        )
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox1}",
                email=ea1.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox1,
            ),
            EmailAccountInfo(
                id=f"dummy-{mailbox2}",
                email=ea2.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox2,
            ),
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=False
        )
        res()

        assert mock_backend.delete_email_account_by_address.call_count == 2
        deleted_addresses = {
            call.args[0]
            for call in mock_backend.delete_email_account_by_address.call_args_list
        }
        assert deleted_addresses == {ea1.email_address, ea2.email_address}
        mock_backend.create_email_account.assert_not_called()
        mock_backend.create_update_email_account.assert_not_called()

    ####################################################################
    #
    def test_enabled_false_noop_for_provider_without_capabilities(
        self,
        mocker: MockerFixture,
        server_factory,
        email_account_factory,
        provider_factory,
    ) -> None:
        """
        GIVEN: a server with email accounts on a provider that lacks MANAGES_EMAIL_ACCOUNTS
        WHEN:  provider_sync_server_email_accounts is called with enabled=False
        THEN:  no accounts are deleted (provider has no per-account entities)
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()
        server.receive_providers.add(provider)

        ea1 = email_account_factory(server=server)
        mailbox1 = ea1.email_address.split("@")[0]

        mock_backend = mocker.Mock()
        mock_backend.CAPABILITIES = frozenset()  # no MANAGES_EMAIL_ACCOUNTS
        mock_backend.list_email_accounts.return_value = [
            EmailAccountInfo(
                id=f"dummy-{mailbox1}",
                email=ea1.email_address,
                domain=server.domain_name,
                enabled=True,
                name=mailbox1,
            ),
        ]
        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mock_backend,
        )

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=False
        )
        res()

        mock_backend.delete_email_account_by_address.assert_not_called()
        mock_backend.create_email_account.assert_not_called()
        mock_backend.create_update_email_account.assert_not_called()

    ####################################################################
    #
    @pytest.mark.parametrize(
        "enabled",
        [
            pytest.param(True, id="enabled-true"),
            pytest.param(False, id="enabled-false"),
        ],
    )
    def test_list_email_accounts_key_error_logs_error_and_returns(
        self,
        mocker: MockerFixture,
        server_factory,
        provider_factory,
        caplog,
        enabled: bool,
    ) -> None:
        """
        GIVEN: list_email_accounts raises KeyError (domain does not exist on provider)
        WHEN:  provider_sync_server_email_accounts is called with either enabled value
        THEN:  an error is logged (no traceback), the task returns quietly, and
               Huey does not retry (no exception is raised)
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory()

        mock_backend = mocker.Mock()
        mock_backend.list_email_accounts.side_effect = KeyError(
            f"Domain '{server.domain_name}' does not exist on provider"
        )
        mocker.patch("as_email.tasks.get_backend", return_value=mock_backend)

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=enabled
        )
        res()  # must not raise

        assert "domain does not exist on provider" in caplog.text
        assert server.domain_name in caplog.text
        mock_backend.create_email_account.assert_not_called()
        mock_backend.delete_email_account_by_address.assert_not_called()


########################################################################
########################################################################
#
class TestProviderSyncAllEmailAccounts:
    """Tests for provider_sync_all_email_accounts periodic task."""

    ####################################################################
    #
    def test_sync_all_email_accounts_caps_dispatches(
        self,
        mocker: MockerFixture,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
    ) -> None:
        """
        GIVEN: 4 server/provider pairs, none synced yet
        WHEN:  provider_sync_all_email_accounts runs
        THEN:  at most ALIAS_SYNC_MAX_PER_RUN (3) syncs are dispatched
        """
        provider1 = provider_factory(backend_name="dummy")
        provider2 = provider_factory(backend_name="dummy")

        server1 = server_factory(receive_providers=[provider1])
        server2 = server_factory(receive_providers=[provider1])
        server3 = server_factory(receive_providers=[provider2])
        server4 = server_factory(receive_providers=[provider2])

        for server in (server1, server2, server3, server4):
            email_account_factory(server=server)
            email_account_factory(server=server)

        # Factory setup triggers signals that run
        # provider_sync_server_email_accounts, setting last_ok keys.  Clear
        # them so all 4 pairs appear "never synced" to the scheduler.
        #
        r = redis_client()
        for key in r.scan_iter("alias_sync:*"):
            r.delete(key)

        mock_sync = mocker.patch(
            "as_email.tasks.provider_sync_server_email_accounts"
        )
        res = provider_sync_all_email_accounts()
        res()

        # With ALIAS_SYNC_MAX_PER_RUN=3, only 3 of 4 pairs are dispatched.
        #
        assert mock_sync.call_count == 3

    ####################################################################
    #
    def test_sync_all_email_accounts_handles_backend_errors(
        self, mocker: MockerFixture, server_factory, provider_factory, caplog
    ) -> None:
        """
        Given a provider that raises an exception getting backend
        When provider_sync_all_email_accounts is called
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

        mock_enable_task = mocker.Mock()
        mocker.patch(
            "as_email.tasks.provider_sync_server_email_accounts",
            return_value=mock_enable_task,
        )

        res = provider_sync_all_email_accounts()
        res()

        # Verify error was logged for invalid backend
        assert "Failed to get backend" in caplog.text
        assert "invalid_backend" in caplog.text


########################################################################
########################################################################
#
class TestAliasSyncStaleness:
    """Tests for the Redis-based alias sync staleness and spreading logic."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "age_seconds,expected_dispatches,expected_log",
        [
            (0, 0, None),
            (ALIAS_SYNC_INTERVAL_SECONDS - 60, 0, None),
            (ALIAS_SYNC_INTERVAL_SECONDS + 1, 1, None),
            (ALIAS_SYNC_STALE_THRESHOLD_SECONDS + 1, 1, "has not succeeded"),
        ],
        ids=[
            "recent",
            "within-interval",
            "past-interval",
            "stale-24h-error",
        ],
    )
    def test_dispatch_based_on_sync_age(
        self,
        age_seconds: int,
        expected_dispatches: int,
        expected_log: str | None,
        mocker: MockerFixture,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
        caplog: LogCaptureFixture,
    ) -> None:
        """
        GIVEN: a server/provider pair synced <age_seconds> ago
        WHEN:  provider_sync_all_email_accounts runs
        THEN:  the pair is dispatched only if older than the sync interval,
               and an error is logged if older than the stale threshold
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory(receive_providers=[provider])
        email_account_factory(server=server)

        r = redis_client()
        r.set(
            f"alias_sync:last_ok:{server.pk}:{provider.backend_name}",
            str(time.time() - age_seconds),
            ex=172800,
        )

        mock_sync = mocker.patch(
            "as_email.tasks.provider_sync_server_email_accounts"
        )
        with caplog.at_level("ERROR", logger="as_email.tasks"):
            res = provider_sync_all_email_accounts()
            res()

        assert mock_sync.call_count == expected_dispatches

        if expected_log is not None:
            assert expected_log in caplog.text
            assert server.domain_name in caplog.text
        else:
            assert "has not succeeded" not in caplog.text

    ####################################################################
    #
    def test_least_recently_synced_dispatched_first(
        self,
        mocker: MockerFixture,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
    ) -> None:
        """
        GIVEN: multiple due pairs with different last_ok timestamps
        WHEN:  provider_sync_all_email_accounts runs
        THEN:  pairs are dispatched oldest-first, up to the per-run cap
        """
        provider = provider_factory(backend_name="dummy")
        servers = [
            server_factory(receive_providers=[provider]) for _ in range(4)
        ]
        for s in servers:
            email_account_factory(server=s)

        # Set stale timestamps: servers[0] is oldest, servers[3] is newest
        # (but all are past the interval).
        #
        r = redis_client()
        base = time.time() - ALIAS_SYNC_INTERVAL_SECONDS - 3600
        for i, s in enumerate(servers):
            r.set(
                f"alias_sync:last_ok:{s.pk}:{provider.backend_name}",
                str(base + i * 100),
                ex=172800,
            )

        mock_sync = mocker.patch(
            "as_email.tasks.provider_sync_server_email_accounts"
        )
        res = provider_sync_all_email_accounts()
        res()

        assert mock_sync.call_count == ALIAS_SYNC_MAX_PER_RUN

        # The first 3 dispatched should be the 3 oldest (servers 0, 1, 2).
        #
        dispatched_pks = [call[0][0] for call in mock_sync.call_args_list]
        expected_pks = [s.pk for s in servers[:ALIAS_SYNC_MAX_PER_RUN]]
        assert dispatched_pks == expected_pks

    ####################################################################
    #
    def test_successful_sync_sets_last_ok(
        self,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
    ) -> None:
        """
        GIVEN: a server/provider pair with no prior sync
        WHEN:  provider_sync_server_email_accounts completes successfully
        THEN:  the Redis last_ok key is set
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory(receive_providers=[provider])
        email_account_factory(server=server)

        # Factory signals trigger a sync that sets last_ok — clear it so
        # we can verify the task sets it on its own.
        #
        r = redis_client()
        r.delete(f"alias_sync:last_ok:{server.pk}:{provider.backend_name}")

        assert _alias_sync_last_ok(server.pk, provider.backend_name) is None

        res = provider_sync_server_email_accounts(
            server.pk, provider.backend_name, enabled=True
        )
        res()

        last_ok = _alias_sync_last_ok(server.pk, provider.backend_name)
        assert last_ok is not None
        assert time.time() - last_ok < 5  # set within last 5 seconds

    ####################################################################
    #
    def test_connection_error_does_not_retry(
        self,
        mocker: MockerFixture,
        dummy_provider: DummyProviderBackend,
        server_factory,
        email_account_factory,
        provider_factory,
        requests_mock,
        caplog: LogCaptureFixture,
    ) -> None:
        """
        GIVEN: a server/provider pair where list_email_accounts raises
               ConnectionError
        WHEN:  provider_sync_server_email_accounts runs
        THEN:  a warning is logged, last_ok is NOT set, and the task
               returns without raising (no Huey retry)
        """
        provider = provider_factory(backend_name="dummy")
        server = server_factory(receive_providers=[provider])
        email_account_factory(server=server)

        # Factory signals trigger a sync that sets last_ok — clear it so
        # we can verify the failed task does NOT set it.
        #
        r = redis_client()
        r.delete(f"alias_sync:last_ok:{server.pk}:{provider.backend_name}")

        mocker.patch(
            "as_email.tasks.get_backend",
            return_value=mocker.Mock(
                list_email_accounts=mocker.Mock(
                    side_effect=requests.exceptions.ConnectionError(
                        "Network is unreachable"
                    )
                )
            ),
        )

        with caplog.at_level("WARNING", logger="as_email.tasks"):
            res = provider_sync_server_email_accounts(
                server.pk, provider.backend_name, enabled=True
            )
            res()

        assert "Network error" in caplog.text
        assert _alias_sync_last_ok(server.pk, provider.backend_name) is None


########################################################################
########################################################################
#
class TestProviderReportUnusedDomains:
    """Tests for provider_report_unused_servers periodic task."""

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
        When provider_report_unused_servers is called
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

        res = provider_report_unused_servers()
        res()

        # Verify email was sent
        assert len(django_outbox) == 1
        email = django_outbox[0]
        assert "unused server" in email.subject.lower()
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
        When provider_report_unused_servers is called
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

        res = provider_report_unused_servers()
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
        When provider_report_unused_servers is called
        Then no email should be sent
        """

        provider = provider_factory(
            backend_name=DummyProviderBackend.PROVIDER_NAME
        )
        server = server_factory(receive_providers=[provider])
        # server.receive_providers.add(provider)

        # Setup enabled email accounts in our dummy provider Since
        # create_provider_aliases signal is mocked, manually add to provider
        #
        email_account = email_account_factory(server=server)
        dummy_provider.create_update_email_account(email_account)

        # Call the task that generates the email that will list any unused
        # domains. Since we have only one domain with one active email account
        # there should be no unused domains, so no email is sent.
        #
        res = provider_report_unused_servers()
        res()

        # Verify no email was sent
        #
        assert len(django_outbox) == 0

    ####################################################################
    #
    def test_report_unused_domains_provider_no_servers(
        self,
        provider_factory,
        django_outbox,
    ) -> None:
        """
        Given a provider with no receiving servers
        When provider_report_unused_servers is called
        Then no error should occur and no email should be sent
        """
        provider_factory(backend_name="postmark")

        res = provider_report_unused_servers()
        res()

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
        When provider_report_unused_servers is called
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

        res = provider_report_unused_servers()
        res()

        # Verify email was sent with both providers
        assert len(django_outbox) == 1
        email = django_outbox[0]
        assert server1.domain_name in email.body
        assert server2.domain_name in email.body
        assert "forwardemail" in email.body
        assert "postmark" in email.body
