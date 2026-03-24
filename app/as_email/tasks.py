#!/usr/bin/env python
#
"""
Huey dispatchable (and periodic) tasks.
"""

# system imports
#
import asyncio
import email
import email.policy
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

# 3rd party imports
#
import aiospamc
import pytz
import redis as redis_module
import requests.exceptions
from django.conf import settings
from django.core.mail import send_mail
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task, lock_task, task

# Project imports
#
from .deliver import report_failed_message
from .models import (
    DeliveryMethod,
    EmailAccount,
    InactiveEmail,
    LocalDelivery,
    Provider,
    Server,
)
from .providers import get_backend
from .providers.base import BounceEvent, BounceType, Capability
from .reports import REPORTS, ReportSchedule, get_reports_by_schedule
from .utils import (
    PWUser,
    read_emailaccount_pwfile,
    redis_client,
    write_emailaccount_pwfile,
)

TZ = pytz.timezone(settings.TIME_ZONE)
EST = pytz.timezone("EST")  # Postmark API is in EST! Really!
# How many messages do we try to dispatch during a single run of any of the
# dispatch tasks. Makes sure we do not hog the task queues just sending email.
#
# NOTE: Separate metrics gathering jobs will be used to watch dispatch queue
#       sizes.
#
DISPATCH_NUM_PER_RUN = 100

# How many messages do we attempt to redeliver after failure per run.
#
NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN = 5

# Suppress repeated auth-failure DSN / owner-notification emails for this
# many seconds after the first notification (24 hours).
#
DELIVERY_NOTIFY_SUPPRESS_SECONDS = 86400  # 24 h

# Exponential backoff for per-file retry attempts.
#
# Starting from BASE_RETRY_INTERVAL_SECONDS, each successive failure doubles
# the wait before the next attempt (capped at MAX_RETRY_BACKOFF_SECONDS).
# Example schedule: 10 min → 20 → 40 → 80 → 160 → 240 → 240 → …
#
BASE_RETRY_INTERVAL_SECONDS = 600  # 10 minutes (matches task crontab)
MAX_RETRY_BACKOFF_SECONDS = 14400  # 4 hours

# EmailAccount/alias sync: minimum interval between successful syncs for a
# given server/provider pair.  The hourly cron skips pairs synced more
# recently, spreading work across runs instead of bursting all at once.
#
ALIAS_SYNC_INTERVAL_SECONDS = 14400  # 4 hours

# If a server/provider pair has not had a successful EmailAccount/alias sync
# in this window, log an error (which triggers a Sentry alert).
#
ALIAS_SYNC_STALE_THRESHOLD_SECONDS = 86400  # 24 hours

# Maximum number of server/provider pairs to run EmailAccount/alias sync for
# per hourly run.  Keeps API request bursts small; remaining pairs are picked
# up in subsequent runs.
#
ALIAS_SYNC_MAX_PER_RUN = 3

# Keywords in exception messages that indicate an IMAP authentication failure
# rather than a transient network / server problem.
#
AUTH_ERROR_KEYWORDS = frozenset(
    {
        "authentication",
        "credentials",
        "login failed",
        "not authenticated",
        "authenticationfailed",
    }
)


logger = logging.getLogger("as_email.tasks")


####################################################################
#
def _is_auth_error(exc: Exception) -> bool:
    """Return True if the exception looks like an IMAP authentication failure."""
    return any(kw in str(exc).lower() for kw in AUTH_ERROR_KEYWORDS)


####################################################################
#
def _notify_owner_auto_disabled(
    method: DeliveryMethod,
    email_account: EmailAccount,
    reason: str,
) -> None:
    """
    Send a plain-text warning email to the Django User who owns the
    EmailAccount when a delivery method is automatically disabled.
    """
    owner = email_account.owner
    if not owner.email:
        return
    label = str(method)
    send_mail(
        subject=(
            f"Delivery method disabled for {email_account.email_address}: {label}"
        ),
        message=(
            f"A delivery method for your email account "
            f"{email_account.email_address} has been automatically disabled.\n\n"
            f"Delivery method: {label}\n"
            f"Reason: {reason}\n\n"
            f"Please log in to review and re-enable or update this delivery method."
        ),
        from_email=None,
        recipient_list=[owner.email],
        fail_silently=True,
    )
    logger.info(
        "Sent auto-disable notification to '%s' for %s (pk=%d)",
        owner.email,
        label,
        method.pk,
    )


####################################################################
#
def _auto_disable_method(
    method: DeliveryMethod,
    msg: email.message.EmailMessage,
    email_account: EmailAccount,
    reason: str,
    status: str,
    r: redis_module.Redis,
    notify_key: str | None = None,
) -> None:
    """
    Auto-disable a DeliveryMethod: set enabled=False, send a DSN to the
    email account (best-effort), and send a warning email to the account
    owner.

    The ``notify_key`` Redis key gates the DSN and owner email to avoid
    sending repeated notifications within 24 hours. If the key exists the
    notifications are skipped but the method is still disabled.

    Args:
        method: The delivery method to disable.
        msg: The message that failed to deliver (included in the DSN).
        email_account: The EmailAccount that owns the delivery method.
        reason: Human-readable failure description.
        status: RFC 3463 status code (e.g. "5.7.8", "4.4.2").
        r: Redis client (for notification suppression).
        notify_key: Redis key to check/set for 24-hour notification
            suppression. Pass None to always notify.
    """
    method.enabled = False
    method.save(update_fields=["enabled"])
    label = str(method)
    logger.warning(
        "Auto-disabled %s (pk=%d) for '%s': %s",
        label,
        method.pk,
        email_account.email_address,
        reason,
    )

    already_notified = bool(notify_key and r.exists(notify_key))
    if not already_notified:
        report_text = (
            f"Delivery to {label} has been automatically disabled.\n\n"
            f"Reason: {reason}"
        )
        report_failed_message(
            email_account,
            msg,
            report_text=report_text,
            subject=f"Delivery method disabled: {label}",
            action="failed",
            status=status,
            diagnostic=f"delivery; {reason}",
        )
        _notify_owner_auto_disabled(method, email_account, reason)
        if notify_key:
            # Suppress duplicate notifications for 24 hours so a flood of
            # concurrent delivery attempts does not spam the account owner.
            r.set(
                notify_key,
                datetime.now(UTC).isoformat(),
                ex=DELIVERY_NOTIFY_SUPPRESS_SECONDS,
            )


####################################################################
#
@db_periodic_task(crontab(minute="*/10"))
def retry_failed_incoming_email():
    """
    Go through any messages in the failed incoming spool dir and attempt to
    deliver them again, retrying only the specific delivery methods that
    previously failed.

    Per-method retry state is tracked in Redis under the key
    ``delivery_retry:{file_stem}`` as a hash with the following fields
    (all stored as UTF-8 strings):

    ``first_failure``
        ISO-8601 UTC timestamp of the first delivery failure for this file.
        Used to detect when the retry window (DELIVERY_RETRY_DAYS) has been
        exceeded.

    ``attempt_count``
        Integer number of delivery attempts made so far (including the
        original attempt in dispatch_incoming_email).

    ``failed_method_pks``
        JSON-encoded list of integer DeliveryMethod PKs that still need to
        be retried.  Only these methods are attempted on each retry run.

    ``next_retry_at``
        ISO-8601 UTC timestamp before which this file should be skipped.
        Computed with exponential backoff: BASE_RETRY_INTERVAL_SECONDS *
        2^(attempt_count-1), capped at MAX_RETRY_BACKOFF_SECONDS (4 h).

    Files without a Redis record (legacy files pre-dating this feature, or
    whose key TTL has expired) have all enabled methods retried with no age
    check.

    A separate per-method key ``delivery_notify:{pk}`` (plain string, TTL =
    DELIVERY_NOTIFY_SUPPRESS_SECONDS) suppresses duplicate DSN / owner
    notification emails within 24 hours of an auth failure.

    After DELIVERY_RETRY_DAYS days without success the outstanding delivery
    methods are auto-disabled and a DSN is sent to the account.  Auth
    failures trigger immediate auto-disable.
    """
    failing_incoming_dir = Path(settings.FAILED_INCOMING_MSG_DIR)
    if not failing_incoming_dir.exists():
        logger.warning(
            "retry_failed_incoming_email: FAILED_INCOMING_MSG_DIR '%s' does "
            "not exist; no redelivery attempted",
            failing_incoming_dir,
        )
        return

    r = redis_client()
    retry_days = settings.DELIVERY_RETRY_DAYS
    num_still_failing = 0

    for email_file in failing_incoming_dir.iterdir():
        if num_still_failing >= NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN:
            logger.error(
                "Stopping redelivery attempts after %d still-failing messages",
                num_still_failing,
            )
            break

        try:
            email_msg = json.loads(email_file.read_text())
            email_addr = email_msg["recipient"].strip()
            email_account = EmailAccount.objects.get(email_address=email_addr)
            msg = email.message_from_string(
                email_msg["raw_email"], policy=email.policy.default
            )
        except Exception as e:
            logger.exception(
                "Unable to read failed message '%s': %s", email_file, e
            )
            num_still_failing += 1
            continue

        # Look up per-method retry state.  hgetall returns a dict of
        # bytes→bytes, or {} when the key does not exist.
        #
        redis_key = f"delivery_retry:{email_file.stem}"
        retry_data = r.hgetall(redis_key)

        failed_pks: list[int] | None
        first_failure: datetime
        attempt_count: int
        next_retry_at: datetime | None

        if retry_data:
            # All four fields are always written together; a KeyError or
            # ValueError means the record is corrupt — fall back to the
            # legacy (no-record) path so the file still gets processed.
            #
            try:
                failed_pks = json.loads(
                    retry_data[b"failed_method_pks"].decode()
                )
                first_failure = datetime.fromisoformat(
                    retry_data[b"first_failure"].decode()
                )
                attempt_count = int(retry_data[b"attempt_count"].decode())
                next_retry_at = datetime.fromisoformat(
                    retry_data[b"next_retry_at"].decode()
                )
            except (KeyError, ValueError, json.JSONDecodeError):
                logger.warning(
                    "Corrupt retry record for '%s'; treating as legacy file",
                    email_file,
                )
                retry_data = {}
                failed_pks = None
                first_failure = datetime.now(UTC)
                attempt_count = 0
                next_retry_at = None
        else:
            # Legacy file or key TTL-expired: retry all enabled methods,
            # no age check, no backoff.
            #
            failed_pks = None
            first_failure = datetime.now(UTC)
            attempt_count = 0
            next_retry_at = None

        # Honour the backoff delay: skip this file until next_retry_at.
        #
        if next_retry_at and datetime.now(UTC) < next_retry_at:
            continue

        # Auto-disable remaining methods if the retry window has expired.
        #
        age_seconds = (datetime.now(UTC) - first_failure).total_seconds()
        window_expired = bool(retry_data) and age_seconds > retry_days * 86400
        if window_expired:
            methods_to_disable = list(
                email_account.delivery_methods.filter(
                    pk__in=failed_pks, enabled=True
                )
                if failed_pks
                else email_account.delivery_methods.filter(enabled=True)
            )
            for method in methods_to_disable:
                _auto_disable_method(
                    method,
                    msg,
                    email_account,
                    reason=(
                        f"Delivery failed repeatedly for more than "
                        f"{retry_days} days and was automatically disabled."
                    ),
                    status="4.4.2",
                    r=r,
                )
            email_file.unlink(missing_ok=True)
            r.delete(redis_key)
            logger.info(
                "Retry window expired for '%s'; disabled %d method(s)",
                email_file,
                len(methods_to_disable),
            )
            continue

        # Attempt delivery for each outstanding method.
        #
        methods_to_retry = list(
            email_account.delivery_methods.filter(
                pk__in=failed_pks, enabled=True
            )
            if failed_pks
            else email_account.delivery_methods.filter(enabled=True)
        )
        still_failed_pks: list[int] = []
        auto_disabled_pks: set[int] = set()
        visited: set[int] = set()
        for method in methods_to_retry:
            try:
                method.deliver(msg, visited)
                logger.info(
                    "Retry: successfully delivered '%s' via %s (pk=%d)",
                    email_file.name,
                    str(method),
                    method.pk,
                )
            except Exception as exc:
                logger.warning(
                    "Retry: %s (pk=%d) failed for '%s': %s",
                    str(method),
                    method.pk,
                    email_addr,
                    exc,
                )
                if _is_auth_error(exc):
                    notify_key = f"delivery_notify:{method.pk}"
                    _auto_disable_method(
                        method,
                        msg,
                        email_account,
                        reason=f"Authentication error: {exc}",
                        status="5.7.8",
                        r=r,
                        notify_key=notify_key,
                    )
                    auto_disabled_pks.add(method.pk)
                else:
                    still_failed_pks.append(method.pk)

        # Auto-disabled methods are no longer active failures.
        #
        still_failed_pks = [
            pk for pk in still_failed_pks if pk not in auto_disabled_pks
        ]

        if still_failed_pks:
            new_attempt_count = attempt_count + 1
            # Exponential backoff: double the interval with each attempt,
            # capped at MAX_RETRY_BACKOFF_SECONDS (4 hours).
            #
            backoff = min(
                BASE_RETRY_INTERVAL_SECONDS * (2 ** (new_attempt_count - 1)),
                MAX_RETRY_BACKOFF_SECONDS,
            )
            new_next_retry_at = datetime.now(UTC) + timedelta(seconds=backoff)
            new_mapping: dict[str, str] = {
                "attempt_count": str(new_attempt_count),
                "failed_method_pks": json.dumps(still_failed_pks),
                "next_retry_at": new_next_retry_at.isoformat(),
            }
            if not retry_data:
                # First Redis record for a legacy file: record first_failure
                # and set a safety-net TTL of twice the retry window.
                #
                new_mapping["first_failure"] = datetime.now(UTC).isoformat()
                r.hset(redis_key, mapping=new_mapping)  # type: ignore[arg-type]
                r.expire(redis_key, retry_days * 86400 * 2)
            else:
                r.hset(redis_key, mapping=new_mapping)  # type: ignore[arg-type]
            logger.warning(
                "Retry failed for '%s': %d method(s) still failing (next "
                "attempt in %ds): %s",
                email_file,
                len(still_failed_pks),
                backoff,
                still_failed_pks,
            )
            num_still_failing += 1
        else:
            # All methods either succeeded or were auto-disabled: clean up.
            #
            logger.info(
                "Successfully redelivered or resolved '%s' for '%s'",
                email_file,
                email_addr,
            )
            email_file.unlink(missing_ok=True)
            r.delete(redis_key)


####################################################################
#
@db_periodic_task(crontab(minute="*/5"))
def dispatch_spooled_outgoing_email():
    """
    Look for email messages in our outgoing spool folder and attempt to
    send them via the mail provider.  If the attempt fails, try again.

    NOTE: A message failes to be dispatched if our call to the provider
          fail. Not if the provider fails to send the message. This task is
          intended for recovering from provider outages which I expect to be
          few and far between, but still need to account fo rit.

    XXX We need to likely record every attempt and slow down our retries. We
        also need a maximum amount of time we will retry. But I expect this to
        happen so rarely that we will not need to worry about this.
    """
    msg_count = 0
    for server in Server.objects.all():
        if not server.outgoing_spool_dir:
            continue
        outgoing_spool_dir = Path(server.outgoing_spool_dir)
        for spooled_message_file in outgoing_spool_dir.iterdir():
            msg_count += 1
            message = email.message_from_bytes(
                spooled_message_file.read_bytes(),
                policy=email.policy.default,
            )
            rcpt_tos = []
            for hdr in ("To", "Cc", "Bcc"):
                rcpt_tos.extend(message.get_all(hdr, []))

            delete_message = True
            try:
                # Try sending the message again but do not write it to the
                # spool if it fails.
                #
                delete_message = server.send_email(
                    message,
                    email_from=message["From"],
                    rcpt_tos=rcpt_tos,
                    spool_on_retryable=False,
                )
            except Exception as exc:
                # All raised exceptions are a hard fail and the spooled message
                # will be removed.
                #
                delete_message = True
                logger.exception(f"Unable to retry sending email: {exc}")
                failed_message = message

                report_failed_message(
                    failed_message["From"],
                    failed_message,
                    report_text=f"Unable to send email: {str(exc)}",
                    subject=f"Failed to send: {failed_message['Subject']}",
                    action="failed",
                    status="5.1.1",
                    diagnostic=f"smtp; {str(exc)}",
                )

            if delete_message:
                spooled_message_file.unlink(missing_ok=True)

            if msg_count > DISPATCH_NUM_PER_RUN:
                return


####################################################################
#
@db_periodic_task(crontab(day="*", hour="1"))
def decrement_num_bounces_counter():
    """
    EmailAccount.num_bounces decays over time, and this is the task that
    does that decay logic.

    Currently set to decay by one ever 24 hours.
    """
    for ea in EmailAccount.objects.filter(num_bounces__gt=0):
        ea.num_bounces -= 1

        # if the account was deactivated due to number of bounces
        # and we are under the bounce limit, reactivate the account.
        #
        if (
            ea.deactivated
            and ea.deactivated_reason
            == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
            and ea.num_bounces < EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
        ):
            ea.deactivated = False
            ea.deactivated_reason = None
            logger.info(
                "decrement_num_bounces_counters: Email Account %s is no longer "
                "deactivated because the number of bounces has decayed to %d",
                ea,
                ea.num_bounces,
            )
            # XXX We need to send email to the account saying that they are
            #     no longer deacivated and can now send emails again.
            #
        ea.save()


####################################################################
#
def scan_message_for_spam(
    msg: email.message.EmailMessage,
) -> email.message.EmailMessage:
    """
    Scan a message for spam and return it with X-Spam-* headers added.

    SpamAssassin strips any existing X-Spam-* headers before rescanning, so
    provider-injected headers are automatically replaced by our results.
    On failure the original message is returned unmodified and a warning is
    logged so delivery still proceeds.

    Args:
        msg: The email message to scan.

    Returns:
        Message with X-Spam-* headers from our scanner, or the original
        message when the scan fails.
    """
    try:
        # Use as_string() + encode() instead of as_bytes() to avoid
        # UnicodeEncodeError on malformed messages with non-ASCII content
        # but no charset declaration.
        #
        msg_bytes = msg.as_string(policy=email.policy.default).encode("utf-8")

        # NOTE: Use new_event_loop() + run_until_complete() instead of
        # asyncio.run() to avoid touching the global event loop policy.
        #
        # asyncio.run() sets _set_called=True on the policy thread-local,
        # causing subsequent asyncio.get_event_loop() calls (e.g. in pydnsbl)
        # to raise RuntimeError rather than auto-creating a loop.
        #
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                aiospamc.process(
                    msg_bytes,
                    host=settings.SPAMD_HOST,
                    port=settings.SPAMD_PORT,
                )
            )
        finally:
            loop.close()
        return email.message_from_bytes(
            result.body, policy=email.policy.default
        )
    except Exception as e:
        logger.error("Spam scan failed for incoming email: %r", e)
        return msg


####################################################################
#
@db_task()
def dispatch_incoming_email(email_account_pk: int, email_fname: str) -> None:
    """
    Called after a message has been received by the incoming hook.

    Delivers the message to each enabled delivery method individually rather
    than via EmailAccount.deliver() so that per-method failures can be
    tracked.  Successfully-delivered methods are not retried; only the
    methods that raised an exception are recorded in Redis and retried by
    retry_failed_incoming_email.

    Auth failures (bad credentials) trigger immediate auto-disable of the
    delivery method plus a DSN and owner-notification email.  Other failures
    cause the message to be moved to FAILED_INCOMING_MSG_DIR with a Redis
    retry record (delivery_retry:{file_stem}) so the next run of
    retry_failed_incoming_email can pick it up.

    NOTE: Postmark will POST a message for every recipient of that email
          being handled by Postmark, so this task may be called concurrently
          for distinct email accounts with no race conditions between them.
    """
    email_account = EmailAccount.objects.get(pk=email_account_pk)
    email_file = Path(email_fname)
    email_msg = json.loads(email_file.read_text())
    msg = email.message_from_string(
        email_msg["raw_email"], policy=email.policy.default
    )
    if email_account.scan_incoming_spam:
        msg = scan_message_for_spam(msg)

    r = redis_client()
    failed_pks: list[int] = []
    visited: set[int] = set()

    for method in email_account.delivery_methods.filter(enabled=True):
        try:
            method.deliver(msg, visited)
        except Exception as exc:
            logger.exception(
                "Delivery method %s (pk=%d) failed for '%s': %s",
                str(method),
                method.pk,
                email_account.email_address,
                exc,
            )
            if _is_auth_error(exc):
                notify_key = f"delivery_notify:{method.pk}"
                _auto_disable_method(
                    method,
                    msg,
                    email_account,
                    reason=f"Authentication error: {exc}",
                    status="5.7.8",
                    r=r,
                    notify_key=notify_key,
                )
            else:
                failed_pks.append(method.pk)

    if failed_pks:
        # Move the file to FAILED_INCOMING_MSG_DIR and record the failed
        # method PKs in Redis so retry_failed_incoming_email can pick it up.
        #
        recipient = email_msg["recipient"].lower()
        settings.FAILED_INCOMING_MSG_DIR.mkdir(parents=True, exist_ok=True)
        failed_msg_fname = (
            settings.FAILED_INCOMING_MSG_DIR / f"{recipient}-{email_file.name}"
        )
        try:
            email_file.rename(failed_msg_fname)
        except Exception as exc:
            logger.exception(
                "Failed to move '%s' to '%s': %s",
                email_file,
                failed_msg_fname,
                exc,
            )
            email_file.unlink(missing_ok=True)
            return

        # Initial retry record.  next_retry_at is set to one base interval
        # from now so the first retry runs on the next 10-minute task tick.
        #
        redis_key = f"delivery_retry:{failed_msg_fname.stem}"
        first_next_retry_at = datetime.now(UTC) + timedelta(
            seconds=BASE_RETRY_INTERVAL_SECONDS
        )
        r.hset(
            redis_key,
            mapping={
                "first_failure": datetime.now(UTC).isoformat(),
                "attempt_count": "1",
                "failed_method_pks": json.dumps(failed_pks),
                "next_retry_at": first_next_retry_at.isoformat(),
            },
        )
        # Safety-net TTL: twice the retry window so orphaned keys do not
        # accumulate indefinitely if the retry task never processes them.
        #
        r.expire(redis_key, settings.DELIVERY_RETRY_DAYS * 86400 * 2)
        logger.error(
            "Failed to deliver message '%s' for '%s' via method(s) %s; "
            "moved to '%s'",
            email_msg.get("message-id", ""),
            email_account.email_address,
            failed_pks,
            failed_msg_fname,
        )
    else:
        email_file.unlink(missing_ok=True)


####################################################################
#
@db_task(retries=3, retry_delay=15)
def process_bounce(email_account_pk: int, event: BounceEvent) -> None:
    """
    Process a normalized bounce or spam complaint from any provider backend.

    Both delivery bounces and spam complaints go through the same core logic:
      - If non-transient: increment ea.num_bounces and save.
      - If the provider has blacklisted the recipient: record an InactiveEmail.
      - If the bounce limit is exceeded: deactivate the account and notify the
        account owner via send_mail.
      - Send a DSN to the EmailAccount via report_failed_message.

    The BounceEvent dataclass is produced by each provider's
    handle_bounce_webhook() after normalizing its provider-specific payload.

    Args:
        email_account_pk: Primary key of the sending EmailAccount.
        event: Normalized bounce/spam event from the provider backend.
    """
    notify_user = False
    ea = EmailAccount.objects.get(pk=email_account_pk)

    # Derive all user-facing label strings from the bounce type in one place
    # so that adding a new BounceType only requires adding a case here.
    #
    match event.bounce_type:
        case BounceType.SPAM:
            event_label = "spam complaint"
            report_opening = "been marked as spam"
            subject_prefix = "Spam complaint"
        case BounceType.BOUNCE:
            event_label = "bounce"
            report_opening = "bounced"
            subject_prefix = "Bounced email"
        case _:
            event_label = str(event.bounce_type)
            report_opening = f"triggered a {event_label} event"
            subject_prefix = event_label.capitalize()

    report_text = [
        f"Email from {event.email_from} to {event.email_to} has {report_opening}."
    ]

    # Only permanent (non-transient) events count against the bounce limit.
    # Transient failures (e.g. a temporary "defer") are retriable and should
    # not penalize the account.
    #
    if not event.transient:
        ea.num_bounces += 1
        ea.save()
        report_text.append(f"Number of {event_label}s: {ea.num_bounces}")
        report_text.append(
            f"Email account will be deactivated from sending emails if this "
            f"number exceeds {ea.NUM_EMAIL_BOUNCE_LIMIT} in a day "
            "(the number of bounces will automatically decrease by 1 each day.)"
        )

    # Some providers permanently blacklist a recipient after too many bounces.
    # Record that here so the system knows not to attempt delivery to that
    # address in the future, and surface it in the DSN to the sender.
    #
    if event.inactive:
        inactive, _ = InactiveEmail.objects.get_or_create(
            email_address=event.email_to
        )
        if inactive.can_activate != event.can_activate:
            inactive.can_activate = event.can_activate
            inactive.save()
        logger.info(
            "Email %s is marked inactive by provider. Can activate: %s, "
            "sending account: %s",
            event.email_to,
            event.can_activate,
            ea.email_address,
        )
        report_text.append(
            f"The provider has marked this email address ({event.email_to}) "
            "as inactive and will not send email to this address. "
            f"Reactivatable: {event.can_activate}. Contact the system "
            "administrator to see if this can be resolved."
        )

    # Deactivate the account when the permanent-bounce count hits the limit.
    # Transient bounces are intentionally excluded: a temporary deferral should
    # not lock out the account even if the counter is already at its ceiling.
    # Once deactivated the account can still receive mail; it just cannot send.
    #
    if not event.transient and not ea.deactivated:
        if ea.num_bounces >= ea.NUM_EMAIL_BOUNCE_LIMIT:
            notify_user = True
            ea.deactivated = True
            ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BOUNCES_REASON
            ea.save()
            logger.info(
                "process_bounce: Account %s deactivated due to excessive %ss",
                ea,
                event_label,
            )
            report_text.append(
                f"The account ({event.email_from}) has been deactivated from "
                f"sending email due to excessive {event_label}s. The account "
                "will automatically be reactivated after at most a day. "
                "\nNOTE: This account can still receive email. It just cannot "
                "send new emails."
            )

    # Append any provider-supplied description and diagnostic details to the
    # DSN so the account owner has as much context as possible.
    #
    if event.description:
        report_text.append(f"Description: {event.description}")
    if event.details:
        report_text.append(f"Details: {event.details}")

    report_msg = "\n".join(report_text)

    # If the account was just deactivated, also send a plain email to the
    # owner's user account address. The owner may have forwarding set up on
    # their EmailAccount, so the DSN alone might not reach them.
    #
    if notify_user:
        send_mail(
            f"NOTICE: The email account {ea.email_address} has been "
            "deactivated and can not send email",
            report_msg,
            None,
            [ea.owner.email],
            fail_silently=True,
        )

    subject_detail = event.subject if event.subject else event.email_to
    report_failed_message(
        ea,
        failed_message=event.original_message or event.description,
        report_text=report_msg,
        subject=f"{subject_prefix}: {subject_detail}",
        action="failed",
        status="5.1.1",
        diagnostic=f"smtp; {event.details or event.description}",
    )


####################################################################
#
@db_task(retries=10, retry_delay=2)
@lock_task("pwfile")
def check_update_pwfile_for_emailaccount(ea_pk: int) -> None:
    """
    We are doing a manual retry because normal retries still log exceptions
    and there seem to be a problem with huey and the version of redis we are
    using getting a ZADD error like we are using a priority queue or
    something.. so just do our own retries on failures to look up the email
    account.

    NOTE: If this EmailAccount has no LocalDelivery (e.g. it is alias-only),
          the password file will not be updated because there is no local
          maildir to record.
    """
    # The password file is at the root of the maildir directory
    #
    write = False
    ea = EmailAccount.objects.get(pk=ea_pk)

    # NOTE: The path to the mail dir is relative to the directory that the
    #       password file is in. In settings the password file is always in
    #       MAIL_DIRS directory.
    #
    local_delivery = LocalDelivery.objects.filter(email_account=ea).first()
    if not local_delivery or not local_delivery.maildir_path:
        logger.warning(
            "No LocalDelivery with maildir_path for %s; skipping password file update",
            ea.email_address,
        )
        return
    ea_mail_dir = Path(local_delivery.maildir_path).relative_to(
        settings.EXT_PW_FILE.parent
    )
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    if ea.email_address not in accounts:
        accounts[ea.email_address] = PWUser(
            ea.email_address, ea_mail_dir, ea.password
        )
        write = True
        logger.info("Adding '%s' to external password file", ea.email_address)
    else:
        account = accounts[ea.email_address]
        if account.maildir != ea_mail_dir:
            account.maildir = ea_mail_dir
            logger.info(
                "Updating '%s''s mail dir to: '%s' in external password file",
                ea.email_address,
                ea_mail_dir,
            )
            write = True
        if account.pw_hash != ea.password:
            account.pw_hash = ea.password
            logger.info(
                "Updating '%s''s password hash external password file",
                ea.email_address,
            )
            write = True

    if write:
        write_emailaccount_pwfile(settings.EXT_PW_FILE, accounts)


####################################################################
#
@task(retries=5, retry_delay=5)
@lock_task("pwfile")
def delete_emailaccount_from_pwfile(email_address: str):
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    if email_address in accounts:
        logger.info("Deleting '%s' from external password file", email_address)
        del accounts[email_address]
        write_emailaccount_pwfile(settings.EXT_PW_FILE, accounts)


########################################################################
########################################################################
#
# Provider Server and Email Account Management Tasks
#
# These tasks handle server registration and email account
# creation/deletion/synchronization across multiple email providers
# (forwardemail, postmark, etc.)
#
########################################################################
########################################################################


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_create_update_server(server_pk: int, provider_name: str) -> None:
    """
    Register or update a server's domain on the specified provider.

    Idempotent — safe to call when the domain already exists. Triggered
    when a provider is added to a Server's receive_providers, or when
    a Server's send_provider is set or changed.

    Args:
        server_pk: Primary key of the Server instance
        provider_name: Name of the provider backend
                       (e.g., 'forwardemail', 'postmark')
    """

    server = Server.objects.get(pk=server_pk)
    backend = get_backend(provider_name)

    try:
        changed = backend.create_update_domain(server)
        if changed:
            logger.info(
                "Updated domain '%s' on provider '%s'",
                server.domain_name,
                provider_name,
            )
        else:
            logger.debug(
                "Domain '%s' already up to date on provider '%s'",
                server.domain_name,
                provider_name,
            )
    except Exception as e:
        logger.exception(
            "Failed to register server '%s' on provider '%s': %r",
            server.domain_name,
            provider_name,
            e,
        )
        raise


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_create_or_update_email_account(
    email_account_pk: int, provider_name: str
) -> None:
    """
    Create or update an email account on the specified provider.

    This task is triggered when an EmailAccount is created or its enabled state
    changes, and its server has the specified provider configured as a receive
    provider.

    Args:
        email_account_pk: Primary key of the EmailAccount instance
        provider_name: Name of the provider backend (e.g., 'forwardemail',
                      'postmark')
    """
    email_account = EmailAccount.objects.get(pk=email_account_pk)
    backend = get_backend(provider_name)

    try:
        backend.create_update_email_account(email_account)
        logger.info(
            "Created/updated email account '%s' on provider '%s'",
            email_account.email_address,
            provider_name,
        )
    except Exception as e:
        logger.exception(
            "Failed to create/update email account '%s' on provider '%s': %r",
            email_account.email_address,
            provider_name,
            e,
        )
        raise


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_delete_email_account(
    email_address: str, domain_name: str, provider_name: str
) -> None:
    """
    Delete an email account from the specified provider.

    This task is triggered when an EmailAccount is deleted. We pass the
    email_address and domain_name as strings rather than the EmailAccount
    pk because the EmailAccount may no longer exist when this task runs.

    Args:
        email_address: The email address of the email account to delete
        domain_name: The domain name of the server
        provider_name: Name of the provider backend (e.g., 'forwardemail', 'postmark')
    """
    backend = get_backend(provider_name)

    try:
        # We need to look up the server to get provider-specific info
        server = Server.objects.get(domain_name=domain_name)
        backend.delete_email_account_by_address(email_address, server)
        logger.info(
            "Deleted email account '%s' from provider '%s'",
            email_address,
            provider_name,
        )
    except Server.DoesNotExist:
        logger.warning(
            "Cannot delete email account '%s': server '%s' no longer exists",
            email_address,
            domain_name,
        )
    except Exception as e:
        logger.exception(
            "Failed to delete email account '%s' from provider '%s': %r",
            email_address,
            provider_name,
            e,
        )
        raise


####################################################################
#
def _alias_sync_last_ok(server_pk: int, provider_name: str) -> float | None:
    """
    Return the Unix timestamp of the last successful EmailAccount/alias sync
    for the given server/provider pair, or None if never synced (or expired).
    """
    r = redis_client()
    val = r.get(f"alias_sync:last_ok:{server_pk}:{provider_name}")
    if val is None:
        return None
    return float(val)


####################################################################
#
def _alias_sync_set_ok(server_pk: int, provider_name: str) -> None:
    """
    Record a successful EmailAccount/alias sync for the given server/provider
    pair.  The key auto-expires after 48 hours so stale entries clean
    themselves up.
    """
    r = redis_client()
    r.set(
        f"alias_sync:last_ok:{server_pk}:{provider_name}",
        str(time.time()),
        ex=172800,  # 48 hours
    )


####################################################################
#
@db_task()
def provider_sync_server_email_accounts(
    server_pk: int, provider_name: str, enabled: bool
) -> None:
    """
    Bidirectional email account sync between local EmailAccounts and a provider.

    When enabled=True (normal sync, e.g. hourly or on provider add):
      - Creates email accounts on the provider for any local EmailAccount that
        is missing
      - Deletes email accounts on the provider that have no corresponding local
        EmailAccount (catches catch-alls, manually-created strays, leftovers
        from deleted EmailAccounts, etc.)
      - Calls create_update_email_account for each account present on both
        sides, which verifies all provider-specific settings and updates only
        what has drifted

    When enabled=False (provider removed from server's receive_providers):
      - Deletes ALL email accounts for this server from the provider

    Args:
        server_pk: Primary key of the Server instance
        provider_name: Name of the provider backend (e.g., 'forwardemail',
                       'postmark')
        enabled: True for normal sync; False to delete all remote email accounts
    """
    server = Server.objects.get(pk=server_pk)
    backend = get_backend(provider_name)

    # Fetch all existing aliases from the provider.
    #
    try:
        remote_email_accounts = backend.list_email_accounts(server)
    except KeyError as e:
        # Domain does not exist on the provider — nothing to sync or clean up.
        logger.error(
            "Failed to list email accounts for server '%s' on provider '%s'"
            " (domain does not exist on provider): %r",
            server.domain_name,
            provider_name,
            e,
        )
        return
    except requests.exceptions.ConnectionError as e:
        # Network-level failure (e.g. "Network is unreachable").  Don't
        # retry — the hourly scheduling will pick this up next run, and
        # the 24-hour staleness check will alert if it persists.
        logger.warning(
            "Network error syncing email accounts for server '%s' on "
            "provider '%s': %r",
            server.domain_name,
            provider_name,
            e,
        )
        return
    except Exception as e:
        logger.exception(
            "Failed to list email accounts for server '%s' on provider '%s': %r",
            server.domain_name,
            provider_name,
            e,
        )
        raise

    remote_map = {ea.email: ea for ea in remote_email_accounts}

    if not enabled:
        # Provider removed from server.
        #
        if Capability.MANAGES_EMAIL_ACCOUNTS not in backend.CAPABILITIES:
            logger.info(
                "Provider '%s' does not manage email accounts for server '%s'; "
                "no-op on provider removal",
                provider_name,
                server.domain_name,
            )
            return
        # Provider manages accounts — delete all of them (clean slate).
        #
        deleted_count = 0
        error_count = 0
        for email_addr in list(remote_map.keys()):
            try:
                backend.delete_email_account_by_address(email_addr, server)
                deleted_count += 1
                logger.info(
                    "Deleted email account '%s' from provider '%s' (provider removed)",
                    email_addr,
                    provider_name,
                )
            except Exception as e:
                error_count += 1
                logger.exception(
                    "Failed to delete email account '%s' on provider '%s': %r",
                    email_addr,
                    provider_name,
                    e,
                )
        logger.info(
            "Provider removal sync for server '%s' on provider '%s': "
            "%d deleted, %d errors",
            server.domain_name,
            provider_name,
            deleted_count,
            error_count,
        )
        return

    # enabled=True: full bidirectional sync.
    #
    email_accounts = EmailAccount.objects.filter(server=server)
    local_map = {ea.email_address: ea for ea in email_accounts}
    local_set = set(local_map.keys())
    remote_set = set(remote_map.keys())

    to_create = local_set - remote_set  # missing on provider → create
    to_delete = remote_set - local_set  # orphaned on provider → delete
    to_check = local_set & remote_set  # present on both → ensure enabled

    created_count = 0
    deleted_count = 0
    updated_count = 0
    skipped_count = 0
    error_count = 0

    for email_addr in to_create:
        try:
            backend.create_email_account(local_map[email_addr])
            created_count += 1
            logger.info(
                "Created missing email account '%s' on provider '%s'",
                email_addr,
                provider_name,
            )
        except Exception as e:
            error_count += 1
            logger.exception(
                "Failed to create email account '%s' on provider '%s': %r",
                email_addr,
                provider_name,
                e,
            )

    for email_addr in to_delete:
        try:
            backend.delete_email_account_by_address(email_addr, server)
            deleted_count += 1
            logger.info(
                "Deleted orphaned alias '%s' from provider '%s'",
                email_addr,
                provider_name,
            )
        except Exception as e:
            error_count += 1
            logger.exception(
                "Failed to delete orphaned alias '%s' on provider '%s': %r",
                email_addr,
                provider_name,
                e,
            )

    for email_addr in to_check:
        try:
            if backend.create_update_email_account(local_map[email_addr]):
                updated_count += 1
            else:
                skipped_count += 1
        except Exception as e:
            error_count += 1
            logger.exception(
                "Failed to sync email account '%s' on provider '%s': %r",
                email_addr,
                provider_name,
                e,
            )

    logger.info(
        "Alias sync for server '%s' on provider '%s': "
        "%d created, %d deleted, %d updated, %d skipped, %d errors",
        server.domain_name,
        provider_name,
        created_count,
        deleted_count,
        updated_count,
        skipped_count,
        error_count,
    )

    # Record successful sync so the hourly scheduler knows this pair is
    # up to date and can skip it until the interval elapses.
    #
    _alias_sync_set_ok(server_pk, provider_name)


####################################################################
#
@db_periodic_task(crontab(day="*", hour="3"))
def provider_sync_all_server_domains() -> None:
    """
    Daily task to ensure every server's domain configuration is up to date
    on all of its configured provider backends.

    Iterates through all servers and calls provider_create_update_server for
    each provider that the server uses (as either send_provider or
    receive_provider).  This catches configuration drift — for example a
    webhook URL that was corrected in code but never pushed to the remote
    service.
    """
    for server in Server.objects.prefetch_related("receive_providers").all():
        # Collect unique providers for this server (send + receive).
        #
        provider_names: set[str] = {
            p.backend_name for p in server.receive_providers.all()
        }
        if server.send_provider:
            provider_names.add(server.send_provider.backend_name)

        for provider_name in provider_names:
            try:
                backend = get_backend(provider_name)
                changed = backend.create_update_domain(server)
                if changed:
                    logger.info(
                        "Domain sync: updated '%s' on provider '%s'",
                        server.domain_name,
                        provider_name,
                    )
            except requests.exceptions.ConnectionError as e:
                logger.warning(
                    "Network error syncing domain config for server '%s' "
                    "on provider '%s': %r",
                    server.domain_name,
                    provider_name,
                    e,
                )
            except Exception as e:
                logger.exception(
                    "Failed to sync domain config for server '%s' on "
                    "provider '%s': %r",
                    server.domain_name,
                    provider_name,
                    e,
                )


####################################################################
#
@db_periodic_task(crontab(minute="0"))
def provider_sync_all_email_accounts() -> None:
    """
    Hourly task to sync EmailAccount/alias records across providers.

    Instead of syncing every server/provider pair on every run, this task
    spreads the work: it collects all pairs that are *due* (not successfully
    synced within ``ALIAS_SYNC_INTERVAL_SECONDS``), sorts them
    least-recently-synced first, and dispatches at most
    ``ALIAS_SYNC_MAX_PER_RUN`` per run.  Pairs that haven't been synced in
    ``ALIAS_SYNC_STALE_THRESHOLD_SECONDS`` generate an error log (Sentry
    alert).
    """
    now = time.time()

    # Build a list of (last_ok, server, provider_name) for all due pairs.
    #
    due_pairs: list[tuple[float, Server, str]] = []

    for provider in Provider.objects.all():
        try:
            get_backend(provider.backend_name)
        except Exception as e:
            logger.warning(
                "Failed to get backend for provider '%s': %r",
                provider.backend_name,
                e,
            )
            continue

        for server in Server.objects.filter(receive_providers=provider):
            last_ok = _alias_sync_last_ok(server.pk, provider.backend_name)

            # Skip pairs synced recently enough.
            #
            if (
                last_ok is not None
                and (now - last_ok) < ALIAS_SYNC_INTERVAL_SECONDS
            ):
                continue

            # Alert if this pair has gone too long without a successful sync.
            #
            if (
                last_ok is not None
                and (now - last_ok) >= ALIAS_SYNC_STALE_THRESHOLD_SECONDS
            ):
                logger.error(
                    "EmailAccount/alias sync for server '%s' on provider "
                    "'%s' has not succeeded in %.0f hours",
                    server.domain_name,
                    provider.backend_name,
                    (now - last_ok) / 3600,
                )
            elif last_ok is None:
                logger.info(
                    "No prior alias sync recorded for server '%s' on "
                    "provider '%s'; scheduling sync",
                    server.domain_name,
                    provider.backend_name,
                )

            # Use 0.0 for never-synced so they sort first (highest priority).
            #
            due_pairs.append(
                (
                    last_ok if last_ok is not None else 0.0,
                    server,
                    provider.backend_name,
                )
            )

    # Sort least-recently-synced first and cap the number we dispatch.
    #
    due_pairs.sort(key=lambda t: t[0])

    dispatched = 0
    for _last_ok, server, provider_name in due_pairs:
        if dispatched >= ALIAS_SYNC_MAX_PER_RUN:
            break
        try:
            provider_sync_server_email_accounts(
                server.pk, provider_name, enabled=True
            )
            dispatched += 1
        except Exception as e:
            logger.exception(
                "Failed to dispatch alias sync for server '%s' on "
                "provider '%s': %r",
                server.domain_name,
                provider_name,
                e,
            )

    if due_pairs:
        logger.info(
            "Alias sync scheduler: %d due, %d dispatched, %d deferred",
            len(due_pairs),
            dispatched,
            max(0, len(due_pairs) - dispatched),
        )


####################################################################
#
@db_task()
def run_report(report_name: str) -> None:
    """
    Run a single named report and email the result to
    ADMINISTRATIVE_EMAIL_ADDRESS.

    Called by the scheduled report tasks with a delay so that reports
    do not all execute at the same moment.
    """
    if report_name not in REPORTS:
        logger.error("Unknown report name: %s", report_name)
        return

    report_def = REPORTS[report_name]

    output = report_def.generate()
    if not output:
        logger.debug(
            "Report '%s' returned no data, skipping email", report_name
        )
        return

    subject = report_def.subject
    try:
        send_mail(
            subject=subject,
            message=output,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.ADMINISTRATIVE_EMAIL_ADDRESS],
            fail_silently=False,
        )
        logger.info(
            "Sent '%s' report to %s",
            report_name,
            settings.ADMINISTRATIVE_EMAIL_ADDRESS,
        )
    except Exception as e:
        logger.exception("Failed to send '%s' report email: %r", report_name, e)


########################################################################
#
def _schedule_reports(schedule: ReportSchedule) -> None:
    """
    Find all reports for the given schedule and dispatch each one with
    a staggered delay so they do not all run at the same instant.

    Each report is delayed by an additional 10 minutes after the
    previous one.
    """
    reports = get_reports_by_schedule(schedule)
    for idx, report_def in enumerate(reports):
        delay_seconds = idx * 600  # 10 minutes apart
        run_report.schedule(
            args=(report_def.name,),
            delay=delay_seconds,
        )
        logger.info(
            "Scheduled '%s' report with %d second delay",
            report_def.name,
            delay_seconds,
        )


########################################################################
#
@db_periodic_task(crontab(day="*", hour="2"))
def run_daily_reports() -> None:
    """
    Daily task (02:00 UTC) that schedules all daily reports with
    staggered execution.
    """
    _schedule_reports(ReportSchedule.DAILY)


########################################################################
#
@db_periodic_task(crontab(day_of_week="1", hour="6"))
def run_weekly_reports() -> None:
    """
    Weekly task (Monday 06:00 UTC) that schedules all weekly reports
    with staggered execution.
    """
    _schedule_reports(ReportSchedule.WEEKLY)
