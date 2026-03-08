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
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import cast

# 3rd party imports
#
import aiospamc
import pytz
import redis as redis_module
from django.conf import settings
from django.core.mail import send_mail
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task, lock_task, task
from postmarker.exceptions import ClientError

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
from .providers.base import Capability
from .utils import (
    BOUNCE_TYPES_BY_TYPE_CODE,
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
                retry_data = {}  # type: ignore[assignment]
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
                r.hset(redis_key, mapping=new_mapping)
                r.expire(redis_key, retry_days * 86400 * 2)
            else:
                r.hset(redis_key, mapping=new_mapping)
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
                delete_message = server.send_email_via_smtp(
                    message["From"],
                    rcpt_tos,
                    message,
                    spool_on_retryable=False,
                )
            except Exception as exc:
                # All raised exceptions are a hard fail and the spooled message
                # will be removed.
                #
                delete_message = True
                logger.exception(f"Unable to retry sending email: {exc}")
                failed_message = cast(
                    EmailMessage,
                    email.message_from_bytes(
                        message,
                        policy=email.policy.default,
                    ),
                )

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
        msg_bytes = msg.as_bytes(policy=email.policy.default)
        # NOTE: Use new_event_loop() + run_until_complete() instead of
        # asyncio.run() to avoid touching the global event loop policy.
        # asyncio.run() sets _set_called=True on the policy thread-local,
        # causing subsequent asyncio.get_event_loop() calls (e.g. in pydnsbl)
        # to raise RuntimeError rather than auto-creating a loop.
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
        logger.warning("Spam scan failed for incoming email: %r", e)
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
def process_email_bounce(email_account_pk: int, bounce: dict):
    """
    XXX This is specifically for dealing bounce notices from postmark,
        which is currently the only provider that should send these notices
        because it is the only provider with "send email" support.

        This logic should go in the provider backend.

    We have received an incoming bounce notification from postmark. The web
    front end decoded the bounce message and verified the email account that
    sent the message that generated the bounce and incremented the email
    accounts bounce count. This task handles the rest of the associated work:
      - if the number of bounces has been exceeded deactivate the account
      - send a notification email of the bounce to the account.

    NOTE: We have set huey task retries at 3, with a delay of 15s because we
          have seen the request for the bounce failing with "no such bounce"
          .. only to look for it by id later on and it to work fine.
    """
    # When an email account is deactivated we also send a message with just the
    # report text to the email address attached to the user account that is the
    # owner of the email account. This way if the user is unable to access
    # emails sent to their email account (because they have forwarding turned
    # on!) we will at least try to notify them via their user account that
    # there email account has been deactivated.
    #
    notify_user = False

    ea = EmailAccount.objects.get(pk=email_account_pk)
    client = ea.server.client

    # Get the bounce details if they are available.
    #
    to_addr = bounce["Email"]
    from_addr = bounce["From"]
    try:
        bounce_details = client.bounces.get(int(bounce["ID"]))
    except ClientError:
        logger.warning(
            "Unable to retrieve bounce info for bounce id: %d", bounce["ID"]
        )
        raise

    # We generate the human readable 'report_text' by constructing a list of
    # messages that will concatenated into a single string and passed as the
    # 'report_text' when making the DSN. This lets us stack up several parts of
    # the message and make it all at once instead of having to make several
    # different DSN's depending on the circumstances.
    #
    report_text = [f"Email from {from_addr} to {to_addr} has bounced."]

    # IF this bounce is not a transient bounce, then increment the number of
    # bounces this EmailAccount has generated.
    #
    transient = False
    if bounce_details.TypeCode in BOUNCE_TYPES_BY_TYPE_CODE:
        transient = BOUNCE_TYPES_BY_TYPE_CODE[bounce_details.TypeCode][
            "transient"
        ]
    else:
        logger.warning(
            f"Received bounce type code of {bounce_details.TypeCode}. This is "
            "not one of the recognized type code's. Assuming this is a "
            "non-transient bounce.",
            extra=bounce,
        )

    if not transient:
        ea.num_bounces += 1
        ea.save()
        report_text.append(f"Number of bounced emails: {ea.num_bounces}")
        report_text.append(
            f"Email account will be deactivated from sending emails if this "
            f"number exceeds {ea.NUM_EMAIL_BOUNCE_LIMIT} in a day "
            "(the number of bounces will automatically decrease by 1 each day.)"
        )

    # If `Inactive` is true then this bounce has caused postmark to disable
    # sending to this email address.
    #
    if bounce_details.Inactive:
        inactive, _ = InactiveEmail.objects.get_or_create(
            email_address=bounce_details.Email
        )
        if inactive.can_activate != bounce_details.CanActivate:
            inactive.can_activate = bounce_details.CanActivate
            inactive.save()
        logger.info(
            "Email %s is marked inactive by postmark. Can activate: %s, "
            "sending account: %s: %s",
            bounce_details.Inactive,
            bounce_details.CanActivate,
            ea.email_address,
            bounce_details.Description,
            extra=bounce,
        )

        report_text.append(
            f"Postmark has marked this email address ({bounce_details.Email}) "
            "as inactive and will not send email to this address. Postmark "
            "has marked this address as reactivatable as: "
            f"{bounce_details.CanActivate}. Contact the system adminstrator "
            "to see if this can be resolved."
        )

    if not ea.deactivated:
        if ea.num_bounces >= ea.NUM_EMAIL_BOUNCE_LIMIT:
            notify_user = True
            ea.deactivated = True
            ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BOUNCES_REASON
            ea.save()
            logger.info(
                "process_email_bounce: Account %s deactivated due to "
                "excessive bounces",
                ea,
            )
            report_text.append(
                f"The account ({from_addr}) has been deactivated from sending "
                "email due to excessive bounced email messages. email account "
                "Will automatically be reactivated after in at most a day. "
                "\nNOTE: This account can still receive email. It just can not "
                "send new emails."
            )

    report_text.append(f"Bounce type: {bounce_details.Type}")
    report_text.append(f"Bounce description: {bounce_details.Description}")
    report_text.append(f"Bounce details: {bounce_details.Details}")
    report_msg = "\n".join(report_text)

    # `notify_user` means we send the report complaint to the user's email
    # address as well (not just the EmailAccount.)
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

    report_failed_message(
        ea,
        failed_message=bounce_details.Content,
        report_text=report_msg,
        subject="Bounced email: " + bounce_details.Subject,
        action="failed",
        status="5.1.1",
        diagnostic=f"smtp; {bounce_details.Details}",
    )


####################################################################
#
@db_task()
def process_email_spam(email_account_pk: int, spam: dict):
    """
    Our incoming spam complaint webhook was triggered. The view only does
    some curosry work on the data we got. The meat of the work happens in this
    task.

    Spam complaints count as bounces.
    We notify the user that sent the email.
    If `Inactive` is true get/create an InactiveEmail.
    """
    ea = EmailAccount.objects.get(pk=email_account_pk)

    # Get the bounce details if they are available.
    #
    to_addr = spam["Email"]
    from_addr = spam["From"]

    # We generate the human readable 'report_text' by constructing a list of
    # messages that will concatenated into a single string and passed as the
    # 'report_text' when making the DSN. This lets us stack up several parts of
    # the message and make it all at once instead of having to make several
    # different DSN's depending on the circumstances.
    #
    report_text = [
        f"Email marked as spam from {from_addr} to {to_addr}, "
        f"subject: '{spam['Subject']}'"
    ]

    # IF this bounce is not a transient bounce, then increment the number of
    # bounces this EmailAccount has generated.
    #
    notify_user = False
    transient = False
    if spam["TypeCode"] in BOUNCE_TYPES_BY_TYPE_CODE:
        transient = BOUNCE_TYPES_BY_TYPE_CODE[spam["TypeCode"]]["transient"]
    else:
        logger.warning(
            f"Received spam complaint of {spam['TypeCode']}. This is "
            "not one of the recognized type code's.",
            extra=spam,
        )

    if not transient:
        ea.num_bounces += 1
        ea.save()
        report_text.append(f"Number of bounced emails: {ea.num_bounces}")
        report_text.append(
            f"Email account will be deactivated from sending emails if this "
            f"number exceeds {ea.NUM_EMAIL_BOUNCE_LIMIT} in a day "
            "(the number of bounces will automatically decrease by 1 each day.)"
        )

    # If `Inactive` is true then this bounce has caused postmark to disable
    # sending to this email address.
    #
    if spam["Inactive"]:
        inactive, _ = InactiveEmail.objects.get_or_create(
            email_address=spam["Email"]
        )
        if inactive.can_activate != spam["CanActivate"]:
            inactive.can_activate = spam["CanActivate"]
            inactive.save()
        logger.info(
            "Email %s is marked inactive by postmark. Can activate: %s, "
            "sending account: %s: %s",
            spam["Email"],
            spam["CanActivate"],
            ea.email_address,
            spam["Description"],
            extra=spam,
        )

        report_text.append(
            f"Postmark has marked this email address ({spam['Email']}) "
            "as inactive and will not send email to this address. Postmark "
            "has marked this address as reactivatable as: "
            f"{spam['CanActivate']}. Contact the system adminstrator "
            "to see if this can be resolved."
        )

    if not ea.deactivated:
        if ea.num_bounces >= ea.NUM_EMAIL_BOUNCE_LIMIT:
            notify_user = True
            ea.deactivated = True
            ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BOUNCES_REASON
            ea.save()
            logger.info(
                "Account %s deactivated due to excessive spam/bounces",
                ea,
                extra=spam,
            )
            report_text.append(
                f"The account ({from_addr}) has been deactivated from sending "
                "email due to excessive spam email messages. the email account "
                "Will automatically be reactivated after in at most a day. "
                "\nNOTE: This account can still receive email. It just can not "
                "send new emails."
            )

    report_text.append(f"Spam type: {spam['Type']}")
    report_text.append(f"Spam description: {spam['Description']}")
    report_text.append(f"Spam details: {spam['Details']}")
    report_msg = "\n".join(report_text)

    # `notify_user` means we send the report complaint to the user's email
    # address as well (not just the EmailAccount.)
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

    msg = spam["Content"] if "Content" in spam else spam["Description"]
    report_failed_message(
        ea,
        failed_message=msg,
        report_text=report_msg,
        subject="Message marked as spam: " + spam["Subject"],
        action="failed",
        status="5.1.1",
        diagnostic=f"smtp; {spam['Details']}",
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
def provider_create_server(server_pk: int, provider_name: str) -> None:
    """
    Register a server's domain on the specified provider.

    This task is triggered when a provider is added to a Server's
    receive_providers.

    Args:
        server_pk: Primary key of the Server instance
        provider_name: Name of the provider backend
                       (e.g., 'forwardemail', 'postmark')
    """

    server = Server.objects.get(pk=server_pk)
    backend = get_backend(provider_name)

    try:
        backend.create_domain(server)
        logger.info(
            "Registered server '%s' on provider '%s'",
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
@db_task(retries=3, retry_delay=10)
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
        # Log at error level (no traceback) and return so Huey does not retry.
        logger.error(
            "Failed to list email accounts for server '%s' on provider '%s'"
            " (domain does not exist on provider): %r",
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


####################################################################
#
@db_periodic_task(crontab(minute="0"))
def provider_sync_all_email_accounts() -> None:
    """
    Hourly task to sync email accounts across all servers and configured
    providers.

    Enqueues provider_sync_server_email_accounts for every server/provider
    combination, passing enabled=True when the provider is configured as a
    receive provider for that server and enabled=False when it is not.
    """
    # Process each provider that supports email account management
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

        servers_with_provider = Server.objects.filter(
            receive_providers=provider
        )

        for server in servers_with_provider:
            try:
                provider_sync_server_email_accounts(
                    server.pk, provider.backend_name, enabled=True
                )
            except Exception as e:
                logger.exception(
                    "Failed to sync email accounts for server '%s' on provider '%s': %r",
                    server.domain_name,
                    provider.backend_name,
                    e,
                )


####################################################################
#
@db_periodic_task(crontab(day="*", hour="2"))
def provider_report_unused_servers() -> None:
    """
    Daily task to report servers on all providers that have no active email
    accounts.

    This only looks at providers that can receive email that are assigned to at
    least one server.

    NOTE: This only bothers with backend providers that have support for
          individual email accounts per server (ie: on the provider we can
          specify specific email addresses that are active and can receive
          email. `forwardemail`, for instance, lets us specify which email
          addresses on your domain can accept email. All others are
          refused. However `postmark` has no way to say which email accounts
          will accept email: They all will.

    Sends an email report to ADMINISTRATIVE_EMAIL_ADDRESS with details of any
    unused servers.

    XXX: Review whether this report is still useful. Since every Server
         automatically gets a set of administrative EmailAccounts on creation
         (see check_create_maintenance_email_accounts signal), it is rare in
         practice for a server to have zero email accounts.
    """
    all_unused = []

    # Process each provider that supports server management
    #
    for provider in Provider.objects.all():

        for server in provider.receiving_servers.all():
            unused_servers = []
            email_account_count = server.email_accounts.count()
            if email_account_count == 0:
                unused_servers.append((server.domain_name, 0))
            else:
                # Even if there are EmailAccounts, check if any are actually
                # enabled
                #
                try:
                    backend = get_backend(provider.backend_name)
                    remote_email_accounts = backend.list_email_accounts(server)
                    enabled_count = sum(
                        1 for ea in remote_email_accounts if ea.enabled
                    )
                    if enabled_count == 0:
                        unused_servers.append(
                            (server.domain_name, email_account_count)
                        )
                except Exception as e:
                    logger.warning(
                        "Failed to check email accounts for server '%s' on provider '%s': %r",
                        server.domain_name,
                        provider.backend_name,
                        e,
                    )

        if unused_servers:
            all_unused.append((provider.backend_name, unused_servers))

    # Build email report
    if all_unused:
        report_lines = ["Provider unused servers report:", ""]
        total_unused = 0
        for provider_name, servers in all_unused:
            report_lines.append(f"Provider '{provider_name}':")
            for domain_name, count in servers:
                report_lines.append(
                    f"  - {domain_name}: {count} email account(s)"
                )
                total_unused += 1
            report_lines.append("")

        subject = f"AS Email Service: {total_unused} unused server(s) detected"
        message = "\n".join(report_lines)
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.ADMINISTRATIVE_EMAIL_ADDRESS],
                fail_silently=False,
            )
            logger.info(
                "Sent unused servers report to %s: %d unused server(s)",
                settings.ADMINISTRATIVE_EMAIL_ADDRESS,
                total_unused,
            )
        except Exception as e:
            logger.exception(
                "Failed to send unused servers report email: %r", e
            )
    else:
        logger.debug("No unused servers found across all providers")
