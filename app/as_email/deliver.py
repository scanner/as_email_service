#!/usr/bin/env python
#
"""
Utils for actually delivering email.

Delivery entry points
---------------------
For *incoming* user email, the entry point is
``dispatch_incoming_email`` (tasks.py), which iterates each enabled
DeliveryMethod individually so that per-method failures can be tracked in
Redis and retried selectively.

``EmailAccount.deliver(msg)`` still exists and is used in two narrower
contexts where per-method failure tracking is not needed:

- **Alias chains** — ``AliasToDelivery.deliver()`` calls
  ``target_account.deliver()`` to recurse through forwarding chains.
- **DSN / notification messages** — ``report_failed_message()`` calls
  ``ea.deliver(dsn)`` to deliver delivery-status notifications back to the
  account via whatever methods are still active.

This module provides the lower-level helpers called by those delivery methods:

- `deliver_message_locally(local_delivery, msg)` — called by
  `LocalDelivery.deliver()`. Applies message filter rules, spam auto-filing,
  and writes the message to the MH mailbox.

  NOTE: https://www.iana.org/assignments/message-headers/message-headers.xhtml
"""

# system imports
#
import email.utils
import logging
import time
from contextlib import contextmanager
from email.message import EmailMessage
from email.mime.text import MIMEText
from mailbox import MH, ExternalClashError, NoSuchMailboxError

# Project imports
#
from .models import EmailAccount, LocalDelivery, MessageFilterRule
from .utils import get_spam_score

ENCODINGS = ("ascii", "iso-8859-1", "utf-8")

logger = logging.getLogger(__name__)


####################################################################
#
def apply_message_filter_rules(
    email_account: EmailAccount, msg: EmailMessage
) -> list[str]:
    """
    Apply all of the message filter rules for this email account on this
    message.

    We return a list of mailboxes that the message should be delivered to. If
    the list is empty then the message is to be delivered to the 'inbox'
    mailbox.

    NOTE: In the future message filter rules might be able to do other things
          such as modifying the message or maybe even causing it to be
          delivered to a different address. But will leave that for later.
    """
    # XXX this allow matching multiple filter rules which would result in the
    #     message being delivered to multiple mailboxes. We will need to
    #     implement the `result` flag from slocal's maildelivery so we can
    #     differentiate if a message has already matched a filter rule or not
    #     letting the user specify more specific matches first so we can have
    #     it only delivered to one mailbox for those rules.
    #
    deliver_to = []
    frs = MessageFilterRule.objects.filter(email_account=email_account)
    for fr in frs:
        # XXX We are only applying rules that are not DESTROY. We will handle
        #     that later.
        #
        if fr.action == MessageFilterRule.DESTROY:
            continue
        if fr.match(msg):
            deliver_to.append(fr.destination)
            # XXX Because our first version does not have the deliver to
            #     multiple mailbox support, messages that match first in the
            #     rules get delivered to that matching rule's destination.
            #
            #     In the future we will support the different result types that
            #     slocal does.
            #
            #     This makes it important to have your most specific match
            #     ordered first in the rules.
            #
            return deliver_to
    return deliver_to


####################################################################
#
@contextmanager
def lock_folder(folder: MH, timeout: int | float = 20, fail: bool = False):
    """
    Try to get an advisory lock on the MH folder in question.
    We will loop until we manage to get the lock, or we hit our timeout.

    If `fail` is True then if we are unable to get the lock, we re-raise the
    ExternalClashError. If `fail` is False (the default) we proceed as if we
    got the lock.
    """
    while timeout > 0:
        try:
            folder.lock()
            break
        except (ExternalClashError, FileExistsError):
            if fail:
                raise
            timeout -= 0.1
            time.sleep(0.1)
    try:
        yield
    finally:
        folder.unlock()


####################################################################
#
def _add_msg_to_folder(folder: MH, msg: EmailMessage):
    """
    Adding a message to a MH folder requires several simple steps. This
    wraps those steps.
    """
    # To deal with encoding snafus from whoever sent this message we try to
    # encode it as bytes using several different encoders.
    #
    msg_bytes = None
    msg_text = msg.as_string(policy=email.policy.default)
    for encoding in ENCODINGS:
        try:
            msg_bytes = msg_text.encode(encoding)
            break
        except ValueError:
            pass

    if msg_bytes is None:
        raise ValueError(f"Unable to encode message using any of {ENCODINGS}")

    with lock_folder(folder):
        msg_id = int(folder.add(msg_bytes))
        sequences = folder.get_sequences()
        if "unseen" in sequences:
            sequences["unseen"].append(msg_id)
        else:
            sequences["unseen"] = [msg_id]
        folder.set_sequences(sequences)


####################################################################
#
def deliver_message_locally(
    local_delivery: LocalDelivery, msg: EmailMessage
) -> None:
    """
    Deliver the email message to the MH mailbox for the given LocalDelivery
    method. Applies message filter rules first; if none match, delivers to the
    inbox (or the spam folder if autofile_spam is enabled and the score is high
    enough).
    """
    email_account = local_delivery.email_account
    deliver_to = apply_message_filter_rules(email_account, msg)
    delivered_to = []

    mh = local_delivery.MH()
    for mbox in deliver_to:
        try:
            folder = mh.get_folder(mbox)
            _add_msg_to_folder(folder, msg)
            delivered_to.append(mbox)
        except NoSuchMailboxError:
            logger.warning(
                "for email account %s, attempted to deliver message to "
                "non-existing mailbox %s",
                email_account.email_address,
                mbox,
            )

    # If no filter rule matched, deliver to inbox — unless the message looks
    # like spam and autofile_spam is on.
    #
    # XXX Do we want to consider auto-filing spam no matter which mailbox it is
    #     delivered to?
    #
    if not delivered_to:
        if (
            local_delivery.autofile_spam
            and get_spam_score(msg) >= local_delivery.spam_score_threshold
        ):
            junk = local_delivery.spam_delivery_folder
            try:
                folder = mh.get_folder(junk)
            except NoSuchMailboxError:
                folder = mh.add_folder(junk)
            _add_msg_to_folder(folder, msg)
        else:
            try:
                folder = mh.get_folder("inbox")
            except NoSuchMailboxError:
                folder = mh.add_folder("inbox")
            _add_msg_to_folder(folder, msg)


####################################################################
#
def make_delivery_status_notification(
    email_account: EmailAccount,
    report_text: str,
    subject: str,
    from_addr: str,
    action: str,
    diagnostic: str,
    status: str,
    reported_msg: EmailMessage,
) -> EmailMessage:
    """
    Create an email message that is a delivery status notification.

    The DSN follows the standards in:
    - https://www.rfc-editor.org/rfc/rfc3464
    - https://www.rfc-editor.org/rfc/rfc3463

    `report_text` is the overall human readable report.

    - from_addr: the destination email address that the bounce message was
                 being sent to.
    - action: typically the string 'failed'
    - status: status, three digit code.
              5.1.1 - bad dest mailbox,
              5.1.2 - bad dest domain name
    - diagnostic code: typically something like 'smtp; ### <blah blah blah>'

    The `reported_msg` will be attached as an inline message/rfc822.

    The DSN is always from 'mailer-daemon@<account.server.domain_name>'
    """
    server = email_account.server
    to_addr = email_account.email_address

    dsn = EmailMessage(policy=email.policy.default)
    dsn.preamble = "This is a MIME-encapsulated message"
    dsn["From"] = f"mailer-daemon@{server.domain_name}"
    dsn["Subject"] = subject
    dsn["To"] = to_addr
    dsn["Message-ID"] = email.utils.make_msgid(
        idstring="mailer-daemon",
        domain=server.domain_name,
    )
    dsn["Date"] = email.utils.localtime()

    if "Date" in reported_msg:
        arrival_date = reported_msg["Date"]
    else:
        arrival_date = email.utils.formatdate(localtime=True)

    dsn.set_content(report_text)

    last_attempt_date = email.utils.formatdate(localtime=True)
    delivery_status = [
        f"Reporting-MTA: dns; {server.domain_name}",
        f"Arrival-Date: {arrival_date}",
        "",
        f"Original-Recipient: rfc822; {from_addr}",
        f"Final-Recipient: rfc822; {from_addr}",
        f"Action: {action}",
        f"Status: {status}",
        f"Diagnostic-Code: {status}",
        f"Last-Attempt-Date: {last_attempt_date}",
    ]
    status_text = MIMEText(
        "\n".join(delivery_status), policy=email.policy.default
    )

    # We delete the MIMEText's headers because we are attaching this, and
    # replacing the attachment's content-type with
    # 'message/delivery-status'. If we do not do this we have extraneous MIME
    # headers appearing in the message/delivery-status part of the message.
    #
    for header in status_text.keys():
        del status_text[header]

    dsn.add_attachment(status_text, cte="7bit")
    dsn.add_attachment(reported_msg)

    # Update the content-type to reflect that this is a dsn multipart/report
    #
    dsn.replace_header("Content-Type", "multipart/report")
    dsn.set_param("report-type", "delivery-status", replace=True)

    # Make sure our message/delivery-status and message/rfc822 attachments are
    # 'inline'. Also fix the header of the message/delivery-status part to
    # actaully be message/delivery-status.
    #
    parts = list(dsn.iter_attachments())
    parts[-1].replace_header("Content-Disposition", "inline")
    parts[-2].replace_header("Content-Type", "message/delivery-status")
    parts[-2].replace_header("Content-Disposition", "inline")

    return dsn


####################################################################
#
def report_failed_message(
    email_address: str | EmailAccount,
    failed_message: str | bytes | EmailMessage,
    report_text: str,
    subject: str,
    action: str,
    status: str,
    diagnostic: str,
):
    """
    Construct a Delivery Status Notification (DSN) and deliver it to the
    given EmailAccount via ``EmailAccount.deliver()``.

    This is one of the two internal callers of ``EmailAccount.deliver()``
    that intentionally bypass the per-method retry tracking used by
    ``dispatch_incoming_email``.  DSNs are best-effort: if a delivery method
    is down the notification is silently lost rather than queued for retry,
    which avoids recursive failure loops (a DSN failing to deliver should
    not itself generate another DSN).

    Only delivers to addresses that belong to an EmailAccount; if
    ``email_address`` is a string that does not match any account, the call
    is a no-op and an error is logged.

    Args:
        email_address: The account to deliver the DSN to.  May be an
            EmailAccount instance or an email address string.
        failed_message: The original message that failed.  Accepted as a
            string, bytes, or EmailMessage; converted internally as needed.
        report_text: Human-readable explanation included in the DSN body.
        subject: Subject line of the DSN.
        action: Short action word, typically ``"failed"``.
        status: RFC 3463 three-part status code (e.g. ``"5.1.1"``).
        diagnostic: Diagnostic string, e.g. ``"smtp; 550 No such user"``.
    """
    if isinstance(email_address, str):
        try:
            ea = EmailAccount.objects.get(email_address=email_address)
        except EmailAccount.DoesNotExist:
            logger.error(
                "Failed to lookup EmailAccount for '%s' when attempting to deliver a failed message report",
                email_address,
                extra={
                    "subject": subject,
                    "action": action,
                    "diagnostic": diagnostic,
                },
            )
            return
    else:
        ea = email_address

    # B-/ email.policy.default really makes this return an EmailMessage, not a
    # Message. We use cast to make mypy understand this.
    #
    if isinstance(failed_message, bytes):
        message = email.message_from_bytes(
            failed_message,
            policy=email.policy.default,
        )
    elif isinstance(failed_message, str):
        message = email.message_from_string(
            failed_message,
            policy=email.policy.default,
        )
    else:
        message = failed_message

    dsn = make_delivery_status_notification(
        ea,
        report_text=report_text,
        subject=subject,
        from_addr=message["From"],
        action=action,
        status=status,
        diagnostic=diagnostic,
        reported_msg=message,
    )

    try:
        ea.deliver(dsn)
    except Exception:
        logger.exception(
            "Failed to deliver DSN message from %s, '%s' (%s) to %s",
            message["From"],
            subject,
            dsn["Message-ID"],
            ea.email_address,
        )
