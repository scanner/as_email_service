#!/usr/bin/env python
#
"""
SpamAssassin training message processor.

Reads forwarded spam/ham reports from a training inbox and stages the
extracted original messages into directories for ``sa-learn``.
"""

# system imports
#
import email.utils
import logging
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

# 3rd party imports
#
from django.conf import settings
from django.core.management.base import CommandError

# Project imports
#
from .models import EmailAccount, LocalDelivery

logger = logging.getLogger(__name__)

# Recipient headers to inspect, in priority order, when determining
# whether the user forwarded to the spam or not-spam address.
#
RECIPIENT_HEADERS = ("delivered-to", "x-original-to", "to", "envelope-to")


########################################################################
#
@dataclass
class TrainingResult:
    """Summary counters for a single training run."""

    spam_count: int = 0
    ham_count: int = 0
    skipped_invalid_sender: int = 0
    skipped_no_classification: int = 0
    errors: int = 0


########################################################################
#
def find_training_local_delivery() -> LocalDelivery:
    """
    Find the LocalDelivery that receives spam/ham training messages.

    Checks both ``SPAM_TRAINING_ADDRESS`` and
    ``NOT_SPAM_TRAINING_ADDRESS``; returns whichever has an enabled
    LocalDelivery.

    Raises:
        CommandError: if the settings are not configured or neither
                      address has a LocalDelivery.
    """
    spam_addr = settings.SPAM_TRAINING_ADDRESS
    not_spam_addr = settings.NOT_SPAM_TRAINING_ADDRESS

    if not spam_addr and not not_spam_addr:
        raise CommandError(
            "Neither SPAM_TRAINING_ADDRESS nor NOT_SPAM_TRAINING_ADDRESS "
            "is configured in settings."
        )

    for addr in (spam_addr, not_spam_addr):
        if not addr:
            continue
        try:
            ea = EmailAccount.objects.get(
                email_address=addr.lower(), enabled=True
            )
            ld = LocalDelivery.objects.get(email_account=ea, enabled=True)
            return ld
        except (EmailAccount.DoesNotExist, LocalDelivery.DoesNotExist):
            continue

    raise CommandError(
        "No enabled LocalDelivery found for either "
        f"SPAM_TRAINING_ADDRESS ({spam_addr!r}) or "
        f"NOT_SPAM_TRAINING_ADDRESS ({not_spam_addr!r})."
    )


########################################################################
#
def validate_sender(msg: EmailMessage) -> bool:
    """
    Check that the sender is an enabled EmailAccount on this instance.

    Parses the ``From`` header and looks up the address against all
    enabled accounts.
    """
    from_header = msg.get("From", "")
    _, addr = email.utils.parseaddr(from_header)
    if not addr:
        return False

    return EmailAccount.objects.filter(
        email_address=addr.lower(), enabled=True
    ).exists()


########################################################################
#
def determine_classification(
    msg: EmailMessage,
    spam_addr: str,
    not_spam_addr: str,
) -> str | None:
    """
    Determine whether the forwarded message should be classified as
    spam or ham.

    Inspects recipient headers on the outer envelope to decide which
    training address the user sent to.

    Returns:
        ``"spam"``, ``"ham"``, or ``None`` if classification cannot be
        determined.
    """
    spam_addr = spam_addr.lower()
    not_spam_addr = not_spam_addr.lower()

    for header_name in RECIPIENT_HEADERS:
        values = msg.get_all(header_name, [])
        for value in values:
            _, addr = email.utils.parseaddr(str(value))
            addr = addr.lower()
            if addr == spam_addr:
                return "spam"
            if addr == not_spam_addr:
                return "ham"

    return None


########################################################################
#
def extract_forwarded_message(msg: EmailMessage) -> bytes:
    """
    Extract the original message from a forwarded email.

    Three scenarios are handled:

    1. **Forward as attachment** — a ``message/rfc822`` MIME part is
       present.  The attached original message bytes are returned.
    2. **SA-processed false positive** — SpamAssassin replaced the body
       with its report and attached the original as ``.eml``.  Same
       extraction path as (1).
    3. **Inline forward** — no ``message/rfc822`` part.  The entire
       forwarded message is returned as-is; body content still trains
       the Bayesian filter even though the forwarding headers are noise.
    """
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload(0)
            if isinstance(payload, EmailMessage):
                return payload.as_bytes()

    # Fallback: return the whole message
    return msg.as_bytes()


########################################################################
#
def process_training_inbox(
    training_dir: Path,
    stdout: object | None = None,
) -> TrainingResult:
    """
    Process all messages in the SA training inbox.

    Args:
        training_dir: Base directory for training output.  Messages are
                      written to ``training_dir/spam/`` or
                      ``training_dir/ham/``.
        stdout: Optional Django command stdout for progress output.

    Returns:
        TrainingResult with counts of processed messages.
    """
    result = TrainingResult()

    spam_addr = settings.SPAM_TRAINING_ADDRESS
    not_spam_addr = settings.NOT_SPAM_TRAINING_ADDRESS

    if not spam_addr or not not_spam_addr:
        raise CommandError(
            "Both SPAM_TRAINING_ADDRESS and NOT_SPAM_TRAINING_ADDRESS "
            "must be configured in settings."
        )

    local_delivery = find_training_local_delivery()
    mh = local_delivery.MH(create=False)

    try:
        inbox = mh.get_folder("inbox")
    except KeyError:
        logger.info("No inbox folder found in training mailbox")
        return result

    spam_dir = training_dir / "spam"
    ham_dir = training_dir / "ham"
    spam_dir.mkdir(parents=True, exist_ok=True)
    ham_dir.mkdir(parents=True, exist_ok=True)

    keys = inbox.keys()
    if not keys:
        logger.info("Training inbox is empty")
        return result

    for key in keys:
        try:
            msg = inbox.get(key)
            if msg is None:
                continue

            # Validate sender
            #
            if not validate_sender(msg):
                _, from_addr = email.utils.parseaddr(msg.get("From", ""))
                logger.warning(
                    "Discarding message %s from untrusted sender: %s",
                    key,
                    from_addr,
                )
                inbox.remove(key)
                result.skipped_invalid_sender += 1
                continue

            # Determine spam vs ham
            #
            classification = determine_classification(
                msg, spam_addr, not_spam_addr
            )
            if classification is None:
                logger.warning(
                    "Discarding message %s: cannot determine "
                    "classification from recipient headers",
                    key,
                )
                inbox.remove(key)
                result.skipped_no_classification += 1
                continue

            # Extract and save the original message
            #
            original_bytes = extract_forwarded_message(msg)
            dest_dir = spam_dir if classification == "spam" else ham_dir
            dest_path = dest_dir / str(key)
            dest_path.write_bytes(original_bytes)

            inbox.remove(key)

            if classification == "spam":
                result.spam_count += 1
            else:
                result.ham_count += 1

            logger.debug("Processed message %s as %s", key, classification)

        except Exception as e:
            logger.exception("Error processing message %s: %r", key, e)
            result.errors += 1

    return result
