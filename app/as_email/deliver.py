#!/usr/bin/env python
#
"""
Utils for actually delivering email.

There are three main entry points:

- locally deliver to a Mailbox we have direct access to on this machine (file
  system)

- lookup all the aliases for an email account and deliver this message to each
  of those email addresses, which might be more aliases, local, or forwards
  NOTE: we should make sure that an alias does not nest to deep when the
  EmailAccount is saved. (Perhaps three levels?). The first level of alias will
  add an "Original-Recipient" header.

- forward the email to an account not managed by this service.  Forwarded will
  add an "Original-Message-Id", "Original-Recipient", "Resent-From",
  "Original-From", "Reply-To". Also since we can not re-write 'From' to be an
  address that we do not control we will either encapsulate the forwarded
  message or send it as is based on the setting on the EmailAccount.

  NOTE: if forwarded messages bounce, forwarding will be disabled and the
        account will turn back to local delivery.

  NOTE: https://www.iana.org/assignments/message-headers/message-headers.xhtml
"""
# system imports
#
import email.utils
import logging
from email.message import EmailMessage
from email.mime.text import MIMEText
from mailbox import MH, NoSuchMailboxError
from typing import List

# Project imports
#
from .models import EmailAccount, MessageFilterRule

logger = logging.getLogger(__name__)


####################################################################
#
def deliver_message(
    email_account: EmailAccount,
    msg: EmailMessage,
    depth: int = 1,
):
    """
    Deliver the given message to the given email account. This accounts for
    locally delivery, aliases, and forwards to external systems.
    """
    # If the max alias depth is exceeded the message is delivered locally to
    # this account and a message is logged.
    #
    if depth > EmailAccount.MAX_ALIAS_DEPTH:
        deliver_message_locally(email_account, msg)
        logger.warning(
            f"Deliver recursion too deep for message {msg['Message-ID']}, "
            f"for account {email_account.email_address}, depth: {depth}"
        )

    match email_account.delivery_method:
        case EmailAccount.LOCAL_DELIVERY:
            deliver_message_locally(email_account, msg)
        case EmailAccount.IMAP_DELIVERY:
            pass  # XXX implementation forthcoming
        case EmailAccount.ALIAS:
            for alias_for in email_account.alias_for.all():
                deliver_message(alias_for, msg, depth + 1)
        case EmailAccount.FORWARDING:
            forward_message(email_account, msg)


####################################################################
#
def apply_message_filter_rules(
    email_account: EmailAccount, msg: EmailMessage
) -> List[str]:
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
def _add_msg_to_folder(folder: MH, msg: EmailMessage):
    """
    Adding a message to a MH folder requires several simple steps. This
    wraps those steps.
    """
    try:
        folder.lock()
        msg_id = folder.add(msg)
        sequences = folder.get_sequences()
        if "unseen" in sequences:
            sequences["unseen"].append(msg_id)
        else:
            sequences["unseen"] = [msg_id]
        folder.set_sequences(sequences)
    finally:
        folder.unlock()


####################################################################
#
def deliver_message_locally(email_account: EmailAccount, msg: EmailMessage):
    """
    Deliver the email_message in to the MH mail dir for the given email
    account.
    """
    deliver_to = apply_message_filter_rules(email_account, msg)
    delivered_to = []

    # If no mailbox was specified by any of the message filter rules, then
    # deliver this message to the inbox.
    #
    mh = email_account.MH()
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

    # If the message was not delivered to any folders in the above loop,
    # deliver it to the inbox, unless auto filing for spam is turned on and it
    # is spam.
    #
    if not delivered_to:
        spam_score = 0
        if "X-Spam-Score" in msg:
            try:
                spam_score = int(float(msg["X-Spam-Score"].strip()))
            except ValueError:
                spam_score = 0

        if (
            email_account.autofile_spam
            and spam_score >= email_account.spam_score_threshold
        ):
            junk = email_account.spam_delivery_folder
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
def make_encapsulated_fwd_msg(
    email_account: EmailAccount, orig_msg: EmailMessage
):
    """
    Take the original message and add it as an attachment to the message we
    generate that explains that this is the forwarded message.

    The client presentation is not as good depending on how your mail client
    shows rfc822 attachments, but it leaves the original message unmodified.
    """
    msg = EmailMessage()
    if "Subject" in orig_msg:
        msg["Subject"] = f"Fwd: {orig_msg['Subject']}"
    else:
        msg["Subject"] = f"Fwd: from {orig_msg['From']}"

    if "Message-ID" in orig_msg:
        msg["References"] = orig_msg["Message-ID"]

    msg["To"] = email_account.forward_to
    try:
        msg.set_content(orig_msg.get_content())
    except Exception as exc:
        logger.warning(
            "Unable to get content for forwarded message %s for %s: %s",
            msg["Message-ID"],
            email_account.email_address,
            str(exc),
        )
    msg.add_attachment(
        orig_msg.as_bytes(),
        maintype="message",
        subtype="rfc822",
    )
    return msg


####################################################################
#
def forward_message(email_account: EmailAccount, msg: EmailMessage):
    """
    Forward the given message to the email address setup for forwarding to
    on the account.

    If the forwarding email address is not set or the account is deactivated,
    deliver the message locally and log a message.
    """
    if not email_account.forward_to or email_account.deactivated:
        if not email_account.forward_to:
            log_msg = "forwarding address it not set"
        else:
            log_msg = "account is deactivated"
        logger.warning(
            "Forwarding for '%s' denied for message %s: %s",
            email_account.email_address,
            msg["Message-ID"],
            log_msg,
        )
        deliver_message_locally(email_account, msg)
        return

    original_from = msg["From"]
    if email_account.forward_style == EmailAccount.FORWARD_ENCAPSULTE:
        msg = make_encapsulated_fwd_msg(email_account, msg)
    else:
        if "Subject" in msg:
            msg.replace_header("Subject", f"Fwd: {msg['Subject']}")
        else:
            msg["Subject"] = f"Fwd: from {msg['From']}"

    # When forwarding we add `Resent-From`, `Original-From`,
    # `Original-Message-ID`, and `reply-to` headers.
    #
    if "Message-ID" in msg:
        msg["Original-Message-ID"] = msg["Message-ID"]
        msg["Resent-Message-ID"] = msg["Message-ID"]

    # if there already _is_ a reply-to header leave it be, otherwise set
    # reply-to to be the original from so that replies go to the right place.
    #
    if "Reply-To" not in msg:
        msg["Reply-To"] = original_from
    msg["Original-From"] = original_from
    msg["Original-Recipient"] = email_account.email_address
    msg["Resent-From"] = email_account.email_address
    msg["Resent-To"] = email_account.forward_to
    if "From" in msg:
        msg.replace_header("From", email_account.email_address)
    else:
        msg["From"] = email_account.email_address

    email_account.send_email_via_smtp([email_account.forward_to], msg)


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

    `report_text` is the over all human readable report.

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
