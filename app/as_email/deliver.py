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
import logging
from email.message import EmailMessage

# system imports
#
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
        logger.warn(
            f"Deliver recursion too deep for message {msg['Message-ID']}, "
            f"for account {email_account.email_address}, depth: {depth}"
        )

    match email_account.account_type:
        case EmailAccount.LOCAL_DELIVERY:
            deliver_message_locally(email_account, msg)
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
            logger.warn(
                "for email account %s, attempted to deliver message to "
                "non-existing mailbox %s",
                email_account.email_address,
                mbox,
            )

    # If the message was not delivered to any folders in the above loop,
    # deliver it to the inbox. Creating the inbox if it does not already exist.
    #
    if not delivered_to:
        try:
            folder = mh.get_folder("inbox")
        except NoSuchMailboxError:
            folder = mh.add_folder("inbox")
        _add_msg_to_folder(folder, msg)


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
            msg = "forwarding address it not set"
        else:
            msg = "account is deactivated"
        logger.warn(f"For email account {email_account.email_address}, {msg}")
        deliver_message_locally(email_account, msg)
        return
