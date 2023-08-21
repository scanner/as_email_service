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
from email.message import EmailMessage

# Project imports
#
from .models import EmailAccount


####################################################################
#
def deliver_email_locally(
    email_account: EmailAccount, email_message: EmailMessage
):
    """
    Deliver the email_message in to the MH mail dir for the given email
    account.
    """
    pass
