#!/usr/bin/env python
#
"""
Huey dispatchable (and periodic) tasks.
"""
import json
import logging

# system imports
#
from datetime import datetime, timedelta

# 3rd party imports
#
import pytz
from django.conf import settings
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task

# Project imports
#
from .models import BlockedMessage, EmailAccount, Server

MESSAGE_HORIZON = 44  # 44 days, because postmark's horizon is 45 days.
MESSAGE_HORIZON_TD = timedelta(days=MESSAGE_HORIZON)
TZ = pytz.timezone(settings.TIME_ZONE)

logger = logging.getLogger(__name__)


####################################################################
#
@db_periodic_task(crontab(day="*", hour="4"))
def expire_old_blocked_messages():
    """
    Find all blocked message objects that are older than the
    horizon and delete them.
    """
    horizon = datetime.now(tz=TZ) - MESSAGE_HORIZON_TD
    num_deleted, _ = BlockedMessage.objects.filter(created_at__lt=horizon)
    if num_deleted > 0:
        print(f"expired_old_blocked_messages: Deleted {num_deleted}")


####################################################################
#
@db_periodic_task(crontab(minute="*/5"))
def dispatch_outgoing_spooled_email():
    """
    Look for email messages in our outgoing spool folder and
    attempt to send them via the mail provider.
    If the attempt fails, try again.

    XXX We need to likely record every attempt and slow down our
        retries. We also need a maximum amount of time we will retry.
    """
    pass


####################################################################
#
@db_task()
def dispatch_incoming_email(server_pk, email_fname):
    """
    This is called after a message has been received by the incoming
    hook. This decides what do with this email based on the configured email
    accounts.
    """
    server = Server.objects.get(pk=server_pk)
    with open(email_fname, "r") as f:
        email = json.loads(f.read())

    email_addrs = []

    # Collect all the to, cc, bcc addresses.
    #
    for addr_type in ("To", "Cc", "Bcc"):
        key = f"{addr_type}Full"
        if key in email:
            email_addrs.extend([x["Email"] for x in email[f"{addr_type}Full"]])

    # Go through all of our addresses and if they are not for this server,
    # remove them from the list of email addrs.
    #
    email_addrs = [
        x for x in email_addrs if x.split("@")[1] == server.domain_name
    ]

    # Drop and email addresses that do not correspond to any email accounts.
    #
    for addr in email_addrs:
        # mailbox hashes are not part of the actual email address.
        #
        if "+" in addr:
            addr.split("+")[0] + "@" + addr.split("@")[1]
        try:
            email_account = EmailAccount.objects.get(addr)
            print(f"Dispatching email to {addr}:{email_account}")
        except EmailAccount.DoesNotExist:
            continue
        except Exception as exc:
            logger.error(f"Unable to deliver email to {addr}: {exc}")
