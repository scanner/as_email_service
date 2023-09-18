#!/usr/bin/env python
#
"""
Huey dispatchable (and periodic) tasks.
"""
import email
import email.policy
import json
import logging

# system imports
#
from pathlib import Path

# 3rd party imports
#
import pytz
from django.conf import settings
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task

# Project imports
#
from .deliver import deliver_message
from .models import EmailAccount, Server

TZ = pytz.timezone(settings.TIME_ZONE)
EST = pytz.timezone("EST")  # Postmark API is in EST! Really!
# How many messages do we try to dispatch during a single run of any of the
# dispatch tasks. Makes sure we do not hog the task queues just sending email.
#
# NOTE: Separate metrics gathering jobs will be used to watch dispatch queue
#       sizes.
#
DISPATCH_NUM_PER_RUN = 100

logger = logging.getLogger(__name__)


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
            message = spooled_message_file.read_bytes()
            delete_message = True
            try:
                # Try sending the message again but do not write it to the
                # spool if it fails.
                #
                delete_message = server.send_email(
                    message,
                    spool_on_retryable=False,
                )
            except Exception as exc:
                # All raised exceptions are a hard fail and the spooled message
                # will be removed.
                #
                delete_message = True
                logger.exception(f"Unable to retry sending email: {exc}")

            if delete_message:
                spooled_message_file.unlink(messing_ok=True)

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
@db_task()
def dispatch_incoming_email(email_account_pk, email_fname):
    """
    This is called after a message has been received by the incoming
    hook. This decides what do with this email based on the configured email
    accounts.

    NOTE: Postmark will POST a message for every recipient of that email being
          handled by postmark. The only race conditions

    NOTE: This function is likely to be fairly long and complex so we should
          break it up (and maybe even make several chained async requests, like
          actual delivery should be subsequent tasks.. this way delivery to
          multiple addresses can be done in parallel.)
    """
    email_account = EmailAccount.objects.get(pk=email_account_pk)
    email_file = Path(email_fname)
    email_msg = json.loads(email_file.read_text())
    msg = email.message_from_string(
        email_msg["raw_email"], policy=email.policy.default
    )
    try:
        deliver_message(email_account, msg)
    except Exception:
        logger.exception(
            "Failed to deliver message %s to '%s'",
            msg["Message-ID"],
            email_account.email_address,
        )
    finally:
        email_file.unlink()
