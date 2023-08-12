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
from pathlib import Path

# 3rd party imports
#
import pytz
import redis
from django.conf import settings
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task

# Project imports
#
from .models import BlockedMessage, Server
from .utils import email_accounts_by_addr

MESSAGE_HORIZON = 44  # 44 days, because postmark's horizon is 45 days.
MESSAGE_HORIZON_TD = timedelta(days=MESSAGE_HORIZON)
TZ = pytz.timezone(settings.TIME_ZONE)

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
@db_periodic_task(crontab(day="*", hour="4"))
def expire_old_blocked_messages():
    """
    Find all blocked message objects that are older than the
    horizon and delete them.
    """
    horizon = datetime.now(tz=TZ) - MESSAGE_HORIZON_TD
    num_deleted, _ = BlockedMessage.objects.filter(
        created_at__lt=horizon
    ).delete()
    if num_deleted > 0:
        logger.info("expired_old_blocked_messages: Deleted %d", num_deleted)


####################################################################
#
@db_periodic_task(crontab(minute="*/5"))
def dispatch_outgoing_email():
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
@db_task()
def dispatch_incoming_email(server_pk, email_fname, short_hash):
    """
    This is called after a message has been received by the incoming
    hook. This decides what do with this email based on the configured email
    accounts.

    XXX OOo... we are going to get multiple calls if a message to a server is
        sent to multiple addresses on that server. We need a way to skip
        processing the same message and delivering it multiple times.

        The short hash for all three messages will be the same, and we are
        likely to have invoked this async task several times. Maybe use redis
        with a lock (if it is locked in redis, just immediately delete the
        fname and move on.)

    NOTE: This function is likely to be fairly long and complex so we should
          break it up (and maybe even make several chained async requests, like
          actual delivery should be subsequent tasks.. this way delivery to
          multiple addresses can be done in parallel.)
    """
    r = redis.ConnectionPool(host=settings.REDIS_HOST, port=6379, db=0)
    already = f"already-processed-{short_hash}"
    # If short hash is defined in redis as already processed then exit
    #
    if r.exists(already):
        return

    try:
        with r.lock(short_hash).acquire():
            # multiple incoming messages with the same short hash.
            #
            # If short hash is defined in redis as already processed then exit
            # (we check here even after we got the lock for race conditions)
            if r.exists(already):
                return

            # Do stuff
            #
            server = Server.objects.get(pk=server_pk)
            with open(email_fname, "r") as f:
                email = json.loads(f.read())

            deliver_to = email_accounts_by_addr(server, email)

            for addr, email_account in deliver_to:
                logger.info(f"deliver to {addr}:{email_account}")

            # Set key (with ttl of 5 minutes) that says we have processed this
            # short hash.
            #
            r.set(already, email_fname, ex=300)
            Path(email_fname).delete()
    except redis.AlreadyLocked:
        # Another task is already processing this message so nothing to do.
        #
        return
