#!/usr/bin/env python
#
"""
Huey dispatchable (and periodic) tasks.
"""
# system imports
#
from datetime import datetime, timedelta

# 3rd party imports
#
import pytz

# Project imports
#
from as_email.models import BlockedMessage
from django.conf import settings
from huey import crontab
from huey.contrib.djhuey import db_periodic_task

MESSAGE_HORIZON = 44  # 44 days, because postmark's horizon is 45 days.
MESSAGE_HORIZON_TD = timedelta(days=MESSAGE_HORIZON)
TZ = pytz.timezone(settings.TIME_ZONE)


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
