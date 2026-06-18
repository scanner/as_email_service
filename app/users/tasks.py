#!/usr/bin/env python
#
"""
Huey periodic tasks for the users app.
"""

# system imports
#
import logging

from django.utils import timezone

# 3rd party imports
#
from huey import crontab
from huey.contrib.djhuey import db_periodic_task

# Project imports
#
from .models import EmailChangeCooldown, PendingEmailChange

logger = logging.getLogger("users.tasks")


####################################################################
#
@db_periodic_task(crontab(minute="0", hour="2"))
def cleanup_expired_email_change_records() -> None:
    """
    Delete PendingEmailChange and EmailChangeCooldown rows whose
    expires_at has passed.

    Runs daily at 02:00. The lazy-cleanup in AccountInfoView handles the
    common case (active user hits the page), but abandoned pending changes
    and cooldowns for inactive users are only removed here.
    """
    now = timezone.now()
    pending_deleted, _ = PendingEmailChange.objects.filter(
        expires_at__lt=now
    ).delete()
    cooldown_deleted, _ = EmailChangeCooldown.objects.filter(
        expires_at__lt=now
    ).delete()
    if pending_deleted or cooldown_deleted:
        logger.info(
            "cleanup_expired_email_change_records: deleted %d pending, %d cooldown",
            pending_deleted,
            cooldown_deleted,
        )
