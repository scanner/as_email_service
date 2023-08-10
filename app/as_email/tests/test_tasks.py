#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
from datetime import datetime, timedelta

# 3rd party imports
#
import pytest

# Project imports
#
from ..models import BlockedMessage
from ..tasks import (  # dispatch_outgoing_email,; dispatch_incoming_email,
    MESSAGE_HORIZON_TD,
    TZ,
    expire_old_blocked_messages,
)

pytestmark = pytest.mark.django_db


####################################################################
#
def test_expire_old_blocked_messages(blocked_message_factory):
    """
    Run a periodic task that expires messages older than MESSAGE_HORIZON_TD
    in the past.
    """
    # Create a bunch of blocked messages, with dates just before and just after
    # the horizon.
    #
    for i in range(-3, 4):
        offset = MESSAGE_HORIZON_TD + timedelta(days=i)
        bm = blocked_message_factory()
        bm.created_at = datetime.now(tz=TZ) - offset
        bm.save()

    num = BlockedMessage.objects.count()
    assert num == 7

    expire_old_blocked_messages()

    num = BlockedMessage.objects.count()
    assert num == 3
