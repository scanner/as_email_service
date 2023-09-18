#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
import json
from datetime import datetime
from pathlib import Path

# 3rd party imports
#
import pytest

# Project imports
#
from ..tasks import dispatch_incoming_email
from ..utils import spooled_email
from .test_deliver import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
def test_dispatch_incoming_email(
    email_account_factory, email_factory, tmp_path
):
    """
    Write a json file that is in the expected format
    """
    ea = email_account_factory()
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    email_file_name = f"{now.isoformat()}-{message_id}.json"
    fname = Path(tmp_path) / email_file_name
    email_msg = spooled_email(msg["To"], message_id, str(now), msg.as_string())
    fname.write_text(json.dumps(email_msg))

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)
