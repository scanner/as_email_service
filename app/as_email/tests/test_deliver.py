#!/usr/bin/env python
#
"""
Test the various functions in the `deliver` module
"""
# system imports
#

# 3rd party imports
#
import pytest

# Project imports
#
from ..deliver import apply_message_filter_rules, deliver_message_locally
from ..models import MessageFilterRule

pytestmark = pytest.mark.django_db


####################################################################
#
def compare_email_content(msg1, msg2):
    """
    Because we can not directly compare a Message and EmailMessage object
    we need to compare their parts. Since an EmailMessage is a sub-class of
    Message it will have all the same methods necessary for comparison.
    """
    # Compare all headers
    #
    if msg1.items() != msg2.items():
        return False

    if msg1.is_multipart() != msg2.is_multipart():
        return False

    # If not multipart, the payload should be the same.
    #
    if not msg1.is_multipart():
        assert msg1.get_payload() == msg2.get_payload()

    # Otherwise, compare each part.
    #
    parts1 = msg1.get_payload()
    parts2 = msg2.get_payload()
    if len(parts1) != len(parts2):
        return False
    for part1, part2 in zip(parts1, parts2):
        if part1.get_payload() != part2.get_payload():
            return False
    return True


####################################################################
#
def test_apply_message_filter_rules(
    email_account_factory,
    message_filter_rule_factory,
    email_factory,
):
    ea = email_account_factory()
    ea.save()
    msg = email_factory()
    folder = "test"
    mfr = message_filter_rule_factory(
        email_account=ea,
        header=MessageFilterRule.FROM,
        pattern=msg["from"],
        destination=folder,
    )
    mfr.save()

    deliver_to = apply_message_filter_rules(ea, msg)
    assert deliver_to == [folder]

    # Make a new email, since the from is guaranteed to be different this will
    # NOT atch our rule.
    #
    msg = email_factory()
    deliver_to = apply_message_filter_rules(ea, msg)
    assert len(deliver_to) == 0


####################################################################
#
def test_deliver_message_locally(
    email_account_factory, message_filter_rule_factory, email_factory
):
    ea = email_account_factory()
    ea.save()
    msg = email_factory()

    deliver_message_locally(ea, msg)

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert compare_email_content(msg, stored_msg)

    # Now create a mfr and make sure the message is delivered to the proper
    # folder.
    #
    msg = email_factory()
    folder_name = "test"
    folder = mh.add_folder(folder_name)
    mfr = message_filter_rule_factory(
        email_account=ea,
        header=MessageFilterRule.FROM,
        pattern=msg["from"],
        destination=folder_name,
    )
    mfr.save()
    deliver_message_locally(ea, msg)
    stored_msg = folder.get(1)
    assert compare_email_content(msg, stored_msg)
