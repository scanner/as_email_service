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
from ..deliver import apply_message_filter_rules
from ..models import MessageFilterRule

pytestmark = pytest.mark.django_db


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
