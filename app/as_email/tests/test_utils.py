#!/usr/bin/env python
#
"""
Test various functions in the utils module
"""
# system imports
#

# 3rd party imports
#

# Project imports
#
from ..utils import split_email_mailbox_hash


####################################################################
#
def test_split_hash():
    email_addrs = [
        ("foo@example.com", ("foo@example.com", None)),
        ("foo+inbox@example.com", ("foo@example.com", "inbox")),
        ("foo+inbox+bz@example.com", ("foo@example.com", "inbox+bz")),
    ]
    for test_addr, expected in email_addrs:
        result = split_email_mailbox_hash(test_addr)
        assert result == expected
