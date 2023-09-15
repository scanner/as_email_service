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
from ..utils import parse_email_addr, split_email_mailbox_hash


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


####################################################################
#
def test_parse_email_addr(faker):
    """
    email addresses used in email at their simplest form for SMTP in the
    modern era is "foo@example.com". However, this can actually include a
    number of other elements that we ultimate do not care about. We want just
    the "foo@example.com" parse of the email.
    """
    assert parse_email_addr("foo@example.org") == "foo@example.org"
    assert parse_email_addr('"John Doe" <jon@example.org>') == "jon@example.org"
