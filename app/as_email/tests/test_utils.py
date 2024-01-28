#!/usr/bin/env python
#
"""
Test various functions in the utils module
"""
# 3rd party imports
#
from django.contrib.auth.hashers import make_password

# Project imports
#
from ..utils import (
    PWUser,
    read_emailaccount_pwfile,
    split_email_mailbox_hash,
    write_emailaccount_pwfile,
)


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
def test_write_read_emailaccount_pwfile(tmp_path, faker, settings):
    accounts = {}
    pw_file = settings.EXT_PW_FILE
    for _ in range(5):
        email_address = faker.email()
        pw_hash = make_password(faker.password(length=16))
        mail_dir = faker.file_path(depth=3, absolute=False)
        accounts[email_address] = PWUser(email_address, mail_dir, pw_hash)
    write_emailaccount_pwfile(pw_file, accounts)

    read_accounts = read_emailaccount_pwfile(pw_file)

    assert sorted(accounts.keys()) == sorted(read_accounts.keys())
    for email_addr, pw_user in accounts.items():
        assert pw_user.username == email_addr
        rpw_user = read_accounts[email_addr]
        assert rpw_user.username == pw_user.username
        assert rpw_user.maildir == pw_user.maildir
        assert rpw_user.pw_hash == pw_user.pw_hash
