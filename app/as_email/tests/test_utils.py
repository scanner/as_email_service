#!/usr/bin/env python
#
"""
Test various functions in the utils module
"""
# system imports
#
from datetime import UTC, datetime

# 3rd party imports
#
from django.contrib.auth.hashers import make_password

# Project imports
#
from ..utils import (
    PWUser,
    now_str_datetime,
    read_emailaccount_pwfile,
    split_email_mailbox_hash,
    utc_now_str,
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


####################################################################
#
def test_utc_now_str() -> None:
    """
    Given the current UTC time
    When utc_now_str is called
    Then it should return a formatted datetime string with timezone
    """
    # Act
    result = utc_now_str()

    # Assert - verify format by parsing it back
    parsed = datetime.strptime(result, "%Y.%m.%d-%H.%M.%S.%f%z")
    assert parsed.tzinfo is not None
    assert parsed.tzinfo.utcoffset(None).total_seconds() == 0  # UTC offset is 0


####################################################################
#
def test_now_str_datetime() -> None:
    """
    Given a formatted datetime string
    When now_str_datetime is called
    Then it should parse and return a datetime object
    """
    # Arrange
    test_datetime = datetime(2025, 10, 26, 14, 30, 45, 123456, tzinfo=UTC)
    datetime_str = test_datetime.strftime("%Y.%m.%d-%H.%M.%S.%f%z")

    # Act
    result = now_str_datetime(datetime_str)

    # Assert
    assert result == test_datetime
    assert result.year == 2025
    assert result.month == 10
    assert result.day == 26
    assert result.hour == 14
    assert result.minute == 30
    assert result.second == 45
    assert result.microsecond == 123456
    assert result.tzinfo.utcoffset(None).total_seconds() == 0


####################################################################
#
def test_utc_now_str_and_now_str_datetime_roundtrip() -> None:
    """
    Given a datetime string from utc_now_str
    When it is parsed by now_str_datetime
    Then the roundtrip should preserve the datetime value
    """
    # Arrange
    original_str = utc_now_str()

    # Act
    parsed = now_str_datetime(original_str)
    roundtrip_str = parsed.strftime("%Y.%m.%d-%H.%M.%S.%f%z")

    # Assert
    assert original_str == roundtrip_str
    assert parsed.tzinfo is not None
