#!/usr/bin/env python
#
"""
Test various functions in the utils module
"""

# system imports
#
import email.policy
import json
from datetime import UTC, datetime
from pathlib import Path

# 3rd party imports
#
import pytest
from django.conf import LazySettings
from django.contrib.auth.hashers import make_password
from faker import Faker

# Project imports
#
from as_email.utils import (
    PWUser,
    message_as_bytes,
    message_as_string,
    now_str_datetime,
    read_emailaccount_pwfile,
    split_email_mailbox_hash,
    utc_now_str,
    write_emailaccount_pwfile,
    write_spooled_email,
)


####################################################################
#
@pytest.mark.parametrize(
    "fixture_name,marker",
    [
        # A well formed message; both native serializations work and the
        # helpers must match them exactly.
        #
        ("email_factory", "A well formed message"),
        # as_string() raises UnicodeEncodeError on this one: surrogate
        # escaped payload with a declared charset (euc-jp) that gets
        # re-encoded through iso-2022-jp (AS-EMAIL-SERVICE-3S).
        #
        ("undecodable_charset_email", "Hello from a broken mailer"),
        # as_bytes() raises UnicodeEncodeError on this one: non-ASCII
        # content with no charset declaration.
        #
        ("malformed_non_ascii_email", "special"),
    ],
)
def test_message_serialization(
    request: pytest.FixtureRequest, fixture_name: str, marker: str
) -> None:
    """
    GIVEN an email message, well formed or malformed in a way that
          as_string() or as_bytes() can not serialize
    WHEN  serialized with message_as_bytes / message_as_string
    THEN  serialization succeeds, preserves the message content, matches
          the email package's own serialization whenever that works, and
          the string form can be embedded in json (as write_spooled_email
          does)
    """
    msg = request.getfixturevalue(fixture_name)
    if callable(msg):
        msg = msg(subject=marker)

    msg_bytes = message_as_bytes(msg)
    msg_str = message_as_string(msg)

    # Whenever the native serialization works, the helper must produce
    # identical output.
    #
    try:
        assert msg_bytes == msg.as_bytes(policy=email.policy.default)
    except UnicodeEncodeError:
        pass
    try:
        assert msg_str == msg.as_string(policy=email.policy.default)
    except UnicodeEncodeError:
        pass

    assert marker.encode() in msg_bytes
    assert marker in msg_str
    assert json.dumps({"raw_email": msg_str})


####################################################################
#
def test_split_hash() -> None:
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
def test_write_read_emailaccount_pwfile(
    tmp_path: Path, faker: Faker, settings: LazySettings
) -> None:
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
def test_write_spooled_email_with_unsafe_message_id(
    tmp_path: Path, faker: Faker
) -> None:
    """
    GIVEN a message whose Message-ID contains characters that are not valid
           in a file name (GitHub Message-IDs contain `/`)
    WHEN  the message is written to the spool directory
    THEN  the spool file is created directly inside the spool directory and
          the json payload preserves the original, unmodified Message-ID

    Regression test: GitHub Message-IDs such as
    `<kubestellar/console/issues/21134/3123456789@github.com>` used to be
    embedded verbatim in the spool file name, making the file name a path
    into non-existent subdirectories and raising FileNotFoundError (which
    surfaced as a 500 to the provider's incoming webhook).
    """
    recipient = faker.email()
    msg_id = "<kubestellar/console/issues/21134/3123456789@github.com>"
    raw_email = "Subject: test\n\ntest body\n"

    msg_path = write_spooled_email(
        recipient, tmp_path, raw_email, msg_id=msg_id
    )

    assert msg_path.parent == tmp_path
    assert msg_path.exists()

    spooled = json.loads(msg_path.read_text())
    assert spooled["recipient"] == recipient
    assert spooled["message-id"] == msg_id
    assert spooled["raw_email"] == raw_email


####################################################################
#
def test_write_spooled_email_with_overlong_message_id(
    tmp_path: Path, faker: Faker
) -> None:
    """
    GIVEN a message whose Message-ID is longer than the filesystem's file
          name limit
    WHEN  the message is written to the spool directory
    THEN  the spool file is created with a truncated file name and the json
          payload preserves the original, unmodified Message-ID
    """
    recipient = faker.email()
    msg_id = f"<{'x' * 300}@example.com>"

    msg_path = write_spooled_email(
        recipient, tmp_path, "Subject: test\n\ntest body\n", msg_id=msg_id
    )

    assert msg_path.parent == tmp_path
    assert msg_path.exists()
    assert len(msg_path.name) <= 255

    spooled = json.loads(msg_path.read_text())
    assert spooled["message-id"] == msg_id


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
    utcoffset = parsed.tzinfo.utcoffset(None)
    assert utcoffset is not None
    assert utcoffset.total_seconds() == 0  # UTC offset is 0


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
    assert result.tzinfo is not None
    utcoffset = result.tzinfo.utcoffset(None)
    assert utcoffset is not None
    assert utcoffset.total_seconds() == 0


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
