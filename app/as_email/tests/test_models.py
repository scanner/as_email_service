# system imports
#
import email.message
import mailbox
from pathlib import Path
from typing import Callable

# 3rd party imports
#
import pytest
from dirty_equals import Contains
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from pytest_mock import MockerFixture

# Project imports
#
from ..models import (
    AliasToDelivery,
    EmailAccount,
    InactiveEmail,
    LocalDelivery,
    MessageFilterRule,
)
from .conftest import assert_email_equal

User = get_user_model()

pytestmark = pytest.mark.django_db


####################################################################
#
def test_server(server_factory):
    """
    Make sure we can create a server, and all of its dirs are setup properly.
    """
    server = server_factory()
    server.save()

    assert str(server.incoming_spool_dir).endswith("incoming")
    assert server.domain_name in str(server.incoming_spool_dir)
    assert Path(server.incoming_spool_dir).is_dir()

    assert str(server.outgoing_spool_dir).endswith("outgoing")
    assert server.domain_name in str(server.outgoing_spool_dir)
    assert Path(server.outgoing_spool_dir).is_dir()

    assert str(server.mail_dir_parent).endswith(server.domain_name)
    assert Path(server.mail_dir_parent).is_dir()

    assert server.api_key


####################################################################
#
def test_server_creates_admin_emailaccounts(
    user_factory, server_factory, settings
):
    """
    With the defaults from django settings, if a user account with the
    username 'admin' exists, then EmailAccounts defined by the list
    settings.EMAIL_SERVICE_ACCOUNTS will be created and aliased together.

    This will happen when the server account is saved for the first time.
    """
    settings.EMAIL_SERVICE_ACCOUNTS_OWNER = "admin"
    admin = user_factory(username="admin")
    admin.save()
    server = server_factory()
    server.save()

    eas = []
    email_addrs = [
        f"{x}@{server.domain_name}" for x in settings.EMAIL_SERVICE_ACCOUNTS
    ]
    eas = [EmailAccount.objects.get(email_address=x) for x in email_addrs]
    first = eas[0]
    for ea in eas[1:]:
        atd = AliasToDelivery.objects.get(email_account=ea)
        assert atd.target_account == first


####################################################################
#
def test_email_account_set_check_password(
    faker,
    settings,
    email_account_factory: Callable[..., EmailAccount],
    mocker: MockerFixture,
) -> None:
    """
    Given an email account
    When a password is set
    Then the password should be verifiable with check_password
    """
    # Mock the task that updates the password file to avoid file I/O
    mock_task = mocker.patch(
        "as_email.signals.check_update_pwfile_for_emailaccount"
    )

    ea = email_account_factory()
    password = faker.pystr(min_chars=8, max_chars=32)
    assert ea.check_password(password) is False
    ea.set_password(password)
    assert ea.check_password(password)

    # The signal handler should have triggered the task with ea.pk
    # Note: With huey immediate mode, the task runs immediately
    mock_task.assert_called_once_with(ea.pk)


####################################################################
#
def test_email_account_valid_email_address(email_account_factory):
    """
    The `email_address` must have the same domain name as the
    associated server.
    """
    # The factory by default creates an email_address that is valid.
    #
    ea = email_account_factory()
    try:
        ea.clean()
    except ValidationError as exc:
        assert False, exc
    ea.save()

    # The email address must end with the same domain name as the
    # server that it is associated with.
    #
    ea.email_address = "foo@example.org"
    with pytest.raises(ValidationError):
        ea.clean()


####################################################################
#
def test_email_account_mail_dir(settings, email_account_factory) -> None:
    """
    make sure the mailbox.MH directory for the email account exists
    """
    ea = email_account_factory()
    ea.save()

    ld = LocalDelivery.objects.get(email_account=ea)
    assert Path(ld.maildir_path).is_dir()

    # By setting `create=False` this will fail with an exception if
    # the mailbox does not exist. It should exist.
    #
    try:
        mh = ld.MH(create=False)
        assert mh._path == ld.maildir_path
        for folder in settings.DEFAULT_FOLDERS:
            mh.get_folder(folder)
    except mailbox.NoSuchMailboxError as exc:
        assert False, exc


####################################################################
#
def test_alias_to_delivery_self_loop(
    email_account_factory, email_factory, caplog
) -> None:
    """
    GIVEN an AliasToDelivery that points back to its own account (self-loop)
    WHEN  a message is delivered to that account
    THEN  the loop is detected, a warning is logged, and delivery stops cleanly
    """
    ea = email_account_factory(local_delivery=False)
    AliasToDelivery.objects.create(email_account=ea, target_account=ea)

    msg = email_factory()
    ea.deliver(msg)

    assert "Alias loop detected" in caplog.text


####################################################################
#
def test_email_account_email_via_smtp(
    email_account_factory, email_factory, smtp
):
    ea = email_account_factory()
    msg = email_factory(frm=ea.email_address)
    from_addr = ea.email_address
    rcpt_tos = [msg["To"]]
    ea.server.send_email_via_smtp(from_addr, rcpt_tos, msg)

    # NOTE: in the models object we create a smtp_client. On the smtp_client
    #       the only thing we care about is that the `sendmail` method was
    #       called with the appropriate values.
    #
    assert smtp.sendmail.call_count == 1
    assert smtp.sendmail.call_args.args == Contains(
        from_addr,
        rcpt_tos,
    )

    sent_message_bytes = smtp.sendmail.call_args.args[2]
    sent_message = email.message_from_bytes(
        sent_message_bytes, policy=email.policy.default
    )
    assert_email_equal(msg, sent_message)


####################################################################
#
def test_email_account_email_via_smtp_invalid_from(
    email_account_factory, email_factory, faker
):
    """
    You can only send email from the domain name that the server has.
    """
    ea = email_account_factory()
    msg = email_factory(frm=ea.email_address)
    with pytest.raises(ValueError):
        ea.server.send_email_via_smtp(
            faker.email(),
            [
                msg["To"],
            ],
            msg,
        )


####################################################################
#
def test_message_filter_rule_create_from_text(faker, email_account_factory):
    """
    message filter rules are all about filtering messages and are based on
    the `maildelivery` file from mh/nmh using slocal for delivery of messages
    to user's mailboxes. To facilitate this conversion we want to be able to
    create message filter rules from lines of text from the maildelivery file.
    """
    email_account = email_account_factory()
    for header, _ in MessageFilterRule.HEADER_CHOICES:
        # Generate a random file directory path
        #
        destination = str(Path(faker.file_path(faker.random_digit())).parent)
        pattern = faker.email()
        test_rule = (
            f"{header}  {pattern} {MessageFilterRule.FOLDER} ? {destination}"
        )
        rule = MessageFilterRule.create_from_rule(email_account, test_rule)
        assert rule.header == header
        assert rule.pattern == pattern
        assert rule.destination == destination

    for header, _ in MessageFilterRule.HEADER_CHOICES:
        pattern = faker.email()
        test_rule = f"{header}  {pattern} {MessageFilterRule.DESTROY} ?"
        rule = MessageFilterRule.create_from_rule(email_account, test_rule)
        assert rule.header == header
        assert rule.pattern == pattern


####################################################################
#
def test_message_filter_rule_match(faker, message_filter_rule_factory):
    # Generate a random file directory path
    #
    destination = str(Path(faker.file_path(faker.random_digit())).parent)
    rule = message_filter_rule_factory(
        action=MessageFilterRule.FOLDER, destination=destination
    )
    msg = email.message.Message()
    msg[rule.header] = rule.pattern
    assert rule.match(msg)

    msg = email.message.Message()
    # The factory only generates patterns that are email addresses, so a
    # sentence will never match.
    #
    msg[rule.header] = faker.sentence()
    assert rule.match(msg) is False


####################################################################
#
def test_inactive_email_inactives(inactive_email_factory, faker):
    """
    Make some inactive emails, make sure they show up when we query to see
    if any emails are inactive emails.
    """

    inactives = []
    for _ in range(5):
        inact = inactive_email_factory()
        inact.save()
        inactives.append(inact)

    inactive_emails = [x.email_address for x in InactiveEmail.objects.all()]
    emails = [faker.email() for x in range(5)]

    test_against = emails + inactive_emails
    matches = [x.email_address for x in InactiveEmail.inactives(test_against)]
    assert sorted(matches) == sorted(inactive_emails)

    # and to make sure we are not just getting all email addresses
    #
    inactive_emails = inactive_emails[0:2]
    test_against = emails + inactive_emails
    matches = [x.email_address for x in InactiveEmail.inactives(test_against)]
    assert sorted(matches) == sorted(inactive_emails)


####################################################################
#
@pytest.mark.asyncio
async def test_async_inactive_email_inactives(inactive_email_factory, faker):
    """
    Make some inactive emails, make sure they show up when we query to see
    if any emails are inactive emails.
    """

    inactives = []
    for _ in range(5):
        inact = inactive_email_factory()
        await inact.asave()
        inactives.append(inact)

    inactive_emails = []
    async for inactive in InactiveEmail.objects.all():
        inactive_emails.append(inactive.email_address)

    emails = [faker.email() for x in range(5)]

    test_against = emails + inactive_emails
    matches = [
        x.email_address for x in await InactiveEmail.a_inactives(test_against)
    ]
    assert sorted(matches) == sorted(inactive_emails)

    # and to make sure we are not just getting all email addresses
    #
    inactive_emails = inactive_emails[0:2]
    test_against = emails + inactive_emails
    matches = [
        x.email_address for x in await InactiveEmail.a_inactives(test_against)
    ]
    assert sorted(matches) == sorted(inactive_emails)
