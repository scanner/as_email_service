# system imports
#
import email.message
import mailbox
from pathlib import Path

# 3rd party imports
#
import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError

# Project imports
#
from ..models import EmailAccount, InactiveEmail, MessageFilterRule
from ..utils import read_emailaccount_pwfile

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
        assert ea.alias_for.all()[0] == first


####################################################################
#
def test_email_account_set_check_password(
    faker, settings, email_account_factory
):
    ea = email_account_factory()
    ea.save()
    password = faker.pystr(min_chars=8, max_chars=32)
    assert ea.check_password(password) is False
    ea.set_password(password)
    assert ea.check_password(password)

    # make sure that the password hash in the external pw file is updated
    #
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address in accounts
    assert accounts[ea.email_address].pw_hash == ea.password


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
def test_email_account_mail_dir(settings, email_account_factory):
    """
    make sure the mailbox.MH directory for the email account exists
    """
    ea = email_account_factory()
    ea.save()

    assert Path(ea.mail_dir).is_dir()

    # By setting `create=False` this will fail with an exception if
    # the mailbox does not exist. It should exist.
    #
    try:
        mh = ea.MH(create=False)
        assert mh._path == ea.mail_dir
        for folder in settings.DEFAULT_FOLDERS:
            mh.get_folder(folder)
    except mailbox.NoSuchMailboxError as exc:
        assert False, exc

    # make sure that the mail dir in the external pw file is set properly
    # (relative to settings.MAIL_DIRS)
    #
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    assert ea.email_address in accounts
    assert settings.MAIL_DIRS / accounts[ea.email_address].maildir == Path(
        ea.mail_dir
    )


####################################################################
#
def test_email_account_alias_self(email_account_factory):
    """
    We make sure an EmailAccount can not alias itself.

    Obviously we need to do better than this and we should make sure aliases
    do not go to deep, and that at no point in that level of aliasing it loops
    back to alias any of the EmailAccounts that are aliased to themselves.

    But for now this is what we have.
    """
    ea_1 = email_account_factory(delivery_method=EmailAccount.ALIAS)
    ea_1.save()

    ea_2 = email_account_factory(delivery_method=EmailAccount.ALIAS)
    ea_2.save()

    # This is fine.. EmailAccount #1 is an alis for EmailAccount #2.
    ea_1.alias_for.add(ea_2)

    # This is NOT fine. Can not alias to yourself.
    #
    with pytest.raises(IntegrityError):
        ea_1.alias_for.add(ea_1)


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
    #       the only thing we care about is that the `send_message` method was
    #       called with the appropriate values.
    #
    send_message = smtp.return_value.send_message
    assert send_message.call_count == 1
    assert send_message.call_args.args == (msg,)
    assert send_message.call_args.kwargs == {
        "from_addr": from_addr,
        "to_addrs": rcpt_tos,
    }


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
