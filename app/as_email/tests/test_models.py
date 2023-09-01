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
from ..models import EmailAccount, MessageFilterRule

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
def test_email_account_set_check_password(faker, email_account_factory):
    ea = email_account_factory()
    password = faker.pystr(min_chars=8, max_chars=32)
    assert ea.check_password(password) is False
    ea.set_password(password)
    assert ea.check_password(password)


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
def test_email_account_mail_dir(email_account_factory):
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
    except mailbox.NoSuchMailboxError as exc:
        assert False, exc


####################################################################
#
def test_alias_self(email_account_factory):
    """
    We make sure an EmailAccount can not alias itself.

    Obviously we need to do better than this and we should make sure aliases
    do not go to deep, and that at no point in that level of aliasing it loops
    back to alias any of the EmailAccounts that are aliased to themselves.

    But for now this is what we have.
    """
    ea_1 = email_account_factory(account_type=EmailAccount.ALIAS)
    ea_1.save()

    ea_2 = email_account_factory(account_type=EmailAccount.ALIAS)
    ea_2.save()

    # This is fine.. EmailAccount #1 is an alis for EmailAccount #2.
    ea_1.alias_for.add(ea_2)

    # This is NOT fine. Can not alias to yourself.
    #
    with pytest.raises(IntegrityError):
        ea_1.alias_for.add(ea_1)


####################################################################
#
def test_email_via_smtp(email_account_factory, email_factory, mocker):
    # Mock the SMTP object in the models module
    #
    mock_SMTP = mocker.MagicMock(name="as_email.models.smtplib.SMTP")
    mocker.patch("as_email.models.smtplib.SMTP", new=mock_SMTP)

    ea = email_account_factory()
    msg = email_factory(frm=ea.email_address)
    ea.server.send_email_via_smtp(
        ea.email_address,
        [
            msg["To"],
        ],
        msg,
    )

    assert mock_SMTP.return_value.send_message.call_count == 1


####################################################################
#
def test_email_via_smtp_invalid_from(
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
def test_create_rule_from_text(faker, email_account_factory):
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
def test_message_rule_match(faker, message_filter_rule_factory):
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
