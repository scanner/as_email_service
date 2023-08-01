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

# Project imports
#
from ..models import MessageFilterRule

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
