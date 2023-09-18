#!/usr/bin/env python
#
"""
pytest fixtures for our tests
"""
import email.policy

# system imports
#
from email.headerregistry import Address
from email.message import EmailMessage

# 3rd party imports
#
import pytest
from aiosmtpd.smtp import Envelope as SMTPEnvelope
from aiosmtpd.smtp import Session as SMTPSession
from pytest_factoryboy import register

# Project imports
#
from rest_framework.test import APIClient

from .factories import (
    EmailAccountFactory,
    MessageFilterRuleFactory,
    ProviderFactory,
    ServerFactory,
    UserFactory,
)

# This is the magic where we create fixtures that use factories to
# generate the right kind of object.
#
# NOTE: `register(FooFactory)` provides the fixture `foo_factory`
#
register(UserFactory)
register(ProviderFactory)
register(MessageFilterRuleFactory)


####################################################################
#
def assert_email_equal(msg1, msg2, ignore_headers=False):
    """
    Because we can not directly compare a Message and EmailMessage object
    we need to compare their parts. Since an EmailMessage is a sub-class of
    Message it will have all the same methods necessary for comparison.
    """
    # Compare all headers, unless we are ignoring them.
    #
    if ignore_headers is False:
        assert len(msg1.items()) == len(msg2.items())
        for header, value in msg1.items():
            value = value.replace("\n", "")
            assert msg2[header].replace("\n", "") == value

    # If we are ignoring only some headers, then skip those.
    #
    if isinstance(ignore_headers, list):
        ignore_headers = [x.lower() for x in ignore_headers]
        for header, value in msg1.items():
            if header.lower() in ignore_headers:
                continue
            assert msg2[header] != value

    assert msg1.is_multipart() == msg2.is_multipart()

    # If not multipart, the payload should be the same.
    #
    if not msg1.is_multipart():
        assert msg1.get_payload() == msg2.get_payload()

    # Otherwise, compare each part.
    #
    parts1 = msg1.get_payload()
    parts2 = msg2.get_payload()
    assert len(parts1) == len(parts2)

    for part1, part2 in zip(parts1, parts2):
        assert part1.get_payload() == part2.get_payload()


####################################################################
#
@pytest.fixture
def email_factory(faker):
    """
    Returns a factory that creates email.message.EmailMessages

    For now we will always create MIMEMultipart messages with a text part, html
    alternative, and a binary attachment.
    """

    # TODO: have this factory take kwargs for headers the caller can set in the
    #       generated email.
    #
    def make_email(**kwargs):
        """
        if kwargs for 'subject', 'from' or 'to' are provided use those in
        the message instead of faker generated ones.

        NOTE: `from` is a reserverd word in python so you need to specify
              `frm`
        """
        msg = EmailMessage()
        msg["Message-ID"] = faker.uuid4()
        msg["Subject"] = (
            faker.sentence() if "subject" not in kwargs else kwargs["subject"]
        )
        if "msg_from" not in kwargs:
            username, domain_name = faker.email().split("@")
            msg["From"] = Address(faker.name(), username, domain_name)
        else:
            msg["From"] = kwargs["msg_from"]

        if "to" not in kwargs:
            username, domain_name = faker.email().split("@")
            msg["To"] = Address(faker.name(), username, domain_name)
        else:
            msg["To"] = kwargs["to"]

        message_content = faker.paragraphs(nb=5)
        msg.set_content("\n".join(message_content))
        paragraphs = "\n".join([f"<p>{x}</p>" for x in message_content])
        msg.add_alternative(
            f"<html><head></head><body>{paragraphs}</body></html>",
            subtype="html",
        )
        return msg

    return make_email


####################################################################
#
@pytest.fixture
def server_factory(postmark_client, settings, faker):
    """
    A factory for creating server's that have the postmarker pytest
    postmark_client factory returned when you call ".client"
    This also sets makes sure that the API token for the server we create
    is in the django settings.EMAIL_SERVER_TOKENS
    """

    def make_server(*args, **kwargs):
        server = ServerFactory(*args, **kwargs)
        settings.EMAIL_SERVER_TOKENS[server.domain_name] = faker.pystr()
        server._client = postmark_client
        return server

    yield make_server


####################################################################
#
@pytest.fixture
def email_account_factory(server_factory):
    """
    Make sure our email account factory uses the fixtures setup by the
    server_factory.
    """

    def make_email_account(*args, **kwargs):
        kwargs["server"] = server_factory()
        email_account = EmailAccountFactory(*args, **kwargs)
        return email_account

    yield make_email_account


####################################################################
#
@pytest.fixture(autouse=True)
def email_spool_dir(settings, tmp_path):
    """
    We want every test to run with a spool dir that is a fixture (so
    that we do not accidentally forget to set it in a test that uses a
    provider/server without specifically calling out that it does.)
    """
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir(parents=True, exist_ok=True)
    settings.EMAIL_SPOOL_DIR = spool_dir
    yield spool_dir


####################################################################
#
@pytest.fixture(autouse=True)
def mailbox_dir(settings, tmp_path):
    """
    We want every test to run with a MAIL_DIRS that is a fixture (so
    that we do not accidentally forget to set it in a test that uses a
    provider/server without specifically calling out that it does.)
    """
    mail_base_dir = tmp_path / "mail_base_dir"
    mail_base_dir.mkdir(parents=True, exist_ok=True)
    settings.MAIL_DIRS = mail_base_dir
    yield mail_base_dir


####################################################################
#
@pytest.fixture(autouse=True)
def huey_immediate_mode(settings):
    """
    Huey tasks are invoked immediately inline. Can not think of a case
    where we would not want this to happen automatically while running tests.
    """
    from huey.contrib.djhuey import HUEY as huey

    huey.immediate = True
    settings.HUEY["immediate"] = True
    yield huey


####################################################################
#
@pytest.fixture
def api_client():
    """
    fixture for DRF's APIClient object.
    """
    return APIClient


####################################################################
#
@pytest.fixture
def smtp(mocker):
    """
    We frequently need to test something that will send an email via SMTP.
    This fixture encapsulates this and returns a mock object that can be
    interrogated for the SMTP calls against it.

    NOTE: This only mocks the smtplib.SMTP module in the models module
    """
    mock_SMTP = mocker.MagicMock(name="as_email.models.smtplib.SMTP")
    mocker.patch("as_email.models.smtplib.SMTP", new=mock_SMTP)
    return mock_SMTP


####################################################################
#
@pytest.fixture
def aiosmtp_session(faker):
    """
    When testing handlers and authenticators we need a aiosmtp.smtp.Session

    XXX We should make this return a callable and let the user pass in things
        like the peer.
    """
    sess = SMTPSession(None)
    sess.peer = (faker.ipv4(), faker.pyint(0, 65535))
    return sess


####################################################################
#
@pytest.fixture
def aiosmtp_envelope(email_factory):
    """
    Similar to (and uses) email_factory to create a SMTPEnvelope.
    """

    def make_envelope(**kwargs):
        """
        if kwargs for 'subject', 'from' or 'to' are provided use those in
        the message instead of faker generated ones. If they are `None` that
        field is not set at all. Useful for generating envelopes that are pre
        `handle_MAIL` that sets the `mail_from` attribute.

        NOTE: `from` is a reserverd word in python so you need to specify
              `frm`
        """
        env = SMTPEnvelope()
        if "msg_from" in kwargs and kwargs["msg_from"] is not None:
            env.mail_from = kwargs["msg_from"]
        if "mail_options" in kwargs:
            env.mail_options = kwargs["mail_options"]
            del kwargs["mail_options"]
        if "to" in kwargs:
            env.rcpt_tos.append(kwargs["to"])

        msg = email_factory(**kwargs)
        env.content = msg.as_string(policy=email.policy.default)
        env.original_content = msg.as_bytes(policy=email.policy.default)
        return env

    return make_envelope
