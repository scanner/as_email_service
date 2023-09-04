#!/usr/bin/env python
#
"""
pytest fixtures for our tests
"""
from email.headerregistry import Address

# system imports
#
from email.message import EmailMessage

# 3rd party imports
#
import pytest
from pytest_factoryboy import register

# Project imports
#
from rest_framework.test import APIClient

from .factories import (
    BlockedMessageFactory,
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
register(BlockedMessageFactory)
register(MessageFilterRuleFactory)


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
            msg["From"] = kwargs["frm"]

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
