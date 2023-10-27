#!/usr/bin/env python
#
"""
pytest fixtures for our tests
"""
import email.policy

# system imports
#
import json
from datetime import datetime
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import parseaddr

# 3rd party imports
#
import pytest
from aiosmtpd.smtp import Envelope as SMTPEnvelope, Session as SMTPSession
from django.core import mail
from pytest_factoryboy import register
from requests import Response
from rest_framework.test import APIClient, RequestsClient

# Project imports
#
from .factories import (
    EmailAccountFactory,
    InactiveEmailFactory,
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
        if "server" not in kwargs:
            kwargs["server"] = server_factory()
        email_account = EmailAccountFactory(*args, **kwargs)
        return email_account

    yield make_email_account


####################################################################
#
@pytest.fixture
def inactive_email_factory():
    """
    in order to _not_ create and save the object to the db so we can call
    this from async as well as sync tests use the `.build()` method to create
    thte object but not save it.
    """

    def make_inactive_email(*args, **kwargs):
        inactive_email = InactiveEmailFactory.build(*args, **kwargs)
        return inactive_email

    yield make_inactive_email


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
def requests_client():
    """
    fixture for DRF's RequestsClient object.
    """
    return RequestsClient


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


####################################################################
#
# XXX We should consider using requests-mock as a slighty cleaner way of
#     implementing this.
#
@pytest.fixture
def postmark_request_bounce(
    postmark_request, email_account_factory, email_factory, faker
):
    """
    This sets up a fixture that will allow us to use the postmarker client
    for getting information about a bounce that is consistent with the
    provided EmailAccount.
    """

    def setup_responses(email_account=None, email_message=None, **kwargs):
        """
        The fixture returns this function which sets up a side effect on
        the postmark_client mock such that a generated bounce detail is set
        back to the client.

        The EmailAccount to use, the EmailMessage to use, the bounce id that is
        to be request can be passed in.

        Also the caller can setup several fields in the response like
        Description, Details, Inactive, etc so that several different bounces
        can be tested against.
        """
        if email_account is None:
            email_account = email_account_factory()
        from_addr = email_account.email_address
        if email_message is None:
            email_message = email_factory(msg_from=from_addr)

        to_addr = parseaddr(email_message["From"])[1].lower()

        # We construct a dict that will be used to `update` the response we
        # send to the mock postmark client when it requests the bounce
        # details. This lets the person using this fixture setup various values
        # in the response appropriate to their test.
        #
        response_update = {
            k: v
            for k, v in kwargs.items()
            if k
            in (
                "BouncedAt",
                "CanActivate",
                "Description",
                "Details",
                "DumpAvailable",
                "Email",
                "From",
                "ID",
                "Inactive",
                "MessageID",
                "Name",
                "RecordType",
                "ServerID",
                "Subject",
                "Type",
                "TypeCode",
            )
        }
        print(f"Response update: {response_update}")

        response = {
            "BouncedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "CanActivate": True,
            "Content": email_message.as_string(policy=email.policy.default),
            "Description": "The server was unable to deliver your message (ex: unknown user, mailbox not found).",
            "Details": "action: failed",
            "DumpAvailable": False,
            "Email": to_addr,
            "From": from_addr,
            "ID": faker.pyint(1_000_000_000, 9_999_999_999),
            "Inactive": False,
            "MessageID": faker.uuid4(),
            "MessageStream": "outbound",
            "Name": "Hard bounce",
            "RecordType": "Bounce",
            "ServerID": 23,
            "Subject": "The server was unable to deliver your message (ex: unknown user, mailbox not found).",
            "Type": "HardBounce",
            "TypeCode": 1,
        }

        response.update(response_update)

        # A map of responses by the URL being requested.
        #
        responses = {
            f"https://api.postmarkapp.com/bounces/{response['ID']}": response,
        }

        def postmarker_requests(method, url, **kwargs):
            """
            The `postmark_request` fixture substitutes a mock object for
            the `requests.Session().get` function. What we are doing here is
            based on expected URL's return an appropriate response. We use the
            `email_account` and `email_message` values from our wrapping
            function to fill in values in the expected responses.
            """
            resp = Response()
            resp.status_code = 200
            resp._content = bytes(json.dumps(responses[url]), "utf-8")
            return resp

        postmark_request.side_effect = postmarker_requests

    return setup_responses


####################################################################
#
@pytest.fixture
def django_outbox():
    """
    Makes sure that the django outbox is preserved, emptied, and restored
    where it is used.
    """
    old_outbox = mail.outbox
    mail.outbox = []
    yield mail.outbox
    mail.outbox = old_outbox
