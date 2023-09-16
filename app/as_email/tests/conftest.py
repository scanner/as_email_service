#!/usr/bin/env python
#
"""
pytest fixtures for our tests
"""
import email.policy

# system imports
#
import inspect
import socket
from contextlib import suppress
from email.headerregistry import Address
from email.message import EmailMessage
from smtplib import SMTP as SMTPClient
from typing import Any, Callable, Generator, NamedTuple, Optional, Type

# 3rd party imports
#
import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import Envelope as SMTPEnvelope
from aiosmtpd.smtp import Session as SMTPSession
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


# We need to test our handler against various email messages, email accounts,
# and from addresses. These fixtures have been imported with some modifications
# from aiosmtpd:
#   https://github.com/aio-libs/aiosmtpd/blob/master/aiosmtpd/tests/conftest.py
#
handler_data = pytest.mark.handler_data


####################################################################
####################################################################
#
class HostPort(NamedTuple):
    host: str = "localhost"
    port: int = 8025


####################################################################
####################################################################
#
class Global:
    SrvAddr: HostPort = HostPort()
    FQDN: str = socket.getfqdn()

    @classmethod
    def set_addr_from(cls, contr: Controller):
        cls.SrvAddr = HostPort(contr.hostname, contr.port)


####################################################################
#
@pytest.fixture
def smtp_client(
    request: pytest.FixtureRequest,
) -> Generator[SMTPClient, None, None]:
    """
    Generic SMTP Client,
    will connect to the ``host:port`` defined in ``Global.SrvAddr``
    unless overriden using :func:`client_data` marker.
    """
    marker = request.node.get_closest_marker("client_data")
    if marker:
        markerdata = marker.kwargs or {}
    else:
        markerdata = {}
    addrport = markerdata.get("connect_to", Global.SrvAddr)
    with SMTPClient(*addrport) as client:
        yield client


####################################################################
#
@pytest.fixture
def get_controller(request: pytest.FixtureRequest) -> Callable[..., Controller]:
    """
    Provides a function that will return an instance of a controller.

    Default class of the controller is Controller,
    but can be changed via the ``class_`` parameter to the function,
    or via the ``class_`` parameter of :func:`controller_data`

    Example usage::

        def test_case(get_controller):
            handler = SomeHandler()
            controller = get_controller(handler, class_=SomeController)
            ...
    """
    default_class = Controller
    marker = request.node.get_closest_marker("controller_data")
    if marker and marker.kwargs:
        # Must copy so marker data do not change between test cases if marker is
        # applied to test class
        markerdata = marker.kwargs.copy()
    else:
        markerdata = {}

    def getter(
        handler: Any,
        class_: Optional[Type[Controller]] = None,
        **server_kwargs,
    ) -> Controller:
        """
        :param handler: The handler object
        :param class_: If set to None, check controller_data(class_).
            If both are none, defaults to Controller.
        """
        assert not inspect.isclass(handler)
        marker_class: Optional[Type[Controller]]
        marker_class = markerdata.pop("class_", default_class)
        class_ = class_ or marker_class
        if class_ is None:
            raise RuntimeError(
                f"Fixture '{request.fixturename}' needs controller_data to specify "
                f"what class to use"
            )
        ip_port: HostPort = markerdata.pop("host_port", HostPort())
        # server_kwargs takes precedence, so it's rightmost (PEP448)
        server_kwargs = {**markerdata, **server_kwargs}
        server_kwargs.setdefault("hostname", ip_port.host)
        server_kwargs.setdefault("port", ip_port.port)
        return class_(
            handler,
            **server_kwargs,
        )

    return getter


####################################################################
#
@pytest.fixture
def get_handler(request: pytest.FixtureRequest) -> Callable:
    """
    Provides a function that will return an instance of
    a :ref:`handler class <handlers>`.

    Default class of the handler is Sink,
    but can be changed via the ``class_`` parameter to the function,
    or via the ``class_`` parameter of :func:`handler_data`

    Example usage::

        def test_case(get_handler):
            handler = get_handler(class_=SomeHandler)
            controller = Controller(handler)
            ...
    """
    default_class = Sink
    marker = request.node.get_closest_marker("handler_data")
    if marker and marker.kwargs:
        # Must copy so marker data do not change between test cases if marker is
        # applied to test class
        markerdata = marker.kwargs.copy()
    else:
        markerdata = {}

    def getter(*args, **kwargs) -> Any:
        if marker:
            class_ = markerdata.pop("class_", default_class)
            # *args overrides args_ in handler_data()
            args_ = markerdata.pop("args_", tuple())
            # Do NOT inline the above into the line below! We *need* to pop "args_"!
            args = args or args_
            # **kwargs override markerdata, so it's rightmost (PEP448)
            kwargs = {**markerdata, **kwargs}
        else:
            class_ = default_class
        # noinspection PyArgumentList
        return class_(*args, **kwargs)

    return getter


####################################################################
#
@pytest.fixture
def plain_controller(
    get_handler: Callable, get_controller: Callable
) -> Generator[Controller, None, None]:
    """
    Returns a aiosmtpd Controller that, by default, gets invoked with no
    optional args.  Hence the moniker "plain".

    Internally uses the :fixture:`get_controller` and :fixture:`get_handler`
    fixtures, so optional args/kwargs can be specified for the Controller and
    the handler via the :func:`controller_data` and :func:`handler_data`
    markers, respectively.
    """
    handler = get_handler()
    controller = get_controller(handler)
    controller.start()
    Global.set_addr_from(controller)
    #
    yield controller
    #
    # Some test cases need to .stop() the controller inside themselves
    # in such cases, we must suppress Controller's raise of AssertionError
    # because Controller doesn't like .stop() to be invoked more than once
    with suppress(AssertionError):
        controller.stop()
