#!/usr/bin/env python
#
"""
The AsyncIO SMTP Daemon that relays mails to our mail provider.

It gets the mailprovider info from the django configuration.

It authenticates mail accounts from the django as_email.models.Account
object.
"""
# system imports
#
import asyncio
import email
import email.policy
import logging
import ssl
import time
from base64 import b64decode
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any, List, Optional

# 3rd party imports
#
import sentry_sdk
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import (
    MISSING,
    SMTP,
    AuthResult,
    Envelope as SMTPEnvelope,
    LoginPassword,
    Session as SMTPSession,
    TLSSetupException,
    _TriStateType,
)
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.management.base import BaseCommand
from pydantic import BaseModel
from sentry_sdk.integrations.asyncio import AsyncioIntegration

# Project imports
#
from as_email.deliver import make_delivery_status_notification
from as_email.models import EmailAccount, InactiveEmail
from as_email.tasks import dispatch_incoming_email
from as_email.utils import write_spooled_email

DEST_PORT = 587
LISTEN_PORT = 19246

logger = logging.getLogger("as_email.aiosmtpd")


########################################################################
########################################################################
#
class DenyInfo(BaseModel):
    """
    Info for recording failure attempts by a peer.

    NOTE: A peer is the first part of the tuple that we back from `peername` for

    https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseTransport.get_extra_info
    """

    num_fails: int
    peer_addr: str
    expiry: Optional[datetime]


########################################################################
########################################################################
#
class AsyncioAuthSMTP(SMTP):
    """
    Our Authenticator needs to communicate with the django ORM. The default
    version is a non-asynico `__call__`. However this is called from inside
    async functions. However, since the default authenticator `__call__` method
    is NOT async, but IS called from an async context we can not do an `await`
    internally but the ORM requires that it be async. So we have our own SMTP
    server that calls the authenticator via await.
    """

    async def _authenticate(self, mechanism: str, auth_data: Any):
        if self._authenticator is not None:
            # self.envelope is likely still empty, but we'll pass it anyways to
            # make the invocation similar to the one in _call_handler_hook
            auth_result = await self._authenticator(
                self, self.session, self.envelope, mechanism, auth_data
            )
            return auth_result
        else:
            assert self._auth_callback is not None
            assert isinstance(auth_data, LoginPassword)
            if self._auth_callback(mechanism, *auth_data):
                return AuthResult(
                    success=True, handled=True, auth_data=auth_data
                )
            else:
                return AuthResult(success=False, handled=False)

    ####################################################################
    #
    # On the internet at large a number of people connect to our service and
    # try to find stuff out.. a frequent one is "ssl.SSLError: [SSL:
    # NO_SHARED_CIPHER] no shared cipher (_ssl.c:1006)" which causes a stack
    # trace to be logged by this function. When we get this kind of failure,
    # just recording that it happened is enough. Do not need to go into detail.
    #
    async def handle_exception(self, error: Exception) -> str:
        if hasattr(self.event_handler, "handle_exception"):
            status = await self.event_handler.handle_exception(error)
            return status
        else:
            # Log an error instead of an exception if this was caused by ssl
            #
            if (
                isinstance(error, TLSSetupException)
                and hasattr(error, "__cause__")
                and (
                    isinstance(error.__cause__, ssl.SSLError)
                    or isinstance(error.__cause__, ConnectionResetError)
                )
            ):
                logger.error(
                    "%r SMTP session exception: %s",
                    self.session.peer,
                    error.__cause__,
                )
            else:
                logger.exception("%r SMTP session exception", self.session.peer)
            status = "500 Error: ({}) {}".format(
                error.__class__.__name__,
                str(error),
            )
            return status

    ####################################################################
    #
    async def auth_PLAIN(self, _, args: List[str]) -> AuthResult:
        login_and_password: _TriStateType
        if len(args) == 1:
            login_and_password = await self.challenge_auth("")
            if login_and_password is MISSING:
                return AuthResult(success=False)
        else:
            try:
                login_and_password = b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        try:
            # login data is "{authz_id}\x00{login_id}\x00{password}"
            # authz_id can be null, and currently ignored
            # See https://tools.ietf.org/html/rfc4616#page-3
            _, login, password = login_and_password.split(
                b"\x00"
            )  # pytype: disable=attribute-error  # noqa: E501
        except ValueError:  # not enough args
            await self.push("501 5.5.2 Can't split auth value")
            return AuthResult(success=False, handled=True)
        # Verify login data
        assert login is not None
        assert password is not None
        # NOTE: The following `await` is the only difference from the original
        #       source.
        #
        auth_result = await self._authenticate(
            "PLAIN", LoginPassword(login, password)
        )
        return auth_result

    ####################################################################
    #
    async def auth_LOGIN(self, _, args: List[str]) -> AuthResult:
        login: _TriStateType
        if len(args) == 1:
            # Client sent only "AUTH LOGIN"
            login = await self.challenge_auth(self.AuthLoginUsernameChallenge)
            if login is MISSING:
                return AuthResult(success=False)
        else:
            # Client sent "AUTH LOGIN <b64-encoded-username>"
            try:
                login = b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        assert login is not None

        password: _TriStateType
        password = await self.challenge_auth(self.AuthLoginPasswordChallenge)
        if password is MISSING:
            return AuthResult(success=False)
        assert password is not None
        # NOTE: The following `await` is the only difference from the original
        #       source.
        #
        auth_result = await self._authenticate(
            "LOGIN", LoginPassword(login, password)
        )
        return auth_result


########################################################################
########################################################################
#
class AsyncioAuthController(Controller):
    """
    Override the `factory()` method so that it uses our AsyncioAuthSMTP
    """

    ####################################################################
    #
    def factory(self):
        return AsyncioAuthSMTP(self.handler, **self.SMTP_kwargs)

    ####################################################################
    #
    def _run(self, *args, **kwargs):
        """
        Hook sentry_io's AsyncioIntegration in to our event loop.
        """
        asyncio.set_event_loop(self.loop)
        if settings.SENTRY_DSN is not None:
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                # Set traces_sample_rate to 1.0 to capture 100%
                # of transactions for performance monitoring.
                traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
                profiles_sample_rate=settings.SENTRY_PROFILES_SAMPLE_RATE,
                integrations=[
                    AsyncioIntegration(),
                ],
                environment="devel" if settings.DEBUG else "production",
            )
        super()._run(*args, **kwargs)


########################################################################
########################################################################
#
class Command(BaseCommand):
    help = (
        "Runs a SMTP relay for accounts to use to send email. "
        "Relays the email to the mail provider. Uses their account to "
        "validate that they are allowed to send email."
    )

    ####################################################################
    #
    def add_arguments(self, parser):
        parser.add_argument(
            "--listen_port",
            type=int,
            action="store",
            default=LISTEN_PORT,
        )
        parser.add_argument("--ssl_key", action="store", required=True)
        parser.add_argument("--ssl_cert", action="store", required=True)

    ####################################################################
    #
    def handle(self, *args, **options):
        listen_port = options["listen_port"]
        ssl_cert_file = options["ssl_cert"]
        ssl_key_file = options["ssl_key"]
        spool_dir = settings.EMAIL_SPOOL_DIR

        logger.info(
            f"aiosmtpd: Listening on {listen_port} , cert: '{ssl_cert_file}', "
            f"key: '{ssl_key_file}'"
        )

        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.check_hostname = False
        tls_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        authenticator = Authenticator()
        handler = RelayHandler(spool_dir=spool_dir, authenticator=authenticator)
        controller = AsyncioAuthController(
            handler,
            hostname="0.0.0.0",  # This means listens on all interfaces.
            server_hostname=settings.SITE_NAME,
            port=listen_port,
            authenticator=authenticator,
            tls_context=tls_context,
            require_starttls=True,
            auth_required=True,
        )
        logger.info("Starting controller")
        controller.start()
        try:
            while True:
                time.sleep(300)
        except KeyboardInterrupt:
            logger.warning("Keyboard interrupt, exiting")
        finally:
            controller.stop()


########################################################################
########################################################################
#
class Authenticator:
    MAX_NUM_AUTH_FAILURES = 5
    AUTH_FAILURE_EXPIRY = timedelta(hours=1)

    ####################################################################
    #
    def __init__(self):
        """
        The authenicator is what is used to check requests for access to
        this smtp relay. It keeps track of failures and what peer sent them so
        we can quickly deny repeated attempts by the same peer.
        """
        # This blacklist is keyed by ip address.
        #
        self.blacklist = {}

    ####################################################################
    #
    def incr_fails(self, peer):
        """
        Increment fails for a session peer. Since this is called via the
        "__call__" method when we fail an authentication no other coroutines
        can run at the time (__call__ is not an async method.) so we do not
        need to acquire the lock to check or modify the black list here.

        Every auth failure extends the expiry time.
        """
        expiry = datetime.now(UTC) + self.AUTH_FAILURE_EXPIRY
        peer_addr = peer[0]
        if peer_addr not in self.blacklist:
            deny = DenyInfo(num_fails=1, peer_addr=peer[0], expiry=expiry)
            self.blacklist[peer_addr] = deny
        else:
            deny = self.blacklist[peer_addr]
            deny.num_fails += 1
            deny.expiry = expiry

    ####################################################################
    #
    def check_deny(self, peer):
        """
        Return True if we ARE denying this connection.

        Check to see if the given peer has too many auth failures.  If a
        DenyInfo exists and it is _before_ the expiry, and the number of fails
        is above the limit then return True - this peer is denied.

        If the number of fails is below the limit then return False - this peer
        is allowed.

        If the current time is beyond the expiry then return False - this peer
        is allowed. Also delete their entry from the black list.

        If there is no deny info at all, then this peer is allowed.
        """
        peer_addr = peer[0]
        if peer_addr not in self.blacklist:
            return False

        now = datetime.now(UTC)
        deny = self.blacklist[peer_addr]
        if now > deny.expiry:
            del self.blacklist[peer_addr]
            return False

        if deny.num_fails < self.MAX_NUM_AUTH_FAILURES:
            return False
        return True

    ####################################################################
    #
    # XXX We should track metrics of number of emails sent, but which
    #     account, how many failures, of which kind.
    #
    async def __call__(self, server, session, envelope, mechanism, auth_data):
        """
        NOTE: If the datbase is inaccessible or slow this method will be
        slow. Since our initial implementation uses a local sqlite db and there
        should not be that much contention we expect it to be quick.

        NOTE: We only support `plain` and `login` auth methods. CRAM-MD5
        requires that we know the clear text of the password. This requires
        that we only access encrypted connections from the SMTP client trying
        to authenticate.

        If we were to use some sort of cache, we need to make sure that the
        cache is invalidated whenever an email account is saved/deleted/added
        so that there are no delays in authentication changes.
        """
        logger.debug(
            "Authenticator: session: %r, mechanism: %s, auth data: %r, peer: %s",
            session,
            mechanism,
            auth_data,
            session.peer[0],
        )
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in ("LOGIN", "PLAIN"):
            self.incr_fails(session.peer)
            logger.info(
                "Authenticator: FAIL: auth mechanism %s not accepted, from: %s",
                mechanism,
                session.peer[0],
            )
            fail_nothandled.message = (
                f"Authenticator: FAIL: auth mechanism {mechanism} not accepted"
            )
            return fail_nothandled

        if not isinstance(auth_data, LoginPassword):
            self.incr_fails(session.peer)
            logger.info(
                "Authenticator: FAIL: '%r' not LoginPassword, from %s",
                auth_data,
                session.peer[0],
            )
            fail_nothandled.message = "Authentication failed"
            return fail_nothandled

        username = str(auth_data.login, "utf-8")
        password = str(auth_data.password, "utf-8")
        try:
            account = await EmailAccount.objects.aget(email_address=username)
        except EmailAccount.DoesNotExist:
            # XXX We need to keep a count of failures for accounts
            #     that do not exist and if we get above a ceratin amount
            #     of them find a cheap way to block that connection for a
            #     period of time.
            self.incr_fails(session.peer)
            logger.info(
                "Authenticator: FAIL: '%s' not a valid account, from: %s",
                username,
                session.peer[0],
            )
            fail_nothandled.message = "Authentication failed"
            return fail_nothandled

        # If the account is deactivated it is not allowed to relay email.
        #
        if account.deactivated:
            self.incr_fails(session.peer)
            logger.info(
                "Authenticator: FAIL: '%s' is deactivated, from: %s",
                account,
                session.peer[0],
            )
            fail_nothandled.message = "Account deactivated"
            return fail_nothandled

        if not account.check_password(password):
            self.incr_fails(session.peer)
            logger.info(
                "Authenticator: FAIL: '%s' invalid password from %s",
                account,
                session.peer[0],
            )
            fail_nothandled.message = "Authentication failed"
            return fail_nothandled

        # Upon success we pass the account back as the auth_data
        # back. This gets saved in to the session.auth_data attribute
        # and will let the RelayHandler know which account was used so
        # it will know which Server to send the email through.
        #
        logger.info(
            "Authenticator: Success for '%s' from %s",
            account,
            session.peer[0],
        )
        return AuthResult(success=True, auth_data=account)


########################################################################
########################################################################
#
class RelayHandler:
    ####################################################################
    #
    def __init__(self, spool_dir: str, authenticator: Authenticator):
        """
        Sets up the spool_dir where we store messages if we are
        unable to send messages through postmark immediately.
        """
        logger.debug("RelayHandler, init. Spool dir: '%s'", spool_dir)
        self.spool_dir = spool_dir
        self.authenticator = authenticator

    ####################################################################
    #
    async def handle_EHLO(
        self,
        smtp: SMTP,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        hostname,
        responses: List[str],
    ) -> List[str]:
        """
        the primary purpose of having a handler for EHLO is to
        quickly deny hosts that have suffered repeated authentication failures
        """
        logger.debug(
            "handle_EHLO: smtp: %r, session: %r, envelope: %r, hostname: %s, responses: %r",
            smtp,
            session,
            envelope,
            hostname,
            responses,
        )
        # NOTE: We have to at least set session.host_name
        #
        session.host_name = hostname
        if self.authenticator.check_deny(session.peer):
            logger.info(
                "handle_EHLO: Denying %s due to many failed auth attempts",
                session.peer[0],
            )
            # If we deny this connection we also sleep for a short bit before
            # returning the error to the client. This makes a mini-tarpit that
            # will hopefully slow down connection attempts a little bit.
            await asyncio.sleep(30)
            responses.append("550 Too many failed attempts")
        return responses

    ####################################################################
    #
    async def handle_MAIL(
        self,
        server: SMTP,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        address: str,
        mail_options: List[str],
    ) -> str:
        """
        You can ONLY send email _from_ the email address of the email
        account that authenticated to the relay.
        """
        # handle_MAIL is responsible for setting the mail_from and mail_options
        # on the envelope! I am not sure if we should or should not do this
        # when we are going to possibly deny this request.
        #
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)

        # The email address part of `from` MUST be the same as the email
        # address on this EmailAccount.
        #
        account = session.auth_data
        valid_from = account.email_address.lower()
        logger.debug("handle_MAIL: account: %s, address: %s", account, address)
        _, frm = parseaddr(address)
        if frm is None or frm.lower() != valid_from:
            logger.info(
                "handle_MAIL: For account '%s', FROM '%s' (%s) is not valid "
                "(from address %s)",
                account,
                frm,
                address,
                session.peer[0],
            )
            return f"551 FROM must be your email account's email address: '{valid_from}', not '{frm}'"

        return "250 OK valid FROM"

    ####################################################################
    #
    async def handle_DATA(
        self, server: SMTP, session: SMTPSession, envelope: SMTPEnvelope
    ) -> str:
        # The as_email.models.EmailAccount object instance is passed in via
        # session.auth_data.
        #
        account = session.auth_data
        logger.debug(
            "handle_DATA: account: %s, envelope from: %s",
            account,
            envelope.mail_from,
        )

        # Do a double check to make sure that any 'From' headers are the email
        # account sending the message.
        #
        # NOTE: "president of the universe <foo@example.com>" is still
        #       considered a valid "from" address for "foo@example.com"
        #
        msg = email.message_from_bytes(
            envelope.original_content,
            policy=email.policy.default,
        )
        froms = msg.get_all("from")
        valid_from = account.email_address.lower()
        if froms:
            for msg_from in froms:
                _, frm = parseaddr(msg_from)
                if frm is None or frm.lower() != valid_from:
                    logger.info(
                        "handle_DATA: `from` header in email not valid: '%s' (must be from '%s')",
                        frm,
                        valid_from,
                    )
                    return f"551 FROM must be '{valid_from}', not '{frm}'"
        try:
            await relay_email_to_provider(account, envelope.rcpt_tos, msg)
        except Exception as exc:
            logger.error(f"Failed: {exc}")
            return f"500 Mail Provider error: {exc}"

        return "250 OK"


########################################################################
#
def send_email_via_smtp(
    account: EmailAccount, rcpt_tos: List[str], msg: EmailMessage
):
    """
    Use smtplib.SMTP to send the given email. Use the token to authenticate
    to the smtp server.

    This function is synchronous and meant to be called via
    `asyncio.to_thread()`.

    If we fail to send the message due to a network issue the message will be
    written to the spool directory to be sent at a later time.
    """
    logger.info(
        "send_email_via_smtp: account: %s, rcpt_tos: %s",
        account,
        rcpt_tos,
    )
    account.send_email_via_smtp(rcpt_tos, msg)


####################################################################
#
async def relay_email_to_provider(
    account: EmailAccount, rcpt_tos: List[str], msg: EmailMessage
):
    """
    Relay the email we have gotten from the user to our mail provider to
    send out.

    But first we will go through the list of recipients and filter out any that
    are InactiveEmail's.

    If there are any InactiveEmail's we will also send a bounce report to the
    email account sending this email indicating that some of the recipients
    were inactive and the email was not sent to them.
    """
    rcpt_tos = [x.lower() for x in rcpt_tos]
    inactives = [
        x.email_address.lower()
        for x in await InactiveEmail.a_inactives(rcpt_tos)
    ]

    # Filter out any inactive emails from our list of recipients
    #
    rcpt_tos = [x for x in rcpt_tos if x not in inactives]

    # If there any recipients left, send the email to them.
    #
    if rcpt_tos:
        await sync_to_async(send_email_via_smtp)(account, rcpt_tos, msg)

    # If there were no inactive emails then we are done. If there were inactive
    # emails we need to generate a DSN and send it to the account saying that
    # the message was not deliverable to these addresses.
    #
    if not inactives:
        return

    logger.warning(
        "EmailAccount %s attempted to send email to inactive addresses: %s",
        account.email_address,
        ",".join(inactives),
    )

    # If there were any inactives send a DSN to the email account that their
    # email was not sent to some recipients.
    #
    report_text = (
        "Email not sent to the following addresses because they were marked "
        "as 'inactive' due to being blocked by the mail "
        f"provider: {', '.join(inactives)}.\nContact the service admin "
        "for more information."
    )
    from_addr = f"mailer-daemon@{account.server.domain_name}"
    dsn = make_delivery_status_notification(
        account,
        report_text=report_text,
        subject="NOTICE: Email not sent due to destination address marked as inactive",
        from_addr=from_addr,
        action="failed",
        status="5.1.1",
        diagnostic="smtp; Destination is an inactive email address",
        reported_msg=msg,
    )
    fname = write_spooled_email(
        account.email_address,
        account.server.incoming_spool_dir,
        dsn,
        msg_id=dsn["Message-ID"],
    )

    # Fire off async huey task to dispatch the delivery status notification.
    # (we need to sync_to_async this in case it is being called when Huey is in
    # immediate mode.)
    #
    await sync_to_async(dispatch_incoming_email)(account.pk, str(fname))
