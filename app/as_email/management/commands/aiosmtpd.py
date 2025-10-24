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
from typing import Any, Iterable, List, Optional, Tuple

# 3rd party imports
#
import aiospamc
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
from pydnsbl import DNSBLIpChecker
from sentry_sdk.integrations.asyncio import AsyncioIntegration

# Project imports
#
from as_email.deliver import make_delivery_status_notification
from as_email.models import EmailAccount, InactiveEmail, Server
from as_email.tasks import dispatch_incoming_email
from as_email.utils import msg_froms, write_spooled_email

SUBMISSION_PORT = 587
SMTP_PORT = 25
LISTEN_HOST = "0.0.0.0"

logger = logging.getLogger("as_email.aiosmtpd")


########################################################################
#
async def tarpit_delay(seconds: int = 30) -> None:
    """
    Sleep for a period of time to slow down malicious clients.
    This is used when denying connections for blacklisting or auth failures.
    """
    await asyncio.sleep(seconds)


########################################################################
#
def format_dnsbl_providers(detected_by: Iterable[Tuple[str, List[str]]]) -> str:
    """
    Format DNSBL provider information into a readable string.

    Args:
        detected_by: Iterable of tuples containing (provider_name, [categories])

    Returns:
        A comma-separated list of "provider: category" entries.
    """
    providers = []
    for provider in detected_by:
        name, categories = provider
        category = ",".join(categories)
        providers.append(f"{name}: {category}")
    return ", ".join(providers)


########################################################################
#
async def check_spam(msg_bytes: bytes) -> bytes:
    """
    Run the message through SpamAssassin and return it with spam headers added.

    Args:
        msg_bytes: The original message bytes

    Returns:
        Message bytes with spam headers added, or original bytes if check fails
    """
    try:
        result = await aiospamc.process(
            msg_bytes, host=settings.SPAMD_HOST, port=settings.SPAMD_PORT
        )
        return result.body
    except Exception as e:
        logger.error("SpamAssassin check failed: %r", e)
        return msg_bytes


########################################################################
#
def validate_from_header(
    msg: EmailMessage, account: Optional[EmailAccount]
) -> Optional[str]:
    """
    Validate that the FROM header matches the authenticated account.

    Args:
        msg: The email message to validate
        account: The authenticated EmailAccount, or None if not authenticated

    Returns:
        Error message string if validation fails, None if validation succeeds
    """
    if not account:
        # No account means unauthenticated, no validation needed
        return None

    froms = msg.get_all("from")
    if not froms:
        # No FROM header, let it pass (will likely fail elsewhere)
        return None

    valid_from = account.email_address.lower()
    for msg_from in froms:
        _, frm = parseaddr(msg_from)
        if frm is None or frm.lower() != valid_from:
            logger.info(
                "handle_DATA: `from` header in email not valid: '%s' (must be from '%s')",
                frm,
                valid_from,
            )
            return f"551 FROM must be '{valid_from}', not '{frm}'"

    return None


########################################################################
#
async def categorize_recipients(
    rcpt_tos: List[str],
) -> Tuple[List[str], List[str], List[str]]:
    """
    Categorize recipients into local, remote, and invalid local addresses.

    Args:
        rcpt_tos: List of recipient email addresses from the SMTP envelope

    Returns:
        Tuple of (local_addrs, remote_addrs, invalid_local_addrs)
        - local_addrs: Valid email accounts on domains we own
        - remote_addrs: Email addresses on domains we don't own
        - invalid_local_addrs: Addresses on our domains but no EmailAccount exists
    """
    local_addrs = []
    remote_addrs = []
    invalid_local_addrs = []

    for rcpt_to in rcpt_tos:
        _, email_addr = parseaddr(rcpt_to)
        # Extract the domain from the email address
        domain = (
            email_addr.split("@")[-1].lower() if "@" in email_addr else None
        )

        # Check if there is a Server for this domain name. We only consider
        # email addresses for servers we own to be local.
        if (
            domain
            and await Server.objects.filter(
                domain_name__iexact=domain
            ).aexists()
        ):
            # What is more, make sure that the email address is one served by us.
            if await EmailAccount.objects.filter(
                email_address__iexact=email_addr
            ).aexists():
                local_addrs.append(email_addr.lower())
            else:
                invalid_local_addrs.append(email_addr.lower())
        else:
            remote_addrs.append(email_addr)

    return local_addrs, remote_addrs, invalid_local_addrs


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
            status = f"500 Error: ({error.__class__.__name__}) {error!r}"
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
        def port_or_off(value):
            """Parse port argument - either an integer port or 'off' to disable."""
            if isinstance(value, str) and value.lower() == "off":
                return "off"
            try:
                port = int(value)
                if port < 1 or port > 65535:
                    raise ValueError(
                        f"Port must be between 1-65535, got {port}"
                    )
                return port
            except ValueError as e:
                raise ValueError(
                    f"Port must be an integer (1-65535) or 'off', got '{value}'"
                ) from e

        parser.add_argument(
            "--submission_port",
            type=port_or_off,
            action="store",
            default=SUBMISSION_PORT,
        )
        parser.add_argument(
            "--smtp_port",
            type=port_or_off,
            action="store",
            default=SMTP_PORT,
        )
        parser.add_argument(
            "--listen_host",
            action="store",
            default=LISTEN_HOST,
        )
        parser.add_argument("--ssl_key", action="store", required=True)
        parser.add_argument("--ssl_cert", action="store", required=True)

    ####################################################################
    #
    def handle(self, *args, **options):
        submission_port = options["submission_port"]
        smtp_port = options["smtp_port"]
        listen_host = options["listen_host"]
        ssl_cert_file = options["ssl_cert"]
        ssl_key_file = options["ssl_key"]
        spool_dir = settings.EMAIL_SPOOL_DIR

        logger.info(
            "aiosmtpd: Submission port: %s, SMTP port: %s, host: '%s', cert: '%s', key: '%s'",
            submission_port,
            smtp_port,
            listen_host,
            ssl_cert_file,
            ssl_key_file,
        )

        # If `list_host` contains commas we are going to assume it is a set of
        # ip addressses separated by commas.
        #
        if "," in listen_host:
            listen_host = [x.strip() for x in listen_host.split(",")]

        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.check_hostname = False
        tls_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        authenticator = Authenticator()
        handler = RelayHandler(spool_dir=spool_dir, authenticator=authenticator)

        controllers = []

        # Submission port controller (port 587) - requires STARTTLS
        # Only create if submission_port is not "off"
        if submission_port != "off":
            submission_controller = AsyncioAuthController(
                handler,
                hostname=listen_host,
                server_hostname=settings.SITE_NAME,
                port=submission_port,
                authenticator=authenticator,
                tls_context=tls_context,
                require_starttls=True,
                # During communication with the SMTP client we may require
                # authentication, but we do not require it until we know that the
                # SMTP client is trying to relay email to domains that the AS Email
                # service is not hosting.
                #
                auth_required=False,
                # Commands RCPT and NOOP have their own limits; others have an
                # implicit limit of 20 (CALL_LIMIT_DEFAULT)
                #
                command_call_limit={"RCPT": 30, "NOOP": 5},
            )
            controllers.append(("submission", submission_controller))
            logger.info(
                "Starting submission controller on port %d", submission_port
            )
            submission_controller.start()
        else:
            logger.info("Submission port is disabled (off)")

        # SMTP port controller (port 25) - optional STARTTLS for receiving mail
        # Only create if smtp_port is not "off"
        if smtp_port != "off":
            smtp_controller = AsyncioAuthController(
                handler,
                hostname=listen_host,
                server_hostname=settings.SITE_NAME,
                port=smtp_port,
                authenticator=authenticator,
                tls_context=tls_context,
                require_starttls=False,
                # During communication with the SMTP client we may require
                # authentication, but we do not require it until we know that the
                # SMTP client is trying to relay email to domains that the AS Email
                # service is not hosting.
                #
                auth_required=False,
                command_call_limit={"RCPT": 30, "NOOP": 5},
            )
            controllers.append(("smtp", smtp_controller))
            logger.info("Starting SMTP controller on port %d", smtp_port)
            smtp_controller.start()
        else:
            logger.info("SMTP port is disabled (off)")

        try:
            while True:
                time.sleep(300)
        except KeyboardInterrupt:
            logger.warning("Keyboard interrupt, exiting")
        finally:
            logger.info("Stopping controllers")
            for name, controller in controllers:
                logger.info("Stopping %s controller", name)
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
    def _auth_fail(
        self, session, log_msg: str, error_msg: str = "Authentication failed"
    ) -> AuthResult:
        """
        Helper to handle authentication failures consistently.

        Args:
            session: The SMTP session
            log_msg: Log message describing the failure
            error_msg: User-facing error message

        Returns:
            AuthResult indicating failure
        """
        self.incr_fails(session.peer)
        logger.info(
            "Authenticator: FAIL: %s, from: %s", log_msg, session.peer[0]
        )
        result = AuthResult(success=False, handled=False)
        result.message = error_msg
        return result

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

        if mechanism not in ("LOGIN", "PLAIN"):
            return self._auth_fail(
                session,
                f"auth mechanism {mechanism} not accepted",
                f"Authenticator: FAIL: auth mechanism {mechanism} not accepted",
            )

        if not isinstance(auth_data, LoginPassword):
            return self._auth_fail(
                session, f"'{auth_data!r}' not LoginPassword"
            )

        username = str(auth_data.login, "utf-8")
        password = str(auth_data.password, "utf-8")

        try:
            # Preload server relation for relay operations
            account = await EmailAccount.objects.select_related("server").aget(
                email_address=username
            )
        except EmailAccount.DoesNotExist:
            return self._auth_fail(session, f"'{username}' not a valid account")

        # NOTE: We allow deactivated accounts to authenticate because:
        # - They can send to local addresses (no auth required anyway)
        # - They are blocked from relaying in handle_RCPT
        # This way deactivated accounts can still receive and send local mail

        if not account.check_password(password):
            return self._auth_fail(session, f"'{account}' invalid password")

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
        self.dnsbl = DNSBLIpChecker()

    ####################################################################
    #
    async def handle_CONNECT(
        self,
        smtp: SMTP,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        hostname: str,
        port: int,
    ):
        logger.debug(
            "handle_CONNECT: smtp: %r, session: %r, envelope: %r, hostname: %s",
            smtp,
            session,
            envelope,
            hostname,
        )

        # XXX Should we add a configurable white list in case one of our ip
        #     addresses is black listed maliciously? probably not.. been fine
        #     for so many years as it is.  .  If we were maybe we should allow
        #     if the ip address is on a white list and a user authenticated?
        #     (But what if someone's credentaisl get stolen and suddenly they
        #     are used for spam?)
        #
        if self.authenticator.check_deny(session.peer):
            logger.info(
                "Denying %s due to too many failed auth attempts",
                session.peer[0],
            )
            await tarpit_delay()
            return "554 Too many failed attempts"

        peer_ip, _ = session.peer
        result = await self.dnsbl.check(peer_ip)
        if result.blacklisted:
            detected_by = format_dnsbl_providers(result.detected_by)
            logger.info("IP %s is blacklisted: %s", peer_ip, detected_by)
            await tarpit_delay()
            return "554 Your IP is blacklisted. Connection refused."

        return "220 OK"

    ####################################################################
    #
    async def handle_EHLO(
        self,
        smtp: SMTP,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        hostname: str,
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
        Handle the MAIL FROM command. We accept any FROM address here because:
        - For unauthenticated sessions: we need to receive mail from the internet
        - For authenticated sessions: FROM validation happens in handle_DATA
          where we can check the actual message headers

        We also cache the MAIL FROM account lookup for efficient use in handle_RCPT.
        """
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)

        # Cache the MAIL FROM account lookup for use in handle_RCPT
        # Note: We don't need to preload 'server' here since handle_RCPT
        # only checks deactivated status, not server-related fields
        _, from_addr = parseaddr(address)
        try:
            envelope.mail_from_account = await EmailAccount.objects.aget(
                email_address=from_addr.lower()
            )
        except EmailAccount.DoesNotExist:
            envelope.mail_from_account = None

        return "250 OK"

    ####################################################################
    #
    async def handle_RCPT(
        self,
        server: SMTP,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        address: str,
        rcpt_options: List[str],
    ) -> str:
        """
        Handle RCPT TO command. Enforce authentication and validation early.

        Authentication/Authorization logic:
        - Local delivery (our domains): No auth required, but EmailAccount must exist
        - Remote delivery (relay):
          - If MAIL FROM is a deactivated local account → reject immediately
          - Otherwise → require authentication
        """
        _, email_addr = parseaddr(address)
        domain = (
            email_addr.split("@")[-1].lower() if "@" in email_addr else None
        ).lower()

        # Check if this domain is managed by us
        is_local_domain = False
        if domain:
            is_local_domain = await Server.objects.filter(
                domain_name=domain
            ).aexists()

        if is_local_domain:
            # Domain is ours, verify EmailAccount exists
            try:
                await EmailAccount.objects.aget(
                    email_address=email_addr.lower()
                )
                # Valid local account, accept it (no auth required)
                envelope.rcpt_tos.append(address)
                envelope.rcpt_options.extend(rcpt_options)
                return "250 OK"
            except EmailAccount.DoesNotExist:
                # Domain is ours but no account exists
                msg = (
                    f"<{email_addr}>: Recipient address rejected: User unknown"
                )
                logger.info(msg)
                return f"550 5.1.1 {msg}"

        # This is a relay to a remote address. Check if MAIL FROM is a
        # deactivated local account (cached from handle_MAIL)
        #
        if (
            hasattr(envelope, "mail_from_account")
            and envelope.mail_from_account
            and envelope.mail_from_account.deactivated
        ):
            from_addr = envelope.mail_from_account.email_address
            msg = f"<{from_addr}>: Sender address rejected: Account is deactivated and cannot relay"
            logger.warning(msg)
            return f"550 5.7.1 {msg}"

        # Require authentication for relay
        if not session.authenticated:
            return "530 5.7.1 Authentication required for relaying"

        # Accept the recipient
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    ####################################################################
    #
    async def handle_DATA(
        self, server: SMTP, session: SMTPSession, envelope: SMTPEnvelope
    ) -> str:
        # Categorize recipients into local and remote addresses
        # Note: Invalid local addresses are already rejected in handle_RCPT
        # Note: Authentication for relay is already checked in handle_RCPT
        local_addrs, remote_addrs, invalid_local_addrs = (
            await categorize_recipients(envelope.rcpt_tos)
        )

        # Defensive check: if no valid recipients, reject
        if not local_addrs and not remote_addrs:
            logger.info(
                "Error: No valid recipients. Envelope from: %s",
                envelope.mail_from,
            )
            return "554 5.5.1 Error: no valid recipients"

        # Get the authenticated account if present
        account = session.auth_data if session.authenticated else None
        logger.debug(
            "handle_DATA: account: %s, envelope from: %s",
            account,
            envelope.mail_from,
        )

        # Check spam and parse the message
        msg_bytes = envelope.original_content
        msg_bytes_with_spam_headers = await check_spam(msg_bytes)
        msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)

        # Validate FROM header for authenticated sessions
        if from_error := validate_from_header(msg, account):
            return from_error

        # Deliver to local addresses if any
        if local_addrs:
            try:
                await deliver_email_locally(
                    account, local_addrs, msg_bytes_with_spam_headers
                )
            except Exception as exc:
                logger.error("Local delivery failed: %r", exc)
                return f"500 Local delivery error: {exc!r}"

        # Relay to remote addresses if any
        if remote_addrs:
            try:
                await relay_email_to_provider(account, remote_addrs, msg)
            except Exception as exc:
                logger.error("Failed to relay: %r", exc)
                return f"500 Mail Provider error: {exc!r}"

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
async def deliver_email_locally(
    account: EmailAccount, rcpt_tos: List[str], msg_bytes: bytes
) -> None:
    """
    Create delivery email files for each entry in rcpt_tos, and store the
    message in that file, then invoke the async task `dispatch_incoming_email`
    to actually deliver it.

    If a `rcp_to` is not a valid local email account, or one that is blocked
    from receiving email (there is no such setting right now) then the message
    is not dispatched and a warning log message is generated.
    """
    # Convert bytes to EmailMessage once, then to string representation once.
    # This avoids repeated conversions for multiple recipients and handles
    # encoding properly using the email library's built-in conversion.
    #
    msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)
    msg_id = msg.get("Message-ID", "unknown")
    msg_str = msg.as_string(policy=email.policy.default)

    # Get the a formatted list of all the 'from's for this message. Almost
    # always there will only be one from, but it is not specifically disallowed
    # for there to be multiple from's.
    #
    msg_from = msg_froms(msg)
    for rcpt_to in rcpt_tos:
        try:
            # Get the EmailAccount for this recipient (with server for spool_dir)
            recipient_account = await EmailAccount.objects.select_related(
                "server"
            ).aget(email_address=rcpt_to.lower())
        except EmailAccount.DoesNotExist:
            logger.warning(
                "deliver_email_locally: Recipient '%s' does not exist, "
                "skipping delivery for message %s",
                rcpt_to,
                msg_id,
            )
            continue

        # Write the message to the recipient's incoming spool directory
        #
        spool_dir = recipient_account.server.incoming_spool_dir
        fname = write_spooled_email(
            rcpt_to,
            spool_dir,
            msg_str,
            msg_id=msg_id,
        )

        # Dispatch the delivery task to Huey queue
        # Calling the task directly enqueues it (fast, non-blocking).
        # Must wrap in sync_to_async because we're in async context and
        # Huey's enqueue operation uses synchronous Redis client.
        #
        await sync_to_async(
            lambda: dispatch_incoming_email(recipient_account.pk, str(fname))
        )()

        logger.info(
            "deliver_email_locally: Queued delivery for '%s', message %s, from %s",
            rcpt_to,
            msg_id,
            msg_from,
        )


####################################################################
#
async def relay_email_to_provider(
    account: EmailAccount, rcpt_tos: List[str], msg: EmailMessage
) -> None:
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

    # Fire off Huey task to dispatch the delivery status notification.
    # Calling the task directly enqueues it (fast, non-blocking).
    # Must wrap in sync_to_async because we're in async context and
    # Huey's enqueue operation uses synchronous Redis client.
    #
    await sync_to_async(
        lambda: dispatch_incoming_email(account.pk, str(fname))
    )()
