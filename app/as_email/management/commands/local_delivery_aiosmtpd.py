#!/usr/bin/env python
#
"""
An AsyncIO SMTP Daemon that receives email for local delivery to email
accounts in the as_email_service.

It gets the mailprovider info from the django configuration.

- It will deny email for email addresses that do not exist.
- It will deny email for domains not supported by the as email service
- It will deny email from connections that have had <n> of the above denies
  in <m> minutes.
- It can either deny or tag as spam email that:
  - source matches a black list
  - is marked as spam by spam assassin and is above the receipients spam score
    threshold
  - is determined as spam by our own spam detection service

"""
# system imports
#
import asyncio
import email
import email.policy
import logging
import ssl
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Dict, List, Optional, cast

# 3rd party imports
#
import pydnsbl
import sentry_sdk
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope as SMTPEnvelope, Session as SMTPSession
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.management.base import BaseCommand
from pydantic import BaseModel
from sentry_sdk.integrations.asyncio import AsyncioIntegration

# Project imports
#
from as_email.models import EmailAccount
from as_email.tasks import dispatch_incoming_email
from as_email.utils import write_spooled_email

LISTEN_PORT = 19247

logger = logging.getLogger("as_email.local_delivery_aiosmtpd")


########################################################################
########################################################################
#
class DenyInfo(BaseModel):
    """
    Info for recording failure attempts by a peer, domain or email address.

    NOTE: A peer is the first part of the tuple that we back from `peername` for

    https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseTransport.get_extra_info

    We want to immediately know upon EHLO if a SMTP client is to be denied
    before any other processing. We track how often we get connections from a
    source that are to be blocked by some rule or another.

    Once that threshold is met, any connections that match a DenyInfo will
    sleep for a couple of seconds, and then tell the remote connection to go
    away with a 4xx error code. (because it is transient).

    XXX This is not yet thought out. We will likely have different tolerances
        for different things.. like source email address blocks first, then
        sending domain name, then sending peer address.

        We should probably have a different record for each of these things and
        the record should indicate which one it represents.

    NOTE: I guess this record should be created if we get email from a source
          that is on a dnsbl, or if it tried to send email to a non-existent
          account (if someone tries to send to a non-existent account more than
          <n> times after being told there is no such account, it probably is
          the right thing to block them.

          This is probably where the email block reports should collect data.
    """

    num_fails: int
    peer_addr: Optional[str] = None
    email_addr: Optional[str] = None
    domain_name: Optional[str] = None
    expiry: Optional[datetime] = None
    # dnsbl: bool  # XXX if this was was blocked because it was on a dnsbl? Do
    # #     we care? It should be a domain block.


########################################################################
########################################################################
#
class SpamBlocker:
    """
    A class that is used to handle dns black list checking, spam checking,
    and repeated attempts.

    It will use dnsbl's and spam assassin to check if we deny a message based
    on its source domain, source ip address, or email content.

    It will track addresses and source ip's for frequent abuses and provide a
    check to deny them sooner if they are a repeater offender.
    """

    # Max number of allowed failures within the failure expiry time limit.
    #
    MAX_NUM_BLOCKS = 5
    FAILURE_EXPIRY = timedelta(hours=1)

    ####################################################################
    #
    def __init__(self):
        self.blacklist = {}
        self.ip_checker = pydnsbl.DNSBLIpChecker()
        self.domain_checker = pydnsbl.DNSBLDomainChecker()

    ####################################################################
    #
    def _check(self, what: str) -> bool:
        """
        Check to see if `what` is on the blacklist. `what` may be the peer
        address (as a string), an email address, or a domain name.

        This is used as a pre-emptive check for actors believed to be bad. This
        saves us a round trip through the dnsbl or spam assassin giving a
        pre-emptive block for a certain amount of time.

        Check to see if the given peer has too many auth failures.  If a
        DenyInfo exists and it is _before_ the expiry, and the number of fails
        is above the limit then return True

        If the number of fails is below the limit then return False

        If the current time is beyond the expiry then return False. Also delete
        their entry from the black list.

        If there is no deny info at all, then this peer is allowed. Return
        False.

        Keyword Arguments:
        what: str --
        """
        if what not in self.blacklist:
            return False

        now = datetime.utcnow()
        deny = self.blacklist[what]
        if now > deny.expiry:
            # Note that one DenyInfo may be stored until multiple keys so we
            # nee to delete it for all of those possible key.
            #
            del self.blacklist[what]
            for x in (deny.peer_addr, deny.email_addr, deny.domain_name):
                if x in self.blacklist:
                    del self.blacklist[x]
            return False

        if deny.num_fails < self.MAX_NUM_BLOCKS:
            return False
        return True

    ####################################################################
    #
    def _incr_fails(self, what: str, check_type: str):
        """
        Increment fails for an entry in the black list.
        Every deny extends the expiry time.
        """
        expiry = datetime.utcnow() + self.FAILURE_EXPIRY

        if what not in self.blacklist:
            match check_type:
                case "peer":
                    deny = DenyInfo(num_fails=1, peer_addr=what, expiry=expiry)
                case "domain_name":
                    deny = DenyInfo(
                        num_fails=1, domain_name=what, expiry=expiry
                    )
                case "email_address":
                    deny = DenyInfo(num_fails=1, email_addr=what, expiry=expiry)

            self.blacklist[what] = deny
        else:
            deny = self.blacklist[what]
            deny.num_fails += 1
            deny.expiry = expiry

    ####################################################################
    #
    async def check_deny_peer(self, peer: str, mail_from: str) -> bool:
        """
        - Check to see if the peer or mail_from are on the internal black list
          and count >= MAX_NUM_BLOCKS.
          - If they are, and it is not yet expired, then increment the failure
            count, and update the expiry time. Return True (deny)
          - If they are, and it has expired, remove it from the black list.
        - Check to see if the peer is on a DNSBL.
          - If it is then add them to the blacklist by peer and mail_from.
            Add the peer and  mail_from to the blacklist (but count is 1)
            Return True (deny)
        - Return False (allow)
        """
        try:
            addr = email.utils.parseaddr(mail_from)[1]
            domain = addr.split("@")[1]
        except Exception:
            logger.exception("Unable to parse email address '%s'", mail_from)
            return True

        if self._check(peer=peer, addr=addr, domain=domain):
            # See if dnsbl recommends we block based on the peer or domain name
            #
            result = await self.ip_checker(peer)
            if result.blacklisted:
                logger.warn(
                    "check_deny: Deny because peer %s is black listed: %s",
                    peer,
                    result.detected_by,
                )
                self._incr_fails(peer=peer, check_type="peer")
                return True
            result = await self.domain_checker()

        now = datetime.utcnow()
        deny = self.blacklist[peer]
        if now > deny.expiry:
            del self.blacklist[peer]
            return False

        if deny.num_fails < self.MAX_NUM_BLOCKS:
            return False
        return True

    def check_deny_mail_from(self, peer, mail_from: str) -> bool:
        """
        - Check and see if the domain of the mail_from are on the internal
          black list and count >= MAX_NUM_BLOCKS
          - If they are, and it is not yet expired, then increment the failure
            count, and update the expiry time. Return True (deny)
          - If they are, and it has expired, remove it from the black list.
        - Check to see if the domain is on a DNSBL
          - If it is then add them to the blacklist by peer and mail_from.
            Add the peer and  mail_from to the blacklist (but count is 1)
            Return True (deny)
        - Return False (allow)
        """
        return False

    def check_deny_content(self, peer, mail_from: str, content: bytes) -> bool:
        return False


########################################################################
########################################################################
#
# XXX Should put this in a common module so that `aiosmtpd` can import it for
#     `AsyncioAuthController`
#
class SentryController(Controller):
    """
    Make sure sentry is configured to run if enabled.
    """

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
class LocalEmailHandler:
    ####################################################################
    #
    def __init__(self) -> None:
        """
        Sets up the deny info dictionary, spam assassin, local spam system,
        and dns bl info.
        """
        logger.debug("RelayHandler, init")
        self.blacklist: Dict[str, DenyInfo] = {}

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
        if self.check_deny(
            session.peer, hostname, envelope.rcpt_tos, envelope.mail_from
        ):
            # If we deny this connection we also sleep for a short bit before
            # returning the error to the client. This makes a mini-tarpit that
            # will hopefully slow down connection attempts a little bit.
            #
            await asyncio.sleep(30)
            responses.append("550 Too many failed attempts")

        # Deny if:
        # - dns bl
        # - sender on internal black list (probably a new model that lets
        #   us just block some senders outright instead of waiting for dnsbl or
        #   spam rules.)
        # - rcpt_tos contains email for domain not supported by this server
        # - rcpt_tos contains email address not supported by this server
        #   XXX will we get rcpt_tos with both valid emails and emails for other
        #       systems?
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
        You can only send email _to_ an email address supported by this server.
        If the email is tagged as spam, add appropriate headers.
        """
        # handle_MAIL is responsible for setting the mail_from and mail_options
        # on the envelope! I am not sure if we should or should not do this
        # when we are going to possibly deny this request.
        #
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)

        # XXX run envelope through spam assassin
        # XXX run envelope through our spam system
        #
        # XXX add rule to discard mail marked as spam.
        #
        # XXX We should record email that we have received for all valid email
        #     addresses for 30 days, and add a way to re-deliver email.  this
        #     way we can set "do not send spam" and check email that has not
        #     been delivered but marked as spam in the web UI so it can be
        #     resent.

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
        assert envelope.original_content
        msg = cast(
            EmailMessage,
            email.message_from_bytes(
                envelope.original_content,
                policy=email.policy.default,
            ),
        )

        # If everything checks out, deliver the message to our local user.
        #
        try:
            for addr in msg.rcpt_tos:
                addr = addr.lower()
                email_account = await EmailAccount.objects.aget(
                    email_address=addr
                )
                fname = write_spooled_email(
                    email_account.email_address,
                    email_account.server.incoming_spool_dir,
                    msg,
                )
                await sync_to_async(dispatch_incoming_email)(
                    email_account.pk, str(fname)
                )

        except Exception as exc:
            # XXX need to return the correct response to indicate a transient
            #     failure.
            #
            logger.error("Failed to deliver message %s: %s", msg, exc)
            return "400 Transient Failure Delivering message. Try again later."
        return "250 OK"


########################################################################
########################################################################
#
class Command(BaseCommand):
    help = (
        "Runs a SMTP demon to receive email for email accounts on this system. "
        "This serves as a receiver for email from the internet at large. "
        "It supports various spam tagging and filtering."
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

        logger.info(
            f"Listening on {listen_port} , cert: '{ssl_cert_file}', "
            f"key: '{ssl_key_file}'"
        )

        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.check_hostname = False
        tls_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        handler = LocalEmailHandler()
        controller = SentryController(
            handler,
            hostname="0.0.0.0",  # This means listens on all interfaces.
            server_hostname=settings.SITE_NAME,
            port=listen_port,
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
