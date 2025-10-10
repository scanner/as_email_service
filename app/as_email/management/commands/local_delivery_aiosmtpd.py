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
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, cast

# 3rd party imports
#
import aiospamc
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
from as_email.utils import split_email_mailbox_hash, write_spooled_email

LISTEN_PORT = 19247

logger = logging.getLogger("as_email.local_delivery_aiosmtpd")


########################################################################
########################################################################
#
class SpamAassassinService:

    ####################################################################
    #
    def __init__(self, host: str = "localhost", port: int = 783):
        self.svc_host = host
        self.svc_port = port

    ####################################################################
    #
    async def check(self, msg: bytes) -> Dict[str, Any]:
        """
        Passes the given message and return the headers from spam assassin
        """
        r = await aiospamc.check(msg, host=self.svc_host, port=self.svc_port)
        return r.headers


########################################################################
########################################################################
#
class BlackWhiteListInfo(BaseModel):
    """
    Info for recording failure attempts by a peer, domain or email address.

    Also used to record white listed entries (so we are not hitting the DNS BL
    service as often.)

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

    num_fails: int = 0
    addr: Optional[str] = None
    domain_name: Optional[str] = None
    expiry: Optional[datetime] = None
    reason: Optional[str] = None


########################################################################
########################################################################
#
class BlackListService:
    """
    A class that is used to handle dns and ip black list checking as well
    as repeated attempts from the same ip address.

    Once a domain name or ip address is listed as being black listed or white
    listed we cache that information for a short bit to reduce the number of
    times we

    It will track addresses and source ip's for frequent abuses and provide a
    check to deny them sooner if they are a repeater offender.
    """

    # How long before an entry expires and we check directly with pydnsbl
    #
    ENTRY_EXPIRY = timedelta(hours=1)

    # How often is a given IP address marked as doing bad things. Once it
    # exceeds this number that IP address will be added to the black list
    #
    MAX_BAD_ATTEMPTS = 5

    ####################################################################
    #
    def __init__(self, white_listed_ips: Optional[List[str]] = None) -> None:
        if white_listed_ips is None:
            white_listed_ips = []
        self.blacklist: Dict[str, BlackWhiteListInfo] = {}
        self.whitelist: Dict[str, BlackWhiteListInfo] = {}

        # The badness list holds entries by ip address that are getting dinged
        # for some other reason (usually attempting to relay email) and that
        # when they get dinged enough, they get removed from the badness list
        # and added to the blacklist. This is where the `num_fails` attribute
        # on the BlackWhiteListInfo is used.
        #
        self.badnesslist: Dict[str, BlackWhiteListInfo] = {}

        self.ip_checker: Optional[pydnsbl.DNSBLIpChecker] = None
        self.domain_checker: Optional[pydnsbl.DNSBLDomainChecker] = None

        # If we have a set of pre-emptively white listed IP addresses add them
        # to our white list without any expiry time.
        #
        for ip_addr in white_listed_ips:
            self.whitelist[ip_addr] = BlackWhiteListInfo(addr=ip_addr)

    ####################################################################
    #
    async def check_deny(self, ip_addr: str, hostname: str) -> bool:
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
        # We create and set the ip checker and domain checker in this function
        # because they require an active asyncio loop to instantiate.
        #
        if self.ip_checker is None:
            self.ip_checker = pydnsbl.DNSBLIpChecker()
        if self.domain_checker is None:
            self.domain_checker = pydnsbl.DNSBLDomainChecker()

        now = datetime.now(UTC)

        # Check tos ee if the entry is in either whitelist.  If it is in the
        # blacklist, but the expiry for that entry has passed, delete it from
        # the black list and move on. Entries with an expiry of None never
        # expire
        #
        if ip_addr in self.whitelist:
            entry = self.whitelist[ip_addr]
            if entry.expiry is None or entry.expiry > now:
                return False
            del self.whitelist[ip_addr]

        if hostname in self.whitelist:
            entry = self.whitelist[hostname]
            if entry.expiry is None or entry.expiry > now:
                return False
            del self.whitelist[hostname]

        # Check to see if the entry is in either blacklist. If it is in the
        # blacklist, but the expiry for that entry has passed, delete it from
        # the black list and move on. Entries with an expiry of None never
        # expire
        #
        if ip_addr in self.blacklist:
            entry = self.blacklist[ip_addr]
            if entry.expiry is None or entry.expiry > now:
                logger.info("Denied: '%s'", entry.reason)
                return True
            del self.blacklist[ip_addr]

        if hostname in self.blacklist:
            entry = self.blacklist[hostname]
            if entry.expiry is None or entry.expiry > now:
                logger.info("Denied: '%s'", entry.reason)
                return True
            del self.blacklist[hostname]

        # Actually query the blacklist system, and cache the result.
        #
        entry = BlackWhiteListInfo(addr=ip_addr, expiry=now + self.ENTRY_EXPIRY)
        result = await self.ip_checker.check_async(ip_addr)
        if result.blacklisted:
            entry.reason = str(result)
            self.blacklist[ip_addr] = entry
            return True
        else:
            self.whitelist[ip_addr] = entry

        entry = BlackWhiteListInfo(
            domain_name=hostname, expiry=now + self.ENTRY_EXPIRY
        )
        result = await self.domain_checker.check_async(hostname)
        if result.blacklisted:
            entry.reason = str(result)
            self.blacklist[hostname] = entry
            logger.info("Denied: '%s'", entry.reason)
            return True
        else:
            self.whitelist[hostname] = entry

        return False

    ####################################################################
    #
    def incr_badness(self, ip_addr: str) -> None:
        """
        Keyword Arguments:
        ip_addr: str --
        """
        # If the entry is already on the blacklist then return.
        #
        if ip_addr in self.blacklist:
            return

        now = datetime.now(UTC)

        # If they are already in the badness list then increment the number of
        # failures.
        #
        if ip_addr in self.badnesslist:
            entry = self.badnesslist[ip_addr]
            if entry.expiry is None or entry.expiry > now:
                entry.num_fails += 1

                # If the number of failures exceeds the acceptable amount,
                # remove the entry from the badness list, and create a new
                # entry in the black list.
                #
                if entry.num_fails > self.MAX_BAD_ATTEMPTS:
                    del self.badnesslist[ip_addr]
                    entry.expiry = now + self.ENTRY_EXPIRY
                    entry.reason = "Too much badness"
                    self.blacklist[ip_addr] = entry
                    logger.info(
                        "IP Address %s black listed: %s", ip_addr, entry.reason
                    )
                    return
            # Otherwise this entry has expired...
            #
            del self.badnesslist[ip_addr]

        # And create a new entry with a new expiry.
        #
        entry = BlackWhiteListInfo(
            addr=ip_addr, expiry=now + self.ENTRY_EXPIRY, num_fails=1
        )
        self.badnesslist[ip_addr] = entry


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
    def __init__(
        self,
        blacklist_service: BlackListService,
        spama_service: SpamAassassinService,
    ) -> None:
        """
        Sets up the deny info dictionary, spam assassin, local spam system,
        and dns bl info.
        """
        logger.debug("RelayHandler, init")
        self.blacklist = blacklist_service
        self.spama = spama_service

    ####################################################################
    #
    async def check_deny(
        self, session_peer, hostname, rcpt_tos, mail_from
    ) -> bool:
        """
        Check to see if we are denying this email for any number of reasons.
        Returns `True` for deny, and False otherwise.
        """
        return await self.blacklist.check_deny(session_peer[0], hostname)

    ####################################################################
    #
    def incr_badness(self, session):
        """
        Keyword Arguments:
        session --
        """
        self.blacklist.incr_badness(session.peer[0])

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
        quickly deny hosts that are black listed.
        """
        logger.debug(
            "handle_EHLO: smtp: %r, session: %r, envelope: %r, hostname: %s, "
            "responses: %r",
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
            responses.append("550 Denied")

        return responses

    ####################################################################
    #
    async def handle_RCPT(
        self, server, session, envelope, address, rcpt_options
    ):
        """
        Determine if we will accept email to address `address`. We only
        accept delivery for email destined

        Keyword Arguments:
        server       --
        session      --
        envelope     --
        address      --
        rcpt_options --
        """
        addr, _ = split_email_mailbox_hash(address)
        if await EmailAccount.objects.aexists(email_address=addr):
            envelope.rcpt_tos.append(address)
            return "250 OK"

        # if they are trying to send to an email address we do not support then
        # increment their badness level. When it gets to high they will start
        # getting denies during EHLO.
        #
        self.incr_badness(session)

        # And we sleep a bit whenever someone tries to send to a non-existent
        # address to give them a little bit of a tar pit.
        #
        await asyncio.sleep(5)
        return "550 not relaying"

    ####################################################################
    #
    async def handle_DATA(
        self, server: SMTP, session: SMTPSession, envelope: SMTPEnvelope
    ) -> str:

        # Get the spam assassin headers for this message
        #
        assert envelope.original_content
        spama_headers = await self.spama.check(envelope.original_content)

        msg = cast(
            EmailMessage,
            email.message_from_bytes(
                envelope.original_content,
                policy=email.policy.default,
            ),
        )

        # Add the spam assassin headers to our message
        #
        for hdr, value in spama_headers.items():
            msg[hdr] = value

        # If everything checks out, deliver the message to our local user.
        #
        try:
            for addr in envelope.rcpt_tos:
                addr, mhash = split_email_mailbox_hash(addr)
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
        "This serves as a receiver for email from the internet at large. It "
        "will only accept email for accounts in the system."
        "It supports various spam tagging and filtering."
    )

    ####################################################################
    #
    def add_arguments(self, parser):
        parser.add_argument(
            "--server_hostname",
            type=str,
            action="store",
            default=settings.SITE_NAME,
        )
        parser.add_argument(
            "--listen_host",
            type=str,
            action="store",
            default="0.0.0.0",
        )
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
        server_hostname = options["server_hostname"]
        listen_host = options["listen_host"]
        listen_port = options["listen_port"]
        ssl_cert_file = options["ssl_cert"]
        ssl_key_file = options["ssl_key"]

        logger.info(
            f"Listening on {listen_port} , cert: '{ssl_cert_file}', "
            f"key: '{ssl_key_file}'"
        )

        # If `listen_host` contains commas we are going to assume it is a set of
        # ip addressses separated by commas.
        #
        if "," in listen_host:
            listen_host = [x.strip() for x in listen_host.split(",")]

        # TODO: Add support for passing in white listed ip addrs
        #       Either some model in the db, or something passed in via the env
        #
        bl_service = BlackListService()
        spama_service = SpamAassassinService(host="spamassassin")
        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.check_hostname = False
        tls_context.load_cert_chain(ssl_cert_file, ssl_key_file)
        handler = LocalEmailHandler(
            blacklist_service=bl_service, spama_service=spama_service
        )
        controller = SentryController(
            handler,
            hostname=listen_host,
            server_hostname=server_hostname,
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
