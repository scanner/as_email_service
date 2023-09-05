#!/usr/bin/env python
#
"""
The AsyncIO SMTP Daemon that relays mails to our mail provider.

It gets the mailprovider info from the django configuration.

It authenticates mail accounts from the django as_email.models.Account
object.
"""
import asyncio
import email
import email.policy
import logging
import ssl
import sys

# system imports
#
import time
from datetime import datetime
from typing import Dict, List, Optional

# 3rd party imports
#
# from aiologger import Logger
from aiosmtpd.controller import Controller

# from aiosmtpd.smtp import SMTP as SMTPServer
from aiosmtpd.smtp import AuthResult
from aiosmtpd.smtp import Envelope as SMTPEnvelope
from aiosmtpd.smtp import LoginPassword
from aiosmtpd.smtp import Session as SMTPSession

# Project imports
#
from as_email.models import EmailAccount
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.management.base import BaseCommand
from pydantic import BaseModel

DEST_PORT = 587
LISTEN_PORT = 19246

logger = logging.getLogger("mail.log")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


########################################################################
########################################################################
#
class DenyInfo(BaseModel):
    """
    Info for recording failure attempts by a peer.

    NOTE: A peer is what we get back from `peername` for

    https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseTransport.get_extra_info

    XXX Will flesh it out later but we want a certain number of auth
        failures within a certain amount of time to cause them to be
        denied any further attempts for a certain amount of time.
    """

    num_fails: int
    peer_name: str
    expiry: Optional[datetime]


# XXX Maybe this should be a list with a capped size so if we get
#     connections from millions of hosts we do not consume all memory.
#     an LRU.. or we should use our redis server
#
DENY_PEER_LIST: Dict[str, DenyInfo] = {}


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

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(ssl_cert_file, ssl_key_file)
        handler = RelayHandler(spool_dir=spool_dir)
        print("Handler created.. creating controller")
        controller = Controller(
            handler,
            hostname="0.0.0.0",  # This means listens on all interfaces.
            server_hostname=settings.SITE_NAME,
            port=listen_port,
            authenticator=Authenticator(),
            ssl_context=context,
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

        # try:
        #     loop = asyncio.get_running_loop()
        # except RuntimeError:
        #     loop = asyncio.new_event_loop()
        #     asyncio.set_event_loop(loop)
        # loop.run_until_complete(
        #     amain(
        #         loop,
        #         ssl_cert=ssl_cert_file,
        #         ssl_key=ssl_key_file,
        #         spool_dir=spool_dir,
        #         listen_port=listen_port,
        #     )
        # )
        # loop.run_forever()
        # with asyncio.Runner() as runner:
        #     runner.run(
        #         amain(
        #             ssl_cert=ssl_cert_file,
        #             ssl_key=ssl_key_file,
        #             spool_dir=spool_dir,
        #             listen_port=listen_port,
        #         )
        #     )


########################################################################
########################################################################
#
class Authenticator:
    ####################################################################
    #
    # XXX We should track metrics of number of emails sent, but which
    #     account, how many failures, of which kind.
    #
    def __call__(self, server, session, envelope, mechanism, auth_data):
        """
        NOTE: If the datbase is inaccessible or slow this method will be
        slow. Since our initial implementation uses a local sqlite db and there
        should not be that much contention we expect it to be quick.

        If we were to use some sort of cache, we need to make sure that the
        cache is invalidated whenever an email account is saved/deleted/added
        so that there are no delays in authentication changes.
        """
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled

        username = auth_data.login
        password = auth_data.password
        try:
            account = EmailAccount.objects.get(address=username)
        except EmailAccount.DoesNotExist:
            # XXX We need to keep a count of failures for accounts
            #     that do not exist and if we get above a ceratin amount
            #     of them find a cheap way to block that connection for a
            #     period of time.
            return fail_nothandled

        # If the account is deactivated it is not allowed to relay email.
        #
        if account.deactivated:
            return fail_nothandled

        if not account.check_password(password):
            return fail_nothandled

        # Upon success we pass the account back as the auth_data
        # back. This gets saved in to the session.auth_data attribute
        # and will let the RelayHandler know which account was used so
        # it will know which Server to send the email through.
        #
        return AuthResult(success=True, auth_data=account)


########################################################################
########################################################################
#
class RelayHandler:
    ####################################################################
    #
    def __init__(self, spool_dir: str):
        """
        Sets up the spool_dir where we store messages if we are
        unable to send messages through postmark immediately.
        """
        self.spool_dir = spool_dir

    ####################################################################
    #
    async def handle_EHLO(
        self,
        session: SMTPSession,
        envelope: SMTPEnvelope,
        hostname,
        responses: List[str],
    ) -> List[str]:
        """
        the primary purpose of having a handler for EHLO is to
        quickly deny hosts that have suffered repeated authentication failures
        """
        # NOTE: We have to at least set session.host_name
        #
        session.host_name = hostname

        # XXX here is where our logic for failing a connection because
        #     it hit our black list.
        #
        if session.peer in DENY_PEER_LIST:
            responses.append("550 Too many failed auth attempts")
        return responses

    ####################################################################
    #
    # XXX according to docs this should be `async def handle_DATA`
    # .. not sure why their example does not follow that convention.
    #
    async def handle_DATA(
        self, session: SMTPSession, envelope: SMTPEnvelope
    ) -> str:
        # The as_email.models.EmailAccount object instance is passed in via
        # session.auth_data.
        #
        account = session.auth_data

        try:
            await sync_to_async(send_email_via_smtp(account, envelope))
        except Exception as exc:
            await logger.exception(f"Failed: {exc}")
            return f"500 {str(exc)}"

        return "250 OK"


########################################################################
#
def send_email_via_smtp(account, envelope):
    """
    Use smtplib.SMTP to send the given email. Use the token to authenticate
    to the smtp server.

    This function is synchronous and meant to be called via
    `asyncio.to_thread()`.

    If we fail to send the message due to a network issue the message will be
    written to the spool directory to be sent at a later time.
    """
    msg = email.message_from_bytes(
        envelope.raw_content,
        policy=email.policy.default,
    )
    account.send_email_via_smtp(envelope.rcpt_tos, msg)


########################################################################
#
async def amain(
    loop: asyncio.AbstractEventLoop,
    spool_dir: str,
    ssl_cert: str,
    ssl_key: str,
    listen_port: int = LISTEN_PORT,
):
    print("Async main starting...")
    logger.info(
        f"aiosmtpd: Listening on {listen_port} , cert: '{ssl_cert}', key: "
        f"'{ssl_key}'"
    )
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(ssl_cert, ssl_key)
    handler = RelayHandler(spool_dir=spool_dir)
    print("Handler created.. creating controller")
    cont = Controller(
        handler,
        hostname="",  # This means listens on all interfaces.
        server_hostname=settings.SITE_NAME,
        port=listen_port,
        authenticator=Authenticator(),
        ssl_context=context,
        require_starttls=True,
        auth_required=True,
    )
    print("Starting controller")
    cont.begin()
    try:
        while True:
            # Every 5 minutes, submit metrics
            asyncio.sleep(300)
            # await submit_collected_metrics()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt, exiting")
    finally:
        await cont.finalize()
        await logger.shutdown()
