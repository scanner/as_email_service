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
import ssl
from datetime import datetime
from functools import lru_cache
from pathlib import Path

# 3rd party imports
#
import aiofiles
import dns.resolver
import pytz
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

# Project imports
#
from as_email.models import Account
from django.confg import settings
from django.core.management.base import BaseCommand

DEST_PORT = 587
LISTEN_PORT = 19246
DEFAULT_SPOOL_DIR = "/mnt/spool"


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
            "listen_port",
            metavar="p",
            type=int,
            action="store",
            default=LISTEN_PORT,
        )
        parser.add_argument("ssl_key", action="store", required=True)
        parser.add_argument("ssl_cert", action="store", required=True)
        parser.add_argument(
            "spool_dir", action="store", default=DEFAULT_SPOOL_DIR
        )

    ####################################################################
    #
    def handle(self, *args, **options):
        listen_port = options["listen_port"]
        ssl_cert_file = options["ssl_cert"]
        ssl_key_file = options["ssl_key"]
        spool_dir = Path(options["spool_dir"])

        print(
            f"aiosmtpd: Listening on {listen_port}, cert: "
            f"{ssl_cert_file}, key: {ssl_key_file}"
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(
            amain(
                ssl_cert=ssl_cert_file,
                ssl_key=ssl_key_file,
                spool_dir=spool_dir,
                listen_port=listen_port,
            )
        )
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print("KeyboardInterrupt - Exiting")


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
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled

        username = auth_data.login
        password = auth_data.password
        try:
            account = Account.objects.get(address=username)
        except Account.DoesNotExist:
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
#
@lru_cache(maxsize=256)
def get_mx(domain):
    records = dns.resolver.resolve(domain, "MX")
    if not records:
        return None
    records = sorted(records, key=lambda r: r.preference)
    return str(records[0].exchange)


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
    # XXX according to docs this should be `async def handle_DATA`
    # .. not sure why their example does not follow that convention.
    #
    async def handle_DATA(self, server, session, envelope):
        # The as_email.models.Account object instance is passed in via
        # session.auth_data.
        #
        account = session.auth_data

        try:
            await asyncio.to_thread(account.server.send_email(envelope))
        except Exception as e:
            # If postmark is down we need to write the message to a spool
            # directory and have a huey worker check for these unsent
            # messages and send it for us.
            #
            print(f"Failed with exception {e}")
            fname = datetime.now(pytz.timezone(settings.TIME_ZONE)).strftime(
                "%Y.%m.%d-%H.%M.%S.%f%z"
            )
            spool_file = self.spool_dir / fname
            async with aiofiles.open(spool_file, "wb") as f:
                # XXX need to convert envelope to a binary stream that
                #     can be read back in without losing data.
                await f.write(envelope)

        # mx_rcpt = {}
        # for rcpt in envelope.rcpt_tos:
        #     _, _, domain = rcpt.partition("@")
        #     mx = get_mx(domain)
        #     if mx is None:
        #         continue
        #     mx_rcpt.setdefault(mx, []).append(rcpt)

        # for mx, rcpts in mx_rcpt.items():
        #     with SMTPCLient(mx, 25) as client:
        #         client.sendmail(
        #             from_addr=envelope.mail_from,
        #             to_addrs=rcpts,
        #             msg=envelope.original_content,
        #         )


########################################################################
#
async def amain(
    spool_dir: str,
    ssl_cert: str,
    ssl_key: str,
    listen_port: int = LISTEN_PORT,
):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(ssl_cert, ssl_key)
    handler = RelayHandler(spool_dir=spool_dir)
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
    try:
        cont.start()
    finally:
        cont.stop()
