#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views, models,
and tasks so we can import them in all of those other modules without loops and
weirdness.
"""
# system imports
#
import email.generator
import email.policy
import io
import json
import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Tuple, Union

if TYPE_CHECKING:
    from _typeshed import StrPath

logger = logging.getLogger("as_email.utils")

# postmark has various bounce types. Some are permament, some are transient.
# The transient ones do not increase the number of bounces an email account
# has made (they are transient after all).
#
BOUNCE_TYPES_BY_TYPE: Dict[str, Dict[str, int | str | bool]] = {
    "HardBounce": {
        "code": 1,
        "description": "Hard bounce — The server was unable to deliver your message (ex: unknown user, mailbox not found).",
        "transient": False,
    },
    "Transient": {
        "code": 2,
        "description": "Message delayed/Undeliverable — The server could not temporarily deliver your message (ex: Message is delayed due to network troubles).",
        "transient": True,
    },
    "Unsubscribe": {
        "code": 16,
        "description": "Unsubscribe request — Unsubscribe or Remove request.",
        "transient": True,
    },
    "Subscribe": {
        "code": 32,
        "description": "Subscribe request — Subscribe request from someone wanting to get added to the mailing list.",
        "transient": True,
    },
    "AutoResponder": {
        "code": 64,
        "description": 'Auto responder — "Autoresponder" is an automatic email responder including nondescript NDRs and some "out of office" replies.',
        "transient": True,
    },
    "AddressChange": {
        "code": 128,
        "description": "Address change — The recipient has requested an address change.",
        "transient": True,
    },
    "DnsError": {
        "code": 256,
        "description": "DNS error — A temporary DNS error.",
        "transient": True,
    },
    "SpamNotification": {
        "code": 512,
        "description": "Spam notification — The message was delivered, but was either blocked by the user, or classified as spam, bulk mail, or had rejected content.",
        "transient": False,
    },
    "OpenRelayTest": {
        "code": 1024,
        "description": "Open relay test — The NDR is actually a test email message to see if the mail server is an open relay.",
        "transient": True,
    },
    "Unknown": {
        "code": 2048,
        "description": "Unknown — Unable to classify the NDR.",
        "transient": False,
    },
    "SoftBounce/Undeliverable": {
        "code": 4096,
        "description": "Soft bounce/Undeliverable — Unable to temporarily deliver message (i.e. mailbox full, account disabled, exceeds quota, out of disk space).",
        "transient": True,
    },
    "VirusNotification": {
        "code": 8192,
        "description": "Virus notification — The bounce is actually a virus notification warning about a virus/code infected message.",
        "transient": False,
    },
    "ChallengeVerification": {
        "code": 16384,
        "description": "Spam challenge verification — The bounce is a challenge asking for verification you actually sent the email. Typcial challenges are made by Spam Arrest, or MailFrontier Matador.",
        "transient": True,
    },
    "BadEmailAddress": {
        "code": 100000,
        "description": "Invalid email address — The address is not a valid email address.",
        "transient": False,
    },
    "SpamComplaint": {
        "code": 100001,
        "description": "Spam complaint — The subscriber explicitly marked this message as spam.",
        "transient": False,
    },
    "ManuallyDeactivated": {
        "code": 100002,
        "description": "Manually deactivated — The email was manually deactivated.",
        "transient": False,
    },
    "Unconfirmed": {
        "code": 100003,
        "description": "Registration not confirmed — The subscriber has not clicked on the confirmation link upon registration or import.",
        "transient": False,
    },
    "Blocked": {
        "code": 100006,
        "description": "ISP block — Blocked from this ISP due to content or blacklisting.",
        "transient": False,
    },
    "SMTPApiError": {
        "code": 100007,
        "description": "SMTP API error — An error occurred while accepting an email through the SMTP API.",
        "transient": False,
    },
    "InboundError": {
        "code": 100008,
        "description": "Processing failed — Unable to deliver inbound message to destination inbound hook.",
        "transient": True,
    },
    "DMARCPolicy": {
        "code": 100009,
        "description": "DMARC Policy — Email rejected due DMARC Policy.",
        "transient": False,
    },
    "TemplateRenderingFailed": {
        "code": 100010,
        "description": "Template rendering failed — An error occurred while attempting to render your template.",
        "transient": False,
    },
}

BOUNCE_TYPES_BY_TYPE_CODE = {
    v["code"]: {
        "type_code": k,
        "description": v["description"],
        "transient": v["transient"],
    }
    for k, v in BOUNCE_TYPES_BY_TYPE.items()
}


####################################################################
#
def split_email_mailbox_hash(email_address: str) -> Tuple[str, str | None]:
    """
    Split an email address in to the email address and its mailbox
    hash. Mailbox hash is None if there is none.
    """
    addr, domain = email_address.split("@")
    mbox_hash = None
    if "+" in addr:
        addr, mbox_hash = addr.split("+", 1)
    return (f"{addr}@{domain}", mbox_hash)


####################################################################
#
def write_spooled_email(
    recipient: str,
    spool_dir: Union[str | Path],
    msg: Union[str | EmailMessage],
    msg_date=None,
    msg_id=None,
) -> Path:
    """
    Write the given message for the given recipient email address to the
    given spool spool directory. Writes a Path object that is the file the
    spool message and meta information was written to (as json).
    """
    spool_dir = spool_dir if isinstance(spool_dir, Path) else Path(spool_dir)
    msg = (
        msg
        if isinstance(msg, str)
        else msg.as_string(policy=email.policy.default)
    )
    msg_id = msg_id if msg_id is not None else make_msgid(recipient)
    msg_date = (
        msg_date
        if msg_date is not None
        else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    now = datetime.now().isoformat()
    email_file_name = f"{now}-{msg_id}.json"
    fname = Path(spool_dir) / email_file_name

    # To account for other mail providers in the future and to reduce the json
    # dict we write to just what we need to deliver the email we create a new
    # dict that will hold what we write in the incoming spool directory.
    #
    email_json = json.dumps(
        {
            "recipient": recipient,
            "message-id": msg_id,
            "date": msg_date,
            "raw_email": msg,
        }
    )

    # We need to make sure that the file is written before we send our
    # response back to Postmark.. but we should not block other async
    # processing while waiting for the file to be written.
    #
    msg_path = Path(fname)
    msg_path.write_text(email_json)
    return msg_path


##################################################################
##################################################################
#
class PWUser:
    """
    The object for entities stored in our exteranl services pw file. The
    email address, their password hash, and the path to their maildir.
    """

    ##################################################################
    #
    def __init__(self, username: str, maildir: "StrPath", password_hash: str):
        """ """
        self.username = username
        self.maildir = Path(maildir)
        self.pw_hash = password_hash

    ##################################################################
    #
    def __str__(self):
        return self.username


####################################################################
#
def read_emailaccount_pwfile(pwfile: Path) -> Dict[str, PWUser]:
    """
    we support a password file by email account with the password hash and
    maildir for that email account. This is for inteegration with other
    services (such as the asimap service)

    This will read in the entire password and return a dict where the key is
    the email account and the values are the password has and mail directory.
    """
    accounts: Dict[str, PWUser] = {}
    if not pwfile.exists():
        return accounts

    with pwfile.open() as f:
        for line in f:
            line = line.strip()
            if not line or line[0] == "#":
                continue
            try:
                maildir: Union[str | Path]
                account, pw_hash, maildir = [x.strip() for x in line.split(":")]
                maildir = Path(maildir)
                accounts[account] = PWUser(account, maildir, pw_hash)
            except ValueError as exc:
                logger.error(
                    "Unable to unpack password record %s: %s",
                    line,
                    exc,
                )
    return accounts


####################################################################
#
def write_emailaccount_pwfile(pwfile: Path, accounts: Dict[str, PWUser]):
    """
    we support a password file by email account with the password hash and
    maildir for that email account. This is for inteegration with other
    services (such as the asimap service)

    This will write all the entries in the accounts dict in to the indicated
    password file.
    """
    new_pwfile = pwfile.with_suffix(".new")
    with new_pwfile.open("w") as f:
        f.write(f"# File generated by as_email_service at {datetime.now()}\n")
        for email_addr in sorted(
            accounts.keys(), key=lambda x: x.split("@")[1]
        ):
            # Maildir is written as a path relative to the location of the
            # pwfile. This is because we do not know how these files are rooted
            # when other services read them so we them relative to the pwfile.
            #
            account = accounts[email_addr]
            maildir = account.maildir
            f.write(f"{email_addr}:{account.pw_hash}:{maildir}\n")
    new_pwfile.rename(pwfile)


########################################################################
########################################################################
#
class Latin1BytesGenerator(email.generator.BytesGenerator):
    """
    Turns out some of the messages we get can NOT be encoded in to bytes
    via the 'ascii' codec. B-/ So, we replace the method that does the encoding
    and if 'ascii' does not work, it tries 'latin-1'
    """

    ####################################################################
    #
    def write(self, s):
        try:
            msg = s.encode("ascii", "surrogateescape")
        except UnicodeEncodeError:
            msg = s.encode("latin-1", "surrogateescape")
        self._fp.write(msg)

    def _encode(self, s):
        try:
            msg = s.encode("ascii")
        except UnicodeEncodeError:
            msg = s.encode("latin-1")
        return msg


####################################################################
#
def sendmail(
    smtpclient: smtplib.SMTP,
    msg: EmailMessage,
    from_addr: str,
    to_addrs: List[str],
):
    """
    do our own sendmail wrapper because we need to be able to enocde
    messages that have stuff like the `©` in them. We get it, we send it.
    """
    international = False
    mail_options = ()
    rcpt_options = ()
    try:
        "".join([from_addr, *to_addrs]).encode("ascii")
    except UnicodeEncodeError:
        international = True
    with io.BytesIO() as bytesmsg:
        if international:
            g = email.generator.BytesGenerator(
                bytesmsg, policy=msg.policy.clone(utf8=True)
            )
            mail_options = (*mail_options, "SMTPUTF8", "BODY=8BITMIME")
        else:
            g = Latin1BytesGenerator(bytesmsg)
        g.flatten(msg, linesep="\r\n")
        flatmsg = bytesmsg.getvalue()
    return smtpclient.sendmail(
        from_addr, to_addrs, flatmsg, mail_options, rcpt_options
    )
