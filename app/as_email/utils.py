#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views, models,
and tasks so we can import them in all of those other modules without loops and
weirdness.
"""
import email.policy

# system imports
#
import json
import logging
from datetime import datetime
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path
from typing import Dict, Tuple

# Project imports
#


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
    spool_dir: [str | Path],
    msg: [str | EmailMessage],
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
