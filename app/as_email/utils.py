#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views and models
so we can use them in other modules without running the code in app.
"""
# system imports
#
import logging
from email._header_value_parser import get_mailbox
from email.errors import HeaderParseError
from typing import Optional, Tuple

# Project imports
#

logger = logging.getLogger(__name__)


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
def spooled_email(recipient, msg_id, date, raw_email):
    """
    Incoming email is written to a spool directory as json files. It has a
    specific format and this function returns a dict in that format.

    This is encapsulated in this function so that our tests and our incoming
    email hook use the same method for generating this dict.
    """
    return {
        "recipient": recipient,
        "message-id": msg_id,
        "date": date,
        "raw_email": raw_email,
    }


####################################################################
#
#
def parse_email_addr(arg: str) -> Optional[str]:
    """
    Try to parse address given in SMTP command. This will be a "mailbox"
    formatted address. All we care about is the addr spec parse of this address
    ie: the `local` @ `domain` part.
    """
    if not arg:
        return ""
    try:
        address, rest = get_mailbox(arg)
    except HeaderParseError:
        return None, None
    return address.addr_spec.lower()
