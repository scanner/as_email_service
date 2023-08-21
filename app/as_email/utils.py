#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views and models
so we can use them in other modules without running the code in app.
"""
# system imports
#
import logging
from typing import Tuple

# Project imports
#

logger = logging.getLogger(__name__)


####################################################################
#
def split_email_mailbox_hash(email_address: str) -> Tuple[str]:
    """
    Split an email address in to the email address and its mailbox
    hash. Mailbox hash is None if there is none.
    """
    addr, domain = email_address.split("@")
    mbox_hash = None
    if "+" in addr:
        addr, mbox_hash = addr.split("+")
    return (f"{addr}@{domain}", mbox_hash)
