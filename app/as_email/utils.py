#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views and models
so we can use them in other modules without running the code in app.
"""
# system imports
#
import logging
from hashlib import sha256
from typing import List, Tuple

# Project imports
#
from .model import EmailAccount, Server

logger = logging.getLogger(__name__)


####################################################################
#
def short_hash_email(email: dict) -> str:
    """
    Generate a short hash of the email message. We do not know necessarily
    what parts of the message exist so try `RawEmail`, `HTMLBody`, `TextBody`,
    and `MessageID` in that order.
    """
    # Generate a sha256 for the email message
    if "RawEmail" in email:
        text_to_hash = email["RawEmail"]
    elif "HtmlBody" in email:
        text_to_hash = email["HtmlBody"]
    elif "TextBody" in email:
        text_to_hash = email["TextBody"]
    else:
        text_to_hash = email["MessageID"]

    short_hash = sha256(text_to_hash.encode("utf-8")).hexdigest()[:8]
    return short_hash


####################################################################
#
def get_email_accounts_for_this_server(server: Server, email: dict) -> List:
    """
    Collect all the to, cc, bcc addresses that are for the domain name
    represented by this server.
    """
    # Collect all the to, cc, bcc addresses.
    #
    email_addrs = []
    for addr_type in ("To", "Cc", "Bcc"):
        key = f"{addr_type}Full"
        if key in email:
            email_addrs.extend([x["Email"] for x in email[f"{addr_type}Full"]])

    # Go through all of our addresses and if they are not for this
    # server, remove them from the list of email addrs.
    #
    email_addrs = [
        x for x in email_addrs if x.split("@")[1] == server.domain_name
    ]
    return email_addrs


####################################################################
#
def email_accounts_by_addr(server: Server, email: dict) -> List[Tuple]:
    """
    Go through the email (as a dict) we got from the email provider and
    suss out all the email accounts we need to deliver email to.

    Drop any addresses that are not destined for this server.
    Drop any addresses that have no EmailAccount

    Return a list of tuples, one for each valid email address. Each tuple is
    the pair of (email_address, EmailAccount).
    """
    email_addrs = get_email_accounts_for_this_server(server, email)
    results = []
    # Drop and email addresses that do not correspond to any email accounts.
    #
    email_accounts = EmailAccount.object.filter(email_address__in=email_addrs)
    for email_account in email_accounts:
        results.append(email_account.email_address, email_account)

    # for addr in email_addrs:
    #     # mailbox hashes are not part of the actual email address.
    #     #
    #     if "+" in addr:
    #         addr = addr.split("+")[0] + "@" + addr.split("@")[1]
    #     try:
    #         email_account = EmailAccount.objects.get(addr)
    #         logger.info(
    #             f"(not actually) Dispatching email to {addr}:{email_account}"
    #         )
    #         results.append((addr, email_account))
    #     except EmailAccount.DoesNotExist:
    #         continue

    return results


####################################################################
#
async def aemail_accounts_by_addr(server: Server, email: dict) -> List[Tuple]:
    """
    Async version
    Go through the email (as a dict) we got from the email provider and
    suss out all the email accounts we need to deliver email to.

    Drop any addresses that are not destined for this server.
    Drop any addresses that have no EmailAccount

    Return a list of tuples, one for each valid email address. Each tuple is
    the pair of (email_address, EmailAccount).
    """
    email_addrs = get_email_accounts_for_this_server(server, email)
    results = []

    # XXX Hm.. need to make this work with mailbox hashes.. but not sure anyone
    #     is using those for now.. will fix it later.
    #
    async for email_account in EmailAccount.objects.filter(
        email_address__in=email_addrs
    ):
        results.append(email_account.email_address, email_account)

    return results
