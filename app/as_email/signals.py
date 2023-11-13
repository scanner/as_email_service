"""
Where we define our signal receivers
"""
# system imports
#
import logging
from typing import Type

# 3rd party imports
#
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

# Project imports
#
from .models import EmailAccount, Server

User = get_user_model()
logger = logging.getLogger("as_email.models")


####################################################################
#
@receiver(post_save, sender=Server)
def check_create_maintenance_email_accounts(
    sender: Type[Server], instance: Server, created: bool, **kwargs
):
    """
    - sender: The model class (`Server`)
    - instance: The actual Server instance being saved
    - created: boolean, True if a new record was created

    When we create a `Server` we will automatically create a bunch of
    EmailAccounts that represent various service addresses. The list of these
    addresses comes from the django settings.EMAIL_SERVICE_ACCOUNTS. These
    accounts will be owned by user account named in
    settings.EMAIL_SERVICE_ACCOUNTS_OWNER. If that account does not exist then
    these EmailAccounts will not be created.

    Furthermore all but the first of the EmailAccount's created will set their
    delivery method to `alias` set `alias_for` to be the first of the
    EmailAccount's created.

    NOTE: Since these are administrative accounts they are not normally ones
          that _send_ email, so they will also be set in a deactivated state,
          just to be sure.
    """
    # We only attempt to create these EmailAccounts on the initial save of the
    # Server object.
    #
    # We also skip it if the list of EMAIL_SERVICE_ACCOUNTS is empty or if
    # EMAIL_SERVICE_ACCOUNTS_OWNER is not truthy.
    #
    if (
        not created
        or not settings.EMAIL_SERVICE_ACCOUNTS
        or not settings.EMAIL_SERVICE_ACCOUNTS_OWNER
    ):
        return

    # If EMAIL_SERVICE_ACCOUNTS_OWNER does not exist then the EmailAccounts
    # will not be created.
    #
    server = instance
    try:
        owner = User.objects.get(username=settings.EMAIL_SERVICE_ACCOUNTS_OWNER)
    except User.DoesNotExist:
        logger.warning(
            "Unable to create email service accounts for '%s', user account '%s' does not exist",
            server.domain_name,
            settings.EMAIL_SERVICE_ACCOUNTS_OWNER,
        )
        return

    eas = []
    for addr in settings.EMAIL_SERVICE_ACCOUNTS:
        email_address = f"{addr}@{server.domain_name}"
        ea = EmailAccount(
            owner=owner,
            server=server,
            email_address=email_address,
            deactivated=True,
            deactivated_reason="Administrative account",
        )
        eas.append(ea)

    # Set `alias_for`` all the email accounts to the first one.
    #
    first = eas[0]
    first.save()
    for ea in eas[1:]:
        ea.delivery_method = "AL"
        ea.save()
        ea.alias_for.add(first)
