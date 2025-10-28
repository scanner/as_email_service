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
from django.db.models.signals import m2m_changed, post_delete, post_save
from django.dispatch import receiver
from huey.contrib.djhuey import HUEY

# Project imports
#
from .models import EmailAccount, Provider, Server
from .tasks import (
    check_update_pwfile_for_emailaccount,
    delete_emailaccount_from_pwfile,
    provider_create_alias,
    provider_create_domain,
    provider_delete_alias,
    provider_enable_all_aliases,
)

User = get_user_model()
logger = logging.getLogger("as_email.models")


####################################################################
#
@receiver(post_save, sender=EmailAccount)
def fire_off_async_task_update_emailaccount_pwfile(
    sender: Type[EmailAccount], instance: EmailAccount, created: bool, **kwargs
):
    """
    Fire off an async task that will compare the email account entry in the
    password file with the email account object. If they are different, it will
    re-write the password file with the update info.
    """
    check_update_pwfile_for_emailaccount(instance.pk)


####################################################################
#
@receiver(post_save, sender=EmailAccount)
def create_provider_aliases(
    sender: Type[EmailAccount], instance: EmailAccount, created: bool, **kwargs
):
    """
    When an EmailAccount is created, create corresponding aliases on all
    receive providers configured for the account's server.
    """
    if not created:
        return

    server = instance.server
    for provider in server.receive_providers.all():
        provider_create_alias(instance.pk, provider.backend_name)


####################################################################
#
@receiver(post_delete, sender=EmailAccount)
def fire_off_async_task_delete_emailaccount_pwfile(
    sender: Type[EmailAccount], instance: EmailAccount, **kwargs
):
    """
    When an email account is deleted from the system make sure its entry in
    the generated pwfile is also removed.
    """
    delete_emailaccount_from_pwfile(instance.email_address)


####################################################################
#
@receiver(post_delete, sender=EmailAccount)
def delete_provider_aliases(
    sender: Type[EmailAccount], instance: EmailAccount, **kwargs
):
    """
    When an EmailAccount is deleted, delete corresponding aliases from all
    receive providers configured for the account's server.
    """
    server = instance.server
    for provider in server.receive_providers.all():
        provider_delete_alias(
            instance.email_address, server.domain_name, provider.backend_name
        )


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


####################################################################
#
@receiver(m2m_changed, sender=Server.receive_providers.through)
def handle_receive_providers_changed(
    sender, instance: Server, action: str, pk_set, **kwargs
):
    """
    When receive_providers are added or removed from a Server:
    - post_add: Create domain on provider, then enable all aliases
    - post_remove: Disable all aliases (but don't delete domain)

    Args:
        sender: The through model class
        instance: The Server instance
        action: The m2m action ('post_add', 'post_remove', etc.)
        pk_set: Set of primary keys being added/removed
    """
    if action == "post_add":
        # Provider(s) added to server - create domain then enable aliases
        for provider_pk in pk_set:
            provider = Provider.objects.get(pk=provider_pk)
            # Chain tasks: create domain first, then enable aliases
            pipeline = provider_create_domain.s(
                instance.pk, provider.backend_name
            ).then(
                provider_enable_all_aliases,
                instance.pk,
                provider.backend_name,
                True,
            )
            HUEY.enqueue(pipeline)

    elif action == "post_remove":
        # Provider(s) removed from server - disable aliases
        for provider_pk in pk_set:
            provider = Provider.objects.get(pk=provider_pk)
            # Disable all aliases for this server on the provider
            provider_enable_all_aliases(
                instance.pk, provider.backend_name, is_enabled=False
            )
