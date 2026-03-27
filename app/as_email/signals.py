"""
Where we define our signal receivers
"""

# system imports
#
import logging
import random
import string
from pathlib import Path

# 3rd party imports
#
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models.signals import (
    m2m_changed,
    post_delete,
    post_save,
    pre_save,
)
from django.dispatch import receiver
from huey.contrib.djhuey import HUEY

# Project imports
#
from .models import (
    AliasToDelivery,
    EmailAccount,
    LocalDelivery,
    Provider,
    Server,
)
from .tasks import (
    check_update_pwfile_for_emailaccount,
    delete_emailaccount_from_pwfile,
    provider_create_or_update_email_account,
    provider_create_update_server,
    provider_delete_email_account,
    provider_sync_server_email_accounts,
)

User = get_user_model()
logger = logging.getLogger("as_email.models")


####################################################################
#
@receiver(pre_save, sender=EmailAccount)
def email_account_pre_save(
    sender: type[EmailAccount], instance: EmailAccount, **kwargs
) -> None:
    """
    Conduct pre-save EmailAccount actions.
    """
    pass


####################################################################
#
@receiver(post_save, sender=LocalDelivery)
def create_local_delivery_mailbox(
    sender: type[LocalDelivery],
    instance: LocalDelivery,
    created: bool,
    **kwargs,
) -> None:
    """
    When a LocalDelivery is created, ensure the MH mailbox directory
    (and default folders) exist.
    """
    if created:
        instance.MH()


####################################################################
#
@receiver(post_save, sender=EmailAccount)
def fire_off_async_task_update_emailaccount_pwfile(
    sender: type[EmailAccount], instance: EmailAccount, created: bool, **kwargs
):
    """
    Fire off an async task that will compare the email account entry in the
    password file with the email account object. If they are different, it will
    re-write the password file with the update info.
    """
    # If the instance.password field has change, write it to our exported
    # passwords file used by other services (like IMAP). However, if this
    # EmailAccount is being created, and the password field is empty, do not
    # set it.
    #
    if instance.tracker.has_changed("password"):
        # Skip if the password is `XXX` (the default) and the EmailAccount is
        # created.
        #
        if not (created and instance.password == "XXX"):
            # Defer until the transaction commits so the huey worker can
            # see the committed row when it looks up this EmailAccount by pk.
            #
            transaction.on_commit(
                lambda pk=instance.pk: check_update_pwfile_for_emailaccount(  # type: ignore[misc]
                    pk
                )
            )


####################################################################
#
@receiver(post_save, sender=EmailAccount)
def create_or_update_provider_email_accounts(
    sender: type[EmailAccount], instance: EmailAccount, created: bool, **kwargs
):
    """
    When an EmailAccount is created or its enabled state changes, update
    corresponding email accounts on all receive providers configured for the
    account's server.
    """
    if not created and not instance.tracker.has_changed("enabled"):
        return

    # Defer task dispatch until the transaction commits. post_save fires
    # inside the transaction, so the new/updated row is not yet visible to
    # other DB connections (i.e., the huey worker process). on_commit
    # guarantees the row is committed before the task runs.
    #
    server = instance.server
    for provider in server.receive_providers.all():
        transaction.on_commit(
            lambda pk=instance.pk, name=provider.backend_name: (  # type: ignore[misc]
                provider_create_or_update_email_account(pk, name)
            )
        )


####################################################################
#
@receiver(post_delete, sender=EmailAccount)
def fire_off_async_task_delete_emailaccount_pwfile(
    sender: type[EmailAccount], instance: EmailAccount, **kwargs
):
    """
    When an email account is deleted from the system make sure its entry in
    the generated pwfile is also removed.
    """
    # Defer until the delete transaction commits so the pwfile update
    # reflects the final committed state of the database.
    #
    transaction.on_commit(
        lambda addr=instance.email_address: delete_emailaccount_from_pwfile(  # type: ignore[misc]
            addr
        )
    )


####################################################################
#
@receiver(post_delete, sender=EmailAccount)
def delete_provider_email_accounts(
    sender: type[EmailAccount], instance: EmailAccount, **kwargs
):
    """
    When an EmailAccount is deleted, delete corresponding email accounts from
    all receive providers configured for the account's server.
    """
    # Defer until the delete transaction commits so the provider API call
    # reflects the final committed state of the database.
    #
    server = instance.server
    for provider in server.receive_providers.all():
        transaction.on_commit(
            lambda addr=instance.email_address,  # type: ignore[misc]
            domain=server.domain_name,
            name=provider.backend_name: (
                provider_delete_email_account(addr, domain, name)
            )
        )


####################################################################
#
@receiver(post_save, sender=Server)
def check_create_maintenance_email_accounts(
    sender: type[Server], instance: Server, created: bool, **kwargs
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

    # The first account gets a LocalDelivery. All subsequent accounts get an
    # AliasToDelivery pointing to the first.
    #
    first = eas[0]
    first.save()
    local_delivery = LocalDelivery.objects.create(email_account=first)
    local_delivery.MH()
    for ea in eas[1:]:
        ea.save()
        AliasToDelivery.objects.create(email_account=ea, target_account=first)


####################################################################
#
@receiver(pre_save, sender=Server)
def server_pre_save(sender: type[Server], instance: Server, **kwargs):
    """
    Pre-save signal handler for Server that:
    1. Sets initial values for spool directories, mail_dir_parent, and api_key
       if not set on new instances
    2. Creates the directories when the object is being created (new instance)

    This replaces the previous _set_initial_values method and directory creation
    logic from Server.save() and Server.asave().
    """
    # Determine if this is a new instance
    is_new = instance.pk is None

    # Set initial values if not set and this is a new instance
    if is_new:
        if not instance.incoming_spool_dir:
            instance.incoming_spool_dir = str(
                settings.EMAIL_SPOOL_DIR / instance.domain_name / "incoming"
            )
        if not instance.outgoing_spool_dir:
            instance.outgoing_spool_dir = str(
                settings.EMAIL_SPOOL_DIR / instance.domain_name / "outgoing"
            )
        if not instance.mail_dir_parent:
            instance.mail_dir_parent = str(
                settings.MAIL_DIRS / instance.domain_name
            )

        # API Key is created when the object is saved for the first time
        if not instance.api_key:
            instance.api_key = "".join(
                random.choice(string.ascii_letters + string.digits)
                for x in range(40)
            )

    # Create directories if this is a new instance
    if is_new:
        assert instance.incoming_spool_dir is not None
        assert instance.outgoing_spool_dir is not None
        assert instance.mail_dir_parent is not None
        Path(instance.incoming_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(instance.outgoing_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(instance.mail_dir_parent).mkdir(parents=True, exist_ok=True)


@receiver(post_save, sender=Server)
def handle_send_provider_changed(
    sender: type[Server], instance: Server, created: bool, **kwargs
) -> None:
    """
    When a Server's send_provider is set or changed, trigger domain
    registration on the new provider so it can perform any remote
    configuration required to support sending from this domain.

    Clearing send_provider (setting it to None) is intentionally ignored —
    no providers currently need cleanup when removed as send provider.
    We will address that if it becomes necessary to clear something on the
    remote provider.

    Args:
        sender: The model class (`Server`)
        instance: The actual Server instance being saved
        created: boolean, True if a new record was created
    """
    if not instance.tracker.has_changed("send_provider_id"):
        return
    if not instance.send_provider_id:
        return

    # Defer until the transaction commits so the huey worker sees the
    # committed Server row when it looks it up by pk.
    #
    assert instance.send_provider is not None
    transaction.on_commit(
        lambda pk=instance.pk, name=instance.send_provider.backend_name: (  # type: ignore[misc]
            provider_create_update_server(pk, name)
        )
    )


@receiver(m2m_changed, sender=Server.receive_providers.through)
def handle_receive_providers_changed(
    sender, instance: Server, action: str, pk_set, **kwargs
):
    """
    When receive_providers are added or removed from a Server:
    - post_add: Create domain on provider, then sync all email accounts
    - post_remove: Delete all email accounts on the provider for this server

    Args:
        sender: The through model class
        instance: The Server instance
        action: The m2m action ('post_add', 'post_remove', etc.)
        pk_set: Set of primary keys being added/removed
    """
    # Defer task dispatch until the m2m transaction commits so the huey
    # worker sees the committed m2m relationship when it runs.
    #
    match action:
        case "post_add":
            for provider_pk in pk_set:
                provider = Provider.objects.get(pk=provider_pk)

                def _enqueue_add(
                    server_pk=instance.pk, backend=provider.backend_name
                ):
                    pipeline = provider_create_update_server.s(
                        server_pk, backend
                    ).then(
                        provider_sync_server_email_accounts,
                        server_pk,
                        backend,
                        True,
                    )
                    HUEY.enqueue(pipeline)

                transaction.on_commit(_enqueue_add)

        case "post_remove":
            for provider_pk in pk_set:
                provider = Provider.objects.get(pk=provider_pk)
                transaction.on_commit(
                    lambda server_pk=instance.pk,  # type: ignore[misc]
                    backend=provider.backend_name: (
                        provider_sync_server_email_accounts(
                            server_pk, backend, enabled=False
                        )
                    )
                )
