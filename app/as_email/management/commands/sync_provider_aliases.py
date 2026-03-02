#!/usr/bin/env python
#
"""
Management command to synchronise email account aliases across providers.

Calls create_update_email_account() for every EmailAccount on each server
that uses the specified provider (or all providers).  Any alias whose live
settings have drifted from DEFAULT_ALIAS_SETTINGS — including the webhook
URL, which is derived from SITE_NAME — will be updated via a PUT request.

Typical use after changing SITE_NAME or any other per-alias setting:

    python manage.py sync_provider_aliases --provider forwardemail
"""
# system imports
#
import logging
from typing import Any

# 3rd party imports
#
from django.core.management.base import BaseCommand, CommandError

# Project imports
#
from as_email.models import EmailAccount, Provider, Server
from as_email.providers import get_backend

logger = logging.getLogger("as_email")


########################################################################
########################################################################
#
class Command(BaseCommand):
    """
    Synchronise email account aliases on one or all providers.

    Usage:
        # Sync all aliases for all providers
        python manage.py sync_provider_aliases

        # Sync aliases only for forwardemail
        python manage.py sync_provider_aliases --provider forwardemail

        # Sync aliases only for a specific server domain
        python manage.py sync_provider_aliases --provider forwardemail --domain mail.example.com
    """

    help = "Synchronise email account aliases on configured providers"

    ####################################################################
    #
    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--provider",
            type=str,
            metavar="BACKEND",
            help="Only sync aliases for this provider backend (e.g., 'forwardemail')",
        )
        parser.add_argument(
            "--domain",
            type=str,
            metavar="DOMAIN",
            help="Only sync aliases for this server domain",
        )

    ####################################################################
    #
    def handle(self, *args: Any, **options: Any) -> None:
        provider_filter = options.get("provider")
        domain_filter = options.get("domain")

        providers = Provider.objects.all()
        if provider_filter:
            providers = providers.filter(backend_name=provider_filter)
            if not providers.exists():
                raise CommandError(
                    f"No provider found with backend name '{provider_filter}'"
                )

        total_ok = 0
        total_err = 0

        for provider in providers:
            try:
                backend = get_backend(provider.backend_name)
            except Exception as exc:
                self.stdout.write(
                    self.style.WARNING(
                        f"Skipping provider '{provider.backend_name}': {exc}"
                    )
                )
                continue

            servers = Server.objects.filter(receive_providers=provider)
            if domain_filter:
                servers = servers.filter(domain_name=domain_filter)

            for server in servers:
                email_accounts = EmailAccount.objects.filter(server=server)
                self.stdout.write(
                    f"Provider '{provider.backend_name}' / "
                    f"domain '{server.domain_name}': "
                    f"{email_accounts.count()} account(s)"
                )

                for ea in email_accounts:
                    try:
                        backend.create_update_email_account(ea)
                        self.stdout.write(
                            self.style.SUCCESS(f"  OK  {ea.email_address}")
                        )
                        total_ok += 1
                    except Exception as exc:
                        self.stdout.write(
                            self.style.ERROR(f"  ERR {ea.email_address}: {exc}")
                        )
                        logger.exception(
                            "sync_provider_aliases: failed to sync '%s': %r",
                            ea.email_address,
                            exc,
                        )
                        total_err += 1

        summary = f"\nDone: {total_ok} synced, {total_err} failed."
        if total_err:
            self.stdout.write(self.style.ERROR(summary))
        else:
            self.stdout.write(self.style.SUCCESS(summary))
