#!/usr/bin/env python
#
"""
Management command to synchronise domain configuration across providers.

Calls create_update_domain() for every server that uses the specified
provider (or all providers).  Any domain whose live settings have drifted
— for example a corrected bounce webhook URL — will be updated via the
provider's API.

Typical use after changing domain settings in code:

    python manage.py sync_provider_domains
    python manage.py sync_provider_domains --dry-run
    python manage.py sync_provider_domains --domain mail.example.com
    python manage.py sync_provider_domains --provider forwardemail --dry-run
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
from as_email.models import Provider, Server
from as_email.providers import get_backend

logger = logging.getLogger("as_email")


########################################################################
########################################################################
#
class Command(BaseCommand):
    """Synchronise domain configuration on one or all providers."""

    help = "Synchronise domain configuration on configured providers"

    ####################################################################
    #
    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--provider",
            type=str,
            metavar="BACKEND",
            help="Only sync domains for this provider backend "
            "(e.g., 'forwardemail')",
        )
        parser.add_argument(
            "--domain",
            type=str,
            metavar="DOMAIN",
            help="Only sync this server domain",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would change without making any updates",
        )

    ####################################################################
    #
    def handle(self, *args: Any, **options: Any) -> None:
        provider_filter: str | None = options.get("provider")
        domain_filter: str | None = options.get("domain")
        dry_run: bool = options["dry_run"]

        servers = Server.objects.prefetch_related(
            "receive_providers"
        ).select_related("send_provider")

        if domain_filter:
            servers = servers.filter(domain_name=domain_filter)
            if not servers.exists():
                raise CommandError(
                    f"No server found with domain '{domain_filter}'"
                )

        if provider_filter:
            if not Provider.objects.filter(
                backend_name=provider_filter
            ).exists():
                raise CommandError(
                    f"No provider found with backend name "
                    f"'{provider_filter}'"
                )

        total_updated = 0
        total_ok = 0
        total_err = 0

        for server in servers:
            # Collect unique providers for this server (send + receive).
            #
            provider_names: set[str] = {
                p.backend_name for p in server.receive_providers.all()
            }
            if server.send_provider:
                provider_names.add(server.send_provider.backend_name)

            if provider_filter:
                provider_names &= {provider_filter}

            for provider_name in sorted(provider_names):
                try:
                    backend = get_backend(provider_name)
                    changed = backend.create_update_domain(
                        server, dry_run=dry_run
                    )
                except Exception as exc:
                    self.stdout.write(
                        self.style.ERROR(
                            f"ERR {server.domain_name} "
                            f"({provider_name}): {exc}"
                        )
                    )
                    logger.exception(
                        "sync_provider_domains: failed for '%s' on " "'%s': %r",
                        server.domain_name,
                        provider_name,
                        exc,
                    )
                    total_err += 1
                    continue

                if changed:
                    label = "WOULD UPDATE" if dry_run else "UPDATED"
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"{label} {server.domain_name} "
                            f"({provider_name})"
                        )
                    )
                    total_updated += 1
                else:
                    self.stdout.write(
                        f"OK {server.domain_name} ({provider_name})"
                    )
                    total_ok += 1

        summary = (
            f"\nDone: {total_updated} "
            f"{'would update' if dry_run else 'updated'}, "
            f"{total_ok} already up to date, "
            f"{total_err} failed."
        )
        if total_err:
            self.stdout.write(self.style.ERROR(summary))
        else:
            self.stdout.write(self.style.SUCCESS(summary))
