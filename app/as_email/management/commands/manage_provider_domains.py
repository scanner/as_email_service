#!/usr/bin/env python
#
"""
Management command to list and delete unused domains across email providers.

This command helps identify and clean up domains that have no active email
aliases on configured providers (forwardemail.net, postmark, etc.).
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
    Management command to list and delete unused provider domains.

    Usage:
        # List all unused domains across all providers
        python manage.py manage_provider_domains --list

        # List unused domains for specific provider
        python manage.py manage_provider_domains --list --provider forwardemail

        # Delete a specific domain from a provider
        python manage.py manage_provider_domains --delete example.com --provider forwardemail
    """

    help = "List and delete unused domains on email providers"

    ####################################################################
    #
    def add_arguments(self, parser) -> None:
        """Add command arguments."""
        parser.add_argument(
            "--list",
            action="store_true",
            help="List all unused domains across all providers",
        )
        parser.add_argument(
            "--delete",
            type=str,
            metavar="DOMAIN",
            help="Delete the specified domain from the provider",
        )
        parser.add_argument(
            "--provider",
            type=str,
            help="Filter by specific provider backend name (e.g., 'forwardemail', 'postmark')",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation prompt when deleting domains",
        )

    ####################################################################
    #
    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the management command."""
        if options["list"]:
            self._list_unused_domains(options.get("provider"))
        elif options["delete"]:
            self._delete_domain(
                options["delete"],
                options.get("provider"),
                options.get("force", False),
            )
        else:
            raise CommandError(
                "Please specify either --list or --delete DOMAIN. "
                "Use --help for usage information."
            )

    ####################################################################
    #
    def _list_unused_domains(self, provider_filter: str | None = None) -> None:
        """
        List all unused domains across configured providers.

        Args:
            provider_filter: Optional provider backend name to filter by
        """
        providers = Provider.objects.all()
        if provider_filter:
            providers = providers.filter(backend_name=provider_filter)

        if not providers.exists():
            if provider_filter:
                self.stdout.write(
                    self.style.ERROR(
                        f"No provider found with backend name '{provider_filter}'"
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING("No providers configured in the system")
                )
            return

        all_unused = []
        total_unused = 0

        for provider in providers:
            try:
                get_backend(provider.backend_name)
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(
                        f"Failed to get backend for provider '{provider.backend_name}': {e}"
                    )
                )
                continue

            servers_with_provider = Server.objects.filter(
                receive_providers=provider
            )

            if not servers_with_provider.exists():
                self.stdout.write(
                    self.style.WARNING(
                        f"Provider '{provider.backend_name}' has no configured servers"
                    )
                )
                continue

            unused_domains = []

            for server in servers_with_provider:
                alias_count = EmailAccount.objects.filter(server=server).count()

                if alias_count == 0:
                    unused_domains.append((server.domain_name, 0, 0))
                else:
                    # Check if any aliases are actually enabled
                    try:
                        backend = get_backend(provider.backend_name)()
                        aliases = backend.list_email_accounts(server)
                        enabled_count = sum(
                            1 for alias in aliases if alias.get("is_enabled")
                        )
                        if enabled_count == 0:
                            unused_domains.append(
                                (server.domain_name, alias_count, 0)
                            )
                    except Exception as e:
                        self.stdout.write(
                            self.style.WARNING(
                                f"Failed to check aliases for domain '{server.domain_name}': {e}"
                            )
                        )

            if unused_domains:
                all_unused.append((provider.backend_name, unused_domains))
                total_unused += len(unused_domains)

        # Display results
        if all_unused:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nFound {total_unused} unused domain(s) across {len(all_unused)} provider(s):\n"
                )
            )
            for provider_name, domains in all_unused:
                self.stdout.write(
                    self.style.HTTP_INFO(f"\nProvider '{provider_name}':")
                )
                for domain, total_aliases, enabled_aliases in domains:
                    self.stdout.write(
                        f"  - {domain}: {total_aliases} total alias(es), {enabled_aliases} enabled"
                    )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "\nNo unused domains found across all providers."
                )
            )

    ####################################################################
    #
    def _delete_domain(
        self, domain_name: str, provider_name: str | None, force: bool
    ) -> None:
        """
        Delete a domain from a provider.

        Args:
            domain_name: The domain name to delete
            provider_name: The provider backend name (required for delete)
            force: Skip confirmation prompt
        """
        if not provider_name:
            raise CommandError(
                "The --provider option is required when using --delete"
            )

        # Verify provider exists
        try:
            provider = Provider.objects.get(backend_name=provider_name)
        except Provider.DoesNotExist:
            raise CommandError(
                f"Provider '{provider_name}' not found in the system"
            )

        # Verify server exists
        try:
            server = Server.objects.get(domain_name=domain_name)
        except Server.DoesNotExist:
            raise CommandError(
                f"Server with domain '{domain_name}' not found in the system"
            )

        # Verify provider is configured for this server
        if provider not in server.receive_providers.all():
            raise CommandError(
                f"Provider '{provider_name}' is not configured as a receive provider for domain '{domain_name}'"
            )

        # Get backend
        try:
            backend = get_backend(provider_name)()
        except Exception as e:
            raise CommandError(
                f"Failed to get backend for provider '{provider_name}': {e}"
            )

        # Check current state
        alias_count = EmailAccount.objects.filter(server=server).count()

        try:
            aliases = backend.list_email_accounts(server)
            enabled_count = sum(
                1 for alias in aliases if alias.get("is_enabled")
            )
        except Exception as e:
            raise CommandError(
                f"Failed to check aliases for domain '{domain_name}': {e}"
            )

        # Show current state
        self.stdout.write(
            f"\nDomain: {domain_name}\n"
            f"Provider: {provider_name}\n"
            f"Total aliases: {alias_count}\n"
            f"Enabled aliases: {enabled_count}\n"
        )

        if enabled_count > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"\nWARNING: Domain '{domain_name}' has {enabled_count} enabled alias(es)."
                )
            )

        # Confirm deletion
        if not force:
            confirm = input(
                f"\nAre you sure you want to delete domain '{domain_name}' from provider '{provider_name}'? [y/N]: "
            )
            if confirm.lower() not in ("y", "yes"):
                self.stdout.write(self.style.WARNING("Deletion cancelled."))
                return

        # Attempt to delete the domain
        try:
            backend.delete_domain(server)
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nSuccessfully deleted domain '{domain_name}' from provider '{provider_name}'"
                )
            )
            logger.info(
                "Deleted domain '%s' from provider '%s'",
                domain_name,
                provider_name,
            )
        except NotImplementedError:
            self.stdout.write(
                self.style.WARNING(
                    f"\nDomain deletion is not yet implemented for provider '{provider_name}'."
                )
            )
            self.stdout.write(
                "\nTo delete this domain, you must:\n"
                f"1. Manually delete the domain via the {provider_name} web interface\n"
                f"2. Remove the provider from the server's receive_providers in Django admin\n"
                f"3. Or delete the Server object if no longer needed\n"
            )
        except Exception as e:
            raise CommandError(
                f"Failed to delete domain '{domain_name}' from provider '{provider_name}': {e}"
            )
