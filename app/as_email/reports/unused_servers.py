#!/usr/bin/env python
#
"""
Report servers on all providers that have no active email accounts.

This only looks at providers that can receive email that are assigned to at
least one server.

NOTE: This only bothers with backend providers that have support for
      individual email accounts per server (ie: on the provider we can
      specify specific email addresses that are active and can receive
      email. `forwardemail`, for instance, lets us specify which email
      addresses on your domain can accept email. All others are
      refused. However `postmark` has no way to say which email accounts
      will accept email: They all will.

XXX: Review whether this report is still useful. Since every Server
     automatically gets a set of administrative EmailAccounts on creation
     (see check_create_maintenance_email_accounts signal), it is rare in
     practice for a server to have zero email accounts.
"""

# system imports
#
import logging

# Project imports
#
from as_email.models import Provider
from as_email.providers import get_backend

logger = logging.getLogger(__name__)


########################################################################
#
def generate_unused_servers_report() -> str:
    """
    Generate a report of servers with no active email accounts across
    all providers.

    Returns:
        The complete report as a single string, or an empty string if
        there are no unused servers.
    """
    all_unused = []

    for provider in Provider.objects.all():
        unused_servers = []
        for server in provider.receiving_servers.all():
            email_account_count = server.email_accounts.count()
            if email_account_count == 0:
                unused_servers.append((server.domain_name, 0))
            else:
                # Even if there are EmailAccounts, check if any are
                # actually enabled
                #
                try:
                    backend = get_backend(provider.backend_name)
                    remote_email_accounts = backend.list_email_accounts(server)
                    enabled_count = sum(
                        1 for ea in remote_email_accounts if ea.enabled
                    )
                    if enabled_count == 0:
                        unused_servers.append(
                            (server.domain_name, email_account_count)
                        )
                except Exception as e:
                    logger.warning(
                        "Failed to check email accounts for server "
                        "'%s' on provider '%s': %r",
                        server.domain_name,
                        provider.backend_name,
                        e,
                    )

        if unused_servers:
            all_unused.append((provider.backend_name, unused_servers))

    if not all_unused:
        return ""

    report_lines = ["Provider unused servers report:", ""]
    for provider_name, servers in all_unused:
        report_lines.append(f"Provider '{provider_name}':")
        for domain_name, count in servers:
            report_lines.append(f"  - {domain_name}: {count} email account(s)")
        report_lines.append("")

    return "\n".join(report_lines)
