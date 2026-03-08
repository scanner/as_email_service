#!/usr/bin/env python
#
"""
Tests for the manage_provider_domains management command.
"""
# system imports
#
from io import StringIO
from typing import Callable

# 3rd party imports
#
import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from pytest_mock import MockerFixture

# Project imports
#
from as_email.models import EmailAccount, Provider, Server
from as_email.tests.factories import DummyProviderBackend

pytestmark = pytest.mark.django_db


########################################################################
#
def test_command_without_options() -> None:
    """
    Given no command options
    When the command is called
    Then it should raise CommandError
    """
    with pytest.raises(CommandError) as exc_info:
        call_command("manage_provider_domains")

    assert "Please specify either --list or --delete" in str(exc_info.value)


########################################################################
#
def test_list_with_no_providers() -> None:
    """
    Given no providers are configured
    When listing domains
    Then it should display a warning message
    """
    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    assert "No providers configured in the system" in out.getvalue()


########################################################################
#
def test_list_with_nonexistent_provider_filter(
    provider_factory: Callable[..., Provider],
) -> None:
    """
    Given a provider exists but user filters by a different provider
    When listing domains
    Then it should display an error message
    """
    provider_factory(backend_name="dummy")

    out = StringIO()
    call_command(
        "manage_provider_domains",
        "--list",
        "--provider",
        "nonexistent",
        stdout=out,
    )

    assert "No provider found with backend name 'nonexistent'" in out.getvalue()


########################################################################
#
def test_list_with_invalid_backend(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
) -> None:
    """
    Given a provider with an invalid backend name
    When listing domains
    Then it should display a warning and skip that provider
    """
    provider = provider_factory(backend_name="invalid_backend")
    server_factory(receive_providers=[provider])

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    assert (
        "Failed to get backend for provider 'invalid_backend'" in out.getvalue()
    )


########################################################################
#
def test_list_provider_with_no_servers(
    provider_factory: Callable[..., Provider],
) -> None:
    """
    Given a provider exists but has no servers configured
    When listing domains
    Then it should display a warning message
    """
    provider_factory(backend_name="dummy")

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    assert "Provider 'dummy' has no configured servers" in out.getvalue()


########################################################################
#
def test_list_unused_domain_with_no_aliases(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
) -> None:
    """
    Given a server with no email aliases
    When listing unused domains
    Then it should show the domain as unused
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(receive_providers=[provider])

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    output = out.getvalue()
    assert "Found 1 unused domain(s)" in output
    assert server.domain_name in output
    assert "0 total alias(es), 0 enabled" in output


########################################################################
#
def test_list_unused_domain_with_only_disabled_aliases(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
    dummy_provider: DummyProviderBackend,
) -> None:
    """
    Given a server with aliases but all disabled
    When listing unused domains
    Then it should show the domain as unused
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(receive_providers=[provider])

    # Create email account (automatically created on provider via signal)
    email_account = email_account_factory(server=server)
    # Disable it on the provider directly (enable_email_account was removed)
    dummy_provider.email_accounts[email_account.email_address][
        "enabled"
    ] = False

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    output = out.getvalue()
    assert "Found 1 unused domain(s)" in output
    assert server.domain_name in output
    assert "1 total alias(es), 0 enabled" in output


########################################################################
#
def test_list_used_domain_with_enabled_aliases(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
) -> None:
    """
    Given a server with enabled aliases
    When listing unused domains
    Then it should not show the domain as unused
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(receive_providers=[provider])

    # Create email account (enabled by default, automatically created on provider via signal)
    email_account_factory(server=server)

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    output = out.getvalue()
    assert "No unused domains found" in output


########################################################################
#
def test_list_with_provider_filter(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
) -> None:
    """
    Given multiple providers exist
    When listing with a provider filter
    Then it should only show domains for that provider
    """
    provider1 = provider_factory(backend_name="dummy", name="Provider 1")
    provider2 = provider_factory(backend_name="dummy", name="Provider 2")

    server_factory(receive_providers=[provider1])
    server_factory(receive_providers=[provider2])

    out = StringIO()
    call_command(
        "manage_provider_domains", "--list", "--provider", "dummy", stdout=out
    )

    output = out.getvalue()
    # Both servers use the same backend_name, so both should appear
    assert "Found 2 unused domain(s)" in output


########################################################################
#
def test_list_with_backend_list_email_accounts_failure(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a server with aliases but backend fails to list them
    When listing unused domains
    Then it should display a warning and skip that domain
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(receive_providers=[provider])
    email_account_factory(server=server)

    # Make list_email_accounts raise an exception
    mocker.patch.object(
        dummy_provider,
        "list_email_accounts",
        side_effect=Exception("API error"),
    )

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    output = out.getvalue()
    assert "Failed to check aliases for domain" in output
    assert "API error" in output


########################################################################
#
def test_delete_without_provider() -> None:
    """
    Given a domain to delete but no provider specified
    When deleting a domain
    Then it should raise CommandError
    """
    with pytest.raises(CommandError) as exc_info:
        call_command("manage_provider_domains", "--delete", "example.com")

    assert "The --provider option is required when using --delete" in str(
        exc_info.value
    )


########################################################################
#
def test_delete_with_nonexistent_provider() -> None:
    """
    Given a provider that doesn't exist
    When deleting a domain
    Then it should raise CommandError
    """
    with pytest.raises(CommandError) as exc_info:
        call_command(
            "manage_provider_domains",
            "--delete",
            "example.com",
            "--provider",
            "nonexistent",
        )

    assert "Provider 'nonexistent' not found in the system" in str(
        exc_info.value
    )


########################################################################
#
def test_delete_with_nonexistent_server(
    provider_factory: Callable[..., Provider],
) -> None:
    """
    Given a provider exists but the server doesn't
    When deleting a domain
    Then it should raise CommandError
    """
    provider_factory(backend_name="dummy")

    with pytest.raises(CommandError) as exc_info:
        call_command(
            "manage_provider_domains",
            "--delete",
            "nonexistent.com",
            "--provider",
            "dummy",
        )

    assert "Server with domain 'nonexistent.com' not found" in str(
        exc_info.value
    )


########################################################################
#
def test_delete_with_provider_not_configured_for_server(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
) -> None:
    """
    Given a server exists but the provider is not configured for it
    When deleting a domain
    Then it should raise CommandError
    """
    provider1 = provider_factory(backend_name="dummy", name="Provider 1")
    # Use "postmark" for provider2 to avoid "multiple providers with same backend_name" issue
    provider2 = provider_factory(backend_name="postmark", name="Provider 2")
    server = server_factory(
        send_provider=provider1, receive_providers=[provider1]
    )

    with pytest.raises(CommandError) as exc_info:
        call_command(
            "manage_provider_domains",
            "--delete",
            server.domain_name,
            "--provider",
            provider2.backend_name,
        )

    assert (
        f"Provider '{provider2.backend_name}' is not configured as a receive provider"
        in str(exc_info.value)
    )


########################################################################
#
def test_delete_with_backend_list_failure(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a valid domain and provider but backend fails to list aliases
    When deleting a domain
    Then it should raise CommandError
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    mocker.patch.object(
        dummy_provider,
        "list_email_accounts",
        side_effect=Exception("API error"),
    )

    with pytest.raises(CommandError) as exc_info:
        call_command(
            "manage_provider_domains",
            "--delete",
            server.domain_name,
            "--provider",
            "dummy",
            "--force",
        )

    assert "Failed to check aliases for domain" in str(exc_info.value)
    assert "API error" in str(exc_info.value)


########################################################################
#
def test_delete_domain_with_force_success(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Given a valid domain and provider with no aliases
    When deleting with --force flag
    Then it should delete without prompting
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    out = StringIO()
    call_command(
        "manage_provider_domains",
        "--delete",
        server.domain_name,
        "--provider",
        "dummy",
        "--force",
        stdout=out,
    )

    output = out.getvalue()
    assert "Total aliases: 0" in output
    assert "Enabled aliases: 0" in output
    assert f"Successfully deleted domain '{server.domain_name}'" in output

    # Verify logging
    assert f"Deleted domain '{server.domain_name}'" in caplog.text

    # Verify domain was removed from backend
    assert server.domain_name not in dummy_provider.domains


########################################################################
#
def test_delete_domain_with_enabled_aliases_shows_warning(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
) -> None:
    """
    Given a domain with enabled aliases
    When deleting with --force flag
    Then it should show a warning about enabled aliases
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    # Create enabled email account (automatically created on provider via signal)
    email_account_factory(server=server)

    out = StringIO()
    call_command(
        "manage_provider_domains",
        "--delete",
        server.domain_name,
        "--provider",
        "dummy",
        "--force",
        stdout=out,
    )

    output = out.getvalue()
    assert "Enabled aliases: 1" in output
    assert (
        f"WARNING: Domain '{server.domain_name}' has 1 enabled alias(es)"
        in output
    )


########################################################################
#
def test_delete_domain_without_force_prompts_confirmation(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a valid domain and provider
    When deleting without --force flag
    Then it should prompt for confirmation
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    out = StringIO()

    # Simulate user typing 'y'
    mocker.patch("builtins.input", return_value="y")

    call_command(
        "manage_provider_domains",
        "--delete",
        server.domain_name,
        "--provider",
        "dummy",
        stdout=out,
    )

    output = out.getvalue()
    assert f"Successfully deleted domain '{server.domain_name}'" in output


########################################################################
#
def test_delete_domain_cancel_confirmation(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a valid domain and provider
    When user cancels the deletion prompt
    Then it should not delete the domain
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    out = StringIO()

    # Simulate user typing 'n'
    mocker.patch("builtins.input", return_value="n")

    call_command(
        "manage_provider_domains",
        "--delete",
        server.domain_name,
        "--provider",
        "dummy",
        stdout=out,
    )

    output = out.getvalue()
    assert "Deletion cancelled" in output

    # Verify domain still exists
    assert server.domain_name in dummy_provider.domains


########################################################################
#
def test_delete_domain_not_implemented(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a backend that doesn't implement delete_domain
    When deleting a domain
    Then it should show instructions for manual deletion
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    mocker.patch.object(
        dummy_provider,
        "delete_domain",
        side_effect=NotImplementedError,
    )

    out = StringIO()
    call_command(
        "manage_provider_domains",
        "--delete",
        server.domain_name,
        "--provider",
        "dummy",
        "--force",
        stdout=out,
    )

    output = out.getvalue()
    assert "Domain deletion is not yet implemented" in output
    assert "Manually delete the domain" in output


########################################################################
#
def test_delete_domain_backend_failure(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    dummy_provider: DummyProviderBackend,
    mocker: MockerFixture,
) -> None:
    """
    Given a valid domain but backend fails to delete
    When deleting a domain
    Then it should raise CommandError
    """
    provider = provider_factory(backend_name="dummy")
    server = server_factory(
        send_provider=provider, receive_providers=[provider]
    )

    mocker.patch.object(
        dummy_provider,
        "delete_domain",
        side_effect=Exception("API error"),
    )

    with pytest.raises(CommandError) as exc_info:
        call_command(
            "manage_provider_domains",
            "--delete",
            server.domain_name,
            "--provider",
            "dummy",
            "--force",
        )

    assert "Failed to delete domain" in str(exc_info.value)
    assert "API error" in str(exc_info.value)


########################################################################
#
def test_list_multiple_providers_with_mixed_states(
    provider_factory: Callable[..., Provider],
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
) -> None:
    """
    Given multiple providers with different states
    When listing unused domains
    Then it should correctly categorize each
    """
    provider1 = provider_factory(backend_name="dummy", name="Provider 1")
    provider2 = provider_factory(backend_name="dummy", name="Provider 2")

    # Server 1: No aliases (unused)
    server1 = server_factory(receive_providers=[provider1])

    # Server 2: Has enabled aliases (used, automatically created on provider via signal)
    server2 = server_factory(receive_providers=[provider2])
    email_account_factory(server=server2)

    out = StringIO()
    call_command("manage_provider_domains", "--list", stdout=out)

    output = out.getvalue()
    # Only server1 should be listed as unused
    assert "Found 1 unused domain(s)" in output
    assert server1.domain_name in output
    assert server2.domain_name not in output
