#!/usr/bin/env python
#
"""
Test migrations 0005 and 0006 for provider backend support.

These migrations add support for multiple providers by:
1. (0005) Adding backend_name and provider_type fields to Provider
2. (0005) Adding send_provider and receive_providers to Server
3. (0005) Making the old provider field nullable
4. (0005) Migrating data from provider to the new fields
5. (0006) Removing the old provider field
"""
# system imports
#
from typing import Any

# 3rd party imports
#
import pytest

pytestmark = [pytest.mark.django_db, pytest.mark.migration_test]


########################################################################
#
def test_forward_migration_0005_copies_provider_to_send_provider(
    migrator: Any,
) -> None:
    """
    Test forward migration 0005 of provider data.

    Given: A Provider and Server exist with the old schema (Server.provider)
    When: Migration 0005 is applied
    Then: The Provider gets backend_name="postmark" and provider_type="BOTH"
    And: The Server.send_provider is set to the old provider
    And: The Server.receive_providers contains the old provider
    And: The old Server.provider field still exists but is nullable
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0004_alter_messagefilterrule_header")
    )

    # Get the old models before migration
    #
    Provider = old_state.apps.get_model("as_email", "Provider")
    Server = old_state.apps.get_model("as_email", "Server")

    # Create test data using old schema
    #
    provider = Provider.objects.create(
        name="Test Postmark Provider",
        smtp_server="smtp.postmarkapp.com:587",
    )

    server = Server.objects.create(
        domain_name="example.com",
        provider=provider,
    )

    # Apply migration 0005
    #
    new_state = migrator.apply_tested_migration(
        ("as_email", "0005_add_provider_backend_support")
    )

    # Get the new models after migration
    #
    Provider = new_state.apps.get_model("as_email", "Provider")
    Server = new_state.apps.get_model("as_email", "Server")

    # Verify Provider has new fields with correct defaults
    #
    migrated_provider = Provider.objects.get(pk=provider.pk)
    assert migrated_provider.backend_name == "postmark"
    assert migrated_provider.provider_type == "BOTH"
    assert migrated_provider.smtp_server == "smtp.postmarkapp.com:587"

    # Verify Server has send_provider set correctly
    #
    migrated_server = Server.objects.get(pk=server.pk)
    assert migrated_server.send_provider is not None
    assert migrated_server.send_provider.pk == provider.pk

    # Verify Server has receive_providers populated
    #
    receive_providers = list(migrated_server.receive_providers.all())
    assert len(receive_providers) == 1
    assert receive_providers[0].pk == provider.pk

    # Verify the old 'provider' field still exists and is nullable
    #
    assert hasattr(migrated_server, "provider_id")
    assert migrated_server.provider_id == provider.pk


########################################################################
#
def test_forward_migration_0006_removes_provider_field(migrator: Any) -> None:
    """
    Test forward migration 0006 removes old provider field.

    Given: Migration 0005 has been applied
    When: Migration 0006 is applied
    Then: The old Server.provider field no longer exists
    And: The send_provider and receive_providers fields remain
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0005_add_provider_backend_support")
    )

    # Get models after 0005
    #
    Provider = old_state.apps.get_model("as_email", "Provider")
    Server = old_state.apps.get_model("as_email", "Server")

    # Create test data
    #
    provider = Provider.objects.create(
        name="Test Provider",
        backend_name="postmark",
        provider_type="BOTH",
        smtp_server="smtp.example.com:587",
    )

    server = Server.objects.create(
        domain_name="example.com",
        send_provider=provider,
        provider=provider,  # Old field still exists at this point
    )
    server.receive_providers.add(provider)

    # Verify old field exists before migration
    #
    assert hasattr(server, "provider_id")

    # Apply migration 0006
    #
    new_state = migrator.apply_tested_migration(
        ("as_email", "0006_remove_old_provider_field")
    )

    # Get models after 0006
    #
    Server = new_state.apps.get_model("as_email", "Server")

    # Verify the old 'provider' field no longer exists
    #
    migrated_server = Server.objects.get(pk=server.pk)
    assert not hasattr(migrated_server, "provider_id")

    # Verify new fields still exist and have correct values
    #
    assert migrated_server.send_provider.pk == provider.pk
    assert list(migrated_server.receive_providers.all())[0].pk == provider.pk


########################################################################
#
def test_forward_migration_handles_multiple_servers(migrator: Any) -> None:
    """
    Test forward migration with multiple servers sharing a provider.

    Given: Multiple Servers exist sharing the same Provider
    When: Migrations 0005 and 0006 are applied
    Then: Each Server.send_provider points to the shared provider
    And: Each Server.receive_providers contains the shared provider
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0004_alter_messagefilterrule_header")
    )

    Provider = old_state.apps.get_model("as_email", "Provider")
    Server = old_state.apps.get_model("as_email", "Server")

    # Create one provider and multiple servers
    #
    provider = Provider.objects.create(
        name="Shared Provider",
        smtp_server="smtp.shared.com:587",
    )

    server1 = Server.objects.create(
        domain_name="domain1.com",
        provider=provider,
    )

    server2 = Server.objects.create(
        domain_name="domain2.com",
        provider=provider,
    )

    server3 = Server.objects.create(
        domain_name="domain3.com",
        provider=provider,
    )

    # Apply both migrations
    #
    migrator.apply_tested_migration(
        ("as_email", "0005_add_provider_backend_support")
    )
    new_state = migrator.apply_tested_migration(
        ("as_email", "0006_remove_old_provider_field")
    )

    Server = new_state.apps.get_model("as_email", "Server")

    # Verify all servers point to the same provider
    #
    migrated_server1 = Server.objects.get(pk=server1.pk)
    migrated_server2 = Server.objects.get(pk=server2.pk)
    migrated_server3 = Server.objects.get(pk=server3.pk)

    assert migrated_server1.send_provider.pk == provider.pk
    assert migrated_server2.send_provider.pk == provider.pk
    assert migrated_server3.send_provider.pk == provider.pk

    # Verify each has the provider in receive_providers
    #
    assert list(migrated_server1.receive_providers.all())[0].pk == provider.pk
    assert list(migrated_server2.receive_providers.all())[0].pk == provider.pk
    assert list(migrated_server3.receive_providers.all())[0].pk == provider.pk


########################################################################
#
def test_reverse_migration_0006_restores_provider_field(migrator: Any) -> None:
    """
    Test reverse migration 0006 restores the provider field.

    Given: Migrations 0005 and 0006 have been applied
    When: Migration 0006 is reversed
    Then: The old Server.provider field is restored as nullable
    And: The send_provider and receive_providers fields still exist
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0006_remove_old_provider_field")
    )

    # Create data with new schema (no provider field)
    #
    Provider = old_state.apps.get_model("as_email", "Provider")
    Server = old_state.apps.get_model("as_email", "Server")

    provider = Provider.objects.create(
        name="Test Provider",
        backend_name="postmark",
        provider_type="BOTH",
        smtp_server="smtp.example.com:587",
    )

    server = Server.objects.create(
        domain_name="example.com",
        send_provider=provider,
    )
    server.receive_providers.add(provider)

    # Verify provider field doesn't exist
    #
    assert not hasattr(server, "provider_id")

    # Reverse migration 0006
    #
    new_state = migrator.apply_tested_migration(
        ("as_email", "0005_add_provider_backend_support")
    )

    # Get models after reversal
    #
    Server = new_state.apps.get_model("as_email", "Server")

    # Verify provider field is restored
    #
    reverted_server = Server.objects.get(pk=server.pk)
    assert hasattr(reverted_server, "provider_id")

    # Verify new fields still exist
    #
    assert hasattr(reverted_server, "send_provider_id")
    assert reverted_server.send_provider.pk == provider.pk


########################################################################
#
def test_reverse_migration_0005_restores_old_schema(migrator: Any) -> None:
    """
    Test reverse migration 0005 restores the old schema completely.

    Given: Migration 0005 has been applied
    When: Migration 0005 is reversed to 0004
    Then: The Provider loses backend_name and provider_type fields
    And: The Server has only the provider field (non-nullable)
    And: The Server.send_provider and receive_providers no longer exist
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0005_add_provider_backend_support")
    )

    # Create data with new schema
    #
    Provider = old_state.apps.get_model("as_email", "Provider")
    Server = old_state.apps.get_model("as_email", "Server")

    provider = Provider.objects.create(
        name="Test Provider",
        backend_name="postmark",
        provider_type="BOTH",
        smtp_server="smtp.example.com:587",
    )

    server = Server.objects.create(
        domain_name="example.com",
        send_provider=provider,
        provider=provider,
    )
    server.receive_providers.add(provider)

    # Reverse migration to 0004
    #
    new_state = migrator.apply_tested_migration(
        ("as_email", "0004_alter_messagefilterrule_header")
    )

    # Get old models
    #
    Provider = new_state.apps.get_model("as_email", "Provider")
    Server = new_state.apps.get_model("as_email", "Server")

    # Verify Provider no longer has new fields
    #
    reverted_provider = Provider.objects.get(pk=provider.pk)
    assert not hasattr(reverted_provider, "backend_name")
    assert not hasattr(reverted_provider, "provider_type")

    # Verify Server has provider field restored with correct value
    #
    reverted_server = Server.objects.get(pk=server.pk)
    assert hasattr(reverted_server, "provider_id")
    assert reverted_server.provider.pk == provider.pk

    # Verify new fields no longer exist
    #
    assert not hasattr(reverted_server, "send_provider")
    assert not hasattr(reverted_server, "receive_providers")


########################################################################
#
def test_migration_preserves_smtp_server_field(migrator: Any) -> None:
    """
    Test that smtp_server field is preserved during migration.

    Given: A Provider exists with an smtp_server value
    When: Migrations 0005 and 0006 are applied
    Then: The smtp_server value is preserved
    And: The field is now optional (blank=True)
    """
    old_state = migrator.apply_initial_migration(
        ("as_email", "0004_alter_messagefilterrule_header")
    )

    Provider = old_state.apps.get_model("as_email", "Provider")

    provider = Provider.objects.create(
        name="SMTP Test Provider",
        smtp_server="smtp.testprovider.com:2525",
    )

    # Apply both migrations
    #
    migrator.apply_tested_migration(
        ("as_email", "0005_add_provider_backend_support")
    )
    new_state = migrator.apply_tested_migration(
        ("as_email", "0006_remove_old_provider_field")
    )

    Provider = new_state.apps.get_model("as_email", "Provider")

    # Verify smtp_server is preserved
    #
    migrated_provider = Provider.objects.get(pk=provider.pk)
    assert migrated_provider.smtp_server == "smtp.testprovider.com:2525"
