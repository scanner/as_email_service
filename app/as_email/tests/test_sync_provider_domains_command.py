#!/usr/bin/env python
#
"""Tests for the sync_provider_domains management command."""

# system imports
#
from collections.abc import Callable
from io import StringIO

# 3rd party imports
#
import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from pytest_mock import MockerFixture

# Project imports
#
from as_email.models import Provider, Server
from as_email.tests.factories import DummyProviderBackend

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestSyncProviderDomainsCommand:
    """Tests for the sync_provider_domains management command."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "dry_run,expect_persisted,expect_label",
        [
            (False, True, "UPDATED"),
            (True, False, "WOULD UPDATE"),
        ],
        ids=["real_run", "dry_run"],
    )
    def test_sync_new_domain(
        self,
        server_factory: Callable[..., Server],
        dummy_provider: DummyProviderBackend,
        dry_run: bool,
        expect_persisted: bool,
        expect_label: str,
    ) -> None:
        """
        GIVEN: a server whose domain does not yet exist on the provider
        WHEN:  sync_provider_domains is called, with or without --dry-run
        THEN:  output shows the expected label and the domain is only
               persisted when dry_run is False
        """
        server = server_factory()
        # The factory triggers signals that create the domain; clear it
        # so the command sees a fresh state.
        dummy_provider.domains.clear()

        out = StringIO()
        args = ["sync_provider_domains"]
        if dry_run:
            args.append("--dry-run")
        call_command(*args, stdout=out)

        assert (
            server.domain_name in dummy_provider.domains
        ) is expect_persisted
        assert expect_label in out.getvalue()

    ####################################################################
    #
    def test_sync_already_up_to_date(
        self,
        server_factory: Callable[..., Server],
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        GIVEN: a server whose domain already exists on the provider
        WHEN:  sync_provider_domains is called
        THEN:  output shows OK (no changes)
        """
        server = server_factory()
        dummy_provider.create_update_domain(server)

        out = StringIO()
        call_command("sync_provider_domains", stdout=out)

        assert "OK" in out.getvalue()
        assert "UPDATED" not in out.getvalue()

    ####################################################################
    #
    def test_sync_domain_filter(
        self,
        server_factory: Callable[..., Server],
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        GIVEN: two servers with the same provider
        WHEN:  sync_provider_domains is called with --domain for one
        THEN:  only the filtered domain is synced
        """
        server1 = server_factory()
        server2 = server_factory()
        # The factory triggers signals that create both domains; clear
        # so the command sees fresh state.
        dummy_provider.domains.clear()

        out = StringIO()
        call_command(
            "sync_provider_domains",
            "--domain",
            server1.domain_name,
            stdout=out,
        )

        assert server1.domain_name in dummy_provider.domains
        assert server2.domain_name not in dummy_provider.domains

    ####################################################################
    #
    def test_sync_provider_filter(
        self,
        server_factory: Callable[..., Server],
        provider_factory: Callable[..., Provider],
        dummy_provider: DummyProviderBackend,
    ) -> None:
        """
        GIVEN: a server with a send_provider (dummy)
        WHEN:  sync_provider_domains is called with --provider postmark
        THEN:  the dummy provider's domain is not touched by the command
        """
        server = server_factory()
        # The factory triggers signals that create the domain; clear
        # so we can verify the command does not recreate it.
        dummy_provider.domains.clear()

        # Create a postmark provider so the --provider filter is valid,
        # but this server only uses the dummy provider.
        provider_factory(backend_name="postmark")

        out = StringIO()
        call_command(
            "sync_provider_domains",
            "--provider",
            "postmark",
            stdout=out,
        )

        assert server.domain_name not in dummy_provider.domains

    ####################################################################
    #
    @pytest.mark.parametrize(
        "flag,value,match",
        [
            ("--domain", "nonexistent.example.com", "No server found"),
            ("--provider", "nonexistent", "No provider found"),
        ],
        ids=["bad_domain", "bad_provider"],
    )
    def test_sync_nonexistent_filter_raises(
        self, flag: str, value: str, match: str
    ) -> None:
        """
        GIVEN: no server/provider matching the filter value
        WHEN:  sync_provider_domains is called with that filter
        THEN:  CommandError is raised with a descriptive message
        """
        with pytest.raises(CommandError, match=match):
            call_command("sync_provider_domains", flag, value)

    ####################################################################
    #
    def test_sync_backend_exception(
        self,
        server_factory: Callable[..., Server],
        dummy_provider: DummyProviderBackend,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: a backend whose create_update_domain raises an exception
        WHEN:  sync_provider_domains is called
        THEN:  output shows ERR and the summary reports the failure
        """
        server_factory()
        mocker.patch.object(
            dummy_provider,
            "create_update_domain",
            side_effect=Exception("API timeout"),
        )

        out = StringIO()
        call_command("sync_provider_domains", stdout=out)

        output = out.getvalue()
        assert "ERR" in output
        assert "API timeout" in output
        assert "1 failed" in output
