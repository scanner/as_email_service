#!/usr/bin/env python
#

"""
Tests for provider-related Django signals in as_email/signals.py.

Covers:
- create_provider_email_accounts (post_save on EmailAccount, created=True)
- delete_provider_email_accounts (post_delete on EmailAccount)
- handle_receive_providers_changed (m2m_changed on Server.receive_providers)
"""
# system imports
#
from collections.abc import Callable

# 3rd party imports
#
import pytest
from pytest_mock import MockerFixture

# Project imports
#
from ..models import EmailAccount, Provider, Server

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestProviderSignals:
    """Tests for provider-related signal handlers."""

    ####################################################################
    #
    @pytest.fixture(autouse=True)
    def suppress_tasks(self, mocker: MockerFixture):
        """
        Prevent all signal-triggered task execution during factory setup.
        Returns the HUEY.enqueue mock so individual tests can inspect or
        reset it.
        """
        return mocker.patch("as_email.signals.HUEY.enqueue")

    ####################################################################
    #
    def test_create_provider_email_accounts_fires_for_each_receive_provider(
        self,
        server_factory: Callable[..., Server],
        user_factory: Callable,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: a server with one receive provider
        WHEN:  an EmailAccount is created on that server
        THEN:  provider_create_email_account is called once per receive provider
               with the email account pk and provider backend name
        """
        server = server_factory()
        mock_create = mocker.patch(
            "as_email.signals.provider_create_email_account"
        )

        user = user_factory()
        ea = EmailAccount.objects.create(
            owner=user,
            server=server,
            email_address=f"newuser@{server.domain_name}",
        )

        assert mock_create.call_count == server.receive_providers.count()
        for provider in server.receive_providers.all():
            mock_create.assert_any_call(ea.pk, provider.backend_name)

    ####################################################################
    #
    def test_create_provider_email_accounts_not_fired_on_update(
        self,
        server_factory: Callable[..., Server],
        user_factory: Callable,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: an existing EmailAccount
        WHEN:  it is saved again (update, not create)
        THEN:  provider_create_email_account is not called
        """
        server = server_factory()
        user = user_factory()
        ea = EmailAccount.objects.create(
            owner=user,
            server=server,
            email_address=f"newuser@{server.domain_name}",
        )

        mock_create = mocker.patch(
            "as_email.signals.provider_create_email_account"
        )
        ea.save()

        mock_create.assert_not_called()

    ####################################################################
    #
    def test_delete_provider_email_accounts_fires_for_each_receive_provider(
        self,
        server_factory: Callable[..., Server],
        user_factory: Callable,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: an EmailAccount on a server with one receive provider
        WHEN:  the EmailAccount is deleted
        THEN:  provider_delete_email_account is called once per receive provider
               with the email address, domain name, and provider backend name
        """
        server = server_factory()
        user = user_factory()
        ea = EmailAccount.objects.create(
            owner=user,
            server=server,
            email_address=f"newuser@{server.domain_name}",
        )

        mock_delete = mocker.patch(
            "as_email.signals.provider_delete_email_account"
        )
        email_address = ea.email_address
        domain_name = server.domain_name

        ea.delete()

        assert mock_delete.call_count == server.receive_providers.count()
        for provider in server.receive_providers.all():
            mock_delete.assert_any_call(
                email_address, domain_name, provider.backend_name
            )

    ####################################################################
    #
    def test_delete_provider_email_accounts_fires_for_multiple_receive_providers(
        self,
        server_factory: Callable[..., Server],
        provider_factory: Callable[..., Provider],
        user_factory: Callable,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: an EmailAccount on a server with two receive providers
        WHEN:  the EmailAccount is deleted
        THEN:  provider_delete_email_account is called once for each receive provider
        """
        server = server_factory()
        second_provider = provider_factory()
        server.receive_providers.add(second_provider)

        user = user_factory()
        ea = EmailAccount.objects.create(
            owner=user,
            server=server,
            email_address=f"newuser@{server.domain_name}",
        )

        mock_delete = mocker.patch(
            "as_email.signals.provider_delete_email_account"
        )
        email_address = ea.email_address

        ea.delete()

        assert mock_delete.call_count == 2
        for provider in server.receive_providers.all():
            mock_delete.assert_any_call(
                email_address, server.domain_name, provider.backend_name
            )

    ####################################################################
    #
    def test_handle_receive_providers_changed_post_add_enqueues_pipeline(
        self,
        server_factory: Callable[..., Server],
        provider_factory: Callable[..., Provider],
        suppress_tasks,
    ) -> None:
        """
        GIVEN: a server and a provider not yet associated with it
        WHEN:  the provider is added to server.receive_providers
        THEN:  HUEY.enqueue is called once to schedule the
               create_server → enable_all_email_accounts pipeline
        """
        server = server_factory()
        new_provider = provider_factory()
        suppress_tasks.reset_mock()

        server.receive_providers.add(new_provider)

        suppress_tasks.assert_called_once()

    ####################################################################
    #
    def test_handle_receive_providers_changed_post_add_enqueues_one_pipeline_per_provider(
        self,
        server_factory: Callable[..., Server],
        provider_factory: Callable[..., Provider],
        suppress_tasks,
    ) -> None:
        """
        GIVEN: a server and two providers not yet associated with it
        WHEN:  both providers are added to server.receive_providers in one call
        THEN:  HUEY.enqueue is called once per provider (one pipeline each)
        """
        server = server_factory()
        provider_a = provider_factory()
        provider_b = provider_factory()
        suppress_tasks.reset_mock()

        server.receive_providers.add(provider_a, provider_b)

        assert suppress_tasks.call_count == 2

    ####################################################################
    #
    def test_handle_receive_providers_changed_post_remove_disables_email_accounts(
        self,
        server_factory: Callable[..., Server],
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: a server with one receive provider
        WHEN:  that provider is removed from server.receive_providers
        THEN:  provider_enable_email_accounts_for_server is called with enabled=False
        """
        server = server_factory()
        provider = server.receive_providers.first()

        mock_enable = mocker.patch(
            "as_email.signals.provider_enable_email_accounts_for_server"
        )

        server.receive_providers.remove(provider)

        mock_enable.assert_called_once_with(
            server.pk, provider.backend_name, enabled=False
        )

    ####################################################################
    #
    def test_handle_receive_providers_changed_post_remove_disables_email_accounts_per_provider(
        self,
        server_factory: Callable[..., Server],
        provider_factory: Callable[..., Provider],
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN: a server with two receive providers
        WHEN:  both providers are removed from server.receive_providers in one call
        THEN:  provider_enable_email_accounts_for_server is called once per provider
               with enabled=False
        """
        server = server_factory()
        second_provider = provider_factory()
        server.receive_providers.add(second_provider)

        mock_enable = mocker.patch(
            "as_email.signals.provider_enable_email_accounts_for_server"
        )

        providers = list(server.receive_providers.all())
        server.receive_providers.remove(*providers)

        assert mock_enable.call_count == 2
        for provider in providers:
            mock_enable.assert_any_call(
                server.pk, provider.backend_name, enabled=False
            )
