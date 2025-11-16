#!/usr/bin/env python
#
"""
Test our factories. Makes sure the factory does not fail and that
it returns the correct type of object.
"""
# system imports
#
from email.mime.text import MIMEText

# 3rd party imports
#
import pytest

# Project imports
#
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.test import RequestFactory

from ..models import (
    EmailAccount,
    InactiveEmail,
    MessageFilterRule,
    Provider,
    Server,
)
from .factories import DummyProviderBackend

pytestmark = pytest.mark.django_db

User = get_user_model()


####################################################################
#
def test_user_factory(user_factory):
    user = user_factory()
    assert isinstance(user, User)


####################################################################
#
def test_provider_factory(provider_factory):
    provider = provider_factory()
    assert isinstance(provider, Provider)


####################################################################
#
def test_server_factory(server_factory):
    server = server_factory()
    assert isinstance(server, Server)


####################################################################
#
def test_server_factory_client(
    server_factory, settings, faker, postmark_client
):
    """
    Test that server factory creates servers that can send email.

    Given: A server is created via server_factory
    When: send_email() is called on the server
    Then: The email is sent via the provider backend
    """
    server = server_factory()
    # Set up EMAIL_SERVER_TOKENS for the provider backend
    provider_name = "postmark"
    if provider_name not in settings.EMAIL_SERVER_TOKENS:
        settings.EMAIL_SERVER_TOKENS[provider_name] = {}
    settings.EMAIL_SERVER_TOKENS[provider_name][
        server.domain_name
    ] = faker.uuid4()

    message = MIMEText("Test message")
    server.send_email(message)


####################################################################
#
def test_email_account_factory(email_account_factory):
    email_account = email_account_factory()
    assert isinstance(email_account, EmailAccount)


####################################################################
#
def test_message_filter_rule_factory(message_filter_rule_factory):
    message_filter_rule = message_filter_rule_factory()
    assert isinstance(message_filter_rule, MessageFilterRule)


####################################################################
#
def test_inactive_email_factory(inactive_email_factory):
    inactive_email = inactive_email_factory()
    assert isinstance(inactive_email, InactiveEmail)


########################################################################
########################################################################
#
class TestDummyProviderBackend:
    """Tests for the DummyProviderBackend."""

    ####################################################################
    #
    @pytest.fixture
    def mock_email_account(self, mocker, faker):
        """
        Fixture generator that creates mock email accounts.

        Returns:
            A callable that creates mock email account objects.
            If domain_name is provided, creates email with that domain.
            Otherwise generates a random email and extracts domain from it.
        """

        def _make_account(domain_name=None):
            account = mocker.Mock()
            if domain_name:
                account.email_address = f"{faker.user_name()}@{domain_name}"
                account.server.domain_name = domain_name
            else:
                account.email_address = faker.email()
                account.server.domain_name = account.email_address.split("@")[1]
            return account

        return _make_account

    ####################################################################
    #
    def test_initialization(self, dummy_provider) -> None:
        """
        Given a fresh dummy provider instance
        When it is created
        Then it should have empty domains and email_accounts dictionaries
        """
        assert dummy_provider.domains == {}
        assert dummy_provider.email_accounts == {}
        assert dummy_provider.PROVIDER_NAME == "dummy"

    ####################################################################
    #
    def test_create_domain(self, dummy_provider, mocker, faker) -> None:
        """
        Given a domain name
        When create_domain is called directly
        Then the domain should be added to the provider's state
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()

        result = dummy_provider.create_domain(server)

        assert server.domain_name in dummy_provider.domains
        assert result["domain"] == server.domain_name
        assert result["id"] == f"dummy-{server.domain_name}"

    ####################################################################
    #
    def test_create_domain_duplicate_raises_error(
        self, dummy_provider, mocker, faker
    ) -> None:
        """
        Given a domain that already exists
        When create_domain is called again
        Then it should raise a ValueError
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        dummy_provider.create_domain(server)

        with pytest.raises(ValueError, match="already exists"):
            dummy_provider.create_domain(server)

    ####################################################################
    #
    def test_create_update_domain_creates_new(
        self, dummy_provider, mocker, faker
    ) -> None:
        """
        Given a server with no existing domain
        When create_update_domain is called
        Then the domain should be created
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        result = dummy_provider.create_update_domain(server)

        assert server.domain_name in dummy_provider.domains
        assert result["domain"] == server.domain_name

    ####################################################################
    #
    def test_create_update_domain_updates_existing(
        self, dummy_provider, mocker, faker
    ) -> None:
        """
        Given a domain that already exists
        When create_update_domain is called
        Then it should return the existing domain without error
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        result1 = dummy_provider.create_domain(server)
        result2 = dummy_provider.create_update_domain(server)

        assert result1 == result2
        assert len(dummy_provider.domains) == 1

    ####################################################################
    #
    def test_delete_domain(self, dummy_provider, mocker, faker) -> None:
        """
        Given a domain that exists
        When delete_domain is called
        Then the domain should be removed from state
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        dummy_provider.create_domain(server)
        assert server.domain_name in dummy_provider.domains

        dummy_provider.delete_domain(server)
        assert server.domain_name not in dummy_provider.domains

    ####################################################################
    #
    def test_delete_domain_nonexistent(
        self,
        dummy_provider,
        mocker,
        faker,
    ) -> None:
        """
        Given a domain that does not exist
        When delete_domain is called
        Then it should not raise an error
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        dummy_provider.delete_domain(server)  # Should not raise

    ####################################################################
    #
    def test_create_email_account(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account
        When create_email_account is called
        Then the account should be added to the provider's state
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)

        assert account.email_address in dummy_provider.email_accounts
        account_data = dummy_provider.email_accounts[account.email_address]
        assert account_data["email"] == account.email_address
        assert account_data["domain"] == account.server.domain_name
        assert account_data["enabled"] is True

    ####################################################################
    #
    def test_create_email_account_duplicate_raises_error(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that already exists
        When create_email_account is called again
        Then it should raise a ValueError
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)

        with pytest.raises(ValueError, match="already exists"):
            dummy_provider.create_email_account(account)

    ####################################################################
    #
    def test_create_update_email_account_creates_new(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that does not exist
        When create_update_email_account is called
        Then the account should be created
        """
        account = mock_email_account()
        dummy_provider.create_update_email_account(account)

        assert account.email_address in dummy_provider.email_accounts

    ####################################################################
    #
    def test_create_update_email_account_updates_existing(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that already exists
        When create_update_email_account is called
        Then it should update the account without error
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)
        dummy_provider.create_update_email_account(account)

        assert len(dummy_provider.email_accounts) == 1
        assert account.email_address in dummy_provider.email_accounts

    ####################################################################
    #
    def test_delete_email_account(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that exists
        When delete_email_account is called
        Then the account should be removed from state
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)
        assert account.email_address in dummy_provider.email_accounts

        dummy_provider.delete_email_account(account)
        assert account.email_address not in dummy_provider.email_accounts

    ####################################################################
    #
    def test_delete_email_account_by_address(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that exists
        When delete_email_account_by_address is called
        Then the account should be removed from state
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)

        dummy_provider.delete_email_account_by_address(
            account.email_address, account.server.domain_name
        )
        assert account.email_address not in dummy_provider.email_accounts

    ####################################################################
    #
    def test_enable_email_account(
        self, dummy_provider, mock_email_account
    ) -> None:
        """
        Given an email account that exists
        When enable_email_account is called with enable=False
        Then the account's enabled flag should be False
        """
        account = mock_email_account()
        dummy_provider.create_email_account(account)
        assert (
            dummy_provider.email_accounts[account.email_address]["enabled"]
            is True
        )

        dummy_provider.enable_email_account(account, enable=False)
        assert (
            dummy_provider.email_accounts[account.email_address]["enabled"]
            is False
        )

    ####################################################################
    #
    def test_list_email_accounts_empty(
        self, dummy_provider, mocker, faker
    ) -> None:
        """
        Given a server with no email accounts
        When list_email_accounts is called
        Then it should return an empty list
        """
        server = mocker.Mock()
        server.domain_name = faker.domain_name()

        accounts = dummy_provider.list_email_accounts(server)
        assert accounts == []

    ####################################################################
    #
    def test_list_email_accounts_filters_by_domain(
        self,
        dummy_provider,
        faker,
        mock_email_account,
    ) -> None:
        """
        Given multiple email accounts across different domains
        When list_email_accounts is called for one domain
        Then it should return only accounts for that domain
        """
        domain1 = faker.domain_name()
        domain2 = faker.domain_name()

        account1 = mock_email_account(domain1)
        account2 = mock_email_account(domain1)
        account3 = mock_email_account(domain2)

        server1 = account1.server
        server2 = account3.server

        dummy_provider.create_email_account(account1)
        dummy_provider.create_email_account(account2)
        dummy_provider.create_email_account(account3)

        accounts_server1 = dummy_provider.list_email_accounts(server1)
        assert len(accounts_server1) == 2
        assert all(
            acc["domain"] == server1.domain_name for acc in accounts_server1
        )

        accounts_server2 = dummy_provider.list_email_accounts(server2)
        assert len(accounts_server2) == 1
        assert accounts_server2[0]["domain"] == server2.domain_name

    ####################################################################
    #
    def test_send_email_smtp_returns_true(
        self, settings, dummy_provider, mock_email_account, email_factory, faker
    ) -> None:
        """
        Given a dummy provider
        When send_email_smtp is called
        Then it should return True
        """
        account = mock_email_account()
        msg = email_factory()
        settings.EMAIL_SERVER_TOKENS[dummy_provider.PROVIDER_NAME] = {
            account.server.domain_name: faker.uuid4()
        }

        result = dummy_provider.send_email_smtp(
            account.server, account.email_address, [faker.email()], msg
        )
        assert result is True

    ####################################################################
    #
    def test_send_email_api_returns_true(
        self, dummy_provider, mock_email_account, email_factory
    ) -> None:
        """
        Given a dummy provider
        When send_email_api is called
        Then it should return True
        """
        account = mock_email_account()
        msg = email_factory()
        result = dummy_provider.send_email_api(account.server, msg)
        assert result is True

    ####################################################################
    #
    def test_webhook_handlers_return_json_response(
        self, dummy_provider, mocker, faker
    ) -> None:
        """
        Given a dummy provider
        When webhook handlers are called
        Then they should return JsonResponse with success status
        """

        server = mocker.Mock()
        server.domain_name = faker.domain_name()
        request = RequestFactory().post("/webhook")

        incoming_response = dummy_provider.handle_incoming_webhook(
            request, server
        )
        assert isinstance(incoming_response, JsonResponse)

        bounce_response = dummy_provider.handle_bounce_webhook(request, server)
        assert isinstance(bounce_response, JsonResponse)

        spam_response = dummy_provider.handle_spam_webhook(request, server)
        assert isinstance(spam_response, JsonResponse)

    ####################################################################
    #
    def test_state_shared_between_instances(self, mock_email_account) -> None:
        """
        Given two different DummyProviderBackend instances
        When state is modified in one
        Then the other should see the same changes (shared state)
        """
        account = mock_email_account()

        provider1 = DummyProviderBackend()
        provider2 = DummyProviderBackend()

        provider1.create_email_account(account)

        # Both instances share the same state
        assert account.email_address in provider1.email_accounts
        assert account.email_address in provider2.email_accounts
        assert provider1.email_accounts is provider2.email_accounts
