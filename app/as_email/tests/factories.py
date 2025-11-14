#!/usr/bin/env python
#
"""
Factories for testing all of our models and related code
"""
import email.message

# system imports
#
from typing import Any, Sequence

# 3rd party imports
#
import factory
import factory.fuzzy
from django.contrib.auth import get_user_model
from django.http import HttpRequest, JsonResponse
from factory import post_generation
from factory.django import DjangoModelFactory
from faker import Faker

from ..models import (
    EmailAccount,
    InactiveEmail,
    MessageFilterRule,
    Provider,
    Server,
)

# Project imports
#
from ..providers.base import ProviderBackend

User = get_user_model()
fake = Faker()


########################################################################
# Shared state for DummyProviderBackend instances within a test
#
# This is used to ensure all DummyProviderBackend instances in a test
# share the same state (domains and email_accounts). The fixture
# `setup_dummy_provider_backend` resets this state for each test.
#
_DUMMY_PROVIDER_SHARED_STATE: dict[str, Any] = {
    "domains": {},
    "email_accounts": {},
}


########################################################################
########################################################################
#
class DummyProviderBackend(ProviderBackend):
    """
    Stateful dummy provider backend for testing.

    Maintains in-memory state for domains and email accounts to allow testing
    of create/read/update/delete operations. All instances share the same state
    within a test via module-level _DUMMY_PROVIDER_SHARED_STATE.

    Attributes:
        domains: Dictionary mapping domain names to domain data (shared)
        email_accounts: Dictionary mapping email addresses to account data (shared)
    """

    PROVIDER_NAME = "dummy"

    ####################################################################
    #
    def __init__(self) -> None:
        """
        Initialize the dummy provider.

        Uses shared module-level state so all instances within a test
        share the same domains and email_accounts.
        """
        # Reference the shared state instead of creating new dicts
        self.domains = _DUMMY_PROVIDER_SHARED_STATE["domains"]
        self.email_accounts = _DUMMY_PROVIDER_SHARED_STATE["email_accounts"]

    ####################################################################
    #
    def send_email_smtp(
        self,
        server: Server,
        email_from: str,
        rcpt_tos: list[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        return True

    ####################################################################
    #
    def send_email_api(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        return True

    ####################################################################
    #
    def handle_incoming_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        return JsonResponse(
            {"status": "success", "message": "webhook received"}
        )

    ####################################################################
    #
    def handle_bounce_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        return JsonResponse({"status": "success", "message": "bounce received"})

    ####################################################################
    #
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        return JsonResponse({"status": "success", "message": "spam received"})

    ####################################################################
    #
    def create_domain(self, server: "Server") -> dict[str, Any]:
        """
        Create a domain in the dummy provider state.

        Raises:
            ValueError: If domain already exists
        """
        if server.domain_name in self.domains:
            raise ValueError(f"Domain {server.domain_name} already exists")

        domain_data = {
            "id": f"dummy-{server.domain_name}",
            "domain": server.domain_name,
        }
        self.domains[server.domain_name] = domain_data
        return domain_data

    ####################################################################
    #
    def create_update_domain(self, server: "Server") -> dict[str, Any]:
        """Create or update a domain in the dummy provider state."""
        if server.domain_name in self.domains:
            # Update existing domain
            return self.domains[server.domain_name]
        else:
            # Create new domain
            return self.create_domain(server)

    ####################################################################
    #
    def delete_domain(self, server: "Server") -> None:
        """Delete a domain from the dummy provider state."""
        self.domains.pop(server.domain_name, None)

    ####################################################################
    #
    def create_email_account(self, email_account: "EmailAccount") -> None:
        """
        Create an email account in the dummy provider state.

        Raises:
            ValueError: If email account already exists
        """
        if email_account.email_address in self.email_accounts:
            raise ValueError(
                f"Email account {email_account.email_address} already exists"
            )

        self.email_accounts[email_account.email_address] = {
            "id": f"dummy-{email_account.email_address}",
            "email": email_account.email_address,
            "domain": email_account.server.domain_name,
            "enabled": True,
        }

    ####################################################################
    #
    def create_update_email_account(
        self, email_account: "EmailAccount"
    ) -> None:
        """Create or update an email account in the dummy provider state."""
        if email_account.email_address in self.email_accounts:
            # Update existing account
            self.email_accounts[email_account.email_address].update(
                {
                    "email": email_account.email_address,
                    "domain": email_account.server.domain_name,
                }
            )
        else:
            # Create new account
            self.create_email_account(email_account)

    ####################################################################
    #
    def delete_email_account(self, email_account: "EmailAccount") -> None:
        """Delete an email account from the dummy provider state."""
        self.email_accounts.pop(email_account.email_address, None)

    ####################################################################
    #
    def delete_email_account_by_address(
        self, email_address: str, domain_name: str
    ) -> None:
        """Delete an email account by address from the dummy provider state."""
        self.email_accounts.pop(email_address, None)

    ####################################################################
    #
    def enable_email_account(
        self, email_account: "EmailAccount", enable: bool = True
    ) -> None:
        """Enable or disable an email account in the dummy provider state."""
        if email_account.email_address in self.email_accounts:
            self.email_accounts[email_account.email_address]["enabled"] = enable

    ####################################################################
    #
    def list_email_accounts(self, server: "Server") -> list[dict[str, Any]]:
        """List all email accounts for a domain from the dummy provider state."""
        return [
            account
            for account in self.email_accounts.values()
            if account["domain"] == server.domain_name
        ]


########################################################################
########################################################################
#
class UserFactory(DjangoModelFactory):
    username = factory.Faker("user_name")
    email = factory.Faker("email")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("first_name")

    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):
        password = extracted if extracted else fake.password(length=16)
        self.set_password(password)
        self.save()

    class Meta:
        model = get_user_model()
        django_get_or_create = ("username",)
        skip_postgeneration_save = True


########################################################################
########################################################################
#
class ProviderFactory(DjangoModelFactory):
    name = factory.Sequence(lambda n: f"Provider {n}")
    backend_name = "dummy"
    provider_type = Provider.ProviderType.BOTH
    smtp_server = factory.Sequence(lambda n: f"smtp{n}.example.com:587")

    class Meta:
        model = Provider
        django_get_or_create = ("name",)


########################################################################
########################################################################
#
class ServerFactory(DjangoModelFactory):
    domain_name = factory.Sequence(lambda n: f"srvr{n}.example.com")
    send_provider = factory.SubFactory(ProviderFactory)

    @post_generation
    def receive_providers(
        self, create: bool, extracted: Sequence[Any], **kwargs
    ):
        """
        Add receive_providers to the server. By default, adds the send_provider
        as a receive provider as well.
        """
        if not create:
            return

        if extracted:
            # If a list of providers was passed, use those
            for provider in extracted:
                self.receive_providers.add(provider)
        elif self.send_provider:
            # By default, add send_provider as a receive provider
            self.receive_providers.add(self.send_provider)

    class Meta:
        model = Server
        django_get_or_create = ("domain_name",)
        skip_postgeneration_save = True


########################################################################
########################################################################
#
class EmailAccountFactory(DjangoModelFactory):
    owner = factory.SubFactory(UserFactory)
    server = factory.SubFactory(ServerFactory)
    email_address = factory.LazyAttribute(
        lambda o: f"{fake.profile()['username']}@{o.server.domain_name}"
    )

    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):
        password = extracted if extracted else "XXX"
        do_save = password != "XXX"
        self.set_password(password, save=do_save)

    class Meta:
        model = EmailAccount
        skip_postgeneration_save = True
        django_get_or_create = ("owner", "email_address", "server")


########################################################################
########################################################################
#
class InactiveEmailFactory(DjangoModelFactory):
    email_address = factory.Faker("email")

    class Meta:
        model = InactiveEmail
        django_get_or_create = ("email_address",)


########################################################################
########################################################################
#
class MessageFilterRuleFactory(DjangoModelFactory):
    email_account = factory.SubFactory(EmailAccountFactory)
    pattern = factory.Faker("email")
    header = factory.fuzzy.FuzzyChoice(
        [x[0] for x in MessageFilterRule.HEADER_CHOICES if x[0] != "default"]
    )

    class Meta:
        model = MessageFilterRule
