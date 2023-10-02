#!/usr/bin/env python
#
"""
Factories for testing all of our models and related code
"""
# system imports
#
from typing import Any, Sequence

# 3rd party imports
#
import factory
import factory.fuzzy
from django.contrib.auth import get_user_model
from factory import post_generation
from factory.django import DjangoModelFactory
from faker import Faker  # XXX should we move to `factory.Faker()`?

# Project imports
#
from ..models import (
    EmailAccount,
    InactiveEmail,
    MessageFilterRule,
    Provider,
    Server,
)

User = get_user_model()
fake = Faker()


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
    smtp_server = factory.Sequence(lambda n: f"smtp{n}.example.com:587")

    class Meta:
        model = Provider
        django_get_or_create = ("name",)


########################################################################
########################################################################
#
class ServerFactory(DjangoModelFactory):
    domain_name = factory.Sequence(lambda n: f"srvr{n}.example.com")
    provider = factory.SubFactory(ProviderFactory)

    class Meta:
        model = Server
        django_get_or_create = ("domain_name", "provider")


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
        password = extracted if extracted else fake.password(length=16)
        self.set_password(password)

    class Meta:
        model = EmailAccount
        skip_postgeneration_save = True  # Saved when `set_password()` is called
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
        [x[0] for x in MessageFilterRule.HEADER_CHOICES]
    )

    class Meta:
        model = MessageFilterRule
