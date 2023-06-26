#!/usr/bin/env python
#
"""
Factories for testing all of our models and related code
"""
# system imports
#
import random
import string
from typing import Any, Sequence

# 3rd party imports
#
import factory
import factory.fuzzy
from django.contrib.auth import get_user_model
from factory import Faker, post_generation
from factory.django import DjangoModelFactory

# Project imports
#
from ..models import (
    BlockedMessage,
    EmailAccount,
    MessageFilterRule,
    Provider,
    Server,
)

User = get_user_model()


####################################################################
#
def random_string(length: int, character_set: str) -> str:
    """
    Generate a random string of from the given character set up to
    `length` characters long.
    """
    return "".join(random.choice(character_set) for _ in range(length))


########################################################################
########################################################################
#
class UserFactory(DjangoModelFactory):
    username = Faker("user_name")
    email = Faker("email")
    name = Faker("name")

    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):
        password = (
            extracted
            if extracted
            else Faker(
                "password",
                length=42,
                special_chars=True,
                digits=True,
                upper_case=True,
                lower_case=True,
            ).evaluate(None, None, extra={"locale": None})
        )
        self.set_password(password)

    class Meta:
        model = get_user_model()
        django_get_or_create = ["username"]


########################################################################
########################################################################
#
class ProviderFactory(DjangoModelFactory):
    name = factory.Sequence(lambda n: f"Provider {n}")

    class Meta:
        model = Provider
        django_get_or_create = ["name"]


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
    user = factory.SubFactory(UserFactory)
    adddress = Faker("email")
    provider = factory.SubFactory(ProviderFactory)

    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):
        password = (
            extracted
            if extracted
            else Faker(
                "password",
                length=42,
                special_chars=True,
                digits=True,
                upper_case=True,
                lower_case=True,
            ).evaluate(None, None, extra={"locale": None})
        )
        self.set_password(password)

    class Meta:
        model = EmailAccount


########################################################################
########################################################################
#
class BlockedMessageFactory(DjangoModelFactory):
    email_account = factory.SubFactory(EmailAccountFactory)
    message_id = factory.Sequence(lambda n: n)
    status = "Blocked"
    subject = factory.LazyAttribute(
        lambda x: random_string(100, string.ascii_letters)
    )
    from_address = Faker("email")
    cc = Faker("email")
    blocked_reason = factory.LazyAttribute(
        lambda x: random_string(100, string.ascii_letters)
    )

    class Meta:
        model = BlockedMessage


########################################################################
########################################################################
#
class MessageFilterRuleFactory(DjangoModelFactory):
    email_account = factory.SubFactory(EmailAccountFactory)
    header = factory.fuzzy.FuzzyChoice(
        [x[0] for x in MessageFilterRule.HEADER_CHOICES]
    )

    class Meta:
        model = MessageFilterRule
