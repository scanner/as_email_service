#!/usr/bin/env python
#
"""
Fixtures for provider backend tests.
"""

# system imports
#
from collections.abc import Callable

# 3rd party imports
#
import pytest
from django.conf import LazySettings
from faker import Faker

# Project imports
#
from as_email.models import Server


####################################################################
#
@pytest.fixture
def server_with_token(
    server_factory: Callable[..., Server], settings: LazySettings, faker: Faker
) -> Callable[..., Server]:
    """
    Create a server with an automatically configured EMAIL_SERVER_TOKEN.

    Returns a function that creates servers with tokens already set up,
    so provider backend tests don't need to manually configure tokens.
    """

    def make_server(provider_name: str = "postmark", **kwargs) -> Server:
        server = server_factory(**kwargs)
        # Ensure provider dict exists in EMAIL_SERVER_TOKENS
        if provider_name not in settings.EMAIL_SERVER_TOKENS:
            settings.EMAIL_SERVER_TOKENS[provider_name] = {}
        # Set token for this server
        if (
            server.domain_name
            not in settings.EMAIL_SERVER_TOKENS[provider_name]
        ):
            settings.EMAIL_SERVER_TOKENS[provider_name][server.domain_name] = (
                faker.uuid4()
            )
        return server

    return make_server
