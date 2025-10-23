#!/usr/bin/env python
#
"""
Fixtures for provider backend tests.
"""
# 3rd party imports
#
import pytest


####################################################################
#
@pytest.fixture
def server_with_token(server_factory, settings, faker):
    """
    Create a server with an automatically configured EMAIL_SERVER_TOKEN.

    Returns a function that creates servers with tokens already set up,
    so provider backend tests don't need to manually configure tokens.
    """

    def make_server(**kwargs):
        server = server_factory(**kwargs)
        if server.domain_name not in settings.EMAIL_SERVER_TOKENS:
            settings.EMAIL_SERVER_TOKENS[server.domain_name] = faker.uuid4()
        return server

    return make_server
