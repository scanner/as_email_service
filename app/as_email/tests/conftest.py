#!/usr/bin/env python
#
"""
pytest fixtures for our tests
"""
# system imports
#

# 3rd party imports
#
from pytest_factoryboy import register

# Project imports
#
from .factories import (
    BlockedMessageFactory,
    EmailAccountFactory,
    MessageFilterRuleFactory,
    ProviderFactory,
    ServerFactory,
    UserFactory,
)

# This is the magic where we create fixtures that use factories to
# generate the right kind of object.
#
# NOTE: `register(FooFactory)` provides the fixture `foo_factory`
#
register(UserFactory)
register(ProviderFactory)
register(ServerFactory)
register(EmailAccountFactory)
register(BlockedMessageFactory)
register(MessageFilterRuleFactory)
