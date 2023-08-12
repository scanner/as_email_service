#!/usr/bin/env python
#
"""
Test our factories. Makes sure the factory does not fail and that
it returns the correct type of object.
"""
# system imports
#

# 3rd party imports
#
import pytest

# Project imports
#
from django.contrib.auth import get_user_model

from ..models import (
    BlockedMessage,
    EmailAccount,
    MessageFilterRule,
    Provider,
    Server,
)

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
def test_server_factory_client(server_factory):
    server = server_factory()
    server.send_email("test message")


####################################################################
#
def test_email_account_factory(email_account_factory):
    email_account = email_account_factory()
    assert isinstance(email_account, EmailAccount)


####################################################################
#
def test_blocked_message_factory(blocked_message_factory):
    blocked_message = blocked_message_factory()
    assert isinstance(blocked_message, BlockedMessage)


####################################################################
#
def test_message_filter_rule_factory(message_filter_rule_factory):
    message_filter_rule = message_filter_rule_factory()
    assert isinstance(message_filter_rule, MessageFilterRule)
