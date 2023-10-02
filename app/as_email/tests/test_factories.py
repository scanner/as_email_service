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

from ..models import (
    EmailAccount,
    InactiveEmail,
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
