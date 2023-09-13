#!/usr/bin/env python
#
"""
Test the aiosmtpd daemon/django command.
"""
# system imports
#

# 3rd party imports
#
import factory
import pytest

# Project imports
#

pytestmark = pytest.mark.django_db


####################################################################
#
def test_authenticator_authenticate(email_account_factory):
    """
    Given an email account check various authentication attempts and its
    failure methods.
    """
    password = factory.Faker("pystr")
    ea = email_account_factory(password=password)  # noqa: F841
