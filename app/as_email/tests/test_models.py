#!/usr/bin/env python
#
"""
Model tests.
"""
# system imports
#

# 3rd party imports
#
import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from faker import Faker

# Project imports
#


User = get_user_model()
fake = Faker()

pytestmark = pytest.mark.django_db


####################################################################
#
def test_server(server_factory):
    """
    Make sure we can create a server, and all of its filefield
    dirs are setup properly.
    """
    server = server_factory()
    server.save()
    assert str(server.incoming_spool_dir).endswith("incoming")
    assert server.domain_name in str(server.incoming_spool_dir)
    assert server.incoming_spool_dir.is_dir()

    assert str(server.outgoing_spool_dir).endswith("outgoing")
    assert server.domain_name in str(server.outgoing_spool_dir)
    assert server.outgoing_spool_dir.is_dir()


####################################################################
#
def test_email_account_set_check_password(email_account_factory):
    ea = email_account_factory()
    password = fake.pystr(min_chars=8, max_chars=32)
    assert ea.check_password(password) is False
    ea.set_password(password)
    assert ea.check_password(password)


####################################################################
#
def test_email_account_valid_email_address(email_account_factory):
    """
    The `email_address` must have the same domain name as the
    associated server.
    """
    # The factory by default creates an email_address that is valid.
    #
    ea = email_account_factory()
    try:
        ea.clean()
    except ValidationError as exc:
        assert False, exc
    ea.save()

    ea.email_address = "foo@example.org"
    with pytest.raises(ValidationError):
        ea.clean()
