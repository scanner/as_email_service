#!/usr/bin/env python
#
"""
Test the aiosmtpd daemon/django command.
"""
# system imports
#

# 3rd party imports
#
import pytest
from aiosmtpd.smtp import LoginPassword
from aiosmtpd.smtp import Session as SMTPSession

# Project imports
#
from ..management.commands.aiosmtpd import Authenticator

pytestmark = pytest.mark.django_db


####################################################################
#
def test_authenticator_authenticate(email_account_factory, faker):
    """
    Given an email account check various authentication attempts and its
    failure methods.
    """
    password = faker.pystr(min_chars=8, max_chars=32)
    ea = email_account_factory(password=password)
    ea.save()
    auth = Authenticator()

    # Our authenticator only uses the `session`, `mechanism`, and `auth_data`
    # parameters to check authentication. For `session` it only cares about
    # session.peer.. we do not even care what peer is as long as it can be used
    # as a key to a dict. It takes an asyncio event loop, but we never use that
    # in our test so we do not bother passing one in.
    #
    sess = SMTPSession(None)
    sess.peer = ("127.0.0.1", 1234)
    for mechanism in ("LOGIN", "PLAIN"):
        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(password, "utf-8"),
        )
        res = auth(None, sess, None, mechanism, auth_data)
        assert res.success
        assert res.auth_data == ea
    mechanism = "LOGIN"

    # Test invalid password.
    #
    auth_data = LoginPassword(
        login=bytes(ea.email_address, "utf-8"),
        password=bytes(faker.pystr(), "utf-8"),
    )
    res = auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # Test invalid account.
    #
    auth_data = LoginPassword(
        login=bytes(faker.email(), "utf-8"),
        password=bytes(password, "utf-8"),
    )
    res = auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # Test deactivated account.
    #
    ea.deactivated = True
    ea.save()
    auth_data = LoginPassword(
        login=bytes(ea.email_address, "utf-8"),
        password=bytes(password, "utf-8"),
    )
    res = auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # We do not support these auth mechanisms. Also make sure random strings
    # fail. This is mostly so that when we DO support these mechanisms this
    # test will fail to remind us to make sure this test is updated.
    #
    for mechanism in (
        "CRAM-MD5",
        "DIGEST-MD5",
        "NTLM",
        "GSSAPI",
        "XOAUTH",
        "XOAUTH2",
        faker.pystr(),
    ):
        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(password, "utf-8"),
        )
        res = auth(None, sess, None, mechanism, auth_data)
        assert res.success is False
