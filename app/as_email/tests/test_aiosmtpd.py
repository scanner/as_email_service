#!/usr/bin/env python
#
"""
Test the aiosmtpd daemon/django command.
"""
import email
import email.policy

# system imports
#
from datetime import datetime
from email.utils import parseaddr

# 3rd party imports
#
import pytest
from aiosmtpd.smtp import SMTP, LoginPassword
from asgiref.sync import sync_to_async

# Project imports
#
from ..management.commands.aiosmtpd import (
    Authenticator,
    RelayHandler,
    relay_email_to_provider,
)
from ..models import InactiveEmail
from .conftest import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
@pytest.mark.asyncio
async def test_authenticator_authenticate(
    email_account_factory, faker, aiosmtp_session
):
    """
    Given an email account check various authentication attempts and its
    failure methods.
    """
    sess = aiosmtp_session
    password = faker.pystr(min_chars=8, max_chars=32)
    ea = await sync_to_async(email_account_factory)(password=password)
    await ea.asave()
    auth = Authenticator()

    # Our authenticator only uses the `session`, `mechanism`, and `auth_data`
    # parameters to check authentication.
    #
    for mechanism in ("LOGIN", "PLAIN"):
        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(password, "utf-8"),
        )
        res = await auth(None, sess, None, mechanism, auth_data)
        assert res.success
        assert res.auth_data == ea
    mechanism = "LOGIN"

    # Test invalid password.
    #
    auth_data = LoginPassword(
        login=bytes(ea.email_address, "utf-8"),
        password=bytes(faker.pystr(), "utf-8"),
    )
    res = await auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # Test invalid account.
    #
    auth_data = LoginPassword(
        login=bytes(faker.email(), "utf-8"),
        password=bytes(password, "utf-8"),
    )
    res = await auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # Test deactivated account.
    #
    ea.deactivated = True
    await ea.asave()
    auth_data = LoginPassword(
        login=bytes(ea.email_address, "utf-8"),
        password=bytes(password, "utf-8"),
    )
    res = await auth(None, sess, None, mechanism, auth_data)
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
        res = await auth(None, sess, None, mechanism, auth_data)
        assert res.success is False


####################################################################
#
@pytest.mark.asyncio
async def test_authenticator_blacklist(
    email_account_factory, faker, aiosmtp_session
):
    """
    Test the Authenticator blacklist mechanism that blocks too many
    authentication failures.
    """
    # Our authenticator only uses the `session`, `mechanism`, and `auth_data`
    # parameters to check authentication.
    #
    sess = aiosmtp_session
    password = faker.pystr(min_chars=8, max_chars=32)
    ea = await sync_to_async(email_account_factory)(password=password)
    await ea.asave()
    auth = Authenticator()

    # A time before any failed attempts (so we can check expiry against this)
    #
    now = datetime.utcnow()

    # Before any authentications happen connections are not denied.
    #
    assert auth.check_deny(sess.peer) is False

    # After a single unsuccessful login, access is still allowed.
    #
    mechanism = "LOGIN"
    auth_data = LoginPassword(
        login=bytes(ea.email_address, "utf-8"),
        password=bytes(faker.pystr(), "utf-8"),
    )
    res = await auth(None, sess, None, mechanism, auth_data)
    assert res.success is False

    # Before any authentications happen connections are not denied.
    #
    assert auth.check_deny(sess.peer) is False

    # We do a bunch of bad auths in quick succession. access will now be denied.
    #
    for _ in range(Authenticator.MAX_NUM_AUTH_FAILURES):
        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(faker.pystr(), "utf-8"),
        )
        res = await auth(None, sess, None, mechanism, auth_data)
        assert res.success is False

    # Failure is denied. Failure should be denied for all auths in the next
    # AUTH_FAILURE_EXPIRY.
    #
    assert auth.check_deny(sess.peer)
    deny = auth.blacklist[sess.peer[0]]
    assert deny.expiry >= now + auth.AUTH_FAILURE_EXPIRY

    # Reset expiry back to `now` so that the next check will not be denied. It
    # is important to note that when a client connects we check during EHLO,
    # which is before authentication. If the protocol was such that
    # `check_deny()` happened AFTER authentication, then on failed connection
    # attempts the black list would never get a chance to expire (we expire
    # when we check, not when we increment the number of failures.)
    #
    deny.expiry = now
    assert auth.check_deny(sess.peer) is False
    assert sess.peer[0] not in auth.blacklist

    res = await auth(None, sess, None, mechanism, auth_data)
    assert res.success is False
    assert sess.peer[0] in auth.blacklist


####################################################################
#
@pytest.mark.asyncio
async def test_relayhandler_handle_EHLO(
    tmp_path, faker, aiosmtp_session, aiosmtp_envelope
):
    """
    the EHLO handler is where we deny connections from hosts on the
    authenticator's blacklist.
    """
    sess = aiosmtp_session
    authenticator = Authenticator()
    handler = RelayHandler(tmp_path, authenticator)
    smtp = SMTP(handler, authenticator=authenticator)
    envelope = aiosmtp_envelope()
    hostname = faker.hostname()

    # does a `check_deny()` against the session.peer. Okay on the first access.
    responses = await handler.handle_EHLO(smtp, sess, envelope, hostname, [])
    assert len(responses) == 0
    assert sess.host_name == hostname

    # However, if this peer has failed to authenticate multiple times then we
    # will deny them.
    #
    authenticator.incr_fails(sess.peer)
    authenticator.blacklist[sess.peer[0]].num_fails = (
        Authenticator.MAX_NUM_AUTH_FAILURES + 1
    )

    responses = await handler.handle_EHLO(smtp, sess, envelope, hostname, [])
    assert len(responses) == 1
    assert responses[0].startswith("550 ")


####################################################################
#
@pytest.mark.asyncio
async def test_relayhandler_handle_MAIL(
    email_account_factory, faker, aiosmtp_session, aiosmtp_envelope
):
    """
    the `handle_MAIL` is where we set the `mail_from` attribute of the
    SMTPEnvelolope. This is where we make sure that the email account relaying
    through aiosmtpd is using their FROM address (because we only allow them to
    send email from the email address associated with their email account.
    """
    ea = await sync_to_async(email_account_factory)()
    await ea.asave()

    sess = aiosmtp_session
    sess.auth_data = ea
    authenticator = Authenticator()
    handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)
    smtp = SMTP(handler, authenticator=authenticator)
    envelope = aiosmtp_envelope()

    # from address is valid as long as the email part is the same as the
    # ea.email_address.
    #
    from_address = ea.email_address
    response = await handler.handle_MAIL(smtp, sess, envelope, from_address, [])
    assert response.startswith("250 OK")
    assert envelope.mail_from == from_address

    # Even saying you are someone else is okay, as long as your email address
    # is your email address.
    #
    from_address = f"{faker.name()} <{ea.email_address}>"
    response = await handler.handle_MAIL(smtp, sess, envelope, from_address, [])
    assert response.startswith("250 OK")
    assert envelope.mail_from == from_address

    # However anyother email address, even from the same domain will be denied.
    #
    from_address = faker.email()
    response = await handler.handle_MAIL(smtp, sess, envelope, from_address, [])
    assert response.startswith("551 ")
    # NOTE: mail_from is set even if we deny them.
    assert envelope.mail_from == from_address

    # Different username, same domain.
    #
    from_address = f"{faker.user_name()}@{ea.email_address.split('@')[1]}"
    response = await handler.handle_MAIL(smtp, sess, envelope, from_address, [])
    assert response.startswith("551 ")
    assert envelope.mail_from == from_address


####################################################################
#
@pytest.mark.asyncio
async def test_relayhandler_handle_DATA(
    email_account_factory, faker, aiosmtp_session, aiosmtp_envelope, smtp
):
    ea = await sync_to_async(email_account_factory)()
    await ea.asave()

    to = faker.email()

    sess = aiosmtp_session
    sess.auth_data = ea
    authenticator = Authenticator()
    handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)
    aio_smtp = SMTP(handler, authenticator=authenticator)
    envelope = aiosmtp_envelope(msg_from=ea.email_address, to=to)
    envelope.mail_from = ea.email_address

    response = await handler.handle_DATA(aio_smtp, sess, envelope)
    assert response.startswith("250 ")

    send_message = smtp.return_value.send_message
    assert send_message.call_count == 1
    assert send_message.call_args.kwargs == {
        "from_addr": ea.email_address,
        "to_addrs": [to],
    }

    msg = email.message_from_bytes(
        envelope.original_content,
        policy=email.policy.default,
    )
    sent_message = send_message.call_args.args[0]
    assert sent_message["From"] == ea.email_address
    assert sent_message["To"] == to
    assert sent_message["Subject"] == msg["Subject"]

    assert_email_equal(msg, sent_message, ignore_headers=True)

    # If you stick a `From` header in to the message that is NOT your valid
    # from email address, this will fail and the email will not be sent.
    #
    # NOTE: by not supplying msg_from the email generated by
    #       `aiosmtp_envelope()` will have a random from email address that
    #       does NOT match ea.email_address and thus should be denied because
    #       it is the the email account trying to send email
    #
    envelope = aiosmtp_envelope()
    envelope.mail_from = ea.email_address
    msg = email.message_from_bytes(
        envelope.original_content,
        policy=email.policy.default,
    )
    assert parseaddr(msg["From"]) != ea.email_address

    response = await handler.handle_DATA(aio_smtp, sess, envelope)
    assert response.startswith("551 ")

    # '1' because this is the same mock object as before, and its count should
    # not have increased from the previous time in this test.
    #
    assert send_message.call_count == 1


####################################################################
#
@pytest.mark.asyncio
async def test_relay_email_to_provider(
    email_account_factory, email_factory, inactive_email_factory, faker, smtp
):
    """
    Make sure that the function used to relay email to the provider filters
    out inactive emails from recipients, and send a DSN to the email account
    that tried to send email to inactive emails.
    """
    ea = await sync_to_async(email_account_factory)()
    await ea.asave()

    inactives = []
    for _ in range(5):
        inact = inactive_email_factory()
        await inact.asave()
        inactives.append(inact)

    inactive_emails = []
    async for inactive in InactiveEmail.objects.all():
        inactive_emails.append(inactive)

    # If we sending email to just one inactive address it is not delivered to
    # anyone, but a DSN is delivered to the email account that tried to send
    # the message.
    #
    inactive = inactive_emails[0].email_address
    msg = email_factory(msg_from=ea.email_address, to=inactive)
    await relay_email_to_provider(ea, [inactive], msg)

    # First, no email should have been sent to the provider.
    #
    send_message = smtp.return_value.send_message
    assert send_message.call_count == 0

    # Second, the email account will have a single message delivered to its
    # inbox (via local delivery) that is our DSN
    #
    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)

    from_addr = f"mailer-daemon@{ea.server.domain_name}"
    assert stored_msg["From"] == from_addr
    assert stored_msg["To"] == ea.email_address
    assert (
        stored_msg["Subject"]
        == "NOTICE: Email not sent due to destination address marked as inactive"
    )
    assert stored_msg.is_multipart()

    # There should only be one rfc822 part on the message. This should be the
    # message that was being sent.
    #
    for part in stored_msg.walk():
        if part.get_content_type == "message/rfc822":
            assert part.get_content().as_bytes() == msg.as_bytes()
            break

    # Do a similar test, but send to one valid email and one inactive email.
    # We will still get a bounce, but the non-inactve email will be sent the
    # message.
    #
    inactive = inactive_emails[0].email_address
    to = faker.email()
    msg = email_factory(msg_from=ea.email_address, to=to, cc=inactive)
    await relay_email_to_provider(ea, [to, inactive], msg)

    stored_msg = folder.get(2)

    from_addr = f"mailer-daemon@{ea.server.domain_name}"
    assert stored_msg["From"] == from_addr
    assert stored_msg["To"] == ea.email_address
    assert (
        stored_msg["Subject"]
        == "NOTICE: Email not sent due to destination address marked as inactive"
    )

    # And a message was sent..
    #
    assert send_message.call_count == 1
    assert send_message.call_args.kwargs == {
        "from_addr": ea.email_address,
        "to_addrs": [to],
    }

    sent_message = send_message.call_args.args[0]
    assert sent_message["From"] == ea.email_address
    assert sent_message["To"] == to
    assert sent_message["Subject"] == msg["Subject"]

    assert_email_equal(msg, sent_message, ignore_headers=True)
