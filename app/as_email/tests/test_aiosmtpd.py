#!/usr/bin/env python
#
"""
Test the aiosmtpd daemon/django command.
"""
# system imports
#
from datetime import UTC, datetime
from email.message import EmailMessage

# 3rd party imports
#
import pytest
from aiosmtpd.smtp import SMTP, LoginPassword
from asgiref.sync import sync_to_async
from dirty_equals import Contains

# Project imports
#
from ..management.commands.aiosmtpd import (
    Authenticator,
    RelayHandler,
    categorize_recipients,
    check_spam,
    format_dnsbl_providers,
    relay_email_to_provider,
    validate_from_header,
)
from ..models import InactiveEmail

pytestmark = pytest.mark.django_db


########################################################################
#
@pytest.fixture
def mock_aiospamc_process(mocker):
    """
    Fixture to mock aiospamc.process.
    Returns the mock so tests can customize return values or verify calls.
    By default returns a successful response with spam headers.
    """
    mock_result = mocker.Mock()
    mock_result.body = (
        b"X-Spam-Status: No\r\nX-Spam-Score: 0.1\r\n\r\noriginal message body"
    )

    return mocker.patch(
        "as_email.management.commands.aiosmtpd.aiospamc.process",
        new_callable=mocker.AsyncMock,
        return_value=mock_result,
    )


####################################################################
#
@pytest.fixture
def mock_tarpit_delay(mocker):
    """
    Fixture to mock tarpit_delay to avoid waiting during tests.
    Returns the mock so tests can verify it was called if needed.
    """
    return mocker.patch(
        "as_email.management.commands.aiosmtpd.tarpit_delay",
        new_callable=mocker.AsyncMock,
    )


########################################################################
########################################################################
#
class TestHelperFunctions:
    """Tests for standalone helper functions."""

    ####################################################################
    #
    def test_format_dnsbl_providers_empty(self):
        """
        Given an empty list of DNSBL providers
        When format_dnsbl_providers is called
        Then it should return an empty string
        """
        result = format_dnsbl_providers([])
        assert result == ""

    ####################################################################
    #
    def test_format_dnsbl_providers_single_provider_single_category(self):
        """
        Given a single DNSBL provider with one category
        When format_dnsbl_providers is called
        Then it should return "provider: category" format
        """
        providers = [("spamhaus.org", ["spam"])]
        result = format_dnsbl_providers(providers)
        assert result == "spamhaus.org: spam"

    ####################################################################
    #
    def test_format_dnsbl_providers_single_provider_multiple_categories(self):
        """
        Given a single DNSBL provider with multiple categories
        When format_dnsbl_providers is called
        Then it should return categories comma-separated
        """
        providers = [("spamhaus.org", ["spam", "malware"])]
        result = format_dnsbl_providers(providers)
        assert result == "spamhaus.org: spam,malware"

    ####################################################################
    #
    def test_format_dnsbl_providers_multiple_providers(self):
        """
        Given multiple DNSBL providers with various categories
        When format_dnsbl_providers is called
        Then it should return all providers comma-separated
        """
        providers = [
            ("spamhaus.org", ["spam"]),
            ("barracuda.com", ["malware", "phishing"]),
        ]
        result = format_dnsbl_providers(providers)
        assert "spamhaus.org: spam" in result
        assert "barracuda.com: malware,phishing" in result

    ####################################################################
    #
    def test_validate_from_header_unauthenticated(self, email_factory):
        """
        Given an unauthenticated session (no account)
        When validate_from_header is called
        Then it should return None (no validation required)
        """
        msg = email_factory()
        result = validate_from_header(msg, None)
        assert result is None

    ####################################################################
    #
    def test_validate_from_header_no_from_headers(self, email_account_factory):
        """
        Given a message with no FROM headers
        When validate_from_header is called
        Then it should return None (pass validation)
        """
        ea = email_account_factory()
        msg = EmailMessage()
        result = validate_from_header(msg, ea)
        assert result is None

    ####################################################################
    #
    def test_validate_from_header_valid_match(
        self, email_account_factory, email_factory
    ):
        """
        Given a message with FROM matching the authenticated account
        When validate_from_header is called
        Then it should return None (validation passes)
        """
        ea = email_account_factory()
        msg = email_factory(msg_from=ea.email_address)
        result = validate_from_header(msg, ea)
        assert result is None

    ####################################################################
    #
    def test_validate_from_header_with_display_name(
        self, email_account_factory, email_factory, faker
    ):
        """
        Given a message with display name but valid email in FROM
        When validate_from_header is called
        Then it should return None (display name allowed)
        """
        ea = email_account_factory()
        from_with_name = f"{faker.name()} <{ea.email_address}>"
        msg = email_factory(msg_from=from_with_name)
        result = validate_from_header(msg, ea)
        assert result is None

    ####################################################################
    #
    def test_validate_from_header_invalid_mismatch(
        self, email_account_factory, email_factory, faker
    ):
        """
        Given a message with FROM not matching the authenticated account
        When validate_from_header is called
        Then it should return an error message starting with "551 FROM must be"
        """
        ea = email_account_factory()
        msg = email_factory(msg_from=faker.email())
        result = validate_from_header(msg, ea)
        assert result is not None
        assert result.startswith("551 FROM must be")

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_check_spam_success(self, mock_aiospamc_process, mocker):
        """
        Given aiospamc.process that successfully processes a message
        When check_spam is called
        Then it should return the message body with spam headers added
        """
        # Customize the mock result for this test
        mock_result = mocker.Mock()
        mock_result.body = b"message with spam headers"
        mock_aiospamc_process.return_value = mock_result

        original = b"original message"
        result = await check_spam(original)

        assert result == b"message with spam headers"
        mock_aiospamc_process.assert_called_once_with(
            original, host=mocker.ANY, port=mocker.ANY
        )

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_check_spam_failure(self, mock_aiospamc_process):
        """
        Given aiospamc.process that raises an exception
        When check_spam is called
        Then it should return the original message unmodified
        And the error should be logged
        """
        # Configure the mock to raise an exception
        mock_aiospamc_process.side_effect = Exception("Connection failed")

        original = b"original message"
        result = await check_spam(original)

        assert result == original

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_categorize_recipients_all_local(self, email_account_factory):
        """
        Given a list of email addresses that all have local EmailAccounts
        When categorize_recipients is called
        Then all addresses should be categorized as local
        And remote and invalid lists should be empty
        """
        ea1 = await sync_to_async(email_account_factory)()
        ea2 = await sync_to_async(email_account_factory)()
        await ea1.asave()
        await ea2.asave()

        local, remote, invalid = await categorize_recipients(
            [ea1.email_address, ea2.email_address]
        )

        assert len(local) == 2
        assert len(remote) == 0
        assert len(invalid) == 0
        assert ea1.email_address.lower() in local
        assert ea2.email_address.lower() in local

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_categorize_recipients_all_remote(self, faker):
        """
        Given a list of email addresses on external domains
        When categorize_recipients is called
        Then all addresses should be categorized as remote
        And local and invalid lists should be empty
        """
        remote_addrs = [faker.email(), faker.email()]

        local, remote, invalid = await categorize_recipients(remote_addrs)

        assert len(local) == 0
        assert len(remote) == 2
        assert len(invalid) == 0

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_categorize_recipients_mixed(
        self, email_account_factory, faker
    ):
        """
        Given a list with both local and remote email addresses
        When categorize_recipients is called
        Then addresses should be correctly categorized as local or remote
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()
        remote_addr = faker.email()

        local, remote, invalid = await categorize_recipients(
            [ea.email_address, remote_addr]
        )

        assert len(local) == 1
        assert len(remote) == 1
        assert len(invalid) == 0
        assert ea.email_address.lower() in local
        assert remote_addr in remote

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_categorize_recipients_invalid_local(
        self, server_factory, faker
    ):
        """
        Given an email address on our domain but with no EmailAccount
        When categorize_recipients is called
        Then the address should be categorized as invalid
        """
        server = await sync_to_async(server_factory)()
        await server.asave()
        invalid_addr = f"{faker.user_name()}@{server.domain_name}"

        local, remote, invalid = await categorize_recipients([invalid_addr])

        assert len(local) == 0
        assert len(remote) == 0
        assert len(invalid) == 1
        assert invalid_addr.lower() in invalid

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_categorize_recipients_case_insensitive(
        self, email_account_factory
    ):
        """
        Given an email address with uppercase characters
        When categorize_recipients is called
        Then it should match case-insensitively and normalize to lowercase
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        # Test with uppercase version
        upper_addr = ea.email_address.upper()
        local, remote, invalid = await categorize_recipients([upper_addr])

        assert len(local) == 1
        assert len(remote) == 0
        assert len(invalid) == 0
        assert ea.email_address.lower() in local


########################################################################
########################################################################
#
class TestAuthentication:
    """Tests for authentication and authorization."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_authenticator_authenticate_success(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given valid credentials for an active EmailAccount
        When authenticating with LOGIN or PLAIN mechanism
        Then authentication should succeed
        And the account should be returned in auth_data
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

        for mechanism in ("LOGIN", "PLAIN"):
            auth_data = LoginPassword(
                login=bytes(ea.email_address, "utf-8"),
                password=bytes(password, "utf-8"),
            )
            res = await auth(None, sess, None, mechanism, auth_data)
            assert res.success
            assert res.auth_data == ea

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_authenticator_invalid_password(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given valid account credentials with incorrect password
        When authenticating
        Then authentication should fail
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(faker.pystr(), "utf-8"),
        )
        res = await auth(None, sess, None, "LOGIN", auth_data)
        assert res.success is False

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_authenticator_invalid_account(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given credentials for a non-existent account
        When authenticating
        Then authentication should fail
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

        auth_data = LoginPassword(
            login=bytes(faker.email(), "utf-8"),
            password=bytes(password, "utf-8"),
        )
        res = await auth(None, sess, None, "LOGIN", auth_data)
        assert res.success is False

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_authenticator_deactivated_account(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given valid credentials for a deactivated account
        When authenticating
        Then authentication should fail
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

        ea.deactivated = True
        await ea.asave()

        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(password, "utf-8"),
        )
        res = await auth(None, sess, None, "LOGIN", auth_data)
        assert res.success is False

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_authenticator_unsupported_mechanisms(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given valid credentials but unsupported authentication mechanism
        When authenticating with mechanisms other than LOGIN or PLAIN
        Then authentication should fail
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

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
    async def test_authenticator_blacklist_mechanism(
        self, email_account_factory, faker, aiosmtp_session
    ):
        """
        Given a peer with repeated authentication failures
        When the number of failures exceeds MAX_NUM_AUTH_FAILURES
        Then the peer should be blacklisted
        And access should be denied until expiry time passes
        """
        sess = aiosmtp_session
        password = faker.pystr(min_chars=8, max_chars=32)
        ea = await sync_to_async(email_account_factory)(password=password)
        await ea.asave()
        auth = Authenticator()

        now = datetime.now(UTC)

        # Before any authentications, connections are not denied
        assert auth.check_deny(sess.peer) is False

        # Single failed auth still allows access
        auth_data = LoginPassword(
            login=bytes(ea.email_address, "utf-8"),
            password=bytes(faker.pystr(), "utf-8"),
        )
        res = await auth(None, sess, None, "LOGIN", auth_data)
        assert res.success is False
        assert auth.check_deny(sess.peer) is False

        # Multiple failed auths trigger denial
        for _ in range(Authenticator.MAX_NUM_AUTH_FAILURES):
            auth_data = LoginPassword(
                login=bytes(ea.email_address, "utf-8"),
                password=bytes(faker.pystr(), "utf-8"),
            )
            res = await auth(None, sess, None, "LOGIN", auth_data)
            assert res.success is False

        # Now access is denied
        assert auth.check_deny(sess.peer)
        deny = auth.blacklist[sess.peer[0]]
        assert deny.expiry >= now + auth.AUTH_FAILURE_EXPIRY

        # Expiry works - reset to past and check is no longer denied
        deny.expiry = now
        assert auth.check_deny(sess.peer) is False
        assert sess.peer[0] not in auth.blacklist

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_relayhandler_handle_EHLO_denies_blacklisted(
        self,
        tmp_path,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mock_tarpit_delay,
    ):
        """
        Given a peer that has been blacklisted for auth failures
        When handle_EHLO is called
        Then the connection should be denied with a 550 error
        """
        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()
        hostname = faker.hostname()

        # First access is okay
        responses = await handler.handle_EHLO(
            smtp, sess, envelope, hostname, []
        )
        assert len(responses) == 0
        assert sess.host_name == hostname

        # Blacklist the peer
        authenticator.incr_fails(sess.peer)
        authenticator.blacklist[sess.peer[0]].num_fails = (
            Authenticator.MAX_NUM_AUTH_FAILURES + 1
        )

        # Now they're denied
        responses = await handler.handle_EHLO(
            smtp, sess, envelope, hostname, []
        )
        assert len(responses) == 1
        assert responses[0].startswith("550 ")


########################################################################
########################################################################
#
class TestSMTPHandlers:
    """Tests for SMTP protocol handlers."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_MAIL_authenticated(
        self, email_account_factory, faker, aiosmtp_session, aiosmtp_envelope
    ):
        """
        Given an authenticated SMTP session
        When handle_MAIL is called with any FROM address
        Then the request should be accepted (validation happens in handle_DATA)
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea
        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        # Any FROM is accepted (validation happens in handle_DATA)
        from_address = ea.email_address
        response = await handler.handle_MAIL(
            smtp, sess, envelope, from_address, []
        )
        assert response.startswith("250 OK")
        assert envelope.mail_from == from_address

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_MAIL_unauthenticated(
        self, faker, aiosmtp_session, aiosmtp_envelope, tmp_path
    ):
        """
        Given an unauthenticated SMTP session
        When handle_MAIL is called with any FROM address
        Then the request should be accepted (needed for incoming mail)
        """
        sess = aiosmtp_session
        sess.authenticated = False
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        # Any FROM is accepted (needed for incoming mail)
        from_address = faker.email()
        response = await handler.handle_MAIL(
            smtp, sess, envelope, from_address, []
        )
        assert response.startswith("250 OK")
        assert envelope.mail_from == from_address


########################################################################
########################################################################
#
class TestRecipientHandling:
    """Tests for recipient categorization and delivery."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_unauthenticated_to_local(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an unauthenticated SMTP session sending to a local address
        When handle_DATA is called
        Then the message should be accepted and delivered locally
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        # Mock external services
        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)
        envelope.rcpt_tos = [ea.email_address]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 OK")
        mock_deliver_local.assert_called_once()
        assert ea.email_address.lower() in mock_deliver_local.call_args[0][1]

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_unauthenticated_to_remote(
        self,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an unauthenticated SMTP session sending to a remote address
        When handle_DATA is called
        Then the request should be rejected with "530 Authentication required"
        """
        sess = aiosmtp_session
        sess.authenticated = False

        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        remote_addr = faker.email()
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=remote_addr)
        envelope.rcpt_tos = [remote_addr]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("530 Authentication required")

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_unauthenticated_mixed_recipients(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an unauthenticated session sending to local and remote addresses
        When handle_DATA is called
        Then the request should be rejected (authentication required for relay)
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        remote_addr = faker.email()
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)
        envelope.rcpt_tos = [ea.email_address, remote_addr]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("530 Authentication required")

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_authenticated_to_remote(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an authenticated session sending to a remote address
        When handle_DATA is called
        Then the message should be relayed to the mail provider
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea.email_address, to=to)
        envelope.rcpt_tos = [to]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 ")
        send_message = smtp.return_value.sendmail
        assert send_message.call_count == 1

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_authenticated_mixed_recipients(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an authenticated session sending to both local and remote addresses
        When handle_DATA is called
        Then messages should be delivered locally AND relayed to provider
        """
        ea1 = await sync_to_async(email_account_factory)()
        await ea1.asave()
        ea2 = await sync_to_async(email_account_factory)()
        await ea2.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea1

        # Mock deliver_email_locally
        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        authenticator = Authenticator()
        handler = RelayHandler(ea1.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        remote_to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea1.email_address, to=remote_to)
        envelope.rcpt_tos = [ea2.email_address, remote_to]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 OK")
        # Both local delivery and relay should be called
        mock_deliver_local.assert_called_once()
        smtp.return_value.sendmail.assert_called_once()

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_invalid_local_addresses_only(
        self,
        server_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given a message sent only to invalid local addresses (domain exists, no account)
        When handle_DATA is called
        Then the request should be rejected with "550 5.1.1 Recipient address rejected"
        """
        server = await sync_to_async(server_factory)()
        await server.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        authenticator = Authenticator()
        handler = RelayHandler(server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        invalid_addr = f"{faker.user_name()}@{server.domain_name}"
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=invalid_addr)
        envelope.rcpt_tos = [invalid_addr]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("550 5.1.1 Recipient address rejected")
        assert invalid_addr.lower() in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_some_invalid_local_addresses(
        self,
        email_account_factory,
        server_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given a message with both valid and invalid local addresses
        When handle_DATA is called
        Then the message should be delivered only to valid addresses
        And a warning should be logged for invalid addresses
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        invalid_addr = f"{faker.user_name()}@{ea.server.domain_name}"
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)
        envelope.rcpt_tos = [ea.email_address, invalid_addr]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        # Should succeed but only deliver to valid address
        assert response.startswith("250 OK")
        mock_deliver_local.assert_called_once()
        # Only valid address in delivery list
        assert ea.email_address.lower() in mock_deliver_local.call_args[0][1]
        assert len(mock_deliver_local.call_args[0][1]) == 1


########################################################################
########################################################################
#
class TestFromHeaderValidation:
    """Tests for FROM header validation in handle_DATA."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_authenticated_valid_from(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an authenticated session with correct FROM header
        When handle_DATA is called
        Then the message should be accepted and relayed
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea.email_address, to=to)
        envelope.rcpt_tos = [to]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 ")

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_authenticated_invalid_from(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an authenticated session with wrong FROM header
        When handle_DATA is called
        Then the request should be rejected with "551 FROM must be"
        And no message should be sent
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        # Envelope has wrong FROM address in message body
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=to)
        envelope.rcpt_tos = [to]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("551 FROM must be")
        # Message should not be sent
        assert smtp.return_value.sendmail.call_count == 0


########################################################################
########################################################################
#
class TestDNSBL:
    """Tests for DNSBL checking in handle_CONNECT."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_CONNECT_not_blacklisted(
        self, aiosmtp_session, aiosmtp_envelope, tmp_path, mocker
    ):
        """
        Given a connecting IP that is not on any DNSBL
        When handle_CONNECT is called
        Then the connection should be accepted with "220 OK"
        """
        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)

        # Mock DNSBL check - not blacklisted
        mock_result = mocker.Mock()
        mock_result.blacklisted = False
        handler.dnsbl = mocker.AsyncMock()
        handler.dnsbl.check = mocker.AsyncMock(return_value=mock_result)

        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        response = await handler.handle_CONNECT(
            smtp_server, sess, envelope, "hostname", 25
        )

        assert response == "220 OK"

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_CONNECT_blacklisted(
        self, aiosmtp_session, aiosmtp_envelope, tmp_path, mocker
    ):
        """
        Given a connecting IP that is on a DNSBL
        When handle_CONNECT is called
        Then the connection should be rejected with "554 Your IP is blacklisted"
        And a tarpit delay should be applied
        """
        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)

        # Mock DNSBL check - blacklisted
        mock_result = mocker.Mock()
        mock_result.blacklisted = True
        mock_result.detected_by = [("spamhaus.org", ["spam"])]
        handler.dnsbl = mocker.AsyncMock()
        handler.dnsbl.check = mocker.AsyncMock(return_value=mock_result)

        # Mock tarpit delay to avoid waiting
        mocker.patch(
            "as_email.management.commands.aiosmtpd.tarpit_delay",
            new_callable=mocker.AsyncMock,
        )

        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        response = await handler.handle_CONNECT(
            smtp_server, sess, envelope, "hostname", 25
        )

        assert response.startswith("554 Your IP is blacklisted")


########################################################################
########################################################################
#
class TestSpamAssassinIntegration:
    """Tests for SpamAssassin spam checking."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_spam_check_success(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given a successful SpamAssassin check that adds headers
        When handle_DATA is called for local delivery
        Then the spam-checked message with headers should be delivered
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        # Mock successful spam check with headers
        spam_headers = b"X-Spam-Score: 5.0\r\nX-Spam-Status: Yes\r\n"
        mock_result = mocker.Mock()
        mock_result.body = spam_headers
        mock_aiospamc_process.return_value = mock_result

        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)
        envelope.rcpt_tos = [ea.email_address]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 OK")
        # Verify spam-checked bytes passed to deliver_email_locally
        mock_deliver_local.assert_called_once()
        assert mock_deliver_local.call_args[0][2] == spam_headers

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_spam_check_failure(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given a SpamAssassin check that fails with an exception
        When handle_DATA is called
        Then the original message should be delivered unchanged
        And the error should be logged
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False

        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        authenticator = Authenticator()
        handler = RelayHandler(ea.server.outgoing_spool_dir, authenticator)

        # Mock spam check failure
        mock_aiospamc_process.side_effect = Exception(
            "SpamAssassin connection failed"
        )

        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)
        envelope.rcpt_tos = [ea.email_address]

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        # Should still succeed
        assert response.startswith("250 OK")
        # Should deliver original message
        mock_deliver_local.assert_called_once()
        assert mock_deliver_local.call_args[0][2] == envelope.original_content


########################################################################
########################################################################
#
class TestRelayToProvider:
    """Tests for relay_email_to_provider function."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_relay_email_to_provider_filters_inactives(
        self,
        email_account_factory,
        email_factory,
        inactive_email_factory,
        faker,
        smtp,
    ):
        """
        Given a message sent only to inactive email addresses
        When relay_email_to_provider is called
        Then no message should be sent to the provider
        And a delivery status notification should be sent to the sender
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

        # Send to only inactive address
        inactive = inactive_emails[0].email_address
        msg = email_factory(msg_from=ea.email_address, to=inactive)
        await relay_email_to_provider(ea, [inactive], msg)

        # No email sent to provider
        send_message = smtp.return_value.sendmail
        assert send_message.call_count == 0

        # DSN delivered locally
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

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_relay_email_to_provider_mixed_valid_inactive(
        self,
        email_account_factory,
        email_factory,
        inactive_email_factory,
        faker,
        smtp,
    ):
        """
        Given a message sent to both valid and inactive addresses
        When relay_email_to_provider is called
        Then the message should be sent only to valid addresses
        And a delivery status notification should be sent for inactive addresses
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        inact = inactive_email_factory()
        await inact.asave()

        inactive = inact.email_address
        to = faker.email()
        msg = email_factory(msg_from=ea.email_address, to=to, cc=inactive)
        await relay_email_to_provider(ea, [to, inactive], msg)

        # Message sent to valid address
        send_message = smtp.return_value.sendmail
        assert send_message.call_count == 1
        assert send_message.call_args.args == Contains(
            ea.email_address,
            [to],
        )

        # DSN also sent
        mh = ea.MH()
        folder = mh.get_folder("inbox")
        stored_msg = folder.get(1)
        assert (
            stored_msg["Subject"]
            == "NOTICE: Email not sent due to destination address marked as inactive"
        )
