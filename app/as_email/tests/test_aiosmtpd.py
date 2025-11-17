#!/usr/bin/env python
#
"""
Test the aiosmtpd daemon/django command.
"""
# system imports
#
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

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
        Then authentication should succeed
        (Deactivated accounts are blocked from relaying in handle_RCPT, not here)
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
        assert res.success is True
        assert res.auth_data == ea
        assert res.auth_data.deactivated is True

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
    async def test_relayhandler_handle_CONNECT_denies_blacklisted(
        self,
        tmp_path,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mock_tarpit_delay,
        mocker,
    ):
        """
        Given a peer that has been blacklisted for auth failures
        When handle_CONNECT is called
        Then the connection should be denied with a 554 error
        """
        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()
        hostname = faker.hostname()

        # Mock DNSBL check - not blacklisted
        mock_result = mocker.Mock()
        mock_result.blacklisted = False
        handler.dnsbl = mocker.AsyncMock()
        handler.dnsbl.check = mocker.AsyncMock(return_value=mock_result)

        # First connection is okay (not blacklisted yet)
        response = await handler.handle_CONNECT(
            smtp, sess, envelope, hostname, 25
        )
        assert response == "220 OK"

        # Blacklist the peer for auth failures
        authenticator.incr_fails(sess.peer)
        authenticator.blacklist[sess.peer[0]].num_fails = (
            Authenticator.MAX_NUM_AUTH_FAILURES + 1
        )

        # Now they're denied at connection time (auth failure blacklist)
        response = await handler.handle_CONNECT(
            smtp, sess, envelope, hostname, 25
        )
        assert response.startswith("554")


########################################################################
########################################################################
#
class TestHandleMAIL:
    """Tests for handle_MAIL SMTP command handler."""

    ####################################################################
    #
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "from_type,deactivated,case_transform,expected_account",
        [
            ("local", False, None, "same"),  # Local active account
            (
                "local",
                True,
                None,
                "same",
            ),  # Local deactivated account (cached for RCPT check)
            ("local", False, str.upper, "same"),  # Case-insensitive lookup
            ("remote", False, None, None),  # Remote address, no account
        ],
    )
    async def test_handle_MAIL_caches_from_account(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
        from_type,
        deactivated,
        case_transform,
        expected_account,
    ):
        """
        Given MAIL FROM with various address types
        When handle_MAIL is called
        Then the request should be accepted (250 OK)
        And envelope.mail_from_account should be cached correctly
        """
        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        if from_type == "local":
            ea = await sync_to_async(email_account_factory)()
            if deactivated:
                ea.deactivated = True
            await ea.asave()
            from_address = ea.email_address
            if case_transform:
                from_address = case_transform(from_address)
        else:
            ea = None
            from_address = faker.email()

        response = await handler.handle_MAIL(
            smtp, sess, envelope, from_address, []
        )

        assert response.startswith("250 OK")
        assert envelope.mail_from == from_address

        if expected_account == "same":
            assert envelope.mail_from_account == ea
            if deactivated:
                assert envelope.mail_from_account.deactivated is True
        elif expected_account is None:
            assert envelope.mail_from_account is None


########################################################################
########################################################################
#
class TestHandleRCPT:
    """Tests for handle_RCPT SMTP command handler."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_local_valid_recipient(
        self, email_account_factory, aiosmtp_session, aiosmtp_envelope, tmp_path
    ):
        """
        Given RCPT TO with a valid local EmailAccount
        When handle_RCPT is called
        Then the request should be accepted without authentication
        And the recipient should be added to envelope.rcpt_tos
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        response = await handler.handle_RCPT(
            smtp, sess, envelope, ea.email_address, []
        )
        assert response == "250 OK"
        assert ea.email_address in envelope.rcpt_tos

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_local_invalid_recipient(
        self, server_factory, faker, aiosmtp_session, aiosmtp_envelope, tmp_path
    ):
        """
        Given RCPT TO with an address on our domain but no EmailAccount exists
        When handle_RCPT is called
        Then the request should be rejected with "550 5.1.1 User unknown"
        """
        server = await sync_to_async(server_factory)()
        await server.asave()

        sess = aiosmtp_session
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        invalid_addr = f"{faker.user_name()}@{server.domain_name}"
        response = await handler.handle_RCPT(
            smtp, sess, envelope, invalid_addr, []
        )
        assert response.startswith("550 5.1.1")
        assert "User unknown" in response
        assert invalid_addr in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_remote_unauthenticated(
        self, faker, aiosmtp_session, aiosmtp_envelope, tmp_path
    ):
        """
        Given RCPT TO with a remote address and no authentication
        When handle_RCPT is called
        Then the request should be rejected with "530 Authentication required"
        """
        sess = aiosmtp_session
        sess.authenticated = False
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        remote_addr = faker.email()
        response = await handler.handle_RCPT(
            smtp, sess, envelope, remote_addr, []
        )
        assert response.startswith("530")
        assert "Authentication required" in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_remote_authenticated(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
    ):
        """
        Given RCPT TO with a remote address and authenticated session
        When handle_RCPT is called
        Then the request should be accepted
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        remote_addr = faker.email()
        response = await handler.handle_RCPT(
            smtp, sess, envelope, remote_addr, []
        )
        assert response == "250 OK"
        assert remote_addr in envelope.rcpt_tos

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_remote_from_deactivated_local_account(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
    ):
        """
        Given MAIL FROM is a deactivated local account
        And RCPT TO is a remote address
        When handle_RCPT is called
        Then the request should be rejected with "550 Account is deactivated"
        And no authentication is required to reject
        """
        ea = await sync_to_async(email_account_factory)()
        ea.deactivated = True
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        # First set MAIL FROM to cache the account
        await handler.handle_MAIL(smtp, sess, envelope, ea.email_address, [])

        # Now try to relay
        remote_addr = faker.email()
        response = await handler.handle_RCPT(
            smtp, sess, envelope, remote_addr, []
        )
        assert response.startswith("550")
        assert "deactivated" in response
        assert "cannot relay" in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_remote_from_active_local_account_unauthenticated(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
    ):
        """
        Given MAIL FROM is an active local account but session is not authenticated
        And RCPT TO is a remote address
        When handle_RCPT is called
        Then authentication should still be required
        """
        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        sess = aiosmtp_session
        sess.authenticated = False
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        # Set MAIL FROM
        await handler.handle_MAIL(smtp, sess, envelope, ea.email_address, [])

        # Try to relay without authentication
        remote_addr = faker.email()
        response = await handler.handle_RCPT(
            smtp, sess, envelope, remote_addr, []
        )
        assert response.startswith("530")
        assert "Authentication required" in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_RCPT_multiple_recipients(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
    ):
        """
        Given multiple RCPT TO commands (local and remote)
        When handle_RCPT is called multiple times
        Then each should be validated independently
        And all valid recipients should be added to envelope
        """
        ea1 = await sync_to_async(email_account_factory)()
        await ea1.asave()
        ea2 = await sync_to_async(email_account_factory)()
        await ea2.asave()

        sess = aiosmtp_session
        sess.authenticated = True
        sess.auth_data = ea1
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope()

        remote_addr = faker.email()

        # Add local recipient
        response = await handler.handle_RCPT(
            smtp, sess, envelope, ea2.email_address, []
        )
        assert response == "250 OK"

        # Add remote recipient
        response = await handler.handle_RCPT(
            smtp, sess, envelope, remote_addr, []
        )
        assert response == "250 OK"

        assert len(envelope.rcpt_tos) == 2
        assert ea2.email_address in envelope.rcpt_tos
        assert remote_addr in envelope.rcpt_tos


########################################################################
########################################################################
#
class TestHandleDATA:
    """Tests for handle_DATA SMTP command handler."""

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_local_delivery(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
        tmp_path,
    ):
        """
        Given a valid SMTP transaction with local recipient
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
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope(msg_from=faker.email(), to=ea.email_address)

        # Simulate proper SMTP flow: MAIL FROM -> RCPT TO -> DATA
        await handler.handle_MAIL(
            smtp_server, sess, envelope, faker.email(), []
        )
        await handler.handle_RCPT(
            smtp_server, sess, envelope, ea.email_address, []
        )

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 OK")
        mock_deliver_local.assert_called_once()
        assert ea.email_address.lower() in mock_deliver_local.call_args[0][1]

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_no_valid_recipients(
        self,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        tmp_path,
        mocker,
        mock_aiospamc_process,
    ):
        """
        Given an envelope with no valid recipients (all rejected in RCPT)
        When handle_DATA is called
        Then the request should be rejected with "554 no valid recipients"
        """
        sess = aiosmtp_session
        sess.authenticated = False

        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        from_addr = faker.email()
        envelope = aiosmtp_envelope(msg_from=from_addr, to=faker.email())

        # Simulate MAIL FROM but no successful RCPT TO
        # This means all recipients were rejected in RCPT
        await handler.handle_MAIL(smtp_server, sess, envelope, from_addr, [])
        # Don't call handle_RCPT - clear rcpt_tos to simulate all rejected
        envelope.rcpt_tos = []

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("554")
        assert "no valid recipients" in response

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_relay_to_remote(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea.email_address, to=to)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(
            smtp_server, sess, envelope, ea.email_address, []
        )
        await handler.handle_RCPT(smtp_server, sess, envelope, to, [])

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 ")
        assert smtp.sendmail.call_count == 1

    ####################################################################
    #
    @pytest.mark.asyncio
    async def test_handle_DATA_mixed_local_and_remote(
        self,
        email_account_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        smtp,
        mocker,
        mock_aiospamc_process,
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        remote_to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea1.email_address, to=remote_to)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(
            smtp_server, sess, envelope, ea1.email_address, []
        )
        await handler.handle_RCPT(
            smtp_server, sess, envelope, ea2.email_address, []
        )
        await handler.handle_RCPT(smtp_server, sess, envelope, remote_to, [])

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("250 OK")
        # Both local delivery and relay should be called
        mock_deliver_local.assert_called_once()
        smtp.sendmail.assert_called_once()


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
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        envelope = aiosmtp_envelope(msg_from=ea.email_address, to=to)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(
            smtp_server, sess, envelope, ea.email_address, []
        )
        await handler.handle_RCPT(smtp_server, sess, envelope, to, [])

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
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        to = faker.email()
        wrong_from = faker.email()
        # Envelope has wrong FROM address in message body
        envelope = aiosmtp_envelope(msg_from=wrong_from, to=to)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(smtp_server, sess, envelope, wrong_from, [])
        await handler.handle_RCPT(smtp_server, sess, envelope, to, [])

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        assert response.startswith("551 FROM must be")
        # Message should not be sent
        assert smtp.sendmail.call_count == 0


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
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)

        # Mock successful spam check with headers
        spam_headers = b"X-Spam-Score: 5.0\r\nX-Spam-Status: Yes\r\n"
        mock_result = mocker.Mock()
        mock_result.body = spam_headers
        mock_aiospamc_process.return_value = mock_result

        smtp_server = SMTP(handler, authenticator=authenticator)
        from_addr = faker.email()
        envelope = aiosmtp_envelope(msg_from=from_addr, to=ea.email_address)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(smtp_server, sess, envelope, from_addr, [])
        await handler.handle_RCPT(
            smtp_server, sess, envelope, ea.email_address, []
        )

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
        tmp_path,
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
        handler = RelayHandler(tmp_path, authenticator)

        # Mock spam check failure
        mock_aiospamc_process.side_effect = Exception(
            "SpamAssassin connection failed"
        )

        smtp_server = SMTP(handler, authenticator=authenticator)
        from_addr = faker.email()
        envelope = aiosmtp_envelope(msg_from=from_addr, to=ea.email_address)

        # Simulate proper SMTP flow
        await handler.handle_MAIL(smtp_server, sess, envelope, from_addr, [])
        await handler.handle_RCPT(
            smtp_server, sess, envelope, ea.email_address, []
        )

        response = await handler.handle_DATA(smtp_server, sess, envelope)

        # Should still succeed
        assert response.startswith("250 OK")
        # Should deliver original message
        mock_deliver_local.assert_called_once()
        assert mock_deliver_local.call_args[0][2] == envelope.original_content


########################################################################
########################################################################
#
class TestSMTPIntegration:
    """Integration tests for complete SMTP transactions (MAIL → RCPT → DATA)."""

    ####################################################################
    #
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "scenario,mail_from_type,rcpt_to_type,authenticated,from_deactivated,expected_rcpt_result,expected_data_result",
        [
            # Incoming mail scenarios (unauthenticated)
            (
                "incoming_to_valid_local",
                "remote",
                "local_valid",
                False,
                False,
                "250 OK",
                "250 OK",
            ),
            (
                "incoming_to_invalid_local",
                "remote",
                "local_invalid",
                False,
                False,
                "550 5.1.1",
                None,
            ),
            (
                "incoming_to_remote",
                "remote",
                "remote",
                False,
                False,
                "530",
                None,
            ),
            # Outgoing mail scenarios (authenticated)
            (
                "outgoing_to_remote",
                "local",
                "remote",
                True,
                False,
                "250 OK",
                "250 OK",
            ),
            (
                "outgoing_to_local",
                "local",
                "local_valid",
                True,
                False,
                "250 OK",
                "250 OK",
            ),
            (
                "outgoing_mixed",
                "local",
                "mixed",
                True,
                False,
                "250 OK",
                "250 OK",
            ),
            # Deactivated account scenarios
            (
                "deactivated_to_remote_unauth",
                "local",
                "remote",
                False,
                True,
                "550",
                None,
            ),
            (
                "deactivated_to_local",
                "local",
                "local_valid",
                False,
                True,
                "250 OK",
                "250 OK",
            ),
            # Authentication failures
            (
                "local_to_remote_no_auth",
                "local",
                "remote",
                False,
                False,
                "530",
                None,
            ),
        ],
    )
    async def test_smtp_transaction_flow(
        self,
        scenario,
        mail_from_type,
        rcpt_to_type,
        authenticated,
        from_deactivated,
        expected_rcpt_result,
        expected_data_result,
        email_account_factory,
        server_factory,
        faker,
        aiosmtp_session,
        aiosmtp_envelope,
        mocker,
        mock_aiospamc_process,
        smtp,
        tmp_path,
    ):
        """
        Test complete SMTP transaction flows for various scenarios.

        Scenarios tested:
        - Incoming mail (unauthenticated) to valid/invalid local addresses
        - Incoming mail attempting relay (should fail)
        - Outgoing mail (authenticated) to remote/local/mixed addresses
        - Deactivated accounts attempting to send
        - Authentication requirements for relay
        """
        # Setup accounts
        local_account = await sync_to_async(email_account_factory)()
        if from_deactivated:
            local_account.deactivated = True
        await local_account.asave()

        local_account2 = await sync_to_async(email_account_factory)()
        await local_account2.asave()

        # Setup session
        sess = aiosmtp_session
        sess.authenticated = authenticated
        if authenticated:
            sess.auth_data = local_account

        # Setup MAIL FROM
        if mail_from_type == "local":
            mail_from = local_account.email_address
        else:
            mail_from = faker.email()

        # Setup RCPT TO
        rcpt_tos = []
        if rcpt_to_type == "local_valid":
            rcpt_tos = [local_account2.email_address]
        elif rcpt_to_type == "local_invalid":
            # Invalid local address (our domain, no account)
            server = local_account.server
            invalid_addr = f"{faker.user_name()}@{server.domain_name}"
            rcpt_tos = [invalid_addr]
        elif rcpt_to_type == "remote":
            rcpt_tos = [faker.email()]
        elif rcpt_to_type == "mixed":
            rcpt_tos = [local_account2.email_address, faker.email()]

        # Mock external services
        mock_deliver_local = mocker.patch(
            "as_email.management.commands.aiosmtpd.deliver_email_locally",
            new_callable=mocker.AsyncMock,
        )

        # Setup handler
        authenticator = Authenticator()
        handler = RelayHandler(tmp_path, authenticator)
        smtp_server = SMTP(handler, authenticator=authenticator)
        envelope = aiosmtp_envelope(
            msg_from=mail_from, to=rcpt_tos[0] if rcpt_tos else faker.email()
        )

        # Execute SMTP transaction: MAIL FROM → RCPT TO → DATA

        # Step 1: MAIL FROM
        mail_response = await handler.handle_MAIL(
            smtp_server, sess, envelope, mail_from, []
        )
        assert mail_response.startswith(
            "250 OK"
        ), f"MAIL FROM failed: {mail_response}"

        # Step 2: RCPT TO (may be called multiple times for mixed)
        rcpt_responses = []
        for rcpt_to in rcpt_tos:
            rcpt_response = await handler.handle_RCPT(
                smtp_server, sess, envelope, rcpt_to, []
            )
            rcpt_responses.append(rcpt_response)

        # Check RCPT TO response
        if expected_rcpt_result:
            # For mixed scenario, check that at least one succeeds
            if rcpt_to_type == "mixed":
                assert any(
                    r.startswith("250 OK") for r in rcpt_responses
                ), f"Expected at least one RCPT OK in mixed scenario, got: {rcpt_responses}"
            else:
                assert rcpt_responses[0].startswith(
                    expected_rcpt_result
                ), f"Scenario '{scenario}': Expected RCPT '{expected_rcpt_result}', got '{rcpt_responses[0]}'"

        # Step 3: DATA (only if RCPT succeeded)
        if expected_data_result:
            data_response = await handler.handle_DATA(
                smtp_server, sess, envelope
            )
            assert data_response.startswith(
                expected_data_result
            ), f"Scenario '{scenario}': Expected DATA '{expected_data_result}', got '{data_response}'"

            # Verify appropriate delivery method was called
            if "local" in rcpt_to_type or rcpt_to_type == "mixed":
                mock_deliver_local.assert_called_once()

            if rcpt_to_type == "remote" or rcpt_to_type == "mixed":
                smtp.sendmail.assert_called_once()


########################################################################
########################################################################
#
class TestCommandArguments:
    """Tests for Command argument parsing and controller management."""

    ####################################################################
    #
    def test_port_or_off_accepts_valid_port(self):
        """
        Given a valid port number as a string
        When port_or_off is called
        Then it should return the port as an integer
        """
        from ..management.commands.aiosmtpd import Command

        cmd = Command()
        parser = cmd.create_parser("manage.py", "aiosmtpd")
        # Extract the port_or_off function from the argument parser
        port_or_off = parser._option_string_actions["--submission_port"].type

        assert port_or_off("25") == 25
        assert port_or_off("587") == 587
        assert port_or_off("8025") == 8025

    ####################################################################
    #
    def test_port_or_off_accepts_off_case_insensitive(self):
        """
        Given the string 'off' in any case
        When port_or_off is called
        Then it should return the string "off"
        """
        from ..management.commands.aiosmtpd import Command

        cmd = Command()
        parser = cmd.create_parser("manage.py", "aiosmtpd")
        port_or_off = parser._option_string_actions["--submission_port"].type

        assert port_or_off("off") == "off"
        assert port_or_off("OFF") == "off"
        assert port_or_off("Off") == "off"

    ####################################################################
    #
    def test_port_or_off_rejects_invalid_port(self):
        """
        Given an invalid port number (out of range or non-numeric)
        When port_or_off is called
        Then it should raise ValueError
        """
        from ..management.commands.aiosmtpd import Command

        cmd = Command()
        parser = cmd.create_parser("manage.py", "aiosmtpd")
        port_or_off = parser._option_string_actions["--submission_port"].type

        with pytest.raises(
            ValueError, match="Port must be an integer.*or 'off'"
        ):
            port_or_off("0")

        with pytest.raises(
            ValueError, match="Port must be an integer.*or 'off'"
        ):
            port_or_off("65536")

        with pytest.raises(
            ValueError, match="Port must be an integer.*or 'off'"
        ):
            port_or_off("invalid")

    ####################################################################
    #
    def test_handle_with_both_ports_enabled(self, mocker, tmp_path, faker):
        """
        Given both submission_port and smtp_port are valid integers
        When handle() is called
        Then both controllers should be created and started
        """
        from ..management.commands.aiosmtpd import Command

        # Mock the Controller class to prevent actual server startup
        mock_controller_class = mocker.patch(
            "as_email.management.commands.aiosmtpd.AsyncioAuthController"
        )
        mock_submission_controller = mocker.Mock()
        mock_smtp_controller = mocker.Mock()
        mock_controller_class.side_effect = [
            mock_submission_controller,
            mock_smtp_controller,
        ]

        # Mock time.sleep to prevent infinite loop
        mock_sleep = mocker.patch(
            "as_email.management.commands.aiosmtpd.time.sleep"
        )
        mock_sleep.side_effect = KeyboardInterrupt()

        # Mock ssl context creation
        mocker.patch(
            "as_email.management.commands.aiosmtpd.ssl.create_default_context"
        )

        cmd = Command()
        options = {
            "submission_port": 587,
            "smtp_port": 25,
            "listen_host": "0.0.0.0",
            "ssl_cert": str(tmp_path / "cert.pem"),
            "ssl_key": str(tmp_path / "key.pem"),
        }

        cmd.handle(**options)

        # Verify both controllers were created
        assert mock_controller_class.call_count == 2

        # Verify both controllers were started
        mock_submission_controller.start.assert_called_once()
        mock_smtp_controller.start.assert_called_once()

        # Verify both controllers were stopped
        mock_submission_controller.stop.assert_called_once()
        mock_smtp_controller.stop.assert_called_once()

    ####################################################################
    #
    def test_handle_with_submission_port_off(self, mocker, tmp_path):
        """
        Given submission_port is "off" and smtp_port is a valid integer
        When handle() is called
        Then only the SMTP controller should be created and started
        """
        from ..management.commands.aiosmtpd import Command

        # Mock the Controller class
        mock_controller_class = mocker.patch(
            "as_email.management.commands.aiosmtpd.AsyncioAuthController"
        )
        mock_smtp_controller = mocker.Mock()
        mock_controller_class.return_value = mock_smtp_controller

        # Mock time.sleep to prevent infinite loop
        mock_sleep = mocker.patch(
            "as_email.management.commands.aiosmtpd.time.sleep"
        )
        mock_sleep.side_effect = KeyboardInterrupt()

        # Mock ssl context creation
        mocker.patch(
            "as_email.management.commands.aiosmtpd.ssl.create_default_context"
        )

        cmd = Command()
        options = {
            "submission_port": "off",
            "smtp_port": 25,
            "listen_host": "0.0.0.0",
            "ssl_cert": str(tmp_path / "cert.pem"),
            "ssl_key": str(tmp_path / "key.pem"),
        }

        cmd.handle(**options)

        # Verify only one controller was created (SMTP)
        assert mock_controller_class.call_count == 1

        # Verify the controller was created with port 25
        call_kwargs = mock_controller_class.call_args.kwargs
        assert call_kwargs["port"] == 25
        assert call_kwargs["require_starttls"] is False

        # Verify controller was started and stopped
        mock_smtp_controller.start.assert_called_once()
        mock_smtp_controller.stop.assert_called_once()

    ####################################################################
    #
    def test_handle_with_smtp_port_off(self, mocker, tmp_path):
        """
        Given smtp_port is "off" and submission_port is a valid integer
        When handle() is called
        Then only the submission controller should be created and started
        """
        from ..management.commands.aiosmtpd import Command

        # Mock the Controller class
        mock_controller_class = mocker.patch(
            "as_email.management.commands.aiosmtpd.AsyncioAuthController"
        )
        mock_submission_controller = mocker.Mock()
        mock_controller_class.return_value = mock_submission_controller

        # Mock time.sleep to prevent infinite loop
        mock_sleep = mocker.patch(
            "as_email.management.commands.aiosmtpd.time.sleep"
        )
        mock_sleep.side_effect = KeyboardInterrupt()

        # Mock ssl context creation
        mocker.patch(
            "as_email.management.commands.aiosmtpd.ssl.create_default_context"
        )

        cmd = Command()
        options = {
            "submission_port": 587,
            "smtp_port": "off",
            "listen_host": "0.0.0.0",
            "ssl_cert": str(tmp_path / "cert.pem"),
            "ssl_key": str(tmp_path / "key.pem"),
        }

        cmd.handle(**options)

        # Verify only one controller was created (submission)
        assert mock_controller_class.call_count == 1

        # Verify the controller was created with port 587
        call_kwargs = mock_controller_class.call_args.kwargs
        assert call_kwargs["port"] == 587
        assert call_kwargs["require_starttls"] is True

        # Verify controller was started and stopped
        mock_submission_controller.start.assert_called_once()
        mock_submission_controller.stop.assert_called_once()

    ####################################################################
    #
    def test_handle_with_both_ports_off(self, mocker, tmp_path):
        """
        Given both submission_port and smtp_port are "off"
        When handle() is called
        Then no controllers should be created
        And the daemon should still run (and be stoppable)
        """
        from ..management.commands.aiosmtpd import Command

        # Mock the Controller class
        mock_controller_class = mocker.patch(
            "as_email.management.commands.aiosmtpd.AsyncioAuthController"
        )

        # Mock time.sleep to prevent infinite loop
        mock_sleep = mocker.patch(
            "as_email.management.commands.aiosmtpd.time.sleep"
        )
        mock_sleep.side_effect = KeyboardInterrupt()

        # Mock ssl context creation
        mocker.patch(
            "as_email.management.commands.aiosmtpd.ssl.create_default_context"
        )

        cmd = Command()
        options = {
            "submission_port": "off",
            "smtp_port": "off",
            "listen_host": "0.0.0.0",
            "ssl_cert": str(tmp_path / "cert.pem"),
            "ssl_key": str(tmp_path / "key.pem"),
        }

        cmd.handle(**options)

        # Verify no controllers were created
        assert mock_controller_class.call_count == 0


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
        mocker,
    ):
        """
        Given a message sent only to inactive email addresses
        When relay_email_to_provider is called
        Then no message should be sent to the provider
        And a delivery status notification should be enqueued
        """
        # Mock dispatch_incoming_email to verify DSN is enqueued
        # The task won't execute immediately in async context even with huey.immediate=True
        mock_dispatch = mocker.patch(
            "as_email.management.commands.aiosmtpd.dispatch_incoming_email"
        )

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
        assert smtp.sendmail.call_count == 0

        # Verify DSN was enqueued for delivery
        assert mock_dispatch.call_count == 1
        call_args = mock_dispatch.call_args
        assert call_args.args[0] == ea.pk
        # Verify the spooled file exists
        spool_file = Path(call_args.args[1])
        assert spool_file.exists()

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
        mocker,
    ):
        """
        Given a message sent to both valid and inactive addresses
        When relay_email_to_provider is called
        Then the message should be sent only to valid addresses
        And a delivery status notification should be enqueued for inactive addresses
        """
        # Mock dispatch_incoming_email to verify DSN is enqueued
        # The task won't execute immediately in async context even with huey.immediate=True
        mock_dispatch = mocker.patch(
            "as_email.management.commands.aiosmtpd.dispatch_incoming_email"
        )

        ea = await sync_to_async(email_account_factory)()
        await ea.asave()

        inact = inactive_email_factory()
        await inact.asave()

        inactive = inact.email_address
        to = faker.email()
        msg = email_factory(msg_from=ea.email_address, to=to, cc=inactive)
        await relay_email_to_provider(ea, [to, inactive], msg)

        # Message sent to valid address
        assert smtp.sendmail.call_count == 1
        assert smtp.sendmail.call_args.args == Contains(
            ea.email_address,
            [to],
        )

        # Verify DSN was enqueued for inactive addresses
        assert mock_dispatch.call_count == 1
        call_args = mock_dispatch.call_args
        assert call_args.args[0] == ea.pk
        # Verify the spooled file exists
        spool_file = Path(call_args.args[1])
        assert spool_file.exists()
