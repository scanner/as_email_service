#!/usr/bin/env python
#
"""
Test the ForwardEmail provider backend.
"""
# system imports
#
import email.policy
import json

# 3rd party imports
#
import pytest
from dirty_equals import IsPartialDict
from django.http import HttpRequest

# Project imports
#
from as_email.providers.forwardemail import ForwardEmailBackend

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestForwardEmailBackend:
    """Tests for ForwardEmail provider backend."""

    ####################################################################
    #
    def test_provider_name(self) -> None:
        """
        Given a ForwardEmailBackend instance
        When accessing PROVIDER_NAME
        Then it should be "forwardemail"
        """
        backend = ForwardEmailBackend()
        assert backend.PROVIDER_NAME == "forwardemail"

    ####################################################################
    #
    def test_send_email_smtp_not_supported(
        self, server_factory, email_factory
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When attempting to send email via SMTP
        Then it should raise NotImplementedError
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        msg = email_factory()

        with pytest.raises(NotImplementedError) as exc_info:
            backend.send_email_smtp(
                server=server,
                email_from="test@example.com",
                rcpt_tos=["recipient@example.com"],
                msg=msg,
            )

        assert "receive-only provider" in str(exc_info.value)
        assert "does not support sending email" in str(exc_info.value)

    ####################################################################
    #
    def test_send_email_api_not_supported(
        self, server_factory, email_factory
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When attempting to send email via API
        Then it should raise NotImplementedError
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        msg = email_factory()

        with pytest.raises(NotImplementedError) as exc_info:
            backend.send_email_api(server=server, message=msg)

        assert "receive-only provider" in str(exc_info.value)
        assert "does not support sending email" in str(exc_info.value)

    ####################################################################
    #
    def test_handle_bounce_webhook_not_supported(
        self, server_factory, mocker, caplog
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When receiving a bounce webhook
        Then it should return a "not supported" response and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        request = mocker.Mock(spec=HttpRequest)

        response = backend.handle_bounce_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "not supported"
        assert "receive-only provider" in response_data["message"]

        # Verify logging
        assert (
            "Received bounce webhook for receive-only provider" in caplog.text
        )
        assert server.domain_name in caplog.text

    ####################################################################
    #
    def test_handle_spam_webhook_not_supported(
        self, server_factory, mocker, caplog
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When receiving a spam complaint webhook
        Then it should return a "not supported" response and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        request = mocker.Mock(spec=HttpRequest)

        response = backend.handle_spam_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "not supported"
        assert "receive-only provider" in response_data["message"]

        # Verify logging
        assert "Received spam webhook for receive-only provider" in caplog.text
        assert server.domain_name in caplog.text

    ####################################################################
    #
    def test_handle_incoming_webhook_invalid_json(
        self, server_factory, mocker, caplog
    ) -> None:
        """
        Given an incoming webhook with invalid JSON
        When the webhook is processed
        Then it should return a 400 error and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Create request with invalid JSON
        request = mocker.Mock(spec=HttpRequest)
        request.body = b"not valid json{{"

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        assert response.status_code == 400
        assert "invalid json" in response.content.decode()

        # Verify logging
        assert "Incoming webhook for" in caplog.text
        assert server.domain_name in caplog.text

    ####################################################################
    #
    def test_handle_incoming_webhook_missing_raw_field(
        self, server_factory, faker, mocker, caplog
    ) -> None:
        """
        Given an incoming webhook without the "raw" email field
        When the webhook is processed
        Then it should return error status and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Create webhook payload without "raw" field
        payload = {
            "messageId": faker.uuid4(),
            "from": {"text": faker.email()},
            "recipients": [faker.email()],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "error"
        assert "missing raw email content" in response_data["message"]

        # Verify logging
        assert (
            "Email received from forwardemail without `raw` field"
            in caplog.text
        )

    ####################################################################
    #
    def test_handle_incoming_webhook_no_recipients(
        self, server_factory, email_factory, faker, mocker, caplog
    ) -> None:
        """
        Given an incoming webhook with no recipients
        When the webhook is processed
        Then it should return "all good" status and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        msg = email_factory()
        raw_email = msg.as_string(policy=email.policy.default)

        # Create webhook payload without recipients
        payload = {
            "messageId": faker.uuid4(),
            "from": {"text": faker.email()},
            "raw": raw_email,
            "recipients": [],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert "no recipients" in response_data["message"]

        # Verify logging
        assert (
            "Email received from forwardemail without recipients" in caplog.text
        )

    ####################################################################
    #
    def test_handle_incoming_webhook_nonexistent_account(
        self, server_factory, email_factory, faker, mocker, caplog
    ) -> None:
        """
        Given an incoming webhook for a non-existent EmailAccount
        When the webhook is processed
        Then it should log info message and include failed recipient in response
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        msg = email_factory()
        raw_email = msg.as_string(policy=email.policy.default)

        nonexistent_email = faker.email()
        from_email = faker.email()

        # Create webhook payload
        payload = {
            "messageId": faker.uuid4(),
            "from": {"text": from_email},
            "raw": raw_email,
            "recipients": [nonexistent_email],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert "no valid recipients" in response_data["message"]
        assert nonexistent_email in response_data["failed_recipients"]

        # Verify logging
        assert (
            "Received email for EmailAccount that does not exist" in caplog.text
        )
        assert nonexistent_email in caplog.text
        assert from_email in caplog.text

    ####################################################################
    #
    def test_handle_incoming_webhook_successful_delivery(
        self,
        server_factory,
        email_account_factory,
        email_factory,
        faker,
        mocker,
        caplog,
    ) -> None:
        """
        Given an incoming webhook for a valid EmailAccount
        When the webhook is processed
        Then it should spool the email, dispatch task, and return success
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        email_account = email_account_factory(server=server)
        msg = email_factory()
        raw_email = msg.as_string(policy=email.policy.default)

        message_id = faker.uuid4()
        from_email = faker.email()

        # Create webhook payload
        payload = {
            "messageId": message_id,
            "from": {"text": from_email},
            "raw": raw_email,
            "recipients": [email_account.email_address],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert response_data["delivered"] == 1
        assert (
            "queued delivery for 1 of 1 recipients" in response_data["message"]
        )

        # Verify logging
        assert "deliver_email_locally: Queued delivery for" in caplog.text
        assert email_account.email_address in caplog.text
        assert message_id in caplog.text
        assert from_email in caplog.text

    ####################################################################
    #
    def test_handle_incoming_webhook_multiple_recipients(
        self,
        server_factory,
        email_account_factory,
        email_factory,
        faker,
        mocker,
        caplog,
    ) -> None:
        """
        Given an incoming webhook with multiple recipients
        When the webhook is processed
        Then it should deliver to all valid recipients and track failures
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Create two valid accounts and one nonexistent
        account1 = email_account_factory(server=server)
        account2 = email_account_factory(server=server)
        nonexistent_email = faker.email()

        msg = email_factory()
        raw_email = msg.as_string(policy=email.policy.default)
        message_id = faker.uuid4()

        # Create webhook payload with multiple recipients
        payload = {
            "messageId": message_id,
            "from": {"text": faker.email()},
            "raw": raw_email,
            "recipients": [
                account1.email_address,
                nonexistent_email,
                account2.email_address,
            ],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert response_data["delivered"] == 2
        assert (
            "queued delivery for 2 of 3 recipients" in response_data["message"]
        )
        assert nonexistent_email in response_data["failed_recipients"]

        # Verify logging - should have two successful deliveries
        assert (
            caplog.text.count("deliver_email_locally: Queued delivery for") == 2
        )
        assert account1.email_address in caplog.text
        assert account2.email_address in caplog.text
        assert "EmailAccount that does not exist" in caplog.text

    ####################################################################
    #
    def test_handle_incoming_webhook_with_hash_addressing(
        self,
        server_factory,
        email_account_factory,
        email_factory,
        faker,
        mocker,
        caplog,
    ) -> None:
        """
        Given an incoming webhook with +hash addressing
        When the webhook is processed
        Then it should strip the hash and deliver to base address
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        email_account = email_account_factory(server=server)

        # Use +hash addressing
        base_addr = email_account.email_address
        hash_addr = base_addr.replace("@", "+somehash@")

        msg = email_factory()
        raw_email = msg.as_string(policy=email.policy.default)

        # Create webhook payload
        payload = {
            "messageId": faker.uuid4(),
            "from": {"text": faker.email()},
            "raw": raw_email,
            "recipients": [hash_addr],
        }

        request = mocker.Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert response_data["delivered"] == 1

        # Verify logging shows the hash address was used
        assert "deliver_email_locally: Queued delivery for" in caplog.text
        assert hash_addr in caplog.text


########################################################################
########################################################################
#
class TestForwardEmailAPIMethods:
    """Tests for ForwardEmail API management methods."""

    ####################################################################
    #
    @pytest.fixture(autouse=True)
    def mock_signal_tasks(self, mocker):
        """
        Mock HUEY.enqueue to prevent signals from executing tasks during
        test setup when factories create model instances.
        """
        mocker.patch("as_email.signals.HUEY.enqueue")

    ####################################################################
    #
    def test_create_domain_new_domain(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a server with a domain that doesn't exist on forwardemail.net
        When create_domain is called
        Then it should create the domain via API and cache the domain ID
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Patch Redis - domain doesn't exist in cache
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )

        # Mock API request
        domain_id = faker.uuid4()
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": domain_id,
            "name": server.domain_name,
        }
        mock_req = mocker.patch.object(
            backend, "_req", return_value=mock_response
        )

        # Mock update_domains
        mocker.patch.object(backend, "update_domains")

        # Call create_domain
        backend.create_domain(server)

        # Verify API was called with correct data
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][1] == "v1/domains"
        assert call_args[1]["data"] == IsPartialDict(
            domain=server.domain_name, plan="enhanced_protection"
        )

        # Verify domain ID was cached
        assert mock_redis.get(server.domain_name) == domain_id

    ####################################################################
    #
    def test_create_domain_already_exists(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a server with a domain that already exists on forwardemail.net
        When create_domain is called
        Then it should not create a new domain
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Patch Redis - domain exists
        existing_domain_id = faker.uuid4()
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )
        mock_redis.set(
            f"forwardemail:domain:{server.domain_name}", existing_domain_id
        )

        # Mock update_domains
        mocker.patch.object(backend, "update_domains")

        # Mock API request
        mock_req = mocker.patch.object(backend, "_req")

        # Call create_domain
        backend.create_domain(server)

        # Verify API was NOT called
        mock_req.assert_not_called()

    ####################################################################
    #
    def test_delete_domain_exists_in_cache(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a domain that exists in Redis cache
        When delete_domain is called
        Then it should delete the domain via API and remove from cache
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Patch Redis - domain exists in cache
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )
        redis_key = f"forwardemail:domain:{server.domain_name}"
        mock_redis.set(redis_key, domain_id)

        # Mock API request
        mock_req = mocker.patch.object(backend, "_req")

        # Call delete_domain
        backend.delete_domain(server)

        # Verify API was called with DELETE
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][1] == f"v1/domains/{domain_id}"

        # Verify cache was cleared
        assert mock_redis.get(redis_key) is None

    ####################################################################
    #
    def test_delete_domain_not_in_cache_refresh_finds_it(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a domain not in Redis cache but exists on forwardemail.net
        When delete_domain is called
        Then it should refresh domains, then delete via API
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Patch Redis
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )

        # Mock list_domains to populate cache
        def populate_cache(redis=None):
            redis_key = f"forwardemail:domain:{server.domain_name}"
            mock_redis.set(redis_key, domain_id)

        mock_list_domains = mocker.patch.object(
            backend, "list_domains", side_effect=populate_cache
        )

        # Mock API request
        mock_req = mocker.patch.object(backend, "_req")

        # Call delete_domain
        backend.delete_domain(server)

        # Verify list_domains was called to refresh
        mock_list_domains.assert_called_once()

        # Verify API was called with DELETE
        mock_req.assert_called_once()

    ####################################################################
    #
    def test_delete_domain_does_not_exist(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a domain that doesn't exist on forwardemail.net
        When delete_domain is called
        Then it should raise ValueError
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Patch Redis - domain not in cache
        patch_redis_client("as_email.providers.forwardemail.redis_client")

        # Mock list_domains (doesn't populate cache)
        mocker.patch.object(backend, "list_domains")

        # Call delete_domain - should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            backend.delete_domain(server)

        assert "does not exist on forwardemail.net" in str(exc_info.value)
        assert server.domain_name in str(exc_info.value)

    ####################################################################
    #
    def test_create_email_account(
        self, email_account_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given an EmailAccount
        When create_email_account is called
        Then it should create an alias via API and cache the alias ID
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Patch Redis
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )

        # Mock update_domains to avoid API calls
        mocker.patch.object(backend, "update_domains")

        # Mock _get_domain_id
        mocker.patch.object(backend, "_get_domain_id", return_value=domain_id)

        # Mock _get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "_get_webhook_url", return_value=webhook_url
        )

        # Mock API request
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {"id": alias_id}
        mock_req = mocker.patch.object(
            backend, "_req", return_value=mock_response
        )

        # Call create_email_account
        backend.create_email_account(email_account)

        # Verify API was called with correct data
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases" in call_args[0][1]
        assert call_args[1]["data"] == IsPartialDict(
            name=email_account.email_address.split("@")[0],
            recipients=[webhook_url],
            is_enabled=True,
        )

        # Verify alias ID was cached
        redis_key = f"forwardemail:alias:{email_account.email_address}"
        assert mock_redis.get(redis_key) == alias_id

    ####################################################################
    #
    def test_delete_email_account_by_address(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given an email address with cached alias ID
        When delete_email_account_by_address is called
        Then it should delete the alias via API and remove from cache
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        email_address = f"test@{server.domain_name}"
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Patch Redis and set up cache
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )
        mock_redis.set(f"forwardemail:domain:{server.domain_name}", domain_id)
        mock_redis.set(f"forwardemail:alias:{email_address}", alias_id)

        # Mock API request
        mock_req = mocker.patch.object(backend, "_req")

        # Call delete_email_account_by_address
        backend.delete_email_account_by_address(email_address, server)

        # Verify API was called with DELETE
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in call_args[0][1]

        # Verify cache was cleared
        assert mock_redis.get(f"forwardemail:alias:{email_address}") is None

    ####################################################################
    #
    def test_enable_email_account(
        self, email_account_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given an EmailAccount
        When enable_email_account is called with is_enabled=True
        Then it should update the alias via API
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Patch Redis and populate with alias ID
        mock_redis = patch_redis_client(
            "as_email.providers.forwardemail.redis_client"
        )
        redis_key = f"forwardemail:alias:{email_account.email_address}"
        mock_redis.set(redis_key, alias_id)

        # Mock update_domains to avoid API calls
        mocker.patch.object(backend, "update_domains")

        # Mock _get_domain_id
        mocker.patch.object(backend, "_get_domain_id", return_value=domain_id)

        # Mock API request
        mock_req = mocker.patch.object(backend, "_req")

        # Call enable_email_account
        backend.enable_email_account(email_account, enable=True)

        # Verify API was called with correct data
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in call_args[0][1]
        assert call_args[1]["data"] == IsPartialDict(is_enabled=True)

    ####################################################################
    #
    def test_list_email_accounts(
        self, server_factory, patch_redis_client, mocker, faker
    ) -> None:
        """
        Given a server
        When list_email_accounts is called
        Then it should return all aliases from the API
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Patch Redis
        patch_redis_client("as_email.providers.forwardemail.redis_client")

        # Mock update_domains to avoid API calls
        mocker.patch.object(backend, "update_domains")

        # Mock _get_domain_id
        mocker.patch.object(backend, "_get_domain_id", return_value=domain_id)

        # Mock API response
        aliases_list = [
            {"id": faker.uuid4(), "name": "user1", "is_enabled": True},
            {"id": faker.uuid4(), "name": "user2", "is_enabled": False},
        ]
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = aliases_list
        mock_req = mocker.patch.object(
            backend, "_req", return_value=mock_response
        )

        # Call list_email_accounts
        result = backend.list_email_accounts(server)

        # Verify API was called
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases" in call_args[0][1]

        # Verify result is a dict keyed by email address
        assert isinstance(result, dict)
        assert f"user1@{server.domain_name}" in result
        assert f"user2@{server.domain_name}" in result
        assert result[f"user1@{server.domain_name}"]["name"] == "user1"
        assert result[f"user2@{server.domain_name}"]["name"] == "user2"

    ####################################################################
    #
    def test_create_update_email_account_creates_new_alias(
        self, email_account_factory, mocker, faker, caplog
    ) -> None:
        """
        Given an EmailAccount that doesn't exist on forwardemail.net
        When create_update_email_account is called
        Then it should create a new alias via POST
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Mock get_domain_id
        mocker.patch.object(backend, "get_domain_id", return_value=domain_id)

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to raise 404 (alias doesn't exist)
        from io import BytesIO
        from urllib.error import HTTPError

        mock_error = HTTPError(
            url="http://test.com",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=BytesIO(b""),
        )
        mocker.patch.object(backend, "get_alias_id", side_effect=mock_error)

        # Mock API request for POST (create)
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        # Mock set_alias_info
        mock_set_alias_info = mocker.patch.object(backend, "set_alias_info")

        # Call create_update_email_account
        backend.create_update_email_account(email_account)

        # Verify get_alias_id was called
        backend.get_alias_id.assert_called_once_with(
            domain_id, email_account.email_address
        )

        # Verify POST was called with correct data
        mock_api_req.assert_called_once()
        call_args = mock_api_req.call_args
        assert call_args[0][0].value == "post"  # HTTPMethod.POST
        assert f"v1/domains/{domain_id}/aliases" in call_args[0][1]
        assert call_args[1]["data"] == IsPartialDict(
            name=email_account.email_address.split("@")[0],
            recipients=[webhook_url],
            is_enabled=True,
            description=f"Email account for {email_account.owner.username}",
        )

        # Verify set_alias_info was called
        mock_set_alias_info.assert_called_once()

        # Verify logging
        assert "Created forwardemail.net alias for" in caplog.text
        assert email_account.email_address in caplog.text

    ####################################################################
    #
    def test_create_update_email_account_updates_existing_alias(
        self, email_account_factory, mocker, faker, caplog
    ) -> None:
        """
        Given an EmailAccount that already exists on forwardemail.net
        When create_update_email_account is called
        Then it should update the existing alias via PUT
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Mock get_domain_id
        mocker.patch.object(backend, "get_domain_id", return_value=domain_id)

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to return existing alias ID
        mocker.patch.object(backend, "get_alias_id", return_value=alias_id)

        # Mock API request for PUT (update)
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        # Mock set_alias_info
        mock_set_alias_info = mocker.patch.object(backend, "set_alias_info")

        # Call create_update_email_account
        backend.create_update_email_account(email_account)

        # Verify get_alias_id was called
        backend.get_alias_id.assert_called_once_with(
            domain_id, email_account.email_address
        )

        # Verify PUT was called with correct data
        mock_api_req.assert_called_once()
        call_args = mock_api_req.call_args
        assert call_args[0][0].value == "put"  # HTTPMethod.PUT
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in call_args[0][1]
        assert call_args[1]["data"] == IsPartialDict(
            name=email_account.email_address.split("@")[0],
            recipients=[webhook_url],
            is_enabled=True,
            description=f"Email account for {email_account.owner.username}",
        )

        # Verify set_alias_info was called
        mock_set_alias_info.assert_called_once()

        # Verify logging
        assert "Updated forwardemail.net alias for" in caplog.text
        assert email_account.email_address in caplog.text
        assert alias_id in caplog.text

    ####################################################################
    #
    def test_create_update_email_account_raises_on_non_404_error(
        self, email_account_factory, mocker, faker
    ) -> None:
        """
        Given an EmailAccount
        When create_update_email_account is called and get_alias_id raises non-404 error
        Then it should re-raise the error
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()

        # Mock get_domain_id
        mocker.patch.object(backend, "get_domain_id", return_value=domain_id)

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to raise 500 error (server error)
        from io import BytesIO
        from urllib.error import HTTPError

        mock_error = HTTPError(
            url="http://test.com",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b""),
        )
        mocker.patch.object(backend, "get_alias_id", side_effect=mock_error)

        # Call should raise the HTTPError
        with pytest.raises(HTTPError) as exc_info:
            backend.create_update_email_account(email_account)

        assert exc_info.value.code == 500

    ####################################################################
    #
    def test_create_update_email_account_constructs_correct_alias_data(
        self, email_account_factory, mocker, faker
    ) -> None:
        """
        Given an EmailAccount
        When create_update_email_account is called
        Then it should construct alias data with correct fields
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        # Mock get_domain_id
        mocker.patch.object(backend, "get_domain_id", return_value=domain_id)

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to return existing alias ID
        mocker.patch.object(backend, "get_alias_id", return_value=alias_id)

        # Mock API request
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        # Mock set_alias_info
        mocker.patch.object(backend, "set_alias_info")

        # Call create_update_email_account
        backend.create_update_email_account(email_account)

        # Verify alias data structure
        call_args = mock_api_req.call_args
        alias_data = call_args[1]["data"]

        assert alias_data["name"] == email_account.email_address.split("@")[0]
        assert alias_data["recipients"] == [webhook_url]
        assert (
            alias_data["description"]
            == f"Email account for {email_account.owner.username}"
        )
        assert alias_data["labels"] == ""
        assert alias_data["has_recipient_verification"] is False
        assert alias_data["is_enabled"] is True
        assert alias_data["has_imap"] is False
        assert alias_data["has_pgp"] is False
