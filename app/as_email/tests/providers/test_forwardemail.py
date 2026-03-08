#!/usr/bin/env python
#
"""
Test the ForwardEmail provider backend.
"""
# system imports
#
import email.policy
import json
import time
from io import BytesIO
from urllib.error import HTTPError

# 3rd party imports
#
import pytest
from dirty_equals import IsPartialDict
from django.http import HttpRequest

# Project imports
#
from as_email.providers.forwardemail import (
    APIClient,
    ForwardEmailBackend,
    ForwardEmailCache,
    HTTPMethod,
    RateLimitInfo,
)

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestForwardEmailBackend:
    """"""

    "Tests for ForwardEmail provider backend." ""

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
    def test_create_update_domain_creates_new_domain(
        self, server_factory, use_fakeredis, mocker, faker
    ) -> None:
        """
        GIVEN: a server whose domain does not exist on forwardemail.net
        WHEN:  create_update_domain is called
        THEN:  a single POST is issued with DEFAULT_DOMAIN_SETTINGS (no plan),
               the domain ID is cached, and the domain info is returned
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        mock_redis = use_fakeredis

        mocker.patch.object(
            backend.cache, "get_domain_id", side_effect=KeyError()
        )

        domain_id = faker.uuid4()
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": domain_id,
            "name": server.domain_name,
        }
        mock_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        result = backend.create_update_domain(server)

        backend.cache.get_domain_id.assert_called_once_with(server.domain_name)

        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][0] == HTTPMethod.POST
        assert call_args[0][1] == "v1/domains"
        # plan must not appear in the POST data
        assert "plan" not in call_args[1]["data"]
        # all DEFAULT_DOMAIN_SETTINGS fields must be present
        assert call_args[1]["data"] == IsPartialDict(
            domain=server.domain_name,
            **ForwardEmailBackend.DEFAULT_DOMAIN_SETTINGS,
        )

        redis_key = f"forwardemail:domain:{server.domain_name}"
        assert mock_redis.get(redis_key) == domain_id.encode()
        assert result["id"] == domain_id
        assert result["name"] == server.domain_name

    ####################################################################
    #
    def test_create_update_domain_no_put_when_settings_match(
        self, server_factory, mocker, faker
    ) -> None:
        """
        GIVEN: a domain that already exists with all settings matching DEFAULT_DOMAIN_SETTINGS
        WHEN:  create_update_domain is called
        THEN:  only one GET is issued (no PUT) and the domain info is returned
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        existing_domain_id = faker.uuid4()

        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=existing_domain_id
        )

        # GET response includes all DEFAULT_DOMAIN_SETTINGS at their correct values
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": existing_domain_id,
            "name": server.domain_name,
            **ForwardEmailBackend.DEFAULT_DOMAIN_SETTINGS,
        }
        mock_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        result = backend.create_update_domain(server)

        backend.cache.get_domain_id.assert_called_once_with(server.domain_name)
        mock_req.assert_called_once()
        assert mock_req.call_args[0][0] == HTTPMethod.GET
        assert result["id"] == existing_domain_id

    ####################################################################
    #
    def test_create_update_domain_puts_updated_settings(
        self, server_factory, mocker, faker, caplog
    ) -> None:
        """
        GIVEN: a domain that already exists but with one setting out of date
        WHEN:  create_update_domain is called
        THEN:  GET is followed by a PUT containing only the changed field,
               the info log records the updated fields, and the updated domain
               info is returned
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        existing_domain_id = faker.uuid4()

        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=existing_domain_id
        )

        # GET response has has_virus_protection wrong
        current_settings = {**ForwardEmailBackend.DEFAULT_DOMAIN_SETTINGS}
        current_settings["has_virus_protection"] = False

        get_response = mocker.MagicMock()
        get_response.json.return_value = {
            "id": existing_domain_id,
            "name": server.domain_name,
            **current_settings,
        }
        put_response = mocker.MagicMock()
        put_response.json.return_value = {
            "id": existing_domain_id,
            "name": server.domain_name,
            **ForwardEmailBackend.DEFAULT_DOMAIN_SETTINGS,
        }
        mock_req = mocker.patch.object(
            backend.api, "req", side_effect=[get_response, put_response]
        )

        result = backend.create_update_domain(server)

        assert mock_req.call_count == 2
        get_call, put_call = mock_req.call_args_list
        assert get_call[0][0] == HTTPMethod.GET
        assert put_call[0][0] == HTTPMethod.PUT
        assert f"v1/domains/{existing_domain_id}" in put_call[0][1]
        # Only the changed field should be sent
        assert put_call[1]["data"] == {"has_virus_protection": True}

        assert "settings updated" in caplog.text
        assert server.domain_name in caplog.text
        assert result["id"] == existing_domain_id

    ####################################################################
    #
    def test_delete_domain_exists_in_cache(
        self, server_factory, use_fakeredis, mocker, faker
    ) -> None:
        """
        Given a domain that exists in Redis cache
        When delete_domain is called
        Then it should delete the domain via API and remove from cache
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Use setup_redis_forwardemail fixture
        mock_redis = use_fakeredis
        redis_key = f"forwardemail:domain:{server.domain_name}"
        mock_redis.set(redis_key, domain_id)

        # Mock API request
        mock_req = mocker.patch.object(backend.api, "req")

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
    def test_delete_domain_not_in_cache_fetches_from_api(
        self, server_factory, use_fakeredis, mocker, faker
    ) -> None:
        """
        Given a domain not in Redis cache but exists on forwardemail.net
        When delete_domain is called
        Then it should fetch domain ID from API, then delete via API
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Use the fakeredis client from autouse fixture - domain not in cache initially
        mock_redis = use_fakeredis

        # Mock API request - first GET to get domain ID, then DELETE
        def api_request_side_effect(method, url, data=None):
            if method == HTTPMethod.GET:
                # GET returns domain info
                mock_response = mocker.MagicMock()
                mock_response.json.return_value = {
                    "id": domain_id,
                    "name": server.domain_name,
                }
                return mock_response
            elif method == HTTPMethod.DEL:
                # DELETE succeeds
                mock_response = mocker.MagicMock()
                return mock_response

        mock_req = mocker.patch.object(
            backend.api, "req", side_effect=api_request_side_effect
        )

        # Call delete_domain
        backend.delete_domain(server)

        # Verify API was called twice: GET then DELETE
        assert mock_req.call_count == 2
        # First call: GET to fetch domain ID
        assert mock_req.call_args_list[0][0][0] == HTTPMethod.GET
        assert (
            f"v1/domains/{server.domain_name}"
            in mock_req.call_args_list[0][0][1]
        )
        # Second call: DELETE
        assert mock_req.call_args_list[1][0][0] == HTTPMethod.DEL
        assert f"v1/domains/{domain_id}" in mock_req.call_args_list[1][0][1]

        # Verify cache was cleared
        redis_key = f"forwardemail:domain:{server.domain_name}"
        assert mock_redis.get(redis_key) is None

    ####################################################################
    #
    def test_delete_domain_does_not_exist(
        self, server_factory, mocker, faker, caplog
    ) -> None:
        """
        Given a domain that doesn't exist on forwardemail.net
        When delete_domain is called
        Then it should be a no-op and log an info message
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Mock get_domain_id to raise KeyError (domain doesn't exist)
        mocker.patch.object(
            backend.cache, "get_domain_id", side_effect=KeyError()
        )

        # Mock API request - should not be called
        mock_req = mocker.patch.object(backend.api, "req")

        # Call delete_domain - should succeed without error
        backend.delete_domain(server)

        # Verify API was NOT called (nothing to delete)
        mock_req.assert_not_called()

        # Verify logging
        assert "does not exist on forwardemail.net" in caplog.text
        assert "nothing to delete" in caplog.text
        assert server.domain_name in caplog.text

    ####################################################################
    #
    def test_create_email_account(
        self, email_account_factory, use_fakeredis, mocker, faker
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

        mock_redis = use_fakeredis

        # Mock get_domain_id
        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to raise KeyError (alias doesn't exist)
        mocker.patch.object(
            backend.cache, "get_alias_id", side_effect=KeyError()
        )

        # Mock API request for POST (create)
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
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
        assert mock_redis.get(redis_key) == alias_id.encode()

    ####################################################################
    #
    def test_delete_email_account_by_address(
        self, server_factory, use_fakeredis, mocker, faker
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

        # Use the fakeredis client from autouse fixture and set up cache
        mock_redis = use_fakeredis
        mock_redis.set(f"forwardemail:domain:{server.domain_name}", domain_id)
        mock_redis.set(f"forwardemail:alias:{email_address}", alias_id)

        # Mock API request
        mock_req = mocker.patch.object(backend.api, "req")

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
        self, email_account_factory, use_fakeredis, mocker, faker
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

        # Use the fakeredis client from autouse fixture and populate with alias ID
        mock_redis = use_fakeredis
        redis_key = f"forwardemail:alias:{email_account.email_address}"
        mock_redis.set(redis_key, alias_id)

        # Mock update_domains to avoid API calls
        mocker.patch.object(backend, "update_domains")

        # Mock get_domain_id on the cache
        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )

        # Mock API request
        mock_req = mocker.patch.object(backend.api, "req")

        # Call enable_email_account
        backend.enable_email_account(email_account, enabled=True)

        # Verify API was called with correct data
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in call_args[0][1]
        assert call_args[1]["data"] == IsPartialDict(is_enabled=True)

    ####################################################################
    #
    def test_list_email_accounts(self, server_factory, mocker, faker) -> None:
        """
        Given a server
        When list_email_accounts is called
        Then it should return all aliases from the API
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        domain_id = faker.uuid4()

        # Mock get_domain_id
        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )

        # Mock API response - paginated_request expects headers
        aliases_list = [
            {"id": faker.uuid4(), "name": "user1", "is_enabled": True},
            {"id": faker.uuid4(), "name": "user2", "is_enabled": False},
        ]
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = aliases_list
        mock_response.headers = {"Link": ""}  # No pagination
        mock_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        # Call list_email_accounts
        result = backend.list_email_accounts(server)

        # Verify API was called
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert f"v1/domains/{domain_id}/aliases" in call_args[0][1]

        # Verify result is a list of EmailAccountInfo objects
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0].email == f"user1@{server.domain_name}"
        assert result[0].name == "user1"
        assert result[0].enabled is True
        assert result[1].email == f"user2@{server.domain_name}"
        assert result[1].name == "user2"
        assert result[1].enabled is False

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
        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to raise KeyError (alias doesn't exist)
        mocker.patch.object(
            backend.cache, "get_alias_id", side_effect=KeyError()
        )

        # Mock API request for POST (create)
        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )

        # Mock cache.set_alias
        mock_set_alias = mocker.patch.object(backend.cache, "set_alias")

        # Call create_update_email_account
        backend.create_update_email_account(email_account)

        # Verify get_alias_id was called
        backend.cache.get_alias_id.assert_called_once_with(
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

        # Verify cache.set_alias was called
        mock_set_alias.assert_called_once()

        # Verify logging
        assert "Created forwardemail.net alias for" in caplog.text
        assert email_account.email_address in caplog.text

    ####################################################################
    #
    def test_create_update_email_account_updates_existing_alias(
        self, email_account_factory, mocker, faker, caplog
    ) -> None:
        """
        Given an EmailAccount that already exists on forwardemail.net with a
        stale webhook URL
        When create_update_email_account is called
        Then it should GET the live alias, detect the drift, and PUT only the
        changed fields
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )
        mocker.patch.object(
            backend.cache, "get_alias_id", return_value=alias_id
        )

        # GET returns alias with a stale webhook URL so recipients will drift
        get_response = mocker.MagicMock()
        get_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
            "recipients": ["https://old-internal-host.example.com/hook"],
            "description": f"Email account for {email_account.owner.username}",
            "has_recipient_verification": False,
            "is_enabled": True,
            "has_imap": False,
            "has_pgp": False,
        }
        put_response = mocker.MagicMock()
        mock_api_req = mocker.patch.object(
            backend.api, "req", side_effect=[get_response, put_response]
        )
        mock_set_alias = mocker.patch.object(backend.cache, "set_alias")
        mock_delete_alias_data = mocker.patch.object(
            backend.cache, "delete_alias_data"
        )

        backend.create_update_email_account(email_account)

        backend.cache.get_alias_id.assert_called_once_with(
            domain_id, email_account.email_address
        )

        # First call: GET to fetch live settings
        get_call = mock_api_req.call_args_list[0]
        assert get_call[0][0] == HTTPMethod.GET
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in get_call[0][1]

        # Second call: PUT with only the drifted field (recipients)
        put_call = mock_api_req.call_args_list[1]
        assert put_call[0][0] == HTTPMethod.PUT
        assert f"v1/domains/{domain_id}/aliases/{alias_id}" in put_call[0][1]
        assert put_call[1]["data"] == {"recipients": [webhook_url]}

        # set_alias called once (for the GET); after PUT the cache is
        # invalidated so the next call fetches fresh state.
        mock_set_alias.assert_called_once()
        mock_delete_alias_data.assert_called_once_with(
            email_account.email_address
        )
        assert "settings updated" in caplog.text
        assert email_account.email_address in caplog.text

    ####################################################################
    #
    def test_create_update_email_account_no_put_when_settings_match(
        self, email_account_factory, mocker, faker, caplog
    ) -> None:
        """
        Given an EmailAccount whose live alias already matches DEFAULT_ALIAS_SETTINGS
        and has the correct webhook URL
        When create_update_email_account is called
        Then it should GET the live alias but issue no PUT
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )
        mocker.patch.object(
            backend.cache, "get_alias_id", return_value=alias_id
        )

        # GET returns alias that already matches everything we want
        get_response = mocker.MagicMock()
        get_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
            "recipients": [webhook_url],
            "description": f"Email account for {email_account.owner.username}",
            **backend.DEFAULT_ALIAS_SETTINGS,
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=get_response
        )
        mock_set_alias = mocker.patch.object(backend.cache, "set_alias")

        backend.create_update_email_account(email_account)

        # Only the GET should have been called; no PUT
        assert mock_api_req.call_count == 1
        assert mock_api_req.call_args[0][0] == HTTPMethod.GET
        mock_set_alias.assert_called_once()

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
        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )

        # Mock get_webhook_url
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Mock get_alias_id to raise 500 error (server error); cache.get_alias_id
        # converts 404 → KeyError but re-raises other HTTPErrors unchanged
        mock_error = HTTPError(
            url="http://test.com",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b""),
        )
        mocker.patch.object(
            backend.cache, "get_alias_id", side_effect=mock_error
        )

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
        Given an EmailAccount that does not yet exist on forwardemail.net
        When create_update_email_account is called
        Then the POST payload should contain name, recipients, description,
        and all DEFAULT_ALIAS_SETTINGS fields
        """
        backend = ForwardEmailBackend()
        email_account = email_account_factory()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()

        mocker.patch.object(
            backend.cache, "get_domain_id", return_value=domain_id
        )
        webhook_url = (
            f"https://example.com/webhook/{email_account.email_address}"
        )
        mocker.patch.object(
            backend, "get_webhook_url", return_value=webhook_url
        )

        # Alias does not exist → POST path
        mocker.patch.object(
            backend.cache, "get_alias_id", side_effect=KeyError()
        )

        mock_response = mocker.MagicMock()
        mock_response.json.return_value = {
            "id": alias_id,
            "name": email_account.email_address.split("@")[0],
        }
        mock_api_req = mocker.patch.object(
            backend.api, "req", return_value=mock_response
        )
        mocker.patch.object(backend.cache, "set_alias")

        backend.create_update_email_account(email_account)

        # Verify POST was called and the payload has the full data structure
        call_args = mock_api_req.call_args
        assert call_args[0][0] == HTTPMethod.POST
        alias_data = call_args[1]["data"]

        assert alias_data["name"] == email_account.email_address.split("@")[0]
        assert alias_data["recipients"] == [webhook_url]
        assert (
            alias_data["description"]
            == f"Email account for {email_account.owner.username}"
        )
        assert alias_data["has_recipient_verification"] is False
        assert alias_data["is_enabled"] is True
        assert alias_data["has_imap"] is False
        assert alias_data["has_pgp"] is False


########################################################################
########################################################################
#
class TestForwardEmailCache:
    """Tests for the ForwardEmailCache Redis-backed cache layer."""

    ####################################################################
    #
    @pytest.fixture
    def mock_api(self, mocker):
        return mocker.MagicMock(spec=APIClient)

    ####################################################################
    #
    @pytest.fixture
    def cache(self, use_fakeredis, mock_api):
        return ForwardEmailCache(use_fakeredis, mock_api)

    ####################################################################
    #
    def test_key_format(self, cache, faker) -> None:
        """
        GIVEN: a ForwardEmailCache instance
        WHEN:  _key() is called with an ObjType and a name
        THEN:  the key should follow the forwardemail:<obj_type>:<name> schema
        """
        from as_email.providers.forwardemail import ObjType

        domain_name = faker.domain_name()
        assert cache._key(ObjType.DOMAIN, domain_name) == (
            f"forwardemail:domain:{domain_name}"
        )

        email = faker.email()
        assert cache._key(ObjType.ALIAS, email) == (
            f"forwardemail:alias:{email}"
        )

    ####################################################################
    #
    def test_set_domain_caches_id(self, cache, use_fakeredis, faker) -> None:
        """
        GIVEN: a domain info dict from the forwardemail.net API
        WHEN:  set_domain() is called
        THEN:  the domain ID is stored in Redis under the correct key
        """
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        cache.set_domain({"name": domain_name, "id": domain_id})

        key = f"forwardemail:domain:{domain_name}"
        assert use_fakeredis.get(key) == domain_id.encode()

    ####################################################################
    #
    def test_set_alias_caches_id(self, cache, use_fakeredis, faker) -> None:
        """
        GIVEN: an alias info dict and the domain name it belongs to
        WHEN:  set_alias() is called
        THEN:  the alias ID is stored keyed by the full email address
        """
        mailbox = faker.user_name()
        domain_name = faker.domain_name()
        alias_id = faker.uuid4()
        cache.set_alias({"name": mailbox, "id": alias_id}, domain_name)

        key = f"forwardemail:alias:{mailbox}@{domain_name}"
        assert use_fakeredis.get(key) == alias_id.encode()

    ####################################################################
    #
    def test_delete_domain_removes_from_cache(
        self, cache, use_fakeredis, faker
    ) -> None:
        """
        GIVEN: a domain ID already in the cache
        WHEN:  delete_domain() is called
        THEN:  the key is removed from Redis
        """
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        cache.set_domain({"name": domain_name, "id": domain_id})

        cache.delete_domain(domain_name)

        assert use_fakeredis.get(f"forwardemail:domain:{domain_name}") is None

    ####################################################################
    #
    def test_delete_alias_removes_from_cache(
        self, cache, use_fakeredis, faker
    ) -> None:
        """
        GIVEN: an alias ID already in the cache
        WHEN:  delete_alias() is called with the full email address
        THEN:  the key is removed from Redis
        """
        mailbox = faker.user_name()
        domain_name = faker.domain_name()
        email_address = f"{mailbox}@{domain_name}"
        alias_id = faker.uuid4()
        cache.set_alias({"name": mailbox, "id": alias_id}, domain_name)

        cache.delete_alias(email_address)

        assert use_fakeredis.get(f"forwardemail:alias:{email_address}") is None

    ####################################################################
    #
    def test_all_domains_fetched_timestamp(self, cache, use_fakeredis) -> None:
        """
        GIVEN: a fresh cache with no refresh timestamp
        WHEN:  set_all_domains_fetched() is called
        THEN:  get_all_domains_fetched() returns a non-None string, and before
               the call it returns None
        """
        assert cache.get_all_domains_fetched() is None

        cache.set_all_domains_fetched()

        timestamp = cache.get_all_domains_fetched()
        assert timestamp is not None
        assert isinstance(timestamp, str)

    ####################################################################
    #
    def test_get_cached_domain_id_returns_none_on_miss(
        self, cache, faker
    ) -> None:
        """
        GIVEN: a domain name not in the cache
        WHEN:  get_cached_domain_id() is called
        THEN:  it returns None without hitting the API
        """
        assert cache.get_cached_domain_id(faker.domain_name()) is None

    ####################################################################
    #
    def test_get_cached_alias_id_returns_none_on_miss(
        self, cache, faker
    ) -> None:
        """
        GIVEN: an email address not in the cache
        WHEN:  get_cached_alias_id() is called
        THEN:  it returns None without hitting the API
        """
        assert cache.get_cached_alias_id(faker.email()) is None

    ####################################################################
    #
    def test_get_domain_id_returns_cached_value(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: a domain ID already in the cache
        WHEN:  get_domain_id() is called
        THEN:  it returns the cached value without calling the API
        """
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        cache.set_domain({"name": domain_name, "id": domain_id})

        result = cache.get_domain_id(domain_name)

        assert result == domain_id
        mock_api.req.assert_not_called()

    ####################################################################
    #
    def test_get_domain_id_fetches_from_api_on_miss(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: a domain not in the cache but existing on forwardemail.net
        WHEN:  get_domain_id() is called
        THEN:  it fetches the domain from the API, caches the ID, and returns it
        """
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        mock_api.req.return_value.json.return_value = {
            "id": domain_id,
            "name": domain_name,
        }

        result = cache.get_domain_id(domain_name)

        assert result == domain_id
        mock_api.req.assert_called_once()
        # Subsequent call should use the cache
        mock_api.req.reset_mock()
        assert cache.get_domain_id(domain_name) == domain_id
        mock_api.req.assert_not_called()

    ####################################################################
    #
    def test_get_domain_id_raises_key_error_when_not_found(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: a domain that does not exist on forwardemail.net
        WHEN:  get_domain_id() is called
        THEN:  it raises KeyError (not Http404 or HTTPError)
        """
        domain_name = faker.domain_name()
        mock_api.req.side_effect = HTTPError(
            url=f"https://api.forwardemail.net/v1/domains/{domain_name}",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=BytesIO(b""),
        )

        with pytest.raises(KeyError) as exc_info:
            cache.get_domain_id(domain_name)

        assert domain_name in str(exc_info.value)
        assert "does not exist on forwardemail.net" in str(exc_info.value)

    ####################################################################
    #
    def test_get_domain_id_reraises_non_404_errors(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: the forwardemail.net API returns a non-404 error
        WHEN:  get_domain_id() is called
        THEN:  the HTTPError is re-raised unchanged
        """
        domain_name = faker.domain_name()
        mock_api.req.side_effect = HTTPError(
            url="http://test.com",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b""),
        )

        with pytest.raises(HTTPError) as exc_info:
            cache.get_domain_id(domain_name)

        assert exc_info.value.code == 500

    ####################################################################
    #
    def test_get_alias_id_returns_cached_value(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: an alias ID already in the cache
        WHEN:  get_alias_id() is called
        THEN:  it returns the cached value without calling the API
        """
        mailbox = faker.user_name()
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()
        cache.set_alias({"name": mailbox, "id": alias_id}, domain_name)

        result = cache.get_alias_id(domain_id, f"{mailbox}@{domain_name}")

        assert result == alias_id
        mock_api.req.assert_not_called()

    ####################################################################
    #
    def test_get_alias_id_fetches_from_api_on_miss(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: an alias not in the cache but existing on forwardemail.net
        WHEN:  get_alias_id() is called
        THEN:  it fetches the alias from the API, caches the ID, and returns it
        """
        mailbox = faker.user_name()
        domain_name = faker.domain_name()
        domain_id = faker.uuid4()
        alias_id = faker.uuid4()
        email_address = f"{mailbox}@{domain_name}"
        mock_api.req.return_value.json.return_value = {
            "id": alias_id,
            "name": mailbox,
        }

        result = cache.get_alias_id(domain_id, email_address)

        assert result == alias_id
        mock_api.req.assert_called_once()
        # Subsequent call should use the cache
        mock_api.req.reset_mock()
        assert cache.get_alias_id(domain_id, email_address) == alias_id
        mock_api.req.assert_not_called()

    ####################################################################
    #
    def test_get_alias_id_raises_key_error_when_not_found(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: an alias that does not exist on forwardemail.net
        WHEN:  get_alias_id() is called
        THEN:  it raises KeyError (not Http404 or HTTPError)
        """
        domain_id = faker.uuid4()
        email_address = faker.email()
        mock_api.req.side_effect = HTTPError(
            url=f"https://api.forwardemail.net/v1/domains/{domain_id}/alias",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=BytesIO(b""),
        )

        with pytest.raises(KeyError) as exc_info:
            cache.get_alias_id(domain_id, email_address)

        assert email_address in str(exc_info.value)
        assert "does not exist on forwardemail.net" in str(exc_info.value)

    ####################################################################
    #
    def test_get_alias_id_reraises_non_404_errors(
        self, cache, mock_api, faker
    ) -> None:
        """
        GIVEN: the forwardemail.net API returns a non-404 error
        WHEN:  get_alias_id() is called
        THEN:  the HTTPError is re-raised unchanged
        """
        domain_id = faker.uuid4()
        email_address = faker.email()
        mock_api.req.side_effect = HTTPError(
            url="http://test.com",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=BytesIO(b""),
        )

        with pytest.raises(HTTPError) as exc_info:
            cache.get_alias_id(domain_id, email_address)

        assert exc_info.value.code == 503


########################################################################
########################################################################
#
class TestRateLimitInfo:
    """Tests for the RateLimitInfo dataclass computed properties."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "remaining,limit,expected",
        [
            pytest.param(25, 100, 25.0, id="normal"),
            pytest.param(0, 0, 100.0, id="zero-limit-avoids-divide-by-zero"),
        ],
    )
    def test_percent_remaining(
        self, remaining: int, limit: int, expected: float
    ) -> None:
        """
        GIVEN: a RateLimitInfo with varying remaining/limit values
        WHEN:  percent_remaining is accessed
        THEN:  it returns (remaining/limit)*100, or 100.0 when limit is 0
        """
        info = RateLimitInfo(
            remaining=remaining, reset_timestamp=0, limit=limit, last_updated=0
        )
        assert info.percent_remaining == expected

    ####################################################################
    #
    @pytest.mark.parametrize(
        "seconds_offset,expected",
        [
            pytest.param(-100, True, id="past-timestamp"),
            pytest.param(3600, False, id="future-timestamp"),
        ],
    )
    def test_is_expired(self, seconds_offset: int, expected: bool) -> None:
        """
        GIVEN: a RateLimitInfo with reset_timestamp in the past or future
        WHEN:  is_expired is accessed
        THEN:  it returns True for past timestamps, False for future ones
        """
        info = RateLimitInfo(
            remaining=10,
            reset_timestamp=int(time.time()) + seconds_offset,
            limit=100,
            last_updated=0,
        )
        assert info.is_expired is expected

    ####################################################################
    #
    @pytest.mark.parametrize(
        "seconds_offset,expected",
        [
            pytest.param(
                60, pytest.approx(60.0, abs=1.0), id="future-timestamp"
            ),
            pytest.param(-100, 0, id="past-timestamp-clamped-to-zero"),
        ],
    )
    def test_seconds_until_reset(
        self, seconds_offset: int, expected: float
    ) -> None:
        """
        GIVEN: a RateLimitInfo with reset_timestamp in the past or future
        WHEN:  seconds_until_reset is accessed
        THEN:  it returns the seconds remaining, or 0 if the window has passed
        """
        info = RateLimitInfo(
            remaining=10,
            reset_timestamp=int(time.time()) + seconds_offset,
            limit=100,
            last_updated=0,
        )
        assert info.seconds_until_reset == expected


########################################################################
########################################################################
#
class TestAPIClientRateLimit:
    """Tests for APIClient rate-limit throttling behavior."""

    ####################################################################
    #
    @pytest.fixture
    def client(self) -> APIClient:
        return APIClient("test_provider")

    ####################################################################
    #
    # _update_rate_limit_from_headers
    ####################################################################

    ####################################################################
    #
    def test_update_from_headers_sets_rate_limit(self, client) -> None:
        """
        GIVEN: a response with all three X-RateLimit-* headers present
        WHEN:  _update_rate_limit_from_headers is called
        THEN:  _rate_limit is populated with the correct values
        """
        assert client._rate_limit is None

        client._update_rate_limit_from_headers(
            {
                "X-RateLimit-Remaining": "42",
                "X-RateLimit-Reset": "9999999999",
                "X-RateLimit-Limit": "100",
            }
        )

        assert client._rate_limit is not None
        assert client._rate_limit.remaining == 42
        assert client._rate_limit.reset_timestamp == 9999999999
        assert client._rate_limit.limit == 100

    ####################################################################
    #
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param(
                {"Content-Type": "application/json"},
                id="no-rate-limit-headers",
            ),
            pytest.param(
                {"X-RateLimit-Remaining": "42", "X-RateLimit-Limit": "100"},
                id="missing-reset-header",
            ),
        ],
    )
    def test_update_from_headers_noop_when_headers_incomplete(
        self, client, headers: dict
    ) -> None:
        """
        GIVEN: a response missing at least one of the three X-RateLimit-* headers
        WHEN:  _update_rate_limit_from_headers is called
        THEN:  _rate_limit remains None (all three must be present)
        """
        client._update_rate_limit_from_headers(headers)

        assert client._rate_limit is None

    ####################################################################
    #
    def test_update_from_headers_handles_malformed_values(
        self, client, caplog
    ) -> None:
        """
        GIVEN: X-RateLimit-* headers containing a non-integer value
        WHEN:  _update_rate_limit_from_headers is called
        THEN:  the parse error is caught and logged; _rate_limit remains None
        """
        client._update_rate_limit_from_headers(
            {
                "X-RateLimit-Remaining": "not-a-number",
                "X-RateLimit-Reset": "9999999999",
                "X-RateLimit-Limit": "100",
            }
        )

        assert client._rate_limit is None
        assert "Failed to parse rate limit headers" in caplog.text

    ####################################################################
    #
    @pytest.mark.parametrize(
        "remaining,expect_warning",
        [
            pytest.param(10, True, id="10-percent-remaining-warns"),
            pytest.param(50, False, id="50-percent-remaining-no-warn"),
        ],
    )
    def test_update_from_headers_low_capacity_warning(
        self, client, caplog, remaining: int, expect_warning: bool
    ) -> None:
        """
        GIVEN: X-RateLimit-* headers with varying remaining capacity
        WHEN:  _update_rate_limit_from_headers is called
        THEN:  a warning is logged when remaining capacity is below 20%
        """
        client._update_rate_limit_from_headers(
            {
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": "9999999999",
                "X-RateLimit-Limit": "100",
            }
        )

        assert ("Rate limit warning" in caplog.text) is expect_warning

    ####################################################################
    #
    # _should_throttle
    ####################################################################

    ####################################################################
    #
    def test_should_throttle_false_when_no_rate_limit(self, client) -> None:
        """
        GIVEN: an APIClient with no rate limit info yet (_rate_limit is None)
        WHEN:  _should_throttle is called
        THEN:  it returns False
        """
        assert client._rate_limit is None
        assert client._should_throttle() is False

    ####################################################################
    #
    @pytest.mark.parametrize(
        "remaining,seconds_offset,expected",
        [
            pytest.param(2, -100, False, id="expired-window"),
            pytest.param(50, 3600, False, id="50-percent-above-threshold"),
            pytest.param(10, 3600, True, id="10-percent-at-threshold-boundary"),
            pytest.param(3, 3600, True, id="3-percent-below-threshold"),
        ],
    )
    def test_should_throttle_with_active_rate_limit(
        self, client, remaining: int, seconds_offset: int, expected: bool
    ) -> None:
        """
        GIVEN: an APIClient with a RateLimitInfo at various remaining levels
        WHEN:  _should_throttle is called
        THEN:  it returns True only when remaining <= 10% of limit and not expired
        """
        client._rate_limit = RateLimitInfo(
            remaining=remaining,
            reset_timestamp=int(time.time()) + seconds_offset,
            limit=100,
            last_updated=0,
        )
        assert client._should_throttle() is expected

    ####################################################################
    #
    # _calculate_sleep_time
    ####################################################################

    ####################################################################
    #
    def test_calculate_sleep_zero_when_no_rate_limit(self, client) -> None:
        """
        GIVEN: an APIClient with no rate limit info (_rate_limit is None)
        WHEN:  _calculate_sleep_time is called
        THEN:  it returns 0
        """
        assert client._rate_limit is None
        assert client._calculate_sleep_time() == 0

    ####################################################################
    #
    def test_calculate_sleep_zero_when_expired(self, client) -> None:
        """
        GIVEN: an APIClient whose rate limit window has already expired
        WHEN:  _calculate_sleep_time is called
        THEN:  it returns 0
        """
        client._rate_limit = RateLimitInfo(
            remaining=2,
            reset_timestamp=int(time.time()) - 100,
            limit=100,
            last_updated=0,
        )
        assert client._calculate_sleep_time() == 0

    ####################################################################
    #
    @pytest.mark.parametrize(
        "remaining,reset_offset,expected",
        [
            pytest.param(
                3,
                60,
                pytest.approx(60.0),
                id="below-min-reserved-waits-for-reset",
            ),
            pytest.param(
                10,
                10,
                pytest.approx(2.0),
                id="spread-evenly-10s-over-5-available",
            ),
            pytest.param(
                10,
                100,
                5.0,
                id="capped-at-five-seconds",
            ),
            pytest.param(
                10,
                0,
                0,
                id="zero-seconds-until-reset",
            ),
        ],
    )
    def test_calculate_sleep_time_with_active_rate_limit(
        self, client, mocker, remaining: int, reset_offset: int, expected: float
    ) -> None:
        """
        GIVEN: an active rate limit window with varying remaining requests and time
        WHEN:  _calculate_sleep_time is called (with time.time mocked to 1000.0)
        THEN:  it spreads remaining requests over the window, capped at 5 seconds
        """
        mocker.patch(
            "as_email.providers.forwardemail.time.time", return_value=1000.0
        )
        client._rate_limit = RateLimitInfo(
            remaining=remaining,
            reset_timestamp=int(1000 + reset_offset),
            limit=100,
            last_updated=1000.0,
        )
        assert client._calculate_sleep_time() == expected

    ####################################################################
    #
    # _wait_if_needed
    ####################################################################

    ####################################################################
    #
    def test_wait_if_needed_sleeps_when_throttling(
        self, client, mocker
    ) -> None:
        """
        GIVEN: an APIClient that needs throttling with a 2.0s calculated sleep
        WHEN:  _wait_if_needed is called
        THEN:  time.sleep is called with the calculated sleep time
        """
        mocker.patch.object(client, "_should_throttle", return_value=True)
        mocker.patch.object(client, "_calculate_sleep_time", return_value=2.0)
        mock_sleep = mocker.patch("as_email.providers.forwardemail.time.sleep")
        # Populate _rate_limit so the log statement inside _wait_if_needed works
        client._rate_limit = RateLimitInfo(
            remaining=5,
            reset_timestamp=int(time.time()) + 60,
            limit=100,
            last_updated=0,
        )

        client._wait_if_needed()

        mock_sleep.assert_called_once_with(2.0)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "should_throttle,sleep_time",
        [
            pytest.param(False, 2.0, id="not-throttling"),
            pytest.param(True, 0, id="throttling-but-zero-sleep-time"),
        ],
    )
    def test_wait_if_needed_no_sleep(
        self, client, mocker, should_throttle: bool, sleep_time: float
    ) -> None:
        """
        GIVEN: either throttling is not needed, or the calculated sleep time is 0
        WHEN:  _wait_if_needed is called
        THEN:  time.sleep is never called
        """
        mocker.patch.object(
            client, "_should_throttle", return_value=should_throttle
        )
        mocker.patch.object(
            client, "_calculate_sleep_time", return_value=sleep_time
        )
        mock_sleep = mocker.patch("as_email.providers.forwardemail.time.sleep")

        client._wait_if_needed()

        mock_sleep.assert_not_called()


########################################################################
########################################################################
#
class TestPaginatedRequest:
    """Tests for ForwardEmailBackend.paginated_request."""

    ####################################################################
    #
    @pytest.fixture
    def backend(self) -> ForwardEmailBackend:
        return ForwardEmailBackend()

    ####################################################################
    #
    def _make_response(self, mocker, items: list, link_header: str = ""):
        """Create a mock HTTP response with items and optional Link header."""
        resp = mocker.MagicMock()
        resp.json.return_value = items
        resp.headers = {"Link": link_header} if link_header else {}
        return resp

    ####################################################################
    #
    @pytest.mark.parametrize(
        "items",
        [
            pytest.param([{"id": "a"}, {"id": "b"}], id="two-items"),
            pytest.param([], id="empty-page"),
        ],
    )
    def test_single_page_returns_items(
        self, backend, mocker, items: list
    ) -> None:
        """
        GIVEN: a single-page endpoint (no Link: next header)
        WHEN:  paginated_request is called
        THEN:  exactly one API request is made and all items from that page are yielded
        """
        resp = self._make_response(mocker, items)
        mock_req = mocker.patch.object(backend.api, "req", return_value=resp)

        result = list(backend.paginated_request("v1/domains"))

        assert result == items
        mock_req.assert_called_once_with(HTTPMethod.GET, "v1/domains")

    ####################################################################
    #
    def test_two_pages_follows_next_link(self, backend, mocker) -> None:
        """
        GIVEN: an endpoint that returns two pages via a Link: next header
        WHEN:  paginated_request is called
        THEN:  two API requests are made and items from both pages are yielded
               with the second request using the URL extracted from the Link header
        """
        next_url = "https://api.forwardemail.net/v1/domains?page=2"
        items_p1 = [{"id": "a"}]
        items_p2 = [{"id": "b"}, {"id": "c"}]
        resp1 = self._make_response(
            mocker,
            items_p1,
            f'<{next_url}>; rel="next", <{next_url}>; rel="last"',
        )
        resp2 = self._make_response(mocker, items_p2)
        mock_req = mocker.patch.object(
            backend.api, "req", side_effect=[resp1, resp2]
        )

        result = list(backend.paginated_request("v1/domains"))

        assert result == items_p1 + items_p2
        assert mock_req.call_count == 2
        mock_req.assert_any_call(HTTPMethod.GET, "v1/domains")
        mock_req.assert_any_call(HTTPMethod.GET, next_url)

    ####################################################################
    #
    def test_http_error_propagates(self, backend, mocker) -> None:
        """
        GIVEN: an endpoint that returns a non-200 HTTP response
        WHEN:  paginated_request is called
        THEN:  the HTTPError raised by raise_for_status propagates to the caller
        """
        mock_req = mocker.patch.object(backend.api, "req")
        mock_req.return_value.raise_for_status.side_effect = HTTPError(
            "http://test.com", 404, "Not Found", {}, BytesIO(b"")
        )

        with pytest.raises(HTTPError):
            list(backend.paginated_request("v1/domains"))

    ####################################################################
    #
    @pytest.mark.parametrize(
        "link_header,expect_second_call",
        [
            pytest.param(
                "",
                False,
                id="empty-link-header",
            ),
            pytest.param(
                '<https://api.forwardemail.net/v1/domains?page=2>; rel="last", '
                '<https://api.forwardemail.net/v1/domains?page=1>; rel="first"',
                False,
                id="link-header-without-next-rel",
            ),
            pytest.param(
                '<https://api.forwardemail.net/v1/domains?page=2>; rel="next", '
                '<https://api.forwardemail.net/v1/domains?page=2>; rel="last"',
                True,
                id="link-header-with-next-rel",
            ),
        ],
    )
    def test_link_header_parsing(
        self,
        backend,
        mocker,
        link_header: str,
        expect_second_call: bool,
    ) -> None:
        """
        GIVEN: a first-page response with various Link header values
        WHEN:  paginated_request is called
        THEN:  a second API call is made only when rel="next" is present in the header
        """
        resp1 = self._make_response(mocker, [{"id": "x"}], link_header)
        resp2 = self._make_response(mocker, [])
        mock_req = mocker.patch.object(
            backend.api, "req", side_effect=[resp1, resp2]
        )

        list(backend.paginated_request("v1/domains"))

        expected_calls = 2 if expect_second_call else 1
        assert mock_req.call_count == expected_calls


########################################################################
########################################################################
#
class TestAPIClientReq:
    """Tests for APIClient.req() HTTP dispatch."""

    ####################################################################
    #
    @pytest.fixture
    def client(self) -> APIClient:
        return APIClient("test_provider")

    ####################################################################
    #
    def test_req_sends_json_not_form_encoded(self, client, mocker) -> None:
        """
        GIVEN: an APIClient and a data dict containing Python booleans
        WHEN:  req() is called with that data
        THEN:  requests.request is called with json=data (not data=data) so
               that Python booleans are serialised as JSON true/false rather
               than the strings "True"/"False" which the ForwardEmail API
               rejects with a 400
        """
        mock_response = mocker.MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_requests = mocker.patch(
            "as_email.providers.forwardemail.requests.request",
            return_value=mock_response,
        )
        mocker.patch(
            "as_email.providers.forwardemail.get_provider_token",
            return_value="test-token",
        )

        payload = {
            "catchall": False,
            "has_virus_protection": True,
            "name": "example.org",
        }
        client.req(HTTPMethod.POST, "v1/domains", data=payload)

        _, kwargs = mock_requests.call_args
        assert "json" in kwargs, "req() must use json= not data="
        assert (
            "data" not in kwargs
        ), "req() must not use data= (causes bool serialisation as 'True'/'False')"
        assert kwargs["json"] == payload
