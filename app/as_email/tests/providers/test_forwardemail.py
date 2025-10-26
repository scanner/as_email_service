#!/usr/bin/env python
#
"""
Test the ForwardEmail provider backend.
"""
# system imports
#
import email.policy
import json
from unittest.mock import Mock

# 3rd party imports
#
import pytest
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
        self, server_factory, caplog
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When receiving a bounce webhook
        Then it should return a "not supported" response and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        request = Mock(spec=HttpRequest)

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
        self, server_factory, caplog
    ) -> None:
        """
        Given a ForwardEmail backend (receive-only provider)
        When receiving a spam complaint webhook
        Then it should return a "not supported" response and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()
        request = Mock(spec=HttpRequest)

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
        self, server_factory, caplog
    ) -> None:
        """
        Given an incoming webhook with invalid JSON
        When the webhook is processed
        Then it should return a 400 error and log a warning
        """
        backend = ForwardEmailBackend()
        server = server_factory()

        # Create request with invalid JSON
        request = Mock(spec=HttpRequest)
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
        self, server_factory, faker, caplog
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

        request = Mock(spec=HttpRequest)
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
        self, server_factory, email_factory, faker, caplog
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

        request = Mock(spec=HttpRequest)
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
        self, server_factory, email_factory, faker, caplog
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

        request = Mock(spec=HttpRequest)
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

        request = Mock(spec=HttpRequest)
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

        request = Mock(spec=HttpRequest)
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

        request = Mock(spec=HttpRequest)
        request.body = json.dumps(payload).encode()

        response = backend.handle_incoming_webhook(request, server)

        # Verify response
        response_data = json.loads(response.content)
        assert response_data["status"] == "all good"
        assert response_data["delivered"] == 1

        # Verify logging shows the hash address was used
        assert "deliver_email_locally: Queued delivery for" in caplog.text
        assert hash_addr in caplog.text
