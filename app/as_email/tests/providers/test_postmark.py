#!/usr/bin/env python
#
"""
Test the Postmark provider backend.
"""
# system imports
#
import json
from email.mime.text import MIMEText
from pathlib import Path

# 3rd party imports
#
import pytest
from postmarker.exceptions import ClientError
from requests import RequestException

# project imports
#
from ...providers.postmark import PostmarkBackend

pytestmark = pytest.mark.django_db


########################################################################
#
def test_postmark_backend_send_email_smtp_success(server_with_token, smtp):
    """
    Test successful SMTP email sending via Postmark backend.

    Given: A server with Postmark backend and proper token configuration
    When: send_email_smtp() is called with a valid message
    Then: The email is sent via SMTP successfully
    And: The X-PM-Message-Stream header is set to "outbound"
    """
    server = server_with_token()

    backend = PostmarkBackend()
    message = MIMEText("Test message")
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    result = backend.send_email_smtp(
        server=server,
        email_from=email_from,
        rcpt_tos=rcpt_tos,
        msg=message,
        spool_on_retryable=False,
    )

    assert result is True
    # Verify X-PM-Message-Stream header was added
    assert message["X-PM-Message-Stream"] == "outbound"
    # Verify SMTP was called
    smtp.sendmail.assert_called_once()


########################################################################
#
def test_postmark_backend_send_email_smtp_wrong_domain(server_with_token):
    """
    Test SMTP sending fails when email domain doesn't match server.

    Given: A server with Postmark backend
    When: send_email_smtp() is called with mismatched email domain
    Then: A ValueError is raised
    """
    server = server_with_token()

    backend = PostmarkBackend()
    message = MIMEText("Test message")
    email_from = "test@wrongdomain.com"
    rcpt_tos = ["recipient@example.com"]

    with pytest.raises(ValueError) as exc_info:
        backend.send_email_smtp(
            server=server,
            email_from=email_from,
            rcpt_tos=rcpt_tos,
            msg=message,
        )

    assert "Domain name" in str(exc_info.value)
    assert server.domain_name in str(exc_info.value)


########################################################################
#
def test_postmark_backend_send_email_smtp_missing_token(
    server_factory, settings
):
    """
    Test SMTP sending fails when server token is missing.

    Given: A server without a configured token
    When: send_email_smtp() is called
    Then: A KeyError is raised
    """
    server = server_factory()
    # Ensure token doesn't exist
    provider_name = "postmark"
    if (
        provider_name in settings.EMAIL_SERVER_TOKENS
        and server.domain_name in settings.EMAIL_SERVER_TOKENS[provider_name]
    ):
        del settings.EMAIL_SERVER_TOKENS[provider_name][server.domain_name]

    backend = PostmarkBackend()
    message = MIMEText("Test message")
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    with pytest.raises(KeyError) as exc_info:
        backend.send_email_smtp(
            server=server,
            email_from=email_from,
            rcpt_tos=rcpt_tos,
            msg=message,
        )

    assert "token" in str(exc_info.value).lower()


########################################################################
#
def test_postmark_backend_send_email_smtp_exception_spools(
    server_with_token, smtp, email_spool_dir
):
    """
    Test SMTP exception causes message to be spooled.

    Given: A server with Postmark backend
    When: send_email_smtp() raises SMTPException
    Then: The message is spooled for retry
    And: False is returned
    """
    import smtplib

    server = server_with_token()

    # Make the mock SMTP client raise an exception
    smtp.starttls.side_effect = smtplib.SMTPException("Connection failed")

    backend = PostmarkBackend()
    message = MIMEText("Test message")
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    result = backend.send_email_smtp(
        server=server,
        email_from=email_from,
        rcpt_tos=rcpt_tos,
        msg=message,
        spool_on_retryable=True,
    )

    assert result is False
    # Verify message was spooled
    spool_files = list(Path(server.outgoing_spool_dir).glob("*"))
    assert len(spool_files) == 1


########################################################################
#
def test_postmark_backend_send_email_api_success(server_with_token, mocker):
    """
    Test successful API email sending via Postmark backend.

    Given: A server with Postmark backend and proper token configuration
    When: send_email_api() is called with a valid message
    Then: The email is sent via the Postmark API successfully
    """
    server = server_with_token()

    # Mock PostmarkClient
    mock_client = mocker.MagicMock()
    mocker.patch(
        "as_email.providers.postmark.PostmarkClient", return_value=mock_client
    )

    backend = PostmarkBackend()
    message = MIMEText("Test message")

    result = backend.send_email_api(
        server=server,
        message=message,
        spool_on_retryable=False,
    )

    assert result is True
    # Verify the client was called
    mock_client.emails.send.assert_called_once_with(message)


########################################################################
#
def test_postmark_backend_send_email_api_request_exception(
    server_with_token, email_spool_dir, mocker
):
    """
    Test API sending handles RequestException gracefully.

    Given: A server with Postmark backend
    When: send_email_api() is called and RequestException is raised
    Then: The message is spooled for retry
    And: False is returned
    """
    server = server_with_token()

    # Mock PostmarkClient to raise RequestException
    mock_client = mocker.MagicMock()
    mock_client.emails.send.side_effect = RequestException("Network error")
    mocker.patch(
        "as_email.providers.postmark.PostmarkClient", return_value=mock_client
    )

    backend = PostmarkBackend()
    message = MIMEText("Test message")

    result = backend.send_email_api(
        server=server,
        message=message,
        spool_on_retryable=True,
    )

    assert result is False
    # Verify message was spooled
    spool_files = list(Path(server.outgoing_spool_dir).glob("*"))
    assert len(spool_files) == 1


########################################################################
#
def test_postmark_backend_send_email_api_retryable_client_error(
    server_with_token, email_spool_dir, mocker
):
    """
    Test API sending spools on retryable ClientError codes.

    Given: A server with Postmark backend
    When: send_email_api() raises ClientError with retryable code (100, 405, 429)
    Then: The message is spooled for retry
    And: False is returned
    """
    server = server_with_token()

    backend = PostmarkBackend()

    # Test retryable error codes
    for error_code in [100, 405, 429]:
        message = MIMEText(f"Test message {error_code}")

        # Mock the client to raise ClientError with retryable code
        error = ClientError(error_code=error_code)
        mock_client = mocker.MagicMock()
        mock_client.emails.send.side_effect = error
        mocker.patch(
            "as_email.providers.postmark.PostmarkClient",
            return_value=mock_client,
        )

        result = backend.send_email_api(
            server=server,
            message=message,
            spool_on_retryable=True,
        )

        assert result is False


########################################################################
#
def test_postmark_backend_send_email_api_non_retryable_client_error(
    server_with_token, mocker
):
    """
    Test API sending raises on non-retryable ClientError.

    Given: A server with Postmark backend
    When: send_email_api() raises ClientError with non-retryable code
    Then: The ClientError is propagated
    """
    server = server_with_token()

    # Mock the client to raise ClientError with non-retryable code
    error = ClientError(error_code=401)  # Unauthorized - non-retryable
    mock_client = mocker.MagicMock()
    mock_client.emails.send.side_effect = error
    mocker.patch(
        "as_email.providers.postmark.PostmarkClient", return_value=mock_client
    )

    backend = PostmarkBackend()
    message = MIMEText("Test message")

    with pytest.raises(ClientError):
        backend.send_email_api(
            server=server,
            message=message,
            spool_on_retryable=True,
        )


########################################################################
#
def test_postmark_backend_handle_incoming_webhook_success(
    rf, server_factory, email_account_factory, email_spool_dir, mocker
):
    """
    Test successful incoming email webhook handling.

    Given: A valid incoming email webhook from Postmark
    When: handle_incoming_webhook() is called
    Then: The email is spooled
    And: A success JsonResponse is returned
    And: The dispatch_incoming_email task is queued
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the dispatch task
    mock_dispatch = mocker.patch(
        "as_email.providers.postmark.dispatch_incoming_email"
    )

    backend = PostmarkBackend()

    webhook_payload = {
        "MessageID": "test-message-id",
        "From": "sender@example.com",
        "OriginalRecipient": email_account.email_address,
        "RawEmail": "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody",
        "Date": "2025-10-23T12:00:00Z",
    }

    request = rf.post(
        f"/hook/postmark/incoming/{server.domain_name}/",
        data=json.dumps(webhook_payload),
        content_type="application/json",
    )

    response = backend.handle_incoming_webhook(request, server)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["status"] == "all good"

    # Verify email was spooled
    spool_files = list(Path(server.incoming_spool_dir).glob("*"))
    assert len(spool_files) == 1

    # Verify dispatch task was called
    mock_dispatch.assert_called_once()
    call_args = mock_dispatch.call_args
    assert call_args[0][0] == email_account.pk
    assert str(spool_files[0]) in call_args[0][1]


########################################################################
#
def test_postmark_backend_handle_incoming_webhook_no_account(
    rf, server_factory, email_spool_dir, mocker
):
    """
    Test incoming webhook with non-existent email account.

    Given: An incoming email for non-existent EmailAccount
    When: handle_incoming_webhook() is called
    Then: A success response is returned
    And: No email is spooled
    And: The dispatch task is not called
    """
    server = server_factory()

    # Mock the dispatch task
    mock_dispatch = mocker.patch(
        "as_email.providers.postmark.dispatch_incoming_email"
    )

    backend = PostmarkBackend()

    webhook_payload = {
        "MessageID": "test-message-id",
        "From": "sender@example.com",
        "OriginalRecipient": f"nonexistent@{server.domain_name}",
        "RawEmail": "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody",
        "Date": "2025-10-23T12:00:00Z",
    }

    request = rf.post(
        f"/hook/postmark/incoming/{server.domain_name}/",
        data=json.dumps(webhook_payload),
        content_type="application/json",
    )

    response = backend.handle_incoming_webhook(request, server)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert "no such email account" in data["message"]

    # Verify no email was spooled
    spool_files = list(Path(server.incoming_spool_dir).glob("*"))
    assert len(spool_files) == 0

    # Verify dispatch task was not called
    mock_dispatch.assert_not_called()


########################################################################
#
def test_postmark_backend_handle_incoming_webhook_bad_json(rf, server_factory):
    """
    Test incoming webhook with invalid JSON.

    Given: An incoming webhook with malformed JSON
    When: handle_incoming_webhook() is called
    Then: An HttpResponseBadRequest is returned
    """
    server = server_factory()
    backend = PostmarkBackend()

    request = rf.post(
        f"/hook/postmark/incoming/{server.domain_name}/",
        data="not valid json{",
        content_type="application/json",
    )

    response = backend.handle_incoming_webhook(request, server)

    assert response.status_code == 400
    assert b"invalid json" in response.content


########################################################################
#
def test_postmark_backend_handle_bounce_webhook_success(
    rf, server_factory, email_account_factory, mocker
):
    """
    Test successful bounce webhook handling.

    Given: A valid bounce webhook from Postmark
    When: handle_bounce_webhook() is called
    Then: A success JsonResponse is returned
    And: The process_email_bounce task is queued
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the bounce processing task
    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_email_bounce"
    )

    backend = PostmarkBackend()

    bounce_payload = {
        "From": email_account.email_address,
        "Type": "HardBounce",
        "ID": 12345,
        "Email": "bounced@example.com",
        "Description": "The server was unable to deliver your message",
    }

    request = rf.post(
        f"/hook/postmark/bounce/{server.domain_name}/",
        data=json.dumps(bounce_payload),
        content_type="application/json",
    )

    response = backend.handle_bounce_webhook(request, server)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["status"] == "all good"
    assert "received bounce" in data["message"]

    # Verify bounce processing task was called
    mock_process_bounce.assert_called_once_with(
        email_account.pk, bounce_payload
    )


########################################################################
#
def test_postmark_backend_handle_bounce_webhook_no_account(
    rf, server_factory, mocker
):
    """
    Test bounce webhook for non-existent email account.

    Given: A bounce webhook for non-existent EmailAccount
    When: handle_bounce_webhook() is called
    Then: A success response is returned with appropriate message
    And: The bounce processing task is not called
    """
    server = server_factory()

    # Mock the bounce processing task
    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_email_bounce"
    )

    backend = PostmarkBackend()

    bounce_payload = {
        "From": f"nonexistent@{server.domain_name}",
        "Type": "HardBounce",
        "ID": 12345,
        "Email": "bounced@example.com",
        "Description": "The server was unable to deliver your message",
    }

    request = rf.post(
        f"/hook/postmark/bounce/{server.domain_name}/",
        data=json.dumps(bounce_payload),
        content_type="application/json",
    )

    response = backend.handle_bounce_webhook(request, server)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert "is not an EmailAccount" in data["message"]

    # Verify bounce processing task was not called
    mock_process_bounce.assert_not_called()


########################################################################
#
def test_postmark_backend_handle_bounce_webhook_missing_keys(
    rf, server_factory
):
    """
    Test bounce webhook with missing required keys.

    Given: A bounce webhook missing required keys
    When: handle_bounce_webhook() is called
    Then: An HttpResponseBadRequest is returned
    """
    server = server_factory()
    backend = PostmarkBackend()

    # Missing "Description" key
    bounce_payload = {
        "From": f"test@{server.domain_name}",
        "Type": "HardBounce",
        "ID": 12345,
        "Email": "bounced@example.com",
    }

    request = rf.post(
        f"/hook/postmark/bounce/{server.domain_name}/",
        data=json.dumps(bounce_payload),
        content_type="application/json",
    )

    response = backend.handle_bounce_webhook(request, server)

    assert response.status_code == 400
    assert b"missing expected keys" in response.content


########################################################################
#
def test_postmark_backend_handle_spam_webhook_success(
    rf, server_factory, email_account_factory, mocker
):
    """
    Test successful spam webhook handling.

    Given: A valid spam complaint webhook from Postmark
    When: handle_spam_webhook() is called
    Then: A success JsonResponse is returned
    And: The process_email_spam task is queued
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the spam processing task
    mock_process_spam = mocker.patch(
        "as_email.providers.postmark.process_email_spam"
    )

    backend = PostmarkBackend()

    spam_payload = {
        "From": email_account.email_address,
        "Type": "SpamComplaint",
        "TypeCode": 512,
        "ID": 12345,
        "Email": "complained@example.com",
        "Description": "Recipient marked as spam",
        "Details": "ISP spam complaint",
        "Subject": "Test Subject",
        "MessageID": "test-msg-id",
    }

    request = rf.post(
        f"/hook/postmark/spam/{server.domain_name}/",
        data=json.dumps(spam_payload),
        content_type="application/json",
    )

    response = backend.handle_spam_webhook(request, server)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["status"] == "all good"
    assert "received spam" in data["message"]

    # Verify spam processing task was called
    mock_process_spam.assert_called_once_with(email_account.pk, spam_payload)


########################################################################
#
def test_postmark_backend_handle_spam_webhook_invalid_typecode(
    rf, server_factory, email_account_factory, mocker
):
    """
    Test spam webhook with invalid TypeCode.

    Given: A spam webhook with non-integer TypeCode
    When: handle_spam_webhook() is called
    Then: The TypeCode is set to 2048 (unknown)
    And: A success response is returned
    And: The spam processing task is called with corrected TypeCode
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the spam processing task
    mock_process_spam = mocker.patch(
        "as_email.providers.postmark.process_email_spam"
    )

    backend = PostmarkBackend()

    spam_payload = {
        "From": email_account.email_address,
        "Type": "SpamComplaint",
        "TypeCode": "not-a-number",  # Invalid TypeCode
        "ID": 12345,
        "Email": "complained@example.com",
        "Description": "Recipient marked as spam",
        "Details": "ISP spam complaint",
        "Subject": "Test Subject",
        "MessageID": "test-msg-id",
    }

    request = rf.post(
        f"/hook/postmark/spam/{server.domain_name}/",
        data=json.dumps(spam_payload),
        content_type="application/json",
    )

    response = backend.handle_spam_webhook(request, server)

    assert response.status_code == 200

    # Verify spam processing task was called with corrected TypeCode
    mock_process_spam.assert_called_once()
    call_args = mock_process_spam.call_args[0]
    assert call_args[0] == email_account.pk
    assert call_args[1]["TypeCode"] == 2048  # Should be set to 2048 for unknown


########################################################################
#
def test_postmark_backend_get_client(server_with_token):
    """
    Test _get_client() returns configured PostmarkClient.

    Given: A server with configured token
    When: _get_client() is called
    Then: A PostmarkClient instance is returned
    """
    server = server_with_token()

    backend = PostmarkBackend()
    client = backend._get_client(server)

    assert client is not None


########################################################################
#
def test_postmark_backend_get_client_missing_token(server_factory, settings):
    """
    Test _get_client() raises KeyError when token is missing.

    Given: A server without configured token
    When: _get_client() is called
    Then: A KeyError is raised
    """
    server = server_factory()
    # Ensure token doesn't exist
    provider_name = "postmark"
    if (
        provider_name in settings.EMAIL_SERVER_TOKENS
        and server.domain_name in settings.EMAIL_SERVER_TOKENS[provider_name]
    ):
        del settings.EMAIL_SERVER_TOKENS[provider_name][server.domain_name]

    backend = PostmarkBackend()

    with pytest.raises(KeyError) as exc_info:
        backend._get_client(server)

    assert "token" in str(exc_info.value).lower()
