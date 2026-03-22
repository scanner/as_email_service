#!/usr/bin/env python
#
"""
Test the Postmark provider backend.
"""

# system imports
#
import json
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path

# 3rd party imports
#
import pytest
from django.test import RequestFactory
from postmarker.exceptions import ClientError
from pytest_mock import MockerFixture
from requests import RequestException

# project imports
#
from ...models import EmailAccount, Server
from ...providers.base import BounceType
from ...providers.postmark import PostmarkBackend

pytestmark = pytest.mark.django_db


########################################################################
#
def _make_text_message(body: str = "Test message") -> EmailMessage:
    """Create an EmailMessage with plain-text content."""
    msg = EmailMessage()
    msg.set_content(body)
    return msg


########################################################################
#
def test_postmark_backend_send_email_smtp_success(
    server_with_token, smtp
) -> None:
    """
    Test successful SMTP email sending via Postmark backend.

    Given: A server with Postmark backend and proper token configuration
    When: send_email_smtp() is called with a valid message
    Then: The email is sent via SMTP successfully
    And: The X-PM-Message-Stream header is set to "outbound"
    """
    server = server_with_token()

    backend = PostmarkBackend()
    message = _make_text_message()
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    result = backend.send_email_smtp(
        server=server,
        message=message,
        email_from=email_from,
        rcpt_tos=rcpt_tos,
        spool_on_retryable=False,
    )

    assert result is True
    # Verify X-PM-Message-Stream header was added
    assert message["X-PM-Message-Stream"] == "outbound"
    # Verify SMTP was called
    smtp.sendmail.assert_called_once()


########################################################################
#
def test_postmark_backend_send_email_smtp_wrong_domain(
    server_with_token,
) -> None:
    """
    Test SMTP sending fails when email domain doesn't match server.

    Given: A server with Postmark backend
    When: send_email_smtp() is called with mismatched email domain
    Then: A ValueError is raised
    """
    server = server_with_token()

    backend = PostmarkBackend()
    message = _make_text_message()
    email_from = "test@wrongdomain.com"
    rcpt_tos = ["recipient@example.com"]

    with pytest.raises(ValueError) as exc_info:
        backend.send_email_smtp(
            server=server,
            message=message,
            email_from=email_from,
            rcpt_tos=rcpt_tos,
        )

    assert "Domain name" in str(exc_info.value)
    assert server.domain_name in str(exc_info.value)


########################################################################
#
def test_postmark_backend_send_email_smtp_missing_token(
    server_factory, settings
) -> None:
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
    message = _make_text_message()
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    with pytest.raises(KeyError) as exc_info:
        backend.send_email_smtp(
            server=server,
            message=message,
            email_from=email_from,
            rcpt_tos=rcpt_tos,
        )

    assert "token" in str(exc_info.value).lower()


########################################################################
#
def test_postmark_backend_send_email_smtp_exception_spools(
    server_with_token, smtp, email_spool_dir
) -> None:
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
    message = _make_text_message()
    email_from = f"test@{server.domain_name}"
    rcpt_tos = ["recipient@example.com"]

    result = backend.send_email_smtp(
        server=server,
        message=message,
        email_from=email_from,
        rcpt_tos=rcpt_tos,
        spool_on_retryable=True,
    )

    assert result is False
    # Verify message was spooled
    spool_files = list(Path(server.outgoing_spool_dir).glob("*"))
    assert len(spool_files) == 1


########################################################################
#
def test_postmark_backend_send_email_api_success(
    server_with_token, mocker
) -> None:
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
    message = _make_text_message()

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
) -> None:
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
    message = _make_text_message()

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
) -> None:
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
        message = _make_text_message(f"Test message {error_code}")

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
) -> None:
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
    message = _make_text_message()

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
) -> None:
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
@pytest.mark.parametrize(
    "account_exists, account_enabled, expected_log",
    [
        pytest.param(
            False,
            True,
            "Received email for EmailAccount that does not exist",
            id="nonexistent-account",
        ),
        pytest.param(
            True,
            False,
            "Received email for disabled EmailAccount",
            id="disabled-account",
        ),
    ],
)
def test_postmark_backend_handle_incoming_webhook_no_delivery(
    rf,
    server_factory,
    email_account_factory,
    email_spool_dir,
    mocker,
    caplog,
    account_exists,
    account_enabled,
    expected_log,
) -> None:
    """
    Test incoming webhook when delivery should not occur.

    GIVEN: An incoming email for an account that does not exist OR is disabled
    WHEN:  handle_incoming_webhook() is called
    THEN:  A "no such email account" success response is returned
    AND:   No email is spooled
    AND:   The dispatch task is not called
    AND:   An appropriate log message is emitted
    """
    server = server_factory()
    if account_exists:
        email_account = email_account_factory(
            server=server, enabled=account_enabled
        )
        recipient = email_account.email_address
    else:
        recipient = f"nonexistent@{server.domain_name}"

    mock_dispatch = mocker.patch(
        "as_email.providers.postmark.dispatch_incoming_email"
    )

    backend = PostmarkBackend()

    webhook_payload = {
        "MessageID": "test-message-id",
        "From": "sender@example.com",
        "OriginalRecipient": recipient,
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

    spool_files = list(Path(server.incoming_spool_dir).glob("*"))
    assert len(spool_files) == 0

    mock_dispatch.assert_not_called()
    assert expected_log in caplog.text


########################################################################
#
def test_postmark_backend_handle_incoming_webhook_bad_json(
    rf, server_factory
) -> None:
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
) -> None:
    """
    Test successful bounce webhook handling.

    Given: A valid bounce webhook from Postmark
    When: handle_bounce_webhook() is called
    Then: A success JsonResponse is returned
    And: The process_bounce task is queued with a BounceEvent
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the bounce processing task
    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_bounce"
    )

    backend = PostmarkBackend()

    bounce_payload = {
        "From": email_account.email_address,
        "Type": "HardBounce",
        "TypeCode": 1,
        "ID": 12345,
        "Email": "bounced@example.com",
        "Description": "The server was unable to deliver your message",
        "Details": "Test bounce details",
        "Subject": "Test subject",
        "Inactive": False,
        "CanActivate": True,
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

    # Verify process_bounce was called with a properly normalized BounceEvent
    mock_process_bounce.assert_called_once()
    call_args = mock_process_bounce.call_args[0]
    assert call_args[0] == email_account.pk
    event = call_args[1]
    assert event.bounce_type == BounceType.BOUNCE
    assert event.email_from == email_account.email_address
    assert event.email_to == "bounced@example.com"
    assert event.transient is False  # TypeCode 1 = HardBounce


########################################################################
#
def test_postmark_backend_handle_bounce_webhook_no_account(
    rf, server_factory, mocker
) -> None:
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
        "as_email.providers.postmark.process_bounce"
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
) -> None:
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
) -> None:
    """
    Test successful spam webhook handling.

    Given: A valid spam complaint webhook from Postmark
    When: handle_spam_webhook() is called
    Then: A success JsonResponse is returned
    And: The process_bounce task is queued with a BounceEvent
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the bounce processing task
    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_bounce"
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

    # Verify process_bounce was called with a properly normalized BounceEvent
    mock_process_bounce.assert_called_once()
    call_args = mock_process_bounce.call_args[0]
    assert call_args[0] == email_account.pk
    event = call_args[1]
    assert event.bounce_type == BounceType.SPAM
    assert event.email_from == email_account.email_address
    assert event.email_to == "complained@example.com"
    assert event.transient is False  # TypeCode 512 = SpamNotification


########################################################################
#
def test_postmark_backend_handle_spam_webhook_invalid_typecode(
    rf, server_factory, email_account_factory, mocker
) -> None:
    """
    Test spam webhook with invalid TypeCode.

    Given: A spam webhook with non-integer TypeCode
    When: handle_spam_webhook() is called
    Then: The TypeCode is normalized to 2048 (unknown)
    And: A success response is returned
    And: The process_bounce task is called with a non-transient BounceEvent
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    # Mock the bounce processing task
    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_bounce"
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

    # Invalid TypeCode should be treated as non-transient
    mock_process_bounce.assert_called_once()
    event = mock_process_bounce.call_args[0][1]
    assert event.transient is False
    assert event.bounce_type == BounceType.SPAM


########################################################################
#
@pytest.mark.parametrize(
    "type_code,expected_transient",
    [
        pytest.param(2, True, id="transient-typecode"),
        pytest.param(99999, False, id="unrecognized-typecode"),
        pytest.param(None, False, id="absent-typecode"),
    ],
)
def test_postmark_backend_handle_bounce_webhook_typecode_transient(
    rf: RequestFactory,
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
    mocker: MockerFixture,
    type_code: int | None,
    expected_transient: bool,
) -> None:
    """
    Given: A bounce webhook with various TypeCode values
    When: handle_bounce_webhook() normalizes the payload
    Then: The BounceEvent.transient field reflects the TypeCode category
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_bounce"
    )

    backend = PostmarkBackend()

    bounce_payload = {
        "From": email_account.email_address,
        "Type": "Transient",
        "ID": 12345,
        "Email": "bounced@example.com",
        "Description": "Test bounce",
    }
    if type_code is not None:
        bounce_payload["TypeCode"] = type_code

    request = rf.post(
        f"/hook/postmark/bounce/{server.domain_name}/",
        data=json.dumps(bounce_payload),
        content_type="application/json",
    )

    response = backend.handle_bounce_webhook(request, server)

    assert response.status_code == 200
    event = mock_process_bounce.call_args[0][1]
    assert event.transient is expected_transient


########################################################################
#
def test_postmark_backend_handle_bounce_webhook_all_fields_mapped(
    rf: RequestFactory,
    server_factory: Callable[..., Server],
    email_account_factory: Callable[..., EmailAccount],
    mocker: MockerFixture,
) -> None:
    """
    Given: A bounce webhook with all optional Postmark fields populated
    When: handle_bounce_webhook() normalizes the payload
    Then: Every BounceEvent field is correctly mapped from the payload
    """
    server = server_factory()
    email_account = email_account_factory(server=server)

    mock_process_bounce = mocker.patch(
        "as_email.providers.postmark.process_bounce"
    )

    backend = PostmarkBackend()

    bounce_payload = {
        "From": email_account.email_address,
        "Type": "HardBounce",
        "TypeCode": 1,
        "ID": 12345,
        "Email": "bounced@example.com",
        "Description": "The server was unable to deliver your message",
        "Details": "smtp; 550 5.1.1 unknown user",
        "Subject": "Important message",
        "Inactive": True,
        "CanActivate": True,
        "Content": "Original message body",
    }

    request = rf.post(
        f"/hook/postmark/bounce/{server.domain_name}/",
        data=json.dumps(bounce_payload),
        content_type="application/json",
    )

    response = backend.handle_bounce_webhook(request, server)

    assert response.status_code == 200
    event = mock_process_bounce.call_args[0][1]
    assert event.email_from == email_account.email_address
    assert event.email_to == "bounced@example.com"
    assert event.bounce_type == BounceType.BOUNCE
    assert event.transient is False
    assert event.subject == "Important message"
    assert event.description == "The server was unable to deliver your message"
    assert event.details == "smtp; 550 5.1.1 unknown user"
    assert event.inactive is True
    assert event.can_activate is True
    assert event.original_message == "Original message body"


########################################################################
#
def test_postmark_backend_get_client(server_with_token) -> None:
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
def test_postmark_backend_get_client_missing_token(
    server_factory, settings
) -> None:
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


########################################################################
#
def test_postmark_backend_send_email_dispatches_to_smtp(
    server_with_token: Callable[..., Server],
    email_factory: Callable[..., EmailMessage],
    mocker: MockerFixture,
) -> None:
    """
    GIVEN: a PostmarkBackend and a message
    WHEN:  send_email() is called with email_from and rcpt_tos
    THEN:  it delegates to send_email_smtp() passing them through
    """
    server = server_with_token(provider_name="postmark")
    backend = PostmarkBackend()
    from_addr = f"sender@{server.domain_name}"
    to_addr = "recipient@example.com"
    msg = email_factory(msg_from=from_addr, to=to_addr)

    mock_send_smtp = mocker.patch.object(
        backend, "send_email_smtp", return_value=True
    )

    result = backend.send_email(
        server=server, message=msg, email_from=from_addr, rcpt_tos=[to_addr]
    )

    assert result is True
    mock_send_smtp.assert_called_once_with(
        server, msg, from_addr, [to_addr], True
    )


########################################################################
#
def test_postmark_backend_send_email_passes_none_when_omitted(
    server_with_token: Callable[..., Server],
    email_factory: Callable[..., EmailMessage],
    mocker: MockerFixture,
) -> None:
    """
    GIVEN: a message with To, Cc, and Bcc recipients
    WHEN:  send_email() is called without explicit email_from/rcpt_tos
    THEN:  None values are passed through to send_email_smtp() which
           calls resolve_envelope() to extract them from headers
    """
    server = server_with_token(provider_name="postmark")
    backend = PostmarkBackend()
    from_addr = f"sender@{server.domain_name}"
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = "to@example.com"
    msg["Cc"] = "cc@example.com"
    msg["Bcc"] = "bcc@example.com"
    msg.set_content("body")

    mock_send_smtp = mocker.patch.object(
        backend, "send_email_smtp", return_value=True
    )

    backend.send_email(server=server, message=msg)

    mock_send_smtp.assert_called_once_with(server, msg, None, None, True)
