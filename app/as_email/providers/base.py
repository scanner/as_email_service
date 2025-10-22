#!/usr/bin/env python
#
"""
Base abstract class for email provider backends.

Defines the interface that all provider backends must implement for sending
emails and handling webhooks.
"""
# system imports
#
import email.message
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List

# 3rd party imports
#
from django.http import HttpRequest, JsonResponse

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import Server


########################################################################
########################################################################
#
class ProviderBackend(ABC):
    """
    Abstract base class for email provider backends.

    Each provider (e.g., Postmark, ForwardEmail) must implement this interface
    to provide email sending capabilities via SMTP and API, as well as webhook
    handling for incoming email, bounces, and spam notifications.
    """

    ####################################################################
    #
    @abstractmethod
    def send_email_smtp(
        self,
        server: "Server",
        email_from: str,
        rcpt_tos: List[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send an email via SMTP using this provider.

        Args:
            server: The Server instance sending the email
            email_from: The email address sending from (must match server domain)
            rcpt_tos: List of recipient email addresses
            msg: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise

        Raises:
            ValueError: If email_from domain doesn't match server domain
            KeyError: If server token is not configured in settings
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def send_email_api(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send an email via the provider's web API.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def handle_incoming_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle incoming email webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def handle_bounce_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle bounce notification webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle spam complaint webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        pass
