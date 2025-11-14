#!/usr/bin/env python
#
"""
Base abstract class for email provider backends.

Defines the interface that all provider backends must implement for sending
emails, handling webhooks, and managing provider resources.
"""
# system imports
#
import email.message
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, List

# 3rd party imports
#
from django.http import HttpRequest, JsonResponse

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import EmailAccount, Server


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

    # Provider name constant - must be set by subclasses
    # This is used to look up credentials in EMAIL_SERVER_TOKENS
    PROVIDER_NAME: str | None = None

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
        ...

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
        ...

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
        ...

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
        ...

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
        ...

    ####################################################################
    #
    @abstractmethod
    def create_domain(self, server: "Server") -> Any:
        """
        Create a domain on the provider's service.

        Args:
            server: The Server instance whose domain to create

        Returns:
            Provider-specific response data about the created domain
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def create_update_domain(self, server: "Server") -> Any:
        """
        Create or update a domain on the provider's service.

        This is an idempotent operation - if the domain exists, it should
        be updated (or info fetched), otherwise it should be created.

        Args:
            server: The Server instance whose domain to create or update

        Returns:
            Provider-specific response data about the domain
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def delete_domain(self, server: "Server") -> None:
        """
        Delete a domain from the provider's service.

        Args:
            server: The Server instance whose domain to delete

        Note:
            Providers that don't support domain deletion should implement
            this as a no-op with appropriate logging.
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def create_email_account(self, email_account: "EmailAccount") -> None:
        """
        Create an email account (alias) on the provider's service.

        Args:
            email_account: The EmailAccount instance to create
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def create_update_email_account(
        self, email_account: "EmailAccount"
    ) -> None:
        """
        Create or update an email account (alias) on the provider's service.

        This method should check if the alias already exists and update it if
        so, or create it if it doesn't exist. This is useful for ensuring
        idempotency when syncing email accounts with the provider.

        Args:
            email_account: The EmailAccount instance to create or update
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def delete_email_account(self, email_account: "EmailAccount") -> None:
        """
        Delete an email account (alias) from the provider's service.

        Args:
            email_account: The EmailAccount instance to delete
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def delete_email_account_by_address(
        self, email_address: str, domain_name: str
    ) -> None:
        """
        Delete an email account (alias) by address from the provider's service.

        Args:
            email_address: The full email address to delete
            domain_name: The domain name the email belongs to
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def enable_email_account(
        self, email_account: "EmailAccount", enable: bool = True
    ) -> None:
        """
        Enable or disable an email account (alias) on the provider's service.

        Args:
            email_account: The EmailAccount instance to enable/disable
            enable: True to enable, False to disable
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def list_email_accounts(self, server: "Server") -> Any:
        """
        List all email accounts (aliases) for a domain on the provider's
        service.

        Args:
            server: The Server instance whose aliases to list

        Returns:
            Provider-specific data structure containing alias information
        """
        ...
