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
from dataclasses import dataclass, field
from email.utils import getaddresses, parseaddr
from enum import StrEnum
from typing import TYPE_CHECKING, Any

# 3rd party imports
#
from django.http import HttpRequest, HttpResponse

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import EmailAccount, Server


########################################################################
########################################################################
#
class Capability(StrEnum):
    """
    Capabilities of a provider backend implementation.

    MANAGES_EMAIL_ACCOUNTS: provider maintains per-EmailAccount entities on the
        provider side (e.g. ForwardEmail aliases). create/delete account methods
        are meaningful. Providers without this capability are no-ops for account
        management operations.

    SMTP_RELAY: provider supports outbound relay via SMTP. When present,
        aiosmtpd uses the SMTP path (send_email_smtp) for outbound relay so
        that the original message bytes reach the provider without
        re-serialisation. Providers without this capability (e.g. ForwardEmail)
        use the API path (send_email_api) for outbound relay instead.
    """

    MANAGES_EMAIL_ACCOUNTS = "manages_email_accounts"
    SMTP_RELAY = "smtp_relay"


########################################################################
########################################################################
#
@dataclass
class EmailAccountInfo:
    """
    Information about an email account (alias) from a provider.

    This dataclass normalizes the response from list_email_accounts() across
    different provider backends.

    Attributes:
        id: The provider's unique identifier for this account/alias
        email: The full email address
        domain: The domain name
        enabled: Whether the account is enabled
        name: The mailbox name (local part of email address)
        extra_data: Full raw API response dict from the provider, populated by
            list_email_accounts(). Used by sync_email_account() to compare current
            remote state without issuing an extra GET request.
    """

    id: str
    email: str
    domain: str
    enabled: bool
    name: str
    extra_data: dict[str, Any] = field(default_factory=dict)


########################################################################
########################################################################
#
class BounceType(StrEnum):
    """
    Category of a bounce or complaint event from a provider backend.

    BOUNCE: A delivery failure — the message could not be delivered to
        the recipient.  May be transient (soft) or permanent (hard),
        indicated by BounceEvent.transient.
    SPAM:   A spam complaint — the recipient reported the message as
        spam.  Always non-transient.

    New categories (e.g. UNSUBSCRIBE) can be added here as needed.
    """

    BOUNCE = "bounce"
    SPAM = "spam"


########################################################################
########################################################################
#
@dataclass
class BounceEvent:
    """
    Normalized bounce or spam complaint event from any provider backend.

    Both delivery bounces and spam complaints share the same processing
    logic: increment the account's bounce counter (unless transient),
    deactivate the account if the counter exceeds the limit, optionally
    record an InactiveEmail when the provider has blacklisted the
    recipient, and send a Delivery Status Notification to the sending
    account.

    ``bounce_type`` distinguishes spam complaints from delivery bounces
    (and leaves room for future categories such as UNSUBSCRIBE).
    ``transient`` is orthogonal: it captures permanence (should this
    event count against the bounce limit?) independently of category.

    NOTE: This dataclass is passed as an argument to Huey tasks and must
    remain pickle-serializable.  All fields must be plain Python types
    (str, bool, bytes, None, or StrEnum).  If this project ever migrates
    to a task queue that requires JSON serialization (e.g. Celery with a
    JSON backend), consider switching to a Pydantic model and using its
    ``model_dump()`` / ``model_validate()`` round-trip instead.

    Attributes:
        email_from: The From address — our EmailAccount's email address.
        email_to: The recipient address that bounced or complained.
        subject: Subject of the original email (empty string if unavailable).
        transient: True = temporary failure; do not count against bounce limit.
        bounce_type: Category of the event (BOUNCE, SPAM, …).
        inactive: Provider has blacklisted the recipient address.
        can_activate: Whether the provider-blacklisted address can be reactivated.
        description: Human-readable description of the bounce/complaint.
        details: Additional diagnostic detail (e.g. RFC 3463 status code).
        original_message: Original message body, if available from the provider.
    """

    email_from: str
    email_to: str
    subject: str
    transient: bool
    bounce_type: BounceType
    description: str
    details: str
    inactive: bool = False
    can_activate: bool = False
    original_message: str | bytes | None = None


########################################################################
#
def resolve_envelope(
    message: email.message.EmailMessage,
    email_from: str | None = None,
    rcpt_tos: list[str] | None = None,
) -> tuple[str, list[str]]:
    """
    Return (email_from, rcpt_tos), extracting from message headers when None.

    Args:
        message: The email message to extract envelope from
        email_from: Sender address, or None to extract from From header
        rcpt_tos: Recipient list, or None to extract from To+Cc+Bcc headers

    Returns:
        Tuple of (email_from, rcpt_tos) with values resolved from headers
        when not explicitly provided.
    """
    if email_from is None:
        email_from = parseaddr(message["From"])[1]
    if rcpt_tos is None:
        rcpt_tos = [
            addr
            for _, addr in getaddresses(
                message.get_all("To", [])
                + message.get_all("Cc", [])
                + message.get_all("Bcc", [])
            )
        ]
    return email_from, rcpt_tos


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

    # Capabilities of this provider backend implementation.
    # Subclasses should override this to declare what they support.
    CAPABILITIES: frozenset[Capability] = frozenset()

    ####################################################################
    #
    @abstractmethod
    def send_email_smtp(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send an email via SMTP using this provider.

        When ``email_from`` or ``rcpt_tos`` are None, implementations must
        call ``resolve_envelope()`` to extract them from message headers.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            email_from: The email address sending from, or None to extract
                from the message From header
            rcpt_tos: List of recipient email addresses, or None to extract
                from To+Cc+Bcc headers
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
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send an email via the provider's web API.

        When ``email_from`` or ``rcpt_tos`` are None, implementations must
        call ``resolve_envelope()`` to extract them from message headers.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            email_from: The email address sending from, or None to extract
                from the message From header
            rcpt_tos: List of recipient email addresses, or None to extract
                from To+Cc+Bcc headers
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def send_email(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send an email using this provider's preferred transport.

        Dispatches to the preferred send path for this provider:
        Postmark → send_email_smtp(); ForwardEmail → send_email_api().
        Use this method when you don't need to force a specific transport.

        When ``email_from`` or ``rcpt_tos`` are None, the underlying
        transport method calls ``resolve_envelope()`` to extract them
        from message headers.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            email_from: The email address sending from, or None to extract
                from the message From header
            rcpt_tos: List of recipient email addresses, or None to extract
                from To+Cc+Bcc headers
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
    ) -> HttpResponse:
        """
        Handle incoming email webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            HttpResponse indicating success or failure
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def handle_bounce_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> HttpResponse:
        """
        Handle bounce notification webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            HttpResponse indicating success or failure
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> HttpResponse:
        """
        Handle spam complaint webhook from the provider.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            HttpResponse indicating success or failure
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def create_update_domain(
        self, server: "Server", dry_run: bool = False
    ) -> bool:
        """
        Create or update a domain on the provider's service.

        This is an idempotent operation - if the domain exists, it should
        be updated with any settings that have drifted, otherwise it
        should be created.

        Args:
            server: The Server instance whose domain to create or update
            dry_run: If True, log what would change but do not make any
                remote API calls.

        Returns:
            True if changes were made (or would be made in dry_run),
            False if already correct.
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
    ) -> bool:
        """
        Create or update an email account (alias) on the provider's service.

        This method should check if the alias already exists and update it if
        so, or create it if it doesn't exist. This is useful for ensuring
        idempotency when syncing email accounts with the provider.

        Args:
            email_account: The EmailAccount instance to create or update

        Returns:
            True if the alias was created or if existing settings were updated,
            False if the alias already existed with all correct settings.
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
        self, email_address: str, server: "Server"
    ) -> None:
        """
        Delete an email account (alias) by address from the provider's service.

        This variant is used when the EmailAccount object no longer exists
        (e.g. during post-delete cleanup) but the Server still does.

        Args:
            email_address: The full email address to delete
            server: The Server instance the email address belongs to
        """
        ...

    ####################################################################
    #
    @abstractmethod
    def list_email_accounts(self, server: "Server") -> list[EmailAccountInfo]:
        """
        List all email accounts (aliases) for a domain on the provider's
        service.

        Args:
            server: The Server instance whose aliases to list

        Returns:
            List of EmailAccountInfo objects containing alias information
        """
        ...
