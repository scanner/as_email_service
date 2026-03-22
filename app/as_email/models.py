#!/usr/bin/env python
#
"""
Models for the Apricot Systematic email service.  NOTE: Could
potentially work with various 3rd party email services for now it is
mostly custom for the service I use: postmark.
"""

# system imports
#
import email
import email.message
import email.policy
import logging
import mailbox
import shlex
import socket
import ssl

# 3rd party imports
#
import imapclient
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import QuerySet
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _
from dry_rest_permissions.generics import authenticated_users
from encrypted_fields.fields import EncryptedCharField
from model_utils import FieldTracker
from ordered_model.models import OrderedModel
from polymorphic.models import PolymorphicModel
from postmarker.core import PostmarkClient

# project imports
#
from .providers import get_backend
from .utils import get_spam_score

# Various models that belong to a specific user need the User object.
#
User = get_user_model()
logger = logging.getLogger("as_email.models")


########################################################################
########################################################################
#
class Provider(models.Model):
    """
    Represents an email service provider (e.g., Postmark, ForwardEmail).

    A Provider can be configured for sending email, receiving email, or both.
    The backend_name determines which provider backend implementation handles
    the actual sending and webhook processing.
    """

    ####################################################################
    #
    class ProviderType(models.TextChoices):
        """
        Choices for provider type indicating whether the provider is used
        for sending, receiving, or both operations.
        """

        SEND = "SEND", _("Send Only")
        RECEIVE = "RECEIVE", _("Receive Only")
        BOTH = "BOTH", _("Send and Receive")

    name = models.CharField(unique=True, max_length=200)
    backend_name = models.CharField(
        max_length=50,
        help_text=_(
            "The name of the provider backend to use (e.g., 'postmark', "
            "'forwardemail'). This determines which implementation handles "
            "email sending and webhook processing."
        ),
        default="postmark",
    )
    provider_type = models.CharField(
        max_length=10,
        choices=ProviderType.choices,
        default=ProviderType.BOTH,
        help_text=_(
            "Whether this provider is used for sending email, receiving email, "
            "or both."
        ),
    )
    # XXX Should this be moved in to the provider backend? Since everything
    #    else about the provider actually doing things is configured back there.
    smtp_server = models.CharField(
        help_text=_(
            "The host:port for sending messages via SMTP for this provider "
            "(each server has its own unique login, but all the servers on "
            "the same provider use the same hostname for SMTP). Only required "
            "for providers that support sending email."
        ),
        max_length=200,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    ####################################################################
    #
    def __str__(self) -> str:
        return self.name

    ####################################################################
    #
    @property
    def backend(self):
        """
        Get the provider backend instance for this provider.

        Returns:
            An instance of the provider backend (e.g., PostmarkBackend)

        Raises:
            ImportError: If the backend module does not exist
            AttributeError: If the backend class is not found
        """
        if not hasattr(self, "_backend"):
            self._backend = get_backend(self.backend_name)
        return self._backend


########################################################################
########################################################################
#
class Server(models.Model):
    """
    Represents a domain that sends and/or receives email.

    A Server uses a send_provider for outgoing email and one or more
    receive_providers for incoming email webhooks. The providers determine
    which email service handles the actual email transmission and reception.
    """

    domain_name = models.CharField(
        help_text=_(
            "The domain name this server handles email for (e.g., 'example.com'). "
            "Email accounts on this server will have addresses ending with this domain."
        ),
        max_length=200,
        unique=True,
    )
    send_provider = models.ForeignKey(
        Provider,
        on_delete=models.SET_NULL,
        related_name="sending_servers",
        null=True,
        blank=True,
        help_text=_(
            "The provider used for sending outgoing email from this domain. "
            "If not set, this server can only receive email."
        ),
    )
    receive_providers = models.ManyToManyField(
        Provider,
        related_name="receiving_servers",
        blank=True,
        help_text=_(
            "The providers that can deliver incoming email to this domain. "
            "Multiple providers can be configured to receive email from different sources."
        ),
    )

    # In the future we may want to move API keys in to a more generalized
    # framework but right now the only thing that can use the webhook's are the
    # remote servers and we need a key for them to use so we are tying it to
    # the server itself. It will be generated when the Server object is
    # created.
    #
    api_key = models.CharField(
        help_text=_(
            "In order for the mail provider to be able to post data to the "
            "web hooks on this service, they need an API key that "
            "is unique to this server. NOTE: This is for incoming posts FROM "
            "the mail server to this service. NOT for authenticating this "
            "service to the provider. If this is left blank it will have a "
            "sufficiently random string generated."
        ),
        max_length=40,
        null=True,
        blank=True,
    )
    incoming_spool_dir = models.CharField(
        help_text=_(
            "The directory incoming messages are temporarily spooled to before "
            "being delivered. If not set a reasonable default will be chosen "
            "(this is the recommended way)."
        ),
        max_length=1024,
        null=True,
        blank=True,
    )
    outgoing_spool_dir = models.CharField(
        help_text=_(
            "The directory outgoing messages are temporarily spooled to before "
            "being sent to the server for delivery. If not set a reasonable "
            "default will be chosen (this is the recommended way)."
        ),
        max_length=1024,
        null=True,
        blank=True,
    )
    mail_dir_parent = models.CharField(
        help_text=_(
            "The directory that is the root of all the local mailboxes that "
            "mail will be delivered to if being delivered locally. The "
            "mailboxes are named by the email address being delivered to."
            "If not set a reasonable default will be chosen (this is the "
            "recommended way)."
        ),
        max_length=1024,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    # Track send_provider_id so the post_save signal can detect when the send
    # provider is assigned or changed and trigger any remote configuration the
    # new provider requires to support sending from this domain.
    #
    tracker = FieldTracker(fields=["send_provider_id"])

    class Meta:
        indexes = [
            models.Index(fields=["domain_name"]),
        ]
        ordering = ("domain_name",)

    ####################################################################
    #
    def __str__(self):
        return self.domain_name

    ####################################################################
    #
    @property
    def client(self) -> PostmarkClient:
        """
        Returns a postmark client for this server.

        DEPRECATED: This property is deprecated and will be removed in a future
        version. Use send_provider.backend instead.
        """
        from .provider_tokens import get_provider_token

        if not hasattr(self, "_client"):
            token = get_provider_token("postmark", self.domain_name)
            if not token:
                raise KeyError(
                    f"The token for postmark provider on server '{self.domain_name}' "
                    "is not defined in `settings.EMAIL_SERVER_TOKENS`"
                )
            self._client = PostmarkClient(server_token=token)
        return self._client

    ####################################################################
    #
    def send_email(
        self,
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via the configured send provider's preferred transport.

        Delegates to the backend's ``send_email()`` which dispatches to the
        correct transport (SMTP for Postmark, API for ForwardEmail).  When
        ``email_from`` or ``rcpt_tos`` are None the backend extracts them
        from message headers via ``resolve_envelope()``.

        Args:
            message: The email message to send
            email_from: Sender address, or None to extract from headers
            rcpt_tos: Recipient list, or None to extract from headers
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise

        Raises:
            ValueError: If send_provider is not configured
        """
        if not self.send_provider:
            raise ValueError(
                f"Server '{self.domain_name}' has no send_provider configured"
            )

        return self.send_provider.backend.send_email(
            self, message, email_from, rcpt_tos, spool_on_retryable
        )

    ####################################################################
    #
    async def asend_email(
        self,
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send the given email via this server's send provider (async version).

        Args:
            message: The email message to send
            email_from: Sender address, or None to extract from headers
            rcpt_tos: Recipient list, or None to extract from headers
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        result = await sync_to_async(self.send_email)(
            message,
            email_from=email_from,
            rcpt_tos=rcpt_tos,
            spool_on_retryable=spool_on_retryable,
        )
        return result


########################################################################
########################################################################
#
class EmailAccount(models.Model):  # type: ignore[django-manager-missing]
    """
    User's can have multiple mail accounts. A single mail account
    maps to an email address that can receive and store email.

    Email is delivered to an EmailAccount via one or more `DeliveryMethod`
    objects. See `LocalDelivery` and `AliasToDelivery`.
    """

    # The number of bounced emails that you are allowed before your account
    # gets deactivated. NOTE: A deactivated account can still receive email but
    # it can no longer send email.
    #
    NUM_EMAIL_BOUNCE_LIMIT = 10
    DEACTIVATED_DUE_TO_BOUNCES_REASON = "Deactivated due to excessive bounces"
    DEACTIVATED_BY_POSTMARK = "Postmark deactivated due to bounced email"

    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    server = models.ForeignKey(
        Server, related_name="email_accounts", on_delete=models.CASCADE
    )
    # XXX We should figure out a way to have this still be a validated email
    #     field, but auto-fill the domain name part from the server attribute.
    #     For now we are just going to require that the domain name's match.
    #
    # NOTE: this field needs to be marked disabled so user's can not edit it.
    #
    email_address = models.EmailField(
        unique=True,
        help_text=_(
            "The email address that will receive emails on this server, "
            "and the address that will be used as a login to send emails. "
            "It must have the same domin name as the associated server"
        ),
    )
    password = models.CharField(
        max_length=200,
        help_text=_(
            "Password used for the SMTP and IMAP services for this email "
            "account"
        ),
        default="XXX",
    )
    # Whether this email account is enabled. Disabled accounts do not accept
    # email — treating them as if the account does not exist.
    #
    enabled = models.BooleanField(
        default=True,
        help_text=_(
            "If an account is not enabled, email for this account will not be "
            "accepted. This is equivalent to the email account not existing."
        ),
    )

    # If an account is deactivated it can still receive email. However it is no
    # longer allowed to send email (via SMTP)
    #
    # (and if an account does not exist the email will be dropped, again we
    # need to add logging and metrics for when we receive emails for accounts
    # that do not exist.)
    #
    # NOTE: disabled in user forms.
    #
    deactivated = models.BooleanField(
        help_text=_(
            "If an account is deactivated it can still receive email. However "
            "it is no longer allowed to send email. Aliasing to other email "
            "accounts is allowed, but no forwarding to an email account not on "
            "on the system is allowed."
        ),
        default=False,
    )

    # If the number of bounces exceeds a certain limit then the account is
    # deactivated and not allowed to send new email (it can still
    # receive email) (maybe it should be some sort of percentage of total
    # emails sent by this account.)
    #
    # NOTE: Disabled in user forms.
    #
    num_bounces = models.IntegerField(
        default=0,
        help_text=_(
            "Every time this email account sends an email and it results in a "
            "bounce this counter will increment. The mail provider does not "
            "allow excessive bounced email and this is a check to make sure "
            "that does not happen. An asynchronous task will go through all "
            "accounts that have a non-zero number of bounces and reduce them "
            "by 1 once a day. If you have more than the limit your account "
            "will be deactivated until it goes under the limit."
        ),
    )

    # NOTE: disabled in user forms. A user can not change their deactivated
    #       reason.
    #
    deactivated_reason = models.TextField(
        help_text=_("Reason for the account being deactivated"),
        null=True,
        blank=True,
    )

    scan_incoming_spam = models.BooleanField(
        default=True,
        help_text=_(
            "When enabled, incoming email is scanned by SpamAssassin and "
            "X-Spam-* headers are added. When disabled, provider-injected "
            "spam headers are preserved without rescanning (if they exist)."
        ),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    # We want to track when certain fields change so we can do additional
    # operations that only need to happen when those fields change.
    #
    tracker = FieldTracker(fields=["password", "enabled"])

    class Meta:
        indexes = [
            models.Index(fields=["email_address"]),
            models.Index(fields=["server"]),
            models.Index(fields=["owner"]),
        ]

        ordering = ("server", "email_address")

    ####################################################################
    #
    def __str__(self):
        return self.email_address

    ####################################################################
    #
    def get_absolute_url(self):
        return reverse("as_email:email-account-detail", kwargs={"pk": self.pk})

    #######################
    #######################
    #
    # Permissions:
    #
    # No one can create or delete an EmailAccount (via the rest API).
    # Only `owners` can update, retrieve, list EmailAccounts that they own.
    #
    ####################################################################
    #
    @staticmethod
    def has_write_permission(request):
        return True

    ####################################################################
    #
    # XXX Okay, normally since we do not allow the creation of EmailAccounts by
    #     end users this should return `False`. However, doing that disables
    #     the ability to fetch the object metadata via the HTTP OPTIONS
    #     request. This kind of makes sense. .. but you can update the
    #     object. And the metadata says it is for the 'PUT' command. Not sure
    #     what is up, but we have disabled the 'Create' endpoint anyways so
    #     that keeps users out of creating objects via the endpoint anyway. But
    #     we need to figure out what is going on here.
    #
    #     So we return `True` if asking options for the `PUT` command.
    #
    #     See: https://github.com/scanner/as_email_service/issues/49
    #
    @authenticated_users
    def has_object_write_permission(self, request):
        if request.method == "PUT":
            return True
        return False

    ####################################################################
    #
    @authenticated_users
    def has_object_update_permission(self, request):
        return request.user == self.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_destroy_permission(self, request):
        """
        user's can not delete email accounts.
        """
        return False

    ####################################################################
    #
    @staticmethod
    def has_read_permission(request):
        return True

    ####################################################################
    #
    @authenticated_users
    def has_object_read_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to retrieve/list the
        object if they are the owner.
        """
        return request.user == self.owner

    ####################################################################
    #
    @staticmethod
    def has_set_password_permission(request):
        return True

    ####################################################################
    #
    @authenticated_users
    def has_object_set_password_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to set the email account
        password if they are the owner.
        """
        return request.user == self.owner

    ####################################################################
    #
    def clean(self):
        """
        Make sure that the email address is one that is served by the
        server (domain) associated with this object.
        """
        if not self.email_address.endswith(f"@{self.server.domain_name}"):
            raise ValidationError(
                {
                    "email_address": _(
                        f"email_address '{self.email_address}' must end with "
                        f"{self.server.domain_name}"
                    )
                }
            )

    ####################################################################
    #
    def check_password(self, password: str) -> bool:
        """
        Check the password for this account. Used by the aiosmtpd.
        """
        return check_password(password, self.password)

    ####################################################################
    #
    def set_password(self, raw_password: str, save: bool = True) -> None:
        """
        Keyword Arguments:
        password --
        """
        self.password = make_password(raw_password)
        if save:
            self.save(update_fields=["password"])

    ####################################################################
    #
    def deliver(
        self,
        msg: email.message.EmailMessage,
        visited_accounts: set[int] | None = None,
    ) -> None:
        """
        Deliver ``msg`` to every enabled DeliveryMethod on this account in
        order.

        This method is **not** the entry point for dispatching ordinary
        incoming user email.  For that, use ``dispatch_incoming_email``
        (tasks.py), which iterates methods individually so that per-method
        failures are tracked in Redis and retried selectively with backoff.

        This method is appropriate in two narrower contexts where that
        per-method tracking is not needed:

        - **Alias chains** — ``AliasToDelivery.deliver()`` calls this on the
          target account to recurse through forwarding hops.
        - **DSN / notification messages** — ``report_failed_message()``
          (deliver.py) calls this to deliver delivery-status notifications
          back to the account via whatever methods remain active.

        Args:
            msg: The email message to deliver.
            visited_accounts: PKs of EmailAccounts already visited in this
                delivery chain; initialised to an empty set on first call.
        """
        if visited_accounts is None:
            visited_accounts = set()
        for method in self.delivery_methods.filter(enabled=True):
            method.deliver(msg, visited_accounts)

    delivery_methods: QuerySet["DeliveryMethod"]


########################################################################
########################################################################
#
class MessageFilterRule(OrderedModel):
    # slocal offers "folder", "destroy", "file", "mbox", "mmdf", "pipe",
    # "qpipe" which offer various actions. We are only supporting 'folder' and
    # 'destroy' for now.
    #
    # MessageFilterRule's apply to local and imap delivery.
    #
    # TODO: Consider a 'forward' action that lets matches have the
    #       message forward to another address. (it will act as an
    #       alias if the destination address is one handled by this
    #       system.) Like the email account forward the rule will
    #       remain inactive until a button associated with the rule is
    #       pressed that sends a test email and that test email is
    #       acknowledged does the rule become active.
    #       Also bounces immediately deactivate the rule.
    #
    # XXX `destroy` does nothing currently. So if a message matches a destroy
    #     filter rule, and no other rules, then the message will be delivered
    #     to the inbox.
    #
    # XXX Maybe every email account should get a default message filter rule
    #     that looks for the header from postmark indicating that this email is
    #     spam and deliver it to their Junk mailbox.
    #
    # XXX consider a better langauge for tests.. so we can do soomething like
    #    `if x-spam-assassin-score is >= 15`. This would let us remove
    #     the special attributes about spam filtering for EmailAccounts.
    #
    # NOTE: Due to the plan to have spam filtering handled by message filter
    #       rules, spam filtering is done AFTER message filter rules are
    #       processed on message delivery.
    #
    FOLDER = "folder"
    DESTROY = "destroy"
    ACTION_CHOICES = [
        (FOLDER, FOLDER),
        (DESTROY, DESTROY),
    ]

    # For now just these common headers. Adding more is easy.
    #
    # the address that was used to cause delivery to the recipient
    ADDR = "addr"
    # this always matches
    ANY = "*"
    BCC = "bcc"
    CC = "cc"
    # this matches only if the message hasn't been delivered yet
    DEFAULT = "default"
    FROM = "from"
    REPLY_TO = "reply-to"
    # the out-of-band sender information
    SOURCE = "source"
    SUBJECT = "subject"
    TO = "to"
    DSPAM = "x-dspam-result"
    SPAM_STATUS = "x-spam-status"
    SPAM_SCORE = "x-spam-score"

    HEADER_CHOICES = [
        (ADDR, ADDR),
        (ANY, ANY),
        (BCC, BCC),
        (CC, CC),
        (DEFAULT, DEFAULT),
        (DSPAM, DSPAM),
        (FROM, FROM),
        (REPLY_TO, REPLY_TO),
        (SOURCE, SOURCE),
        (SPAM_SCORE, SPAM_SCORE),
        (SPAM_STATUS, SPAM_STATUS),
        (SUBJECT, SUBJECT),
        (TO, TO),
    ]

    # NOTE: These fields are intentionally left without explicit type
    # annotations.  django-stubs infers descriptor types (e.g.
    # self.email_account → EmailAccount) from the field assignments;
    # adding annotations breaks that inference and causes _ST errors
    # on attribute access.  The [var-annotated] suppressions silence
    # mypy's "Need type annotation" warnings, which are a django-stubs
    # limitation with OrderedModel.
    email_account = models.ForeignKey(  # type: ignore[var-annotated]
        EmailAccount,
        on_delete=models.CASCADE,
        related_name="message_filter_rules",
    )
    header = models.CharField(  # type: ignore[var-annotated]
        max_length=32,
        choices=HEADER_CHOICES,
        default=DEFAULT,
    )
    pattern = models.CharField(blank=True, max_length=256)  # type: ignore[var-annotated]
    action = models.CharField(  # type: ignore[var-annotated]
        max_length=10,
        choices=ACTION_CHOICES,
        default=FOLDER,
    )
    destination = models.CharField(  # type: ignore[var-annotated]
        blank=True, max_length=1024
    )
    order_with_respect_to = "email_account"
    created_at = models.DateTimeField(auto_now_add=True)  # type: ignore[var-annotated]
    modified_at = models.DateTimeField(auto_now=True)  # type: ignore[var-annotated]

    class Meta:
        indexes = [
            models.Index(fields=["email_account"]),
            models.Index(fields=["email_account", "order"]),
        ]
        unique_together = ["email_account", "header", "pattern"]
        ordering = ("email_account", "order")

    ####################################################################
    #
    def __str__(self):
        if self.action == self.FOLDER:
            return (
                f"Match: '{self.header}', '{self.pattern}' folder: "
                f"{self.destination}"
            )
        else:
            return f"Match: '{self.header}', '{self.pattern}' destroy"

    ####################################################################
    #
    def get_absolute_url(self):
        return reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": self.email_account.pk, "pk": self.pk},
        )

    #######################
    #######################
    #
    # Permissions:
    #
    # Only owners can list, retrieve message filter rules that are associated
    # with an email account that they own.
    #
    ####################################################################
    #
    @staticmethod
    def has_write_permission(request):
        """
        A user can only create message filter rules belonging to email
        account's for which they are the owner.
        """
        # Pull out which email account this is for from the PATH of the
        # request. See if the owner of that email request is the same as the
        # logged in user.
        #
        func, args, kwargs = resolve(request.get_full_path())
        ea = EmailAccount.objects.get(pk=int(kwargs["email_account_pk"]))
        return request.user == ea.owner

    ####################################################################
    #
    @staticmethod
    def has_read_permission(request):
        return True

    ####################################################################
    #
    @authenticated_users
    def has_object_read_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to retrieve/list the
        object if they are the owner of the associated email account
        """
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_write_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to write the
        object if they are the owner of the associated email account
        """
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_update_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to update the
        object if they are the owner of the associated email account
        """
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_destroy_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to delete the
        object if they are the owner of the associated email account
        """
        return request.user == self.email_account.owner

    ####################################################################
    #
    @staticmethod
    def has_move_permission(request):
        return True

    ####################################################################
    #
    @authenticated_users
    def has_object_set_move_permission(self, request):
        """
        Using DRY Rest Permissions, allow the user to move the ordering of
        the message fitler rule if the user is the owner of the associated
        email account.
        """
        return request.user == self.email_account.owner

    ####################################################################
    #
    @classmethod
    def create_from_rule(cls, email_account: EmailAccount, rule_text: str):
        """
        The message filter rule is created to match the lines in a
        `maildelivery` (part of mh) file. This class method creates a
        rule based on the syntax of the non-blank, non-comment lines
        in that file.

        The format is:
        <header> <pattern> <action> <result> <string (folder name)>

        The fields are separated by whitespace.

        If the action is "destroy" there is no final string (the folder in case
        of the 'folder' action.)

        We do not currently honor the "result" column so that is just
        ignored. We are also only supporting "folder" and "destroy"
        actions. Once a message is matched by a message filter rule,
        it will be considered delivered and stop processing.
        """
        rule_parts = shlex.split(rule_text)
        if len(rule_parts) < 4 or len(rule_parts) > 5:
            raise ValueError(
                "rule text must be 4 or 5 columns separated white space."
            )

        (header, pattern, action, result) = rule_parts[:4]
        folder = rule_parts[4] if len(rule_parts) >= 5 else ""

        if not folder:
            if action != "destroy":
                raise ValueError(
                    "4 part message filter rule is only valid for 'destroy' "
                    "rules"
                )

        rule, _ = cls.objects.get_or_create(
            email_account=email_account,
            header=header,
            pattern=pattern,
        )
        rule.action = action
        rule.result = result
        rule.destination = folder
        rule.save()
        return rule

    ####################################################################
    #
    def match(self, email_message: email.message.EmailMessage):
        """
        Returns True if the email message matches the header/pattern.

        NOTE: Matches are only case insensitive substring matches! Not regular
              expressions!

        NOTE: If the rule has the header "default" it will always match.

        """
        if self.header == "default":
            return True

        if self.header not in email_message:
            return False

        header_contents: list = email_message.get_all(self.header, [])
        for hc in header_contents:
            if self.pattern.lower() in hc.lower():
                return True

        return False


########################################################################
########################################################################
#
class InactiveEmail(models.Model):
    """
    Postmark can mark destination email addresses as "inactive" which means
    it will not send email to those addresses if one of our server's asks for
    it. This usually happens due to a spam complaint or some persistent bounce.

    This model represents those email addresses and is primarily used to make
    sure we do not send to these addresses, and generate our internal bounce
    messages when someone tries to send to them.

    NOTE: These InactiveEmail's have a `can_activate` boolean attribute that we
          get from postmark. This means we can re-activate this email address
          and send to it again.
    """

    email_address = models.EmailField(
        unique=True,
        help_text=_(
            "The inactive email address. Our mail provider has indicate that "
            "we are not allowed to send emails to this address anymore."
        ),
    )
    can_activate = models.BooleanField(
        default=False,
        help_text=_(
            "If True this indicates that we are able to manually reactivate "
            "sending emails to this address. Before doing so we need to make "
            "sure that any problems sending to this address have been resolved."
        ),
    )

    # XXX Potential future attributes:
    #     boolean to actually not send emails or not (we may want to keep a
    #     record of InactiveEmails even if they have been reactivated.)
    #     number of reports
    #     link to a message that generated the inactive email notification

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["email_address"]),
            models.Index(fields=["can_activate"]),
            models.Index(fields=["email_address", "can_activate"]),
        ]

        ordering = ("email_address",)

    ####################################################################
    #
    def __str__(self):
        return self.email_address

    ####################################################################
    #
    @classmethod
    def inactives(cls, email_addresses: list[str]):
        """
        Given a list of email addresses see if any of those email addresses
        are inactive. Returns the list of email addresses that are inactive.
        """
        inacts = cls.objects.filter(email_address__in=email_addresses)
        return list(inacts)

    ####################################################################
    #
    @classmethod
    async def a_inactives(cls, email_addresses: list[str]):
        """
        Given a list of email addresses see if any of those email addresses
        are inactive. Returns the list of email addresses that are inactive.
        """
        inacts = []
        async for inact in cls.objects.filter(
            email_address__in=email_addresses
        ):
            inacts.append(inact)
        return inacts


########################################################################
########################################################################
#
class DeliveryMethod(PolymorphicModel):
    """
    Base class for delivery methods. An EmailAccount can have multiple
    delivery methods. Each enabled delivery method receives a copy of
    every incoming message.

    Subclasses provide delivery logic via `deliver()`.
    """

    email_account = models.ForeignKey(
        EmailAccount,
        on_delete=models.CASCADE,
        related_name="delivery_methods",
    )
    enabled = models.BooleanField(
        default=True,
        help_text=_(
            "When disabled, this delivery method is skipped during message "
            "delivery."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    ####################################################################
    #
    @staticmethod
    def has_write_permission(request):
        """
        A user can only create delivery methods for email accounts they own.
        """
        func, args, kwargs = resolve(request.get_full_path())
        ea = EmailAccount.objects.get(pk=int(kwargs["email_account_pk"]))
        return request.user == ea.owner

    ####################################################################
    #
    @staticmethod
    def has_read_permission(request):
        return True

    ####################################################################
    #
    @authenticated_users
    def has_object_read_permission(self, request):
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_write_permission(self, request):
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_update_permission(self, request):
        return request.user == self.email_account.owner

    ####################################################################
    #
    @authenticated_users
    def has_object_destroy_permission(self, request):
        return request.user == self.email_account.owner

    ####################################################################
    #
    def deliver(
        self,
        msg: email.message.EmailMessage,
        visited_accounts: set[int],
    ) -> None:
        """
        Deliver the given message. Must be implemented by subclasses.

        Args:
            msg: The email message to deliver
            visited_accounts: PKs of EmailAccounts already visited in this
                delivery chain; used by AliasToDelivery for loop detection.
        """
        raise NotImplementedError


########################################################################
########################################################################
#
class LocalDelivery(DeliveryMethod):
    """
    Delivers messages to a local MH mailbox on the filesystem.

    Spam filtering is applied before filing: messages above the score
    threshold are filed in `spam_delivery_folder` when `autofile_spam`
    is enabled.
    """

    maildir_path = models.CharField(
        max_length=1000,
        null=True,
        blank=True,
        help_text=_(
            "Root folder for the local MH mailbox. Left blank it will be "
            "auto-filled from the account's email address when first saved."
        ),
    )
    autofile_spam = models.BooleanField(
        default=True,
        help_text=_(
            "When enabled, messages above the spam score threshold are "
            "automatically filed in the spam delivery folder."
        ),
    )
    spam_delivery_folder = models.CharField(
        default="Junk",
        max_length=1024,
        help_text=_(
            "Folder to deliver spam into when autofile_spam is enabled."
        ),
    )
    spam_score_threshold = models.IntegerField(
        default=5,
        help_text=_(
            "Messages with a spam score (from X-Spam-Status) at or above this value are "
            "considered spam. 5 is a reasonable default."
        ),
    )

    class Meta:
        verbose_name = "Local Delivery"
        verbose_name_plural = "Local Deliveries"

    ####################################################################
    #
    def __str__(self) -> str:
        return f"LocalDelivery({self.maildir_path})"

    ####################################################################
    #
    def save(self, *args, **kwargs) -> None:
        """
        Auto-fill maildir_path from the email account address if not set.
        """
        if not self.maildir_path and self.email_account_id:
            ea = self.email_account
            self.maildir_path = str(
                settings.MAIL_DIRS / ea.server.domain_name / ea.email_address
            )
        super().save(*args, **kwargs)

    ####################################################################
    #
    def MH(self, create: bool = True) -> mailbox.MH:
        """
        Return a mailbox.MH instance for this delivery method's maildir.
        Creates the mailbox and default folders if `create` is True.
        """
        assert self.maildir_path is not None
        # NOTE: The factory returns EmailMessage (not MHMessage) because
        # policy=email.policy.default produces the richer EmailMessage type
        # that the rest of the codebase expects. MH works fine with this
        # factory at runtime; the type mismatch is only in the stubs.
        mh = mailbox.MH(
            self.maildir_path,
            factory=lambda x: email.message_from_binary_file(  # type: ignore[arg-type,return-value]
                x, policy=email.policy.default
            ),
            create=create,
        )
        for folder in settings.DEFAULT_FOLDERS:
            mh.add_folder(folder)
        return mh

    ####################################################################
    #
    def deliver(
        self,
        msg: email.message.EmailMessage,
        visited_accounts: set[int],
    ) -> None:
        """
        Deliver the message to the local MH mailbox.

        Args:
            msg: The email message to deliver
            visited_accounts: Unused for local delivery; required by interface
        """
        # Inline import to avoid circular: deliver.py → models → LocalDelivery
        from .deliver import deliver_message_locally

        deliver_message_locally(self, msg)


########################################################################
########################################################################
#
class AliasToDelivery(DeliveryMethod):
    """
    Forwards messages to another EmailAccount on this system.

    Alias chains are limited to MAX_HOPS to prevent runaway delivery.
    Loops are detected by tracking visited account PKs.
    """

    MAX_HOPS = 10

    target_account = models.ForeignKey(
        EmailAccount,
        on_delete=models.CASCADE,
        related_name="aliased_from",
        help_text=_("The EmailAccount messages will be aliased to."),
    )

    class Meta:
        verbose_name = "Alias-To Delivery"
        verbose_name_plural = "Alias-To Deliveries"

    ####################################################################
    #
    def __str__(self) -> str:
        return f"AliasToDelivery(-> {self.target_account})"

    ####################################################################
    #
    def deliver(
        self,
        msg: email.message.EmailMessage,
        visited_accounts: set[int],
    ) -> None:
        """
        Forward ``msg`` to the target account by calling
        ``target_account.deliver()``, with alias-loop detection and a hop
        limit.

        This is one of the two internal callers of ``EmailAccount.deliver()``
        that do not need per-method failure tracking (the other is
        ``report_failed_message``).  Ordinary incoming email is dispatched
        via ``dispatch_incoming_email`` (tasks.py) instead.

        Args:
            msg: The email message to forward.
            visited_accounts: PKs of accounts already in this chain; prevents
                loops and enforces the MAX_HOPS limit.
        """
        if len(visited_accounts) >= self.MAX_HOPS:
            logger.warning(
                "Alias hop limit (%d) reached delivering to %s via %s, "
                "stopping",
                self.MAX_HOPS,
                self.target_account.email_address,
                self.email_account.email_address,
            )
            return

        if self.target_account_id in visited_accounts:
            logger.warning(
                "Alias loop detected: %s already visited, stopping delivery",
                self.target_account.email_address,
            )
            return

        visited_accounts.add(self.target_account_id)
        self.target_account.deliver(msg, visited_accounts)


########################################################################
########################################################################
#
class ImapDelivery(DeliveryMethod):
    """
    Delivers incoming email to a remote IMAP server over SSL.

    Credentials are stored encrypted using Fernet symmetric encryption
    (see the FERNET_KEYS Django setting). Spam auto-filing uses the server's
    SPECIAL-USE \\Junk mailbox (RFC 6154); falls back to the literal folder
    name "Junk", then to INBOX if neither exists.
    """

    imap_host = models.CharField(
        max_length=253,
        help_text=_("Hostname of the remote IMAP server."),
    )
    imap_port = models.PositiveIntegerField(
        default=993,
        help_text=_("IMAP port (default 993 for IMAPS)."),
    )
    username = EncryptedCharField(
        max_length=254,
        help_text=_("IMAP login username. Stored encrypted at rest."),
    )
    password = EncryptedCharField(
        max_length=1024,
        help_text=_("IMAP login password. Stored encrypted at rest."),
    )
    autofile_spam = models.BooleanField(
        default=True,
        help_text=_(
            "When enabled, messages whose spam score (from X-Spam-Status) meets or exceeds the "
            "threshold are filed in the server's Junk folder instead of INBOX."
        ),
    )
    spam_score_threshold = models.IntegerField(
        default=5,
        help_text=_(
            "Messages with a spam score (from X-Spam-Status) at or above this value are "
            "considered spam. 5 is a reasonable default."
        ),
    )

    class Meta:
        verbose_name = "IMAP Delivery"
        verbose_name_plural = "IMAP Deliveries"

    ####################################################################
    #
    def __str__(self) -> str:
        return (
            f"ImapDelivery({self.username}@{self.imap_host}:{self.imap_port})"
        )

    ####################################################################
    #
    @staticmethod
    def _resolve_junk_folder(client: imapclient.IMAPClient) -> str:
        """
        Resolve the junk folder name on the IMAP server.

        Resolution order (RFC 6154):
        1. A folder advertising the \\Junk SPECIAL-USE attribute.
        2. The literal folder name "Junk".
        3. "INBOX" as a last-resort fallback.

        Returns the folder name to use for spam messages.
        """
        try:
            for flags, _delimiter, name in client.list_folders():
                if r"\Junk" in flags:
                    return name
        except Exception:
            pass

        try:
            if client.folder_exists("Junk"):
                return "Junk"
        except Exception:
            pass

        return "INBOX"

    ####################################################################
    #
    @staticmethod
    def test_connection(
        host: str, port: int, username: str, password: str
    ) -> tuple[bool, str]:
        """
        Attempt to connect and authenticate to an IMAP server.

        Returns ``(True, "Connection successful.")`` on success, or
        ``(False, <user-friendly message>)`` on any failure. Common failures
        are mapped to specific messages; unexpected errors fall back to a
        generic message that includes the exception text.

        Args:
            host: IMAP server hostname.
            port: IMAP server port (e.g. 993).
            username: IMAP login username.
            password: IMAP login password.
        """
        try:
            with imapclient.IMAPClient(
                host=host, port=port, ssl=True, timeout=10
            ) as client:
                try:
                    client.login(username, password)
                except Exception as exc:
                    # imapclient passes server error responses as bytes (or as
                    # str(bytes), e.g. b"'bad!'"). Unwrap either form and strip
                    # IMAP quoted-string delimiters for a readable message.
                    raw = exc.args[0] if exc.args else str(exc)
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    else:
                        raw = str(raw)
                        # Strip Python bytes-literal repr: b'...' or b"..."
                        if (
                            len(raw) >= 4
                            and raw[0] == "b"
                            and raw[1] in ('"', "'")
                        ):
                            raw = raw[2:-1]
                    raw = raw.strip('"')
                    return False, f"Authentication failed: {raw}"
        except socket.gaierror:
            return (
                False,
                f"Host '{host}' not found — check the server hostname.",
            )
        except ConnectionRefusedError:
            return (
                False,
                f"Connection to {host}:{port} was refused — check the hostname and port.",
            )
        except TimeoutError:
            return (
                False,
                f"Connection to {host}:{port} timed out — server may be unreachable.",
            )
        except ssl.SSLError as exc:
            return False, f"SSL/TLS error: {str(exc)}"
        except Exception as exc:
            return False, f"Connection failed: {exc!r}"
        return True, "Connection successful."

    ####################################################################
    #
    def deliver(
        self,
        msg: email.message.EmailMessage,
        visited_accounts: set[int],
    ) -> None:
        """
        Deliver the message to the remote IMAP server.

        Connects over SSL, authenticates, resolves the target folder (Junk
        for spam when autofile_spam is enabled, INBOX otherwise), and appends
        the message. Any exception is re-raised so the caller can move the
        message to the failed-incoming queue.

        Args:
            msg: The email message to deliver.
            visited_accounts: Unused for IMAP delivery; required by interface.
        """
        # Use as_string() + encode() instead of as_bytes() to avoid
        # UnicodeEncodeError on malformed messages with non-ASCII content
        # but no charset declaration.  as_string() returns a Python str
        # (Unicode), sidestepping the ASCII-only serialization in
        # as_bytes().
        #
        msg_bytes = msg.as_string(policy=email.policy.default).encode("utf-8")

        with imapclient.IMAPClient(
            host=self.imap_host, port=self.imap_port, ssl=True
        ) as client:
            client.login(self.username, self.password)

            if (
                self.autofile_spam
                and get_spam_score(msg) >= self.spam_score_threshold
            ):
                folder = self._resolve_junk_folder(client)
            else:
                folder = "INBOX"

            client.append(folder, msg_bytes)
