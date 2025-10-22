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
import logging
import mailbox
import random
import shlex
import smtplib  # noqa: F401 - used by test mocking
import string
from pathlib import Path
from typing import List

# 3rd party imports
#
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _
from dry_rest_permissions.generics import authenticated_users
from ordered_model.models import OrderedModel
from postmarker.core import PostmarkClient

# project imports
#

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
            from .providers import get_backend

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
    def _set_initial_values(self):
        """
        A helper method that sets initial values on object creation.
        """
        # If the object has not been created yet then if the various file
        # fields have not been set, set them based on django settings and the
        # domain name.
        #
        # XXX We should also check to see if the path exists and if it does it
        #     must be a directory.
        #
        if not self.id:
            if not self.incoming_spool_dir:
                self.incoming_spool_dir = str(
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "incoming"
                )
            if not self.outgoing_spool_dir:
                self.outgoing_spool_dir = str(
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "outgoing"
                )
            if not self.mail_dir_parent:
                self.mail_dir_parent = str(
                    settings.MAIL_DIRS / self.domain_name
                )

            # API Key is created when the object is saved for the first time.
            #
            if not self.api_key:
                self.api_key = "".join(
                    random.choice(string.ascii_letters + string.digits)
                    for x in range(40)
                )

    ####################################################################
    #
    def save(self, *args, **kwargs):
        """
        On pre-save of the Server instance if this is when it is being
        created pre-fill the incoming spool dir, outgoing spool dir, and
        mail_dir_parent based on the domain_name of the server.

        This lets the default creation automatically set where these
        directories are without requiring input if they are not set on create.
        """
        self._set_initial_values()
        Path(self.incoming_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.outgoing_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.mail_dir_parent).mkdir(parents=True, exist_ok=True)

        super().save(*args, **kwargs)

    ####################################################################
    #
    async def asave(self, *args, **kwargs):
        """
        On pre-save of the Server instance if this is when it is being
        created pre-fill the incoming spool dir, outgoing spool dir, and
        mail_dir_parent based on the domain_name of the server.

        This lets the default creation automatically set where these
        directories are without requiring input if they are not set on create.

        After we have called the parent save method we make sure that the
        directory specified exists.
        """
        self._set_initial_values()
        Path(self.incoming_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.outgoing_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.mail_dir_parent).mkdir(parents=True, exist_ok=True)

        await super().asave(*args, **kwargs)

    ####################################################################
    #
    @property
    def client(self) -> PostmarkClient:
        """
        Returns a postmark client for this server.

        DEPRECATED: This property is deprecated and will be removed in a future
        version. Use send_provider.backend instead.
        """
        if not hasattr(self, "_client"):
            if self.domain_name not in settings.EMAIL_SERVER_TOKENS:
                raise KeyError(
                    f"The token for the server '{self.domain_name} is not "
                    "defined in `settings.EMAIL_SERVER_TOKENS`"
                )
            self._client = PostmarkClient(
                server_token=settings.EMAIL_SERVER_TOKENS[self.domain_name]
            )
        return self._client

    ####################################################################
    #
    def send_email_via_smtp(
        self,
        email_from: str,
        rcpt_tos: List[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via SMTP using the configured send provider.

        This method delegates to the send provider's backend to handle the
        actual SMTP transmission. It's used for relaying email (via the
        aiosmptd daemon) and for retrying spooled messages.

        Args:
            email_from: Email address to send from (must match server domain)
            rcpt_tos: List of recipient email addresses
            msg: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise

        Raises:
            ValueError: If send_provider is not configured
            ValueError: If email_from domain doesn't match server domain
        """
        if not self.send_provider:
            raise ValueError(
                f"Server '{self.domain_name}' has no send_provider configured"
            )

        return self.send_provider.backend.send_email_smtp(
            self, email_from, rcpt_tos, msg, spool_on_retryable
        )

    ####################################################################
    #
    def send_email(self, message, spool_on_retryable=True) -> bool:
        """
        Send email via the configured send provider's web API.

        This method delegates to the send provider's backend to handle the
        actual API transmission. It's used for administrative purposes like
        mailer-daemon bounce notifications.

        Args:
            message: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise

        Raises:
            ValueError: If send_provider is not configured

        Note:
            In the future, this method may support batched emails and templates.
        """
        if not self.send_provider:
            raise ValueError(
                f"Server '{self.domain_name}' has no send_provider configured"
            )

        return self.send_provider.backend.send_email_api(
            self, message, spool_on_retryable
        )

    ####################################################################
    #
    async def asend_email(self, message, spool_on_retryable=True) -> bool:
        """
        Send the given email via this server's send provider (async version).

        Args:
            message: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        result = await sync_to_async(self.send_email)(
            message, spool_on_retryable=spool_on_retryable
        )
        return result


########################################################################
########################################################################
#
class EmailAccount(models.Model):
    """
    User's can have multiple mail accounts. A single mail account
    maps to an email address that can receive and store email.

    XXX Should "forward" and "alias" be the same thing? ie: you just set an
        email address and the code figures out if it needs to forward it as
        email, or just deliver it to a different mail account.

    NOTE: This class is a bit messy because we actually have three account
          types: an account, a forward, and an alias.

          If ALIAS then email is delivered to the account indicated by
          `alias_for`

          If FORWARDING then the message being delivered is sent as a new a new
          email to the `forward_to` address.

    NOTE: Even if an account is "forwarding" or "alias" you can still connect
          to the SMTP relay and send email! You can still connect to the IMAP
          server as well. Just as long as forwarding and aliasing is setup
          properly no new mail will be delivered to this account.

    NOTE: Forwarding can potentially create bounces. If too many bounces are
          received the account will be deactivated and messages will be
          delivered locally instead of being forwarded!
    """

    # The number of bounced emails that you are allowed before your account
    # gets deactivated. NOTE: A deactivated account can still receive email but
    # it can no longer send email.
    #
    NUM_EMAIL_BOUNCE_LIMIT = 10
    DEACTIVATED_DUE_TO_BOUNCES_REASON = "Deactivated due to excessive bounces"
    DEACTIVATED_BY_POSTMARK = "Postmark deactivated due to bounced email"
    DEACTIVATED_DUE_TO_BAD_FORWARD_TO = (
        "Deactivated due to bounce when sending email to `forward_to` address"
    )
    # EmailAccount delivery methods - local, imap, alias, forwarding
    #
    LOCAL_DELIVERY = "LD"
    IMAP_DELIVERY = "IM"
    ALIAS = "AL"
    FORWARDING = "FW"
    DELIVERY_METHOD_CHOICES = [
        (LOCAL_DELIVERY, "Local Delivery"),
        # (IMAP_DELIVERY), "IMAP",   # XXX coming soon
        (ALIAS, "Alias"),
        (FORWARDING, "Forwarding"),
    ]

    # Max number of levels you can nest an alias. There is no easy way to check
    # this except for traversing all the aliases.
    #
    MAX_ALIAS_DEPTH = 3

    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
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
    delivery_method = models.CharField(
        max_length=2,
        choices=DELIVERY_METHOD_CHOICES,
        default=LOCAL_DELIVERY,
        help_text=_(
            "Delivery method indicates how email for this account is "
            "delivered. This is either delivery to a local mailbox, delivery "
            "to an IMAP mailbox, an alias to another email account on this "
            "system or forwarding to an email address by encapsulating the "
            "message or rewriting the headers."
        ),
    )

    # NOTE: In a system with arbitrary user's this field should not be settable
    #       by users. Probably should not even be visible. So I guess make sure
    #       it is not in the serializer, not in any forms. (ie: mark it
    #       disabled in user forms)
    #
    mail_dir = models.CharField(
        help_text=_(
            "The root folder for the local mail delivery for this email "
            "account. This should be left blank and it will be auto-filled "
            "in when the email account is created. Only fill it in if you "
            "have a specific location in the file system you want this user's "
            "local mailbox to be stored at."
        ),
        max_length=1000,
        null=True,
        blank=True,
    )
    password = models.CharField(
        max_length=200,
        help_text=_(
            "Password used for the SMTP and IMAP services for this email "
            "account"
        ),
        default="XXX",
    )
    autofile_spam = models.BooleanField(
        default=True,
        help_text=_(
            "When incoming mail exceeds the threshold set in "
            "`spam_score_threshold` then this email will "
            "automatically be filed in the `spam_delivery_folder` mailbox "
            "if delivery method is `Local Delivery` or `IMAP`. This option has no effect "
            "if the delivery method is `Alias` or `Forwarding`."
        ),
    )
    spam_delivery_folder = models.CharField(
        default="Junk",
        max_length=1024,
        help_text=_(
            "For delivery methods of `Local Delivery` and `IMAP`, if this "
            "message is considered spam it and `Autofile Spam` is set then "
            "this message will be delivered to this folder, overriding and "
            "message filter rules."
        ),
    )
    spam_score_threshold = models.IntegerField(
        default=15,
        help_text=_(
            "This is the value at which an incoming message is considered "
            "spam or not. The higher the value the more tolerant the rules. "
            "15 is a good default. Lower may cause more false positives. If "
            "the delivery method is `Local delivery` or `IMAP` then incoming "
            "spam will be filed in the `spam delivery folder`. If the delivery "
            "method is `Forwrding` then instead of just re-sending the email "
            "to the forwarding address the message will be encapsulated and "
            "attached as a `message/rfc822` when being forwarded."
        ),
    )

    # If delivery_method is ALIAS then messages are not delivered to this
    # account. Instead they are delivered to the accounts in the `alias_for`
    # attribute.
    #
    # NOTE: This means you can alias across domains as long as those domains
    #       are hosted by this app.
    #
    # NOTE: We have no restrictions about what email account you can add to
    #       alias_for. There are a number of valid cases where you want an
    #       email address to alias for several different email addresses that
    #       belong to EmailAccount's that are not the same one that is being
    #       aliased from. In the world of this app there is very little chance
    #       for abuse (it is just me, my family, and my friends) but if this
    #       were a more open service it could be abused become someone could
    #       make an account, alias_for your account, and then add you to many
    #       email lists filling your account with unwanted mail and you have no
    #       way to turn it off. So, this should be something requiring approval
    #       by the account your adding to alias_for.
    #
    alias_for = models.ManyToManyField(
        "self",
        related_name="aliases",
        related_query_name="alias",
        through="Alias",
        symmetrical=False,
        help_text=_(
            "If the delivery method is `Alias` this is a list of the email "
            "accounts that the email will be delivered to instead of this "
            "email account. You are declaring that this account is an "
            "`alias for` these other accounts. So, say `root@example.com` "
            "is an alias for `admin@example.com`, or `thetwoofus@example.com` "
            "is an alis for `me@example.com` and `you@example.com`. NOTE: "
            "you can only alias to email accounts that are managed by this "
            "system. If you want to have email forwarded to a email address "
            "not managed by this system you need to choose the delivery method "
            "`Forwarding` and properly specify the destination address in the "
            "`forward_to` field. NOTE: `alias_for` is only relevant when "
            "the delivery method is `Alias`. The field is otherwise ignored."
        ),
    )

    # If delivery_method is FORWARDING then messages are not delivered
    # locally. Instead a new email message is generated and sent to the
    # `forward_to` address.
    #
    # NOTE: Unlike 'alias' you can only forward to a single address.
    #
    # NOTE: We need to make a 'forward check' system. If you set a
    #       forward, the system will send a test email to the
    #       forwarded address. The test email has a link back to a
    #       form on this system that acknowldges the forward.
    #
    #       How does that work in terms of UX? We should not
    #       automatically send a test email when the email account is
    #       saved. We should have some indicator along with a button
    #       you press to actually send the test email.
    #
    forward_to = models.EmailField(
        null=True,
        blank=True,
        help_text=_(
            "When the email account delivery method is set to `Forwarding` "
            "this is the email address that this email is forwarded to. NOTE: "
            "`forward_to` is only relevant when the delivery method is "
            "`Forwarding`. The field is otherwise ignored."
        ),
    )

    # If an account is deactivated it can still receive email. However it is no
    # longer allowed to send email. Also, no forwarding or aliasing is allowed.
    # All email received by a deactivated account is delivered locally.
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

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        # If an EmailAccount has the permission "can_have_foreign_aliases" then
        # when the EmailAccount is being modified via a view we will allow it
        # to have `alais_for` and `aliases` that are owned by a different
        # acount.
        #
        permissions = [("can_have_foreign_aliases", "Can have foreign aliases")]
        indexes = [
            models.Index(fields=["forward_to"]),
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
    def _pre_save_logic(self):
        """
        Common function for doing any pre-save processing of the email
        account setting the mail_dir attribute and creating the associated
        mailbox.MH.
        """
        # If the object has not been created yet and if the mail_dir
        # is not set set it based on the associated Server's parent
        # mail dir and email address.
        #
        if not self.id:
            if not self.mail_dir:
                md = Path(self.server.mail_dir_parent) / self.email_address
                self.mail_dir = str(md)

        # Create the mail dir if it does not already exist. We do this
        # even if self.id is set because the mail dir may have been
        # changed and we want this process to ensure that it exists.
        #
        self.MH()

    ####################################################################
    #
    def save(self, *args, **kwargs):
        """
        Make sure the mail_dir field is set (and if not fill it in)
        """
        self._pre_save_logic()
        super().save(*args, **kwargs)

    ####################################################################
    #
    async def asave(self, *args, **kwargs):
        """
        Make sure the mail_dir field is set (and if not fill it in)
        """
        self._pre_save_logic()
        await super().asave(*args, **kwargs)

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
    def set_password(self, raw_password: str):
        """
        Keyword Arguments:
        password --
        """
        self.password = make_password(raw_password)
        self.save(update_fields=["password"])

    ####################################################################
    #
    def MH(self, create: bool = True) -> mailbox.MH:
        """
        Return a mailbox.MH instance for this user's mail
        dir. Attempts to create it if it does not already exist.
        Also make sure that the inbox also exists.
        """
        # NOTE: Various bits of code treats the object we get from MH as an
        #       EmailMessage. Thus we need to make sure when we read the
        #       message from a binary file we get back an EmailMessage. That is
        #       what the email.policy.default is for (otherwise it uses
        #       compat32 which would give us an email.Message object.)
        #
        mh = mailbox.MH(
            self.mail_dir,
            factory=lambda x: email.message_from_binary_file(
                x, policy=email.policy.default
            ),
            create=create,
        )
        for folder in settings.DEFAULT_FOLDERS:
            mh.add_folder(folder)
        return mh

    ####################################################################
    #
    def send_email_via_smtp(
        self,
        rcpt_tos: List[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ):
        """
        Wrapper around self.server.send_email_via_smtp ....
        """
        self.server.send_email_via_smtp(
            self.email_address,
            rcpt_tos,
            msg,
            spool_on_retryable=spool_on_retryable,
        )


########################################################################
########################################################################
#
class Alias(models.Model):
    """
    Through relation for EmailAccount aliases. Make sure we do not alias to
    ourselves.
    """

    from_email_account = models.ForeignKey(
        EmailAccount, on_delete=models.CASCADE, related_name="+"
    )
    to_email_account = models.ForeignKey(
        EmailAccount, on_delete=models.CASCADE, related_name="+"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                name="%(app_label)s_%(class)s_unique_relationships",
                fields=["from_email_account", "to_email_account"],
            ),
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_prevent_self_alias",
                condition=~models.Q(
                    from_email_account=models.F("to_email_account")
                ),
            ),
        ]


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

    email_account = models.ForeignKey(
        EmailAccount,
        on_delete=models.CASCADE,
        related_name="message_filter_rules",
    )
    header = models.CharField(
        max_length=32,
        choices=HEADER_CHOICES,
        default=DEFAULT,
    )
    pattern = models.CharField(blank=True, max_length=256)
    action = models.CharField(
        max_length=10,
        choices=ACTION_CHOICES,
        default=FOLDER,
    )
    destination = models.CharField(blank=True, max_length=1024)
    order_with_respect_to = "email_account"
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

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
    def inactives(cls, email_addresses: List[str]):
        """
        Given a list of email addresses see if any of those email addresses
        are inactive. Returns the list of email addresses that are inactive.
        """
        inacts = cls.objects.filter(email_address__in=email_addresses)
        return list(inacts)

    ####################################################################
    #
    @classmethod
    async def a_inactives(cls, email_addresses: List[str]):
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
