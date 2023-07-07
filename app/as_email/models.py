#!/usr/bin/env python
#
"""
Models for the Apricot Systematic email service.  NOTE: Could
potentially work with various 3rd party email services for now it is
mostly custom for the service I use: postmark.
"""
# system imports
#
import asyncio
from functools import lru_cache
from pathlib import Path

# 3rd party imports
#
import aiofiles
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from ordered_model.models import OrderedModel
from postmarker.core import PostmarkClient

# Various models that belong to a specific user need the User object.
#
User = get_user_model()


########################################################################
########################################################################
#
class Provider(models.Model):
    name = models.CharField(unique=True, max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)


####################################################################
#
def spool_dir_path():
    """
    The spool dir is defined in the django settings. This lets us assign the
    root spool dir to use for a server dynamically.
    """
    return settings.EMAIL_SPOOL_DIR


####################################################################
#
def email_base_dir():
    """
    Look the spool dir path this is the root directory in settings where
    all the mail folders for the email accounts are stored.
    """
    return settings.EMAIL_BASE_DIR


########################################################################
########################################################################
#
class Server(models.Model):
    domain_name = models.CharField(
        help_text=_(
            "This is the 'server' within postmark to handle email for the "
            "specified domain."
        ),
        max_length=200,
        unique=True,
    )
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    incoming_spool_dir = models.FilePathField(
        spool_dir_path,
        max_length=1000,
        allow_files=False,
        allow_folders=True,
        recursive=True,
    )
    outgoing_spool_dir = models.FilePathField(
        spool_dir_path,
        max_length=1000,
        allow_files=False,
        allow_folders=True,
        recursive=True,
    )
    mail_dir_parent = models.FilePathField(
        email_base_dir,
        max_length=1000,
        allow_files=False,
        allow_folders=True,
        recursive=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    ####################################################################
    #
    def save(self, *args, **kwargs):
        """
        On pre-save of the Server instance if this is when it is being
        created pre-fill the incoming spool dir, outgoing spool dir, and
        mail_dir_parent based on the domain_name of the server.

        This lets the default creation automatically set where these
        directories are without requiring input if they are not set on create.

        After we have called the parent save method we make sure that the
        directory specified exists.
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
                self.incoming_spool_dir = (
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "incoming"
                )
            if not self.outgoing_spool_dir:
                self.outgoing_spool_dir = (
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "outgoing"
                )

            if not self.mail_dir_parent:
                self.mail_dir_parent = (
                    settings.EMAIL_BASE_DIR / self.domain_name
                )
        super().save(*args, **kwargs)

        # Make sure that the directories for the file fields exist.
        incoming_spool_dir = Path(self.incoming_spool_dir)
        outgoing_spool_dir = Path(self.outgoing_spool_dir)
        mail_dir_parent = Path(self.mail_dir_parent)

        incoming_spool_dir.mkdir(parents=True, exist_ok=True)
        outgoing_spool_dir.mkdir(parents=True, exist_ok=True)
        mail_dir_parent.mkdir(parents=True, exist_ok=True)

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
        # If the object has not been created yet then if the various file
        # fields have not been set, set them based on django settings and the
        # domain name.
        #
        # XXX We should also check to see if the path exists and if it does it
        #     must be a directory.
        #
        if not self.id:
            if not self.incoming_spool_dir:
                self.incoming_spool_dir = (
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "incoming"
                )
            if not self.outgoing_spool_dir:
                self.outgoing_spool_dir = (
                    settings.EMAIL_SPOOL_DIR / self.domain_name / "outgoing"
                )

            if not self.mail_dir_parent:
                self.mail_dir_parent = (
                    settings.EMAIL_BASE_DIR / self.domain_name
                )
        await super().asave(*args, **kwargs)

        # Make sure that the directories for the file fields exist.
        #
        if not await aiofiles.os.path.exists(self.incoming_spool_dir):
            await aiofiles.os.mkdirs(self.incoming_spool_dir)
        if not await aiofiles.os.path.exists(self.outgoing_spool_dir):
            await aiofiles.os.mkdirs(self.outgoing_spool_dir)
        if not await aiofiles.os.path.exists(self.mail_dir_parent):
            await aiofiles.os.mkdirs(self.mail_dir_parent)

    ####################################################################
    #
    @lru_cache()
    def client(self) -> PostmarkClient:
        """
        Returns a postmark client for this server
        """
        return PostmarkClient(
            server_token=settings.EMAIL_SERVER_TOKENS[self.domain_name]
        )

    ####################################################################
    #
    def send_email(self, message):
        """
        Send the given email via this server.

        XXX Be sure to record metrics when we send a message, and how large the
            message was.
        """
        return self.client.emails.send(message)

    ####################################################################
    #
    async def asend_email(self, message):
        """
        Send the given email via this server, asyncio version
        """
        return await asyncio.to_thread(self.client.emails.send(message))


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

    BLOCK = "BL"
    DELIVER = "DE"
    BLOCK_CHOICES = [
        (BLOCK, "Block"),
        (DELIVER, "Deliver"),
    ]

    # EmailAccount types - account, alias, forwarding
    #
    ALIAS = "AL"
    FORWARDING = "FW"
    ACCOUNT = "AC"
    ACCOUNT_TYPE_CHOICES = [
        (ACCOUNT, "Account"),
        (ALIAS, "Alias"),
        (FORWARDING, "Forwarding"),
    ]

    user: models.ForeignKey = models.ForeignKey(User, on_delete=models.CASCADE)
    server: models.ForeignKey = models.ForeignKey(
        Server, on_delete=models.CASCADE
    )
    # XXX We should figure out a way to have this still be a validated email
    #     field, but auto-fill the domain name part from the server attribute.
    #     For now we are just going to require that the domain name's match.
    #
    email_address: models.EmailField = models.EmailField(
        unique=True,
        help_text=_(
            "The email address that will receive emails on this server, "
            "and the address that will be used as a login to send emails. "
            "It must have the same domin name as the associated server"
        ),
    )
    account_type = models.CharField(
        max_length=2, choices=ACCOUNT_TYPE_CHOICES, default=ACCOUNT
    )
    mail_dir: models.CharField = models.CharField(max_length=1000)
    password: models.CharField = models.CharField(
        max_length=200,
        help_text=_("Password for SMTP and IMAP auth for this account"),
        default="XXX",
    )
    handle_blocked_messages: models.CharField = models.CharField(
        max_length=2, choices=BLOCK_CHOICES, default=DELIVER
    )
    blocked_messages_delivery_folder: models.CharField = models.CharField(
        default="Junk",
        max_length=1024,
        help_text=_(
            "If `blocked_messages` is set to `Deliver` then this is the mail "
            "folder that they are delivered to."
        ),
    )

    # If account_type is ALIAS then messages are not delivered to this
    # account. Instead they are delivered to the accounts in the `alias_for`
    # attribute. NOTE! This means you can alias across domains.
    #
    alias_for = models.ManyToManyField(
        "self",
        related_name="aliases",
        related_query_name="alias",
        symmetrical=False,
    )

    # If account_type is FORWARDING then messages are not delivered
    # locally. Instead a new email message is generated and sent to the
    # `forward_to` address.
    #
    # NOTE: Unlike 'alias' you can only forward to a single address.
    #
    forward_to: models.EmailField = models.EmailField(null=True, blank=True)

    # If an account is deactivated it can still receive email. However it is no
    # longer allowed to send email.
    #
    # (and if an account does not exist the email will be dropped, again we
    # need to add logging and metrics for when we receive emails for accounts
    # that do not exist.)
    #
    deactivated: models.BooleanField = models.BooleanField(default=False)

    # If the number of bounces exceeds a certain limit then the account is
    # deactivated and not allowed to send new email (it can still
    # receive email) (maybe it should be some sort of percentage of total
    # emails sent by this account.)
    #
    num_bounces: models.IntegerField = models.IntegerField(default=0)
    deactivated_reason: models.TextField = models.TextField(
        help_text=_("Reason for the account being deactivated"),
        null=True,
        blank=True,
    )

    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)
    modified_at: models.DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["forward_to"]),
            models.Index(fields=["email_address"]),
            models.Index(fields=["user"]),
        ]

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


########################################################################
########################################################################
#
class BlockedMessage(models.Model):
    """
    we provide our own UI to all of the blocked emails for users
    to look at. This is a crude front end over postmark's ui. The main
    thing is store a blockd email object by user so user's only see
    their own blocked email. We will have a huey cron task poll
    postmark for blocked emails for all domains and users for those
    domains (so we only store ones for which there are actual users.)

    We will only maintain blocked email objects for a certain amount
    of time (probably 45 days, like postmark's default retention.) A
    huey job will delete all blocked email's that are older than that.
    """

    email_account = models.ForeignKey(EmailAccount, on_delete=models.CASCADE)
    message_id = models.IntegerField(unique=True)
    status = models.CharField(max_length=32)
    from_address = models.EmailField(max_length=256)
    subject = models.CharField(blank=True, max_length=1024)
    cc = models.CharField(blank=True, max_length=1024)
    blocked_reason = models.TextField(blank=True, max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["email_account"])]


########################################################################
########################################################################
#
class MessageFilterRule(OrderedModel):
    # slocal offers "folder", "destroy", "file", "mbox", "mmdf", "pipe",
    # "qpipe" which offer various actions. We are only supporting 'folder' and
    # 'destroy' for now.
    #
    FOLDER = "FO"
    DESTROY = "DE"
    ACTION_CHOICES = [
        (FOLDER, "folder"),
        (DESTROY, "destroy"),
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

    HEADER_CHOICES = [
        (ADDR, ADDR),
        (ANY, ANY),
        (BCC, BCC),
        (CC, CC),
        (DEFAULT, DEFAULT),
        (FROM, FROM),
        (REPLY_TO, REPLY_TO),
        (SOURCE, SOURCE),
        (SUBJECT, SUBJECT),
        (TO, TO),
    ]

    email_account = models.ForeignKey(EmailAccount, on_delete=models.CASCADE)
    header = models.CharField(
        max_length=32, choices=HEADER_CHOICES, default=DEFAULT
    )
    pattern = models.CharField(blank=True, max_length=256)
    action = models.CharField(
        max_length=2, choices=ACTION_CHOICES, default=FOLDER
    )
    folder = models.CharField(blank=True, max_length=1024)
    order_with_respect_to = "email_account"

    class Meta:
        indexes = [models.Index(fields=["email_account"])]
        ordering = ("email_account", "order")
