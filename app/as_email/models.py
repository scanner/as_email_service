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
import email.message
import mailbox
import random
import string
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
    def __str__(self):
        return self.name


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

    # In the future we may want to move API keys in to a more generalized
    # framework but right now the only thing that can use the webhook's are the
    # remote servers and we need a key for them to use so we are tying it to
    # the server itself. It will be generated when the Server object is
    # created.
    #
    api_key = models.CharField(
        help_text=_(
            "In order for the server to be able to post data to the web hooks "
            "provided by this service, they need an API key that is unique to "
            "this server."
        ),
        max_length=40,
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

        After we have called the parent save method we make sure that the
        directory specified exists.
        """
        self._set_initial_values()
        super().save(*args, **kwargs)

        # Make sure that the directories for the file fields exist.
        #
        Path(self.incoming_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.outgoing_spool_dir).mkdir(parents=True, exist_ok=True)
        Path(self.mail_dir_parent).mkdir(parents=True, exist_ok=True)

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
        return await asyncio.to_thread(self.send_email(message))


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
    LOCAL_DELIVERY = "LD"
    ACCOUNT_TYPE_CHOICES = [
        (LOCAL_DELIVERY, "Local Delivery"),
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
        max_length=2, choices=ACCOUNT_TYPE_CHOICES, default=LOCAL_DELIVERY
    )

    mail_dir: models.CharField = models.CharField(
        help_text=_(
            "The root folder of the mail directory for this email account. "
            "This should be left blank and it will be auto-filled in when "
            "the email account is created. Only fill it in if you have a "
            "specific location in the file system you want this user's "
            "mailbox to be stored at."
        ),
        max_length=1000,
        null=True,
        blank=True,
    )
    password: models.CharField = models.CharField(
        max_length=200,
        help_text=_(
            "Password used for the SMTP and IMAP services for this email "
            "account"
        ),
        default="XXX",
    )
    handle_blocked_messages: models.CharField = models.CharField(
        max_length=2,
        choices=BLOCK_CHOICES,
        default=DELIVER,
        help_text=_(
            "When the email provider blocks a message because it is thought "
            "to be spam you can choose to have the email delivered to the "
            "folder set in the `blocked messages delivery folder` or you can"
            "choose them to be blocked. ie: not delivered to your mail box "
            "at all. They will be viewable in the email account's blocked "
            "messages list where you can choose to have them delivered to your "
            "mail box on a message by message basis."
        ),
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
    forward_to = models.EmailField(null=True, blank=True)

    # If an account is deactivated it can still receive email. However it is no
    # longer allowed to send email.
    #
    # (and if an account does not exist the email will be dropped, again we
    # need to add logging and metrics for when we receive emails for accounts
    # that do not exist.)
    #
    deactivated = models.BooleanField(default=False)

    # If the number of bounces exceeds a certain limit then the account is
    # deactivated and not allowed to send new email (it can still
    # receive email) (maybe it should be some sort of percentage of total
    # emails sent by this account.)
    #
    num_bounces = models.IntegerField(default=0)
    deactivated_reason = models.TextField(
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
            models.Index(fields=["server"]),
            models.Index(fields=["user"]),
        ]

        ordering = ("server", "email_address")

    ####################################################################
    #
    def __str__(self):
        return self.email_address

    ####################################################################
    #
    def _setup_mh_mail_dir(self):
        """
        Common function for setting the mail_dir attribute and
        creating the assocaited mailbox.MH.
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
        _ = self.MH()

    ####################################################################
    #
    def save(self, *args, **kwargs):
        """
        Make sure the mail_dir field is set (and if not fill it in)
        """
        self._setup_mh_mail_dir()
        super().save(*args, **kwargs)

    ####################################################################
    #
    async def asave(self, *args, **kwargs):
        """
        Make sure the mail_dir field is set (and if not fill it in)
        """
        self._setup_mh_mail_dir()
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
        """
        return mailbox.MH(self.mail_dir, create=create)


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
        indexes = [
            models.Index(fields=["email_account"]),
            models.Index(fields=["created_at", "email_account"]),
            models.Index(fields=["status", "email_account"]),
        ]
        ordering = ("email_account", "created_at")

    ####################################################################
    #
    def __str__(self):
        return f"{self.email_account.email_address} - {self.from_address}: {self.subject} ({self.created_at})"


########################################################################
########################################################################
#
class MessageFilterRule(OrderedModel):
    # slocal offers "folder", "destroy", "file", "mbox", "mmdf", "pipe",
    # "qpipe" which offer various actions. We are only supporting 'folder' and
    # 'destroy' for now.
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
        max_length=10, choices=ACTION_CHOICES, default=FOLDER
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
        rule_parts = rule_text.split()
        if len(rule_parts) == 5:
            (header, pattern, action, result, folder) = rule_parts
            if action != "folder":
                raise ValueError(
                    "5 part message filter rule is only valid for 'folder' "
                    "rules"
                )
            rule = cls(
                email_account=email_account,
                header=header,
                pattern=pattern,
                action=action,
                destination=folder,
            )
        elif len(rule_parts) == 4:
            (header, pattern, action, result) = rule_parts
            if action != "destroy":
                raise ValueError(
                    "4 part message filter rule is only valid for 'destroy' "
                    "rules"
                )
            rule = cls(
                email_account=email_account,
                header=header,
                pattern=pattern,
                action=action,
            )
        else:
            raise ValueError(
                "rule text must be 4 or 5 columns separated white space."
            )
        rule.save()
        return rule

    ####################################################################
    #
    def match(self, email_message: email.message.Message):
        """
        Returns True if the email message matches the header/pattern.

        NOTE: Matches are only case insensitive substring matches! Not regular
              expressions!
        """
        if self.header not in email_message:
            return False

        header_contents = email_message.get_all(self.header)
        for hc in header_contents:
            if self.pattern.lower() == hc.lower():
                return True

        return False
