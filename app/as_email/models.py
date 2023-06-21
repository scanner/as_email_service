#!/usr/bin/env python
#
"""
Models for the Apricot Systematic email service.  NOTE: Could
potentially work with various 3rd party email services for now it is
mostly custom for the service I use: postmark.
"""
# system imports
#
from functools import lru_cache

# 3rd party imports
#
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from polymorphic.models import PolymorphicModel
from postmarker.core import PostmarkClient

# Various models that belong to a specific user need the User object.
#
User = get_user_model()


########################################################################
########################################################################
#
class Provider(models.Model):
    name = models.CharField(unique=True)
    token_env_name = models.CharField(
        help_text=(
            "The name of the env. var that has the API key for this Provider"
        )
    )
    endpoint_url = models.URLField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)


########################################################################
########################################################################
#
class Server(models.Model):
    domain_name = models.CharField(
        help_text=(
            "This is the 'server' within postmark to handle email for the "
            "specified domain."
        ),
        max_length=200,
        unique=True,
    )
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

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
        self.client.emails.send(message)


########################################################################
########################################################################
#
class Address(PolymorphicModel):
    """
    The abstract base class for the several different types of
    accounts that can be the destination for email.

    This lets us collect 'accounts','aliases', and 'forwards' ensuring
    that the 'mail address' is unique.
    """

    # NOTE: Was unable to work around django-stubs, mypy, django-polymorphic
    #       declaring these fields as needing type annotations so that is why
    #       these have type declarations when models.Model based classes do not
    #       need them.
    #
    user: models.ForeignKey = models.ForeignKey(User, on_delete=models.CASCADE)
    address: models.EmailField = models.EmailField(unique=True)
    server: models.ForeignKey = models.ForeignKey(
        Server, on_delete=models.CASCADE
    )
    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)
    modified_at: models.DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["address"])]


########################################################################
########################################################################
#
# Both Account's and Forward's may choose to 'block' or 'deliver'
# blocked messages.
#
BLOCK = "BL"
DELIVER = "DE"
BLOCK_CHOICES = [
    (BLOCK, "Block"),
    (DELIVER, "Deliver"),
]


########################################################################
########################################################################
#
class Account(Address):
    """
    User's can have multiple mail accounts. A single mail account
    maps to an email address that can receive and store email.
    """

    mail_dir: models.CharField = models.CharField(max_length=1000)
    password: models.CharField = models.CharField(
        help_text=("Password for SMTP and IMAP auth for this account"),
    )
    handle_blocked_messages: models.CharField = models.CharField(
        max_length=2, choices=BLOCK_CHOICES, default=DELIVER
    )
    blocked_messages_delivery_folder: models.CharField = models.CharField(
        default="Junk",
        help_text=(
            "If `blocked_messages` is set to `Deliver` then this is the mail "
            "folder that they are delivered to."
        ),
    )

    # If `forwarding` is true then email is not locally delivered. It is
    # forwarded to the `forward_address`. If the forward_address is not set the
    # email is delivered locally (so both must be set.. but once
    # forward_address is set forwarding can be turned on/off by setting
    # `forwarding` True or False.)
    #
    forwarding: models.BooleanField = models.BooleanField(default=False)
    forward_address: models.EmailField = models.EmailField(null=True)
    deactivated: models.BooleanField = models.BooleanField(default=True)

    # If the number of bounces exceeds a certain limit then the account is
    # temporarily deactivated and not allowed to send new email (it can still
    # receive email) (maybe it should be some sort of percentage of total
    # emails sent by this account.)
    #
    num_bounces: models.IntegerField = models.IntegerField(default=0)
    deactivated_reason: models.TextField = models.TextField(
        help_text=("If this forward is deactivated this indicates why")
    )

    class Meta:
        indexes = [models.Index(fields=["forward_address"])]

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
class Alias(Address):
    """
    An alias for an account. Lets us specify additional email
    addresses that will be directly received by a specific account.

    NOTE: The alias does NOT have to be on the same mail server as the
          account that the alias is for.

    NOTE: We do need to enforce that you can only add aliases to the
          same django user, though.
    """

    account: models.ForeignKey = models.ForeignKey(
        Account, on_delete=models.CASCADE
    )


########################################################################
########################################################################
#
class Forward(Address):
    """
    Forward messages to an email address that is not handled by
    this system (ie; to external systems)

    If a forward bounces too often it will be deactivated and those
    messages will not be delivered at all.

    XXX Yeah.. going to get rid of "Forward" .. you can just set a "forward" on
        an account and this lets users set their own forwards.

        Once an account is set to forward things like local delivery do not do
        anything.
    """

    blocked_messages: models.CharField = models.CharField(
        max_length=2, choices=BLOCK_CHOICES, default=DELIVER
    )
    forward_address: models.EmailField = models.EmailField()
    deactivated: models.BooleanField = models.BooleanField(default=True)
    num_bounces: models.IntegerField = models.IntegerField(default=0)
    deactivated_reason: models.TextField = models.TextField(
        help_text=("If this forward is deactivated this indicates why")
    )

    class Meta:
        indexes = [models.Index(fields=["forward_address"])]


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

    address = models.ForeignKey(Address, on_delete=models.CASCADE)
    message_id = models.IntegerField()
    status = models.CharField()
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
