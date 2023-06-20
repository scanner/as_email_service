#!/usr/bin/env python
#
"""
Models for the Apricot Systematic email service.  NOTE: Could
potentially work with various 3rd party email services for now it is
mostly custom for the service I use: postmark.
"""
# system imports
#

# 3rd party imports
#
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from polymorphic.models import PolymorphicModel

# Various models that belong to a specific user need the User object.
#
User = get_user_model()


########################################################################
########################################################################
#
class Provider(models.Model):
    name = models.CharField(unique=True)
    token_env_name = models.CharField(
        help=("The name of the env. var that has the API key for this Provider")
    )
    endpoint_url = models.URLField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)


########################################################################
########################################################################
#
class Server(models.Model):
    domain_name = models.CharField(max_length=200, unique=True)
    token_env_name = models.CharField(
        help=(
            "The name of the env. var that has the API token for this "
            "Server (postmark 'server')"
        )
    )
    provider = models.ForeignKey(Provider)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)


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

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.EmailField(unique=True)
    server = models.ForeignKey(Server)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

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

    mail_dir = models.CharField(max_length=1000)
    password = models.CharField(
        help=("Password for SMTP and IMAP auth for this account"),
    )
    handle_blocked_messages = models.CharField(
        max_length=2, choices=BLOCK_CHOICES, default=DELIVER
    )
    blocked_messages_delivery_folder = models.CharField(
        default="Junk",
        help=(
            "If `blocked_messages` is set to `Deliver` then this is the mail "
            "folder that they are delivered to."
        ),
    )


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

    account = models.ForeignKey(Account)


########################################################################
########################################################################
#
class Forward(Address):
    """
    Forward messages to an email address that is not handled by
    this system (ie; to external systems)

    If a forward bounces too often it will be deactivated and those
    messages will not be delivered at all.
    """

    blocked_messages = models.CharField(
        max_length=2, choices=BLOCK_CHOICES, default=DELIVER
    )
    forward_address = models.EmailField()
    deactivated = models.BooleanField(default=True)
    num_bounces = models.IntegerField(default=0)
    deactivated_reason = models.TextField(
        help=("If this forward is deactivated this indicates why")
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

    address = models.ForeignKey(Address)
    message_id = models.IntegerField()
    status = models.CharField()
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
