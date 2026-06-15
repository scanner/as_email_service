#!/usr/bin/env python
#
"""
User-account management models for as_email_service.

This app owns the user-management layer above allauth: email change security,
invitations, and future profile data.
"""

# system imports
#
import secrets
from datetime import timedelta

# 3rd party imports
#
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils import timezone

_CHANGE_WINDOW_DAYS = 7
_REVOCATION_KEY_BYTES = 32


########################################################################
########################################################################
#
class PendingEmailChange(models.Model):
    """
    Tracks an in-progress email change request.

    Created when the user submits a new email address (allauth email_added
    signal). Deleted on revocation or when the change is confirmed
    (email_changed signal). The revocation_key is the auth token embedded
    in the cancellation link sent to the old address.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="pending_email_change",
    )
    new_email = models.EmailField()
    revocation_key = models.CharField(max_length=64, unique=True, db_index=True)
    expires_at = models.DateTimeField()

    ####################################################################
    #
    def __str__(self) -> str:
        return f"{self.user} → {self.new_email}"

    ####################################################################
    #
    @classmethod
    def create_for_user(
        cls, user: AbstractBaseUser, new_email: str
    ) -> "PendingEmailChange":
        """Create or replace the pending change record for a user."""
        key = secrets.token_urlsafe(_REVOCATION_KEY_BYTES)
        expires = timezone.now() + timedelta(days=_CHANGE_WINDOW_DAYS)
        obj, _ = cls.objects.update_or_create(
            user=user,
            defaults={
                "new_email": new_email,
                "revocation_key": key,
                "expires_at": expires,
            },
        )
        return obj


########################################################################
########################################################################
#
class EmailChangeCooldown(models.Model):
    """
    Blocks further email changes for 7 days after a confirmed change.

    Created when the email_changed signal fires. An admin can lift the
    block early by deleting this record.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_change_cooldown",
    )
    expires_at = models.DateTimeField()

    ####################################################################
    #
    def __str__(self) -> str:
        return f"{self.user} cooldown until {self.expires_at}"

    ####################################################################
    #
    @property
    def is_active(self) -> bool:
        return self.expires_at > timezone.now()

    ####################################################################
    #
    @classmethod
    def create_for_user(cls, user: AbstractBaseUser) -> "EmailChangeCooldown":
        """Create or reset the cooldown for a user."""
        expires = timezone.now() + timedelta(days=_CHANGE_WINDOW_DAYS)
        obj, _ = cls.objects.update_or_create(
            user=user,
            defaults={"expires_at": expires},
        )
        return obj


########################################################################
########################################################################
#
class UserInvitation(models.Model):
    """
    Tracks an admin-issued invitation for a new user to join the service.

    Flow: admin creates invitation -> invitation email sent -> recipient
    clicks link -> acceptance page -> user activated + password-reset email
    dispatched so they can set their first password.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACCEPTED = "accepted", "Accepted"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"

    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sent_invitations",
    )
    invitee_email = models.EmailField(db_index=True)
    # Set when the inactive placeholder user is created. FK (not OneToOne)
    # because multiple invitation records can exist for the same email over
    # time (e.g. cancel-and-reinvite scenarios).
    invitee_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="invitations",
    )
    token = models.CharField(max_length=64, unique=True, db_index=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    send_count = models.PositiveIntegerField(default=0)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    ####################################################################
    #
    class Meta:
        ordering = ["-created_at"]

    ####################################################################
    #
    def __str__(self) -> str:
        return f"Invitation({self.invitee_email}, {self.status})"

    ####################################################################
    #
    @property
    def is_usable(self) -> bool:
        """True if the invitation can still be accepted."""
        return (
            self.status == self.Status.PENDING
            and self.expires_at > timezone.now()
        )
