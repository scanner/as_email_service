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
