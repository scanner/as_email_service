#!/usr/bin/env python
#
"""
Service layer for user invitations.

All invitation lifecycle operations (create, resend, cancel, accept) go
through this module. The Django admin and acceptance view are the only
callers; they never touch the model directly for mutations.

Two invitation paths exist:

- New user (username does not exist): creates an inactive placeholder,
  sends an invitation email with an acceptance link. On acceptance the
  user is activated and allauth dispatches a password-reset email.

- Existing user (username already exists): creates a UserInvitation with
  status RESET_SENT and immediately sends an admin-initiated
  password-reset email explaining that an admin sent the link.
"""

# system imports
#
import logging
import secrets
from datetime import timedelta

# 3rd party imports
#
from allauth.account import app_settings as allauth_settings
from allauth.account.adapter import get_adapter
from allauth.account.internal.flows.password_reset import request_password_reset
from allauth.account.models import EmailAddress
from allauth.account.utils import user_pk_to_url_str, user_username
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

# Project imports
#
from .models import UserInvitation

logger = logging.getLogger("users.invitation")

User = get_user_model()


########################################################################
########################################################################
# Exceptions
########################################################################
########################################################################
#
class InvitationError(Exception):
    """Base class for invitation service errors."""


####################################################################
#
class InvitationExpiredError(InvitationError):
    """The invitation link has expired."""


####################################################################
#
class InvitationAlreadyAcceptedError(InvitationError):
    """The invitation was already accepted."""


####################################################################
#
class InvitationCancelledError(InvitationError):
    """The invitation has been cancelled."""


####################################################################
#
class InvitationWindowCapError(InvitationError):
    """
    Too many invitations to this address (or total) within the rolling window.
    """


####################################################################
#
class InvitationResendLimitError(InvitationError):
    """The maximum number of resends for this invitation has been reached."""


####################################################################
#
class InvitationResendCooldownError(InvitationError):
    """
    A resend was attempted too soon after the last send.
    """


########################################################################
########################################################################
# Helpers
########################################################################
########################################################################
#
def _make_token() -> str:
    return secrets.token_urlsafe(32)


####################################################################
#
def window_count(invitee_email: str) -> int:
    """
    Return the number of non-cancelled invitations to this address in the
    rolling INVITATION_WINDOW_DAYS window.
    """
    window_start = timezone.now() - timedelta(
        days=settings.INVITATION_WINDOW_DAYS
    )
    return (
        UserInvitation.objects.filter(
            invitee_email__iexact=invitee_email,
            created_at__gte=window_start,
        )
        .exclude(status=UserInvitation.Status.CANCELLED)
        .count()
    )


####################################################################
#
def send_invitation_email(invitation: UserInvitation, request) -> None:
    """
    Send (or resend) the invitation email and update send tracking fields.
    """
    accept_url = request.build_absolute_uri(
        reverse("users:accept_invitation", args=[invitation.token])
    )
    site_name = settings.SITE_NAME
    ctx = {
        "invitation": invitation,
        "accept_url": accept_url,
        "site_name": site_name,
        "expiry_days": settings.INVITATION_EXPIRY_DAYS,
    }
    subject = render_to_string(
        "users/email/user_invitation_subject.txt", ctx
    ).strip()
    body = render_to_string("users/email/user_invitation_message.txt", ctx)
    html_body = render_to_string(
        "users/email/user_invitation_message.html", ctx
    )

    send_mail(
        subject=subject,
        message=body,
        from_email=None,
        recipient_list=[invitation.invitee_email],
        html_message=html_body,
    )

    now = timezone.now()
    invitation.send_count += 1
    invitation.last_sent_at = now
    invitation.save(update_fields=["send_count", "last_sent_at"])

    logger.info(
        "Invitation email sent to %r (send_count=%d)",
        invitation.invitee_email,
        invitation.send_count,
    )


####################################################################
#
def send_admin_reset_email(invitation: UserInvitation, request) -> None:
    """
    Generate an allauth password-reset token for an existing user and
    send the admin-initiated reset email.

    The email explains that an admin sent the link so the recipient can
    set or reset their password, and that they may ignore it if they are
    already set up.
    """
    user = invitation.invitee_user
    adapter = get_adapter()
    token_generator = allauth_settings.PASSWORD_RESET_TOKEN_GENERATOR()
    temp_key = token_generator.make_token(user)
    uid = user_pk_to_url_str(user)
    key = f"{uid}-{temp_key}"
    reset_url = adapter.get_reset_password_from_key_url(key)

    ctx = {
        "invitation": invitation,
        "reset_url": reset_url,
        "site_name": settings.SITE_NAME,
        "username": user_username(user),
        "user": user,
    }
    subject = render_to_string(
        "users/email/admin_password_reset_subject.txt", ctx
    ).strip()
    body = render_to_string("users/email/admin_password_reset_message.txt", ctx)
    html_body = render_to_string(
        "users/email/admin_password_reset_message.html", ctx
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=None,
        recipient_list=[invitation.invitee_email],
        html_message=html_body,
    )

    now = timezone.now()
    invitation.send_count += 1
    invitation.last_sent_at = now
    invitation.save(update_fields=["send_count", "last_sent_at"])

    logger.info(
        "Admin password reset email sent to %r (send_count=%d)",
        invitation.invitee_email,
        invitation.send_count,
    )


####################################################################
#
def trigger_password_reset(request, user, email: str) -> None:
    """
    Dispatch allauth's password-reset email so the newly activated user can
    set their first password.

    The user must already be active (is_active=True) before calling this.
    """
    request_password_reset(
        request=request,
        email=email,
        users=[user],
        token_generator=None,
    )


########################################################################
########################################################################
# Service operations
########################################################################
########################################################################
#
def create_user_invitation(
    invited_by, username: str, request, invitee_email: str | None = None
) -> UserInvitation:
    """
    Create and send a new invitation.

    Invitees are identified by username (unique). Two paths:

    - Username does not exist: a new inactive placeholder account is
      created using 'invitee_email' (required in this case) and a
      standard invitation email is sent. On acceptance the user is
      activated and an allauth password-reset is dispatched.

    - Username already exists: a UserInvitation with status RESET_SENT
      is created and an admin-initiated password-reset email is sent
      immediately to the user's registered address. No acceptance step
      is needed.

    Args:
        invited_by: the admin user issuing the invitation.
        username: the username of the account to invite or create.
        request: current HTTP request (used to build URLs).
        invitee_email: email for a new account; required when the
            username does not yet exist; ignored for existing accounts.

    Raises:
        InvitationError: if invitee_email is missing for a new account.
        InvitationWindowCapError: if the rolling window cap is exceeded.
    """
    existing_user = User.objects.filter(username=username).first()
    if existing_user:
        effective_email = existing_user.email.lower()
        is_new_user = False
    else:
        if not invitee_email:
            raise InvitationError(
                "An email address is required to create a new account."
            )
        effective_email = invitee_email.strip().lower()
        is_new_user = True

    if window_count(effective_email) >= settings.INVITATION_MAX_PER_WINDOW:
        raise InvitationWindowCapError(
            f"Too many invitations to {effective_email!r} in the last "
            f"{settings.INVITATION_WINDOW_DAYS} days "
            f"(limit: {settings.INVITATION_MAX_PER_WINDOW})."
        )

    if is_new_user:
        invitee_user = User.objects.create_user(
            username=username,
            email=effective_email,
            password=None,
            is_active=False,
        )
    else:
        assert existing_user is not None
        invitee_user = existing_user

    expires_at = timezone.now() + timedelta(
        days=settings.INVITATION_EXPIRY_DAYS
    )

    if is_new_user:
        invitation = UserInvitation.objects.create(
            invited_by=invited_by,
            invitee_email=effective_email,
            invitee_user=invitee_user,
            token=_make_token(),
            status=UserInvitation.Status.PENDING,
            expires_at=expires_at,
        )
        send_invitation_email(invitation, request)
    else:
        invitation = UserInvitation.objects.create(
            invited_by=invited_by,
            invitee_email=effective_email,
            invitee_user=invitee_user,
            token=_make_token(),
            status=UserInvitation.Status.RESET_SENT,
            expires_at=expires_at,
        )
        send_admin_reset_email(invitation, request)

    return invitation


####################################################################
#
def cancel_user_invitation(invitation: UserInvitation) -> None:
    """
    Cancel a pending or reset-sent invitation.

    Raises:
        InvitationAlreadyAcceptedError: if already accepted.
        InvitationCancelledError: if already cancelled.
    """
    match invitation.status:
        case UserInvitation.Status.ACCEPTED:
            raise InvitationAlreadyAcceptedError(
                "Cannot cancel an already-accepted invitation."
            )
        case UserInvitation.Status.CANCELLED:
            raise InvitationCancelledError("Invitation is already cancelled.")

    invitation.status = UserInvitation.Status.CANCELLED
    invitation.cancelled_at = timezone.now()
    invitation.save(update_fields=["status", "cancelled_at"])
    logger.info(
        "Invitation %d to %r cancelled.",
        invitation.pk,
        invitation.invitee_email,
    )


####################################################################
#
def resend_user_invitation(invitation: UserInvitation, request) -> None:
    """
    Resend the appropriate email for this invitation.

    For PENDING invitations the standard invitation email is resent.
    For RESET_SENT invitations a fresh admin-initiated password-reset
    email is sent (a new allauth token is generated each time). PENDING
    invitations are also subject to the expiry check; RESET_SENT ones
    are not, because allauth tokens carry their own short expiry window.

    Raises:
        InvitationAlreadyAcceptedError: if already accepted.
        InvitationCancelledError: if cancelled.
        InvitationExpiredError: if PENDING and expired.
        InvitationResendLimitError: if max resends reached.
        InvitationResendCooldownError: if last send was too recent.
    """
    match invitation.status:
        case UserInvitation.Status.ACCEPTED:
            raise InvitationAlreadyAcceptedError("Invitation already accepted.")
        case UserInvitation.Status.CANCELLED:
            raise InvitationCancelledError("Invitation is cancelled.")
        case UserInvitation.Status.PENDING if (
            invitation.expires_at <= timezone.now()
        ):
            raise InvitationExpiredError("Invitation has expired.")
    if invitation.send_count > settings.INVITATION_MAX_RESENDS:
        raise InvitationResendLimitError(
            f"Maximum resends ({settings.INVITATION_MAX_RESENDS}) reached."
        )
    if invitation.last_sent_at is not None:
        cooldown_until = invitation.last_sent_at + timedelta(
            hours=settings.INVITATION_RESEND_COOLDOWN_HOURS
        )
        if timezone.now() < cooldown_until:
            raise InvitationResendCooldownError(
                f"Please wait until {cooldown_until} before resending."
            )

    match invitation.status:
        case UserInvitation.Status.RESET_SENT:
            send_admin_reset_email(invitation, request)
        case _:
            send_invitation_email(invitation, request)


####################################################################
#
def accept_user_invitation(invitation: UserInvitation, request) -> None:
    """
    Accept the invitation: activate the user, create a verified primary
    EmailAddress, mark the invitation accepted, and dispatch the
    password-reset email so the user can set their first password.

    Raises:
        InvitationExpiredError: if the invitation has expired.
        InvitationAlreadyAcceptedError: if already accepted.
        InvitationCancelledError: if cancelled.
        InvitationError: if the invitation is RESET_SENT (no acceptance
            step exists for admin-initiated password-reset invitations).
    """
    match invitation.status:
        case UserInvitation.Status.ACCEPTED:
            raise InvitationAlreadyAcceptedError(
                "This invitation has already been used."
            )
        case UserInvitation.Status.CANCELLED:
            raise InvitationCancelledError(
                "This invitation has been cancelled."
            )
        case UserInvitation.Status.RESET_SENT:
            raise InvitationError(
                "This invitation does not have an acceptance link. "
                "Use the password-reset link sent to your email address."
            )
    if invitation.expires_at <= timezone.now():
        raise InvitationExpiredError("This invitation link has expired.")

    user = invitation.invitee_user
    if user is None:
        # Should not happen, but guard against data inconsistency.
        raise InvitationError("Invitation has no associated user record.")

    # Activate the user.
    user.is_active = True
    user.save(update_fields=["is_active"])

    # Create a verified primary EmailAddress so the user is fully set up
    # for allauth's email-change flow and the password-reset email can be
    # sent. The invitation proves the user controls this address.
    EmailAddress.objects.get_or_create(
        user=user,
        email=invitation.invitee_email,
        defaults={"primary": True, "verified": True},
    )

    # Mark accepted.
    now = timezone.now()
    invitation.status = UserInvitation.Status.ACCEPTED
    invitation.accepted_at = now
    invitation.save(update_fields=["status", "accepted_at"])

    logger.info(
        "Invitation %d accepted; user %r activated.", invitation.pk, user.pk
    )

    # Dispatch allauth's password-reset email so the user can set their
    # first password.
    trigger_password_reset(request, user, invitation.invitee_email)
