#!/usr/bin/env python
#
"""
Service layer for user invitations.

All invitation lifecycle operations (create, resend, cancel, accept) go
through this module. The Django admin and acceptance view are the only
callers; they never touch the model directly for mutations.
"""

# system imports
#
import logging
import secrets
from datetime import timedelta

# 3rd party imports
#
from allauth.account.internal.flows.password_reset import request_password_reset
from allauth.account.models import EmailAddress
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
def _get_or_create_user_for_invite(
    invitee_email: str, username: str | None = None
) -> tuple:
    """
    Return (user, created) for the invitation target.

    If exactly one user already exists for this email (active or inactive),
    return them without modification. If multiple users share the email,
    raise InvitationError -- the admin must resolve the ambiguity manually.
    If no user exists, create an inactive placeholder with an unusable
    password, using the provided username or one auto-derived from the
    email local part.
    """
    matching = list(User.objects.filter(email__iexact=invitee_email))
    if len(matching) > 1:
        raise InvitationError(
            f"Multiple accounts share the address {invitee_email!r}; "
            "resolve the duplicate before sending an invitation."
        )
    if matching:
        return matching[0], False

    derived = (username or invitee_email.split("@")[0])[:150]
    base = derived
    counter = 1
    while User.objects.filter(username=derived).exists():
        derived = f"{base}{counter}"
        counter += 1

    user = User.objects.create_user(
        username=derived,
        email=invitee_email,
        password=None,  # unusable password
        is_active=False,
    )
    return user, True


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
    invited_by, invitee_email: str, request, username: str | None = None
) -> UserInvitation:
    """
    Create and send a new invitation.

    If an account already exists for 'invitee_email', the invitation is
    linked to that account (active or inactive) and a password-reset email
    is dispatched on acceptance so the user can set or change their password.
    If multiple accounts share the address, InvitationError is raised.

    Args:
        invited_by: the admin user issuing the invitation.
        invitee_email: email address to invite.
        request: current HTTP request (used to build the accept URL).
        username: desired username for a newly created placeholder account;
            ignored when an existing account is found for the address.

    Raises:
        InvitationError: if the email is ambiguous (multiple accounts).
        InvitationWindowCapError: if the rolling window cap is exceeded.
    """
    invitee_email = invitee_email.strip().lower()

    if window_count(invitee_email) >= settings.INVITATION_MAX_PER_WINDOW:
        raise InvitationWindowCapError(
            f"Too many invitations to {invitee_email!r} in the last "
            f"{settings.INVITATION_WINDOW_DAYS} days "
            f"(limit: {settings.INVITATION_MAX_PER_WINDOW})."
        )

    invitee_user, _ = _get_or_create_user_for_invite(invitee_email, username)
    expires_at = timezone.now() + timedelta(
        days=settings.INVITATION_EXPIRY_DAYS
    )

    invitation = UserInvitation.objects.create(
        invited_by=invited_by,
        invitee_email=invitee_email,
        invitee_user=invitee_user,
        token=_make_token(),
        status=UserInvitation.Status.PENDING,
        expires_at=expires_at,
    )
    send_invitation_email(invitation, request)
    return invitation


####################################################################
#
def cancel_user_invitation(invitation: UserInvitation) -> None:
    """
    Cancel a pending invitation.

    Raises:
        InvitationAlreadyAcceptedError: if already accepted.
        InvitationCancelledError: if already cancelled.
    """
    if invitation.status == UserInvitation.Status.ACCEPTED:
        raise InvitationAlreadyAcceptedError(
            "Cannot cancel an already-accepted invitation."
        )
    if invitation.status == UserInvitation.Status.CANCELLED:
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
    Resend the invitation email.

    Raises:
        InvitationAlreadyAcceptedError: if already accepted.
        InvitationCancelledError: if cancelled.
        InvitationExpiredError: if expired.
        InvitationResendLimitError: if max resends reached.
        InvitationResendCooldownError: if last send was too recent.
    """
    if invitation.status == UserInvitation.Status.ACCEPTED:
        raise InvitationAlreadyAcceptedError("Invitation already accepted.")
    if invitation.status == UserInvitation.Status.CANCELLED:
        raise InvitationCancelledError("Invitation is cancelled.")
    if invitation.expires_at <= timezone.now():
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
    """
    if invitation.status == UserInvitation.Status.ACCEPTED:
        raise InvitationAlreadyAcceptedError(
            "This invitation has already been used."
        )
    if invitation.status == UserInvitation.Status.CANCELLED:
        raise InvitationCancelledError("This invitation has been cancelled.")
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
