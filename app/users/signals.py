#!/usr/bin/env python
#
"""
Signal receivers for the users app.

Connects to allauth's email_added and email_changed signals to implement
email change security hardening: pre-confirmation notification with a
revocation link, and a 7-day cooldown after a confirmed change.
"""

# system imports
#
import logging

# 3rd party imports
#
from allauth.account.models import EmailAddress
from allauth.account.signals import email_added, email_changed
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.urls import reverse

# Project imports
#
from users.models import EmailChangeCooldown, PendingEmailChange

logger = logging.getLogger("users.signals")


########################################################################
########################################################################
#
@receiver(email_added, sender=EmailAddress)
def on_email_added(
    sender, request, user, email_address: EmailAddress, **kwargs
) -> None:
    """
    Fire when a new email address is added (i.e. a change is requested).

    With CHANGE_EMAIL=True every email_added is a change request. Sends a
    pre-confirmation notification to the old address so the user can cancel
    if the request is not theirs.

    Skipped when:
    - request is None (admin/management-command context -- no URL to build)
    - the user has no old address (genuine first-time email setup)
    """
    if request is None:
        return

    # Find the old address. Prefer a verified+primary EA row; fall back to
    # user.email for accounts that pre-date allauth (no EA row yet).
    old_ea = (
        EmailAddress.objects.filter(user=user, primary=True, verified=True)
        .exclude(pk=email_address.pk)
        .first()
    )
    if old_ea is not None:
        old_email = old_ea.email
    elif user.email and user.email != email_address.email:
        old_email = user.email
    else:
        # Genuine first-time setup: no old address to notify.
        return

    pending = PendingEmailChange.create_for_user(user, email_address.email)
    revocation_url = request.build_absolute_uri(
        reverse("as_email:email_change_revoke", args=[pending.revocation_key])
    )
    site = get_current_site(request)
    ctx = {
        "user": user,
        "old_email": old_email,
        "new_email": email_address.email,
        "revocation_url": revocation_url,
        "expires_at": pending.expires_at,
        "current_site": site,
    }
    subject = render_to_string(
        "users/email/email_change_pending_subject.txt", ctx
    ).strip()
    body = render_to_string("users/email/email_change_pending_message.txt", ctx)
    send_mail(subject, body, from_email=None, recipient_list=[old_email])
    logger.info(
        "Sent email-change cancellation notice to %r for user %r",
        old_email,
        user.pk,
    )


########################################################################
########################################################################
#
@receiver(email_changed, sender=EmailAddress)
def on_email_changed(
    sender, request, user, from_email_address, to_email_address, **kwargs
) -> None:
    """
    Fire when a pending change is confirmed.

    Cleans up the PendingEmailChange record (if still present) and starts
    the 7-day cooldown that prevents rapid re-changes.
    """
    PendingEmailChange.objects.filter(user=user).delete()
    EmailChangeCooldown.create_for_user(user)
    logger.info(
        "Email confirmed for user %r; 7-day cooldown started",
        user.pk,
    )
