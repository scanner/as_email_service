#!/usr/bin/env python
#
"""
Account management views for as_email_service.

Wraps allauth's email and password management with project-specific
templates and URLs, consolidating both onto a single Account Info page.
Also provides the email-change revocation view (no login required).
"""

# system imports
#
import logging

# 3rd party imports
#
from allauth.account.forms import AddEmailForm, ChangePasswordForm
from allauth.account.models import EmailAddress
from allauth.account.views import EmailView, PasswordChangeView
from django.contrib import messages
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import View

# Project imports
#
from users.models import EmailChangeCooldown, PendingEmailChange

logger = logging.getLogger("as_email.account_views")


####################################################################
#
class AccountInfoView(EmailView):
    """
    Account Info page wrapping allauth's email management.

    Uses our crispy-bulma template and posts back to this view's URL
    rather than allauth's default 'account_email' URL. Also injects an
    unbound ChangePasswordForm so the password section renders on GET,
    and enforces the 7-day email-change cooldown server-side.
    """

    template_name = "as_email/account_info.html"
    success_url = reverse_lazy("as_email:account_info")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ea = ctx.get("current_emailaddress")
        ctx["current_email_str"] = ea.email if ea else ""
        ctx["password_change_form"] = ChangePasswordForm(user=self.request.user)
        try:
            cooldown = EmailChangeCooldown.objects.get(user=self.request.user)
            if cooldown.is_active:
                ctx["email_change_cooldown_until"] = cooldown.expires_at
            else:
                cooldown.delete()
        except EmailChangeCooldown.DoesNotExist:
            pass
        return ctx

    def form_valid(self, form):
        # Defense-in-depth: re-check cooldown even if the UI hid the form.
        try:
            cooldown = EmailChangeCooldown.objects.get(user=self.request.user)
            if cooldown.is_active:
                messages.warning(
                    self.request,
                    _("Email changes are blocked until %(until)s.")
                    % {
                        "until": cooldown.expires_at.strftime(
                            "%Y-%m-%d %H:%M UTC"
                        )
                    },
                )
                return self.form_invalid(form)
            else:
                cooldown.delete()
        except EmailChangeCooldown.DoesNotExist:
            pass
        return super().form_valid(form)


####################################################################
#
class AccountPasswordChangeView(PasswordChangeView):
    """
    Password change handler that renders the Account Info page on error
    and redirects back to it on success.

    On form_invalid, renders account_info.html with both the bound
    (errored) password form and an unbound email form so the full page
    is shown correctly.
    """

    template_name = "as_email/account_info.html"
    success_url = reverse_lazy("as_email:account_info")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # super() sets ctx["form"] = password form and ctx["password_change_form"]
        # = same (allauth compat alias). account_info.html uses ctx["form"] for the
        # email section, so replace it with an unbound email form.
        user = self.request.user
        current_ea = EmailAddress.objects.get_verified(user)
        ctx["current_emailaddress"] = current_ea
        ctx["current_email_str"] = current_ea.email if current_ea else ""
        ctx["new_emailaddress"] = EmailAddress.objects.get_new(user)
        ctx["form"] = AddEmailForm(user=user)
        try:
            cooldown = EmailChangeCooldown.objects.get(user=user)
            if cooldown.is_active:
                ctx["email_change_cooldown_until"] = cooldown.expires_at
            else:
                cooldown.delete()
        except EmailChangeCooldown.DoesNotExist:
            pass
        return ctx


####################################################################
#
class EmailChangeRevokeView(View):
    """
    Revocation view for the email-change cancellation link.

    No login required -- the revocation key is the authentication token.

    GET  -- renders a confirmation page ("cancel this change?")
    POST -- performs the revocation and shows a success page

    GET-only revocation was deliberately avoided because corporate email
    security gateways (Proofpoint, Safe Links) prefetch links in messages
    via GET, which would silently cancel legitimate change requests.
    """

    template_name = "as_email/email_change_revoke.html"

    def get(self, request, key: str):
        try:
            pending = PendingEmailChange.objects.get(revocation_key=key)
        except PendingEmailChange.DoesNotExist:
            return render(request, self.template_name, {"state": "expired"})
        return render(
            request,
            self.template_name,
            {"state": "confirm", "key": key, "new_email": pending.new_email},
        )

    def post(self, request, key: str):
        try:
            pending = PendingEmailChange.objects.get(revocation_key=key)
        except PendingEmailChange.DoesNotExist:
            return render(request, self.template_name, {"state": "expired"})

        # Remove the unverified pending EmailAddress so the confirmation
        # link becomes invalid.
        try:
            ea = EmailAddress.objects.get(
                user=pending.user, email=pending.new_email, verified=False
            )
            ea.remove()
        except EmailAddress.DoesNotExist:
            pass

        pending.delete()
        logger.info(
            "Email change to %r revoked for user %r",
            pending.new_email,
            pending.user_id,
        )
        return render(request, self.template_name, {"state": "revoked"})
