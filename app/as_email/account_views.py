#!/usr/bin/env python
#
"""
Account management views for as_email_service.

Wraps allauth's email and password management with project-specific
templates and URLs, consolidating both onto a single Account Info page.
"""

# 3rd party imports
#
from allauth.account.forms import AddEmailForm, ChangePasswordForm
from allauth.account.models import EmailAddress
from allauth.account.views import EmailView, PasswordChangeView
from django.urls import reverse_lazy


####################################################################
#
class AccountInfoView(EmailView):
    """
    Account Info page wrapping allauth's email management.

    Uses our crispy-bulma template and posts back to this view's URL
    rather than allauth's default 'account_email' URL. Also injects an
    unbound ChangePasswordForm so the password section renders on GET.
    """

    template_name = "as_email/account_info.html"
    success_url = reverse_lazy("as_email:account_info")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ea = ctx.get("current_emailaddress")
        ctx["current_email_str"] = ea.email if ea else ""
        ctx["password_change_form"] = ChangePasswordForm(user=self.request.user)
        return ctx


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
        return ctx
