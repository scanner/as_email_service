#!/usr/bin/env python
#
"""
Account management views for as_email_service.

Wraps allauth's email management with project-specific templates and URLs.
"""

# 3rd party imports
#
from allauth.account.views import EmailView
from django.urls import reverse_lazy


####################################################################
#
class AccountInfoView(EmailView):
    """
    Account Info page wrapping allauth's email management.

    Uses our crispy-bulma template and posts back to this view's URL
    rather than allauth's default 'account_email' URL.
    """

    template_name = "as_email/account_info.html"
    success_url = reverse_lazy("as_email:account_info")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ea = ctx.get("current_emailaddress")
        ctx["current_email_str"] = ea.email if ea else ""
        return ctx
