"""
URL configuration for as_email_service project.
"""

from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls, name="admin"),
    path(
        "accounts/",
        RedirectView.as_view(pattern_name="account_login", permanent=True),
        name="accounts",
    ),
    # Shadow allauth's stock email-management page so cooldown enforcement
    # in AccountInfoView is the only entry point for email changes.
    path(
        "accounts/email/",
        RedirectView.as_view(
            pattern_name="as_email:account_info", permanent=False
        ),
    ),
    path("accounts/", include("allauth.account.urls")),
    path(
        "",
        RedirectView.as_view(pattern_name="as_email:index", permanent=True),
        name="home",
    ),
    path("as_email/", include("as_email.urls")),
    path("", include("users.urls")),
]
