"""
URL configuration for as_email_service project.
"""

from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

from as_email.views import autoconfig_mail_config, autodiscover_config

urlpatterns = [
    path("admin/", admin.site.urls, name="admin"),
    # Autoconfig (Thunderbird/Evolution/KDE) and Autodiscover (Outlook) live
    # at well-known root paths, not under /as_email/ -- email clients expect
    # them here. See docs/autoconfig-autodiscover.md for the DNS/reverse-proxy
    # side of this.
    #
    path(
        "mail/config-v1.1.xml",
        autoconfig_mail_config,
        name="autoconfig",
    ),
    path(
        ".well-known/autoconfig/mail/config-v1.1.xml",
        autoconfig_mail_config,
        name="autoconfig_well_known",
    ),
    path(
        "autodiscover/autodiscover.xml",
        autodiscover_config,
        name="autodiscover",
    ),
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
