#!/usr/bin/env python
#
"""
URLS for the AS Email app
"""
# 3rd party imports
#
from django.urls import include, path
from rest_framework_nested import routers

# Project imports
#
from .views import (
    EmailAccountViewSet,
    MessageFilterRuleViewSet,
    hook_bounce,
    hook_forward_valid,
    hook_incoming,
    hook_spam,
    index,
)

###########
# generate:
#  /email_accounts/
#  /email_accounts/{pk}/
#
api_router = routers.DefaultRouter()
api_router.register(
    r"email_accounts",
    EmailAccountViewSet,
    basename="email-account",
)

###########
# generate:
#  /email_accounts/{pk}/message_filter_rules/
#  /email_accounts/{pk}/message_filter_rules/{pk}/
#
api_email_account_router = routers.NestedSimpleRouter(
    api_router, r"email_accounts", lookup="email_account"
)

api_email_account_router.register(
    r"message_filter_rules",
    MessageFilterRuleViewSet,
    basename="message-filter-rule",
)

api_urls = api_router.urls + api_email_account_router.urls

app_name = "as_email"
urlpatterns = [
    path("", index, name="index"),
    path("api/v1/", include(api_urls)),
    # Generic webhook handlers - work with any provider
    # Existing Postmark webhooks at hook/postmark/* will continue to work
    #
    path(
        "hook/<str:provider_name>/incoming/<str:domain_name>/",
        hook_incoming,
        name="hook_incoming",
    ),
    path(
        "hook/<str:provider_name>/bounce/<str:domain_name>/",
        hook_bounce,
        name="hook_bounce",
    ),
    path(
        "hook/<str:provider_name>/spam/<str:domain_name>/",
        hook_spam,
        name="hook_spam",
    ),
    # We want to have a way to validate forwarding addresses. When the user
    # tries to setup a forward we give an action that sends a test message to
    # the forwarded address. This test message contains a link back to this
    # endpoint. If the user clicks on the link and goes back here that
    # indicates that the forwarded message was sent and received properly and
    # we can let this be a valid forwarding address.
    #
    path("hook/forward_valid/", hook_forward_valid, name="hook_forward_valid"),
]
