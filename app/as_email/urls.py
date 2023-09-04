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
    BlockedMessageViewSet,
    EmailAccountViewSet,
    MessageFilterRuleViewSet,
    hook_forward_valid,
    hook_postmark_bounce,
    hook_postmark_incoming,
    hook_postmark_spam,
    index,
)

###########
# generate:
#  /email_accounts/
#  /email_accounts/{pk}/
#
router = routers.DefaultRouter()
router.register(
    r"email_accounts",
    EmailAccountViewSet,
    basename="email_accounts",
)

###########
# generate:
#  /email_accounts/{pk}/blocked_messages/
#  /email_accounts/{pk}/blocked_messages/{pk}/
#  /email_accounts/{pk}/message_filter_rules/
#  /email_accounts/{pk}/message_filter_rules/{pk}/
#
email_account_router = routers.NestedSimpleRouter(
    router, r"email_accounts", lookup="email_account"
)
email_account_router.register(
    r"blocked_messages", BlockedMessageViewSet, basename="blocked_messages"
)
email_account_router.register(
    r"message_filter_rules",
    MessageFilterRuleViewSet,
    basename="message_filter_rules",
)

app_name = "as_email"
urlpatterns = [
    path("", index, name="index"),
    path("api/v1", include(router.urls)),
    path("api/v1", include(email_account_router.urls)),
    path(
        "hook/postmark/incoming/<str:domain_name>/",
        hook_postmark_incoming,
        name="hook_postmark_incoming",
    ),
    path(
        "hook/postmark/bounce/<str:domain_name>/",
        hook_postmark_bounce,
        name="hook_postmark_bounce",
    ),
    path(
        "hook/postmark/spam/<str:domain_name>/",
        hook_postmark_spam,
        name="hook_postmark_spam",
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
