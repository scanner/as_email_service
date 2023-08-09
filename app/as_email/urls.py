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
    hook_bounce,
    hook_incoming,
    hook_spam,
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
        "hook/incoming/<str:domain_name>/",
        hook_incoming,
        name="hook_incoming",
    ),
    path("hook/bounce/<str:domain_name>/", hook_bounce, name="hook_bounce"),
    path("hook/spam/<str:domain_name>/", hook_spam, name="hook_spam"),
]
