#!/usr/bin/env python
#
"""
URLS for the AS Email app
"""
# 3rd party imports
#
from django.urls import path

# Project imports
#
from . import views

app_name = "as_email"
urlpatterns = [
    path("", views.index, name="index"),
    path(
        "hook/incoming/<str:domain_name>/",
        views.hook_incoming,
        name="hook_incoming",
    ),
    path(
        "hook/bounce/<str:domain_name>/", views.hook_bounce, name="hook_bounce"
    ),
    path("hook/spam/<str:domain_name>/", views.hook_incoming, name="hook_spam"),
]
