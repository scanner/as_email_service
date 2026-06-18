#!/usr/bin/env python
#
"""URL patterns for the users app."""

# 3rd party imports
#
from django.urls import path

# Project imports
#
from .invitation_views import AcceptInvitationView

app_name = "users"

urlpatterns = [
    path(
        "invitations/user/<str:token>/",
        AcceptInvitationView.as_view(),
        name="accept_invitation",
    ),
]
