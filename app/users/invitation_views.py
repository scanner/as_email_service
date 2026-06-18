#!/usr/bin/env python
#
"""
Acceptance view for user invitations.

No login required -- the token is the authentication.
"""

# system imports
#
import logging

# 3rd party imports
#
from django.shortcuts import render
from django.views import View

# Project imports
#
from .invitation import (
    InvitationAlreadyAcceptedError,
    InvitationCancelledError,
    InvitationError,
    InvitationExpiredError,
    accept_user_invitation,
)
from .models import UserInvitation

logger = logging.getLogger("users.invitation_views")


########################################################################
########################################################################
#
class AcceptInvitationView(View):
    """
    GET  -- render the acceptance page (email shown read-only, Accept button)
    POST -- accept the invitation and redirect to a success page

    States shown by the template:
    - 'confirm'  -- valid invitation, waiting for user to click Accept
    - 'accepted' -- just accepted; password-reset email on its way
    - 'invalid'  -- expired, cancelled, already used, or token not found
    """

    template_name = "registration/user_invitation.html"

    ####################################################################
    #
    def _get_invitation(self, token: str) -> UserInvitation | None:
        try:
            return UserInvitation.objects.select_related("invitee_user").get(
                token=token
            )
        except UserInvitation.DoesNotExist:
            return None

    ####################################################################
    #
    def get(self, request, token: str):
        invitation = self._get_invitation(token)
        if invitation is None or not invitation.is_usable:
            return render(
                request,
                self.template_name,
                {"state": "invalid", "invitation": invitation},
            )
        return render(
            request,
            self.template_name,
            {"state": "confirm", "invitation": invitation},
        )

    ####################################################################
    #
    def post(self, request, token: str):
        invitation = self._get_invitation(token)
        if invitation is None:
            return render(
                request,
                self.template_name,
                {"state": "invalid", "invitation": None},
            )
        try:
            accept_user_invitation(invitation, request)
        except InvitationAlreadyAcceptedError:
            return render(
                request,
                self.template_name,
                {
                    "state": "invalid",
                    "invitation": invitation,
                    "already_accepted": True,
                },
            )
        except (
            InvitationExpiredError,
            InvitationCancelledError,
            InvitationError,
        ):
            return render(
                request,
                self.template_name,
                {"state": "invalid", "invitation": invitation},
            )
        return render(
            request,
            self.template_name,
            {"state": "accepted", "invitation": invitation},
        )
