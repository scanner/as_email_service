#!/usr/bin/env python
#
"""View tests for the invitation acceptance page."""

# system imports
#
from collections.abc import Callable
from datetime import timedelta

# 3rd party imports
#
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from faker import Faker

# Project imports
#
from users.models import UserInvitation

pytestmark = pytest.mark.django_db

User = get_user_model()


########################################################################
# Shared fixture
########################################################################
#
@pytest.fixture
def invitation(user_factory: Callable, faker: Faker) -> UserInvitation:
    """A pending invitation with a 7-day window."""
    admin = user_factory()
    admin.save()
    invitee = User.objects.create_user(
        username=faker.user_name(), email=faker.email(), is_active=False
    )
    return UserInvitation.objects.create(
        invited_by=admin,
        invitee_email=invitee.email,
        invitee_user=invitee,
        token=faker.uuid4(),
        status=UserInvitation.Status.PENDING,
        expires_at=timezone.now() + timedelta(days=7),
    )


########################################################################
########################################################################
#
class TestAcceptInvitationView:
    """Tests for AcceptInvitationView (GET and POST)."""

    ####################################################################
    #
    def test_get_valid_shows_confirm_page(
        self, client: Client, invitation: UserInvitation
    ) -> None:
        """
        GIVEN: a valid pending invitation
        WHEN:  GET /invitations/user/<token>/
        THEN:  200 with the email and Accept button visible
        """
        resp = client.get(
            reverse("users:accept_invitation", args=[invitation.token])
        )
        assert resp.status_code == 200
        assert invitation.invitee_email.encode() in resp.content
        assert b"Accept Invitation" in resp.content

    ####################################################################
    #
    def test_post_valid_activates_user(
        self, client: Client, invitation: UserInvitation
    ) -> None:
        """
        GIVEN: a valid pending invitation
        WHEN:  POST /invitations/user/<token>/
        THEN:  200 with success content; the invitee user is now active
        """
        resp = client.post(
            reverse("users:accept_invitation", args=[invitation.token])
        )
        assert resp.status_code == 200
        assert b"accepted" in resp.content.lower()

        assert invitation.invitee_user is not None
        invitation.invitee_user.refresh_from_db()
        assert invitation.invitee_user.is_active

    ####################################################################
    #
    @pytest.mark.parametrize(
        "make_invalid",
        [
            "bad_token",
            "expired",
            "cancelled",
            "accepted",
            "reset_sent",
        ],
        ids=[
            "bad-token",
            "expired",
            "cancelled",
            "already-accepted",
            "reset-sent",
        ],
    )
    def test_invalid_invitation_shows_error(
        self,
        client: Client,
        invitation: UserInvitation,
        make_invalid: str,
    ) -> None:
        """
        GIVEN: an invitation that is not usable (wrong token, expired, cancelled,
               or already accepted) for both GET and POST
        WHEN:  GET or POST to the invitation URL
        THEN:  200 with the invalid/expired message shown
        """
        match make_invalid:
            case "expired":
                invitation.expires_at = timezone.now() - timedelta(days=1)
                invitation.save()
                token = invitation.token
            case "cancelled":
                invitation.status = UserInvitation.Status.CANCELLED
                invitation.save()
                token = invitation.token
            case "accepted":
                invitation.status = UserInvitation.Status.ACCEPTED
                invitation.save()
                token = invitation.token
            case "reset_sent":
                invitation.status = UserInvitation.Status.RESET_SENT
                invitation.save()
                token = invitation.token
            case "bad_token":
                token = "no-such-token"

        for method in ("get", "post"):
            resp = getattr(client, method)(
                reverse("users:accept_invitation", args=[token])
            )
            assert resp.status_code == 200
            assert b"Accept Invitation" not in resp.content
