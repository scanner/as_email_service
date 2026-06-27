#!/usr/bin/env python
#
"""Service-layer tests for user invitations."""

# system imports
#
from collections.abc import Callable
from datetime import timedelta
from unittest.mock import Mock

# 3rd party imports
#
import pytest
from allauth.account.models import EmailAddress
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from faker import Faker

# Project imports
#
from users.invitation import (
    InvitationAlreadyAcceptedError,
    InvitationCancelledError,
    InvitationError,
    InvitationExpiredError,
    InvitationResendCooldownError,
    InvitationResendLimitError,
    InvitationWindowCapError,
    accept_user_invitation,
    cancel_user_invitation,
    create_user_invitation,
    resend_user_invitation,
    window_count,
)
from users.models import UserInvitation

pytestmark = pytest.mark.django_db

User = get_user_model()


########################################################################
# Module-level fixtures shared across test classes
########################################################################
#
@pytest.fixture
def fake_request(user_factory: Callable) -> Mock:
    """Mock request with build_absolute_uri and an authenticated user."""
    user = user_factory()
    user.save()
    req = Mock()
    req.user = user
    req.META = {"SERVER_NAME": "testserver", "SERVER_PORT": "443"}
    req.build_absolute_uri.side_effect = lambda p: f"https://testserver{p}"
    return req


@pytest.fixture
def pending_invitation(fake_request, faker: Faker) -> UserInvitation:
    """A fresh pending invitation with a 7-day window, ready for service calls."""
    invitee = User.objects.create_user(
        username=faker.user_name(), email=faker.email(), is_active=False
    )
    return UserInvitation.objects.create(
        invited_by=fake_request.user,
        invitee_email=invitee.email,
        invitee_user=invitee,
        token=faker.uuid4(),
        status=UserInvitation.Status.PENDING,
        expires_at=timezone.now() + timedelta(days=7),
        send_count=1,
        last_sent_at=timezone.now() - timedelta(hours=2),
    )


########################################################################
########################################################################
#
class TestWindowCount:
    """Tests for the window_count helper."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "status,expected_count",
        [
            (UserInvitation.Status.PENDING, 1),
            (UserInvitation.Status.ACCEPTED, 1),
            (UserInvitation.Status.EXPIRED, 1),
            (UserInvitation.Status.RESET_SENT, 1),
            (UserInvitation.Status.CANCELLED, 0),
        ],
        ids=["pending", "accepted", "expired", "reset_sent", "cancelled"],
    )
    def test_window_count_by_status(
        self,
        fake_request,
        faker: Faker,
        status: str,
        expected_count: int,
    ) -> None:
        """
        GIVEN: a single invitation in a given status
        WHEN:  window_count is called for its email
        THEN:  CANCELLED invitations are excluded; all others count
        """
        email = faker.email()
        UserInvitation.objects.create(
            invited_by=fake_request.user,
            invitee_email=email,
            token=faker.uuid4(),
            status=status,
            expires_at=timezone.now() + timedelta(days=7),
        )
        assert window_count(email) == expected_count


########################################################################
########################################################################
#
class TestCreateUserInvitation:
    """Tests for create_user_invitation."""

    ####################################################################
    #
    def test_creates_invitation_and_sends_email(
        self,
        fake_request,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a username that does not yet exist
        WHEN:  create_user_invitation is called with that username and an email
        THEN:  a PENDING UserInvitation is created and an inactive placeholder
               user is created with the given username
        """
        username = faker.user_name()
        email = faker.email()
        inv = create_user_invitation(
            fake_request.user, username, fake_request, invitee_email=email
        )

        assert inv.status == UserInvitation.Status.PENDING
        assert inv.invitee_email == email.lower()
        assert inv.send_count == 1
        assert inv.invitee_user is not None
        assert not inv.invitee_user.is_active
        assert inv.invitee_user.username == username

    ####################################################################
    #
    def test_existing_user_gets_reset_sent_invitation(
        self,
        fake_request,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a username that already belongs to an existing user
        WHEN:  create_user_invitation is called with that username
        THEN:  a RESET_SENT invitation is created and linked to the existing
               user; send_count is 1
        """
        existing = user_factory(email=faker.email())

        inv = create_user_invitation(
            fake_request.user, existing.username, fake_request
        )

        assert inv.status == UserInvitation.Status.RESET_SENT
        assert inv.invitee_user == existing
        assert inv.send_count == 1

    ####################################################################
    #
    def test_existing_user_email_used_regardless_of_supplied_email(
        self,
        fake_request,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a username that already exists
        WHEN:  create_user_invitation is called and an email is also supplied
        THEN:  the invitation uses the existing user's registered email, not
               the supplied one
        """
        existing = user_factory(email=faker.email())

        inv = create_user_invitation(
            fake_request.user,
            existing.username,
            fake_request,
            invitee_email="ignored@example.com",
        )

        assert inv.invitee_email == existing.email.lower()

    ####################################################################
    #
    def test_raises_when_email_missing_for_new_user(
        self,
        fake_request,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a username that does not exist and no email provided
        WHEN:  create_user_invitation is called
        THEN:  InvitationError is raised before any user is created
        """
        username = faker.user_name()

        with pytest.raises(InvitationError, match="email address is required"):
            create_user_invitation(fake_request.user, username, fake_request)

        assert not User.objects.filter(username=username).exists()

    ####################################################################
    #
    def test_raises_window_cap(self, fake_request, faker: Faker) -> None:
        """
        GIVEN: INVITATION_MAX_PER_WINDOW invitations already sent to one address
        WHEN:  another invitation is attempted for the same email
        THEN:  InvitationWindowCapError is raised
        """
        email = faker.email()
        for i in range(settings.INVITATION_MAX_PER_WINDOW):
            create_user_invitation(
                fake_request.user,
                f"windowtestuser{i}",
                fake_request,
                invitee_email=email,
            )

        with pytest.raises(InvitationWindowCapError):
            create_user_invitation(
                fake_request.user,
                "windowtestuserextra",
                fake_request,
                invitee_email=email,
            )


########################################################################
########################################################################
#
class TestCancelUserInvitation:
    """Tests for cancel_user_invitation."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "bad_status,expected_error",
        [
            (UserInvitation.Status.ACCEPTED, InvitationAlreadyAcceptedError),
            (UserInvitation.Status.CANCELLED, InvitationCancelledError),
        ],
        ids=["already-accepted", "already-cancelled"],
    )
    def test_cancel_raises_when_not_allowed(
        self,
        pending_invitation: UserInvitation,
        bad_status: str,
        expected_error: type,
    ) -> None:
        """
        GIVEN: an invitation in a terminal status
        WHEN:  cancel is called
        THEN:  the appropriate error is raised and the record is unchanged
        """
        pending_invitation.status = bad_status
        pending_invitation.save()

        with pytest.raises(expected_error):
            cancel_user_invitation(pending_invitation)

    ####################################################################
    #
    def test_cancel_sets_status_and_timestamp(
        self, pending_invitation: UserInvitation
    ) -> None:
        """
        GIVEN: a pending invitation
        WHEN:  cancel_user_invitation is called
        THEN:  status is CANCELLED and cancelled_at is set
        """
        cancel_user_invitation(pending_invitation)
        pending_invitation.refresh_from_db()

        assert pending_invitation.status == UserInvitation.Status.CANCELLED
        assert pending_invitation.cancelled_at is not None

    ####################################################################
    #
    def test_cancel_reset_sent_invitation(
        self, pending_invitation: UserInvitation
    ) -> None:
        """
        GIVEN: a RESET_SENT invitation
        WHEN:  cancel_user_invitation is called
        THEN:  the invitation is cancelled (prevents future resends)
        """
        pending_invitation.status = UserInvitation.Status.RESET_SENT
        pending_invitation.save()

        cancel_user_invitation(pending_invitation)
        pending_invitation.refresh_from_db()

        assert pending_invitation.status == UserInvitation.Status.CANCELLED


########################################################################
########################################################################
#
class TestResendUserInvitation:
    """Tests for resend_user_invitation."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "mutate,expected_error",
        [
            ("accepted", InvitationAlreadyAcceptedError),
            ("cancelled", InvitationCancelledError),
            ("expired", InvitationExpiredError),
            ("max_resends", InvitationResendLimitError),
            ("cooldown", InvitationResendCooldownError),
        ],
        ids=["accepted", "cancelled", "expired", "max-resends", "cooldown"],
    )
    def test_resend_pending_raises_when_not_allowed(
        self,
        pending_invitation: UserInvitation,
        fake_request,
        mutate: str,
        expected_error: type,
    ) -> None:
        """
        GIVEN: a PENDING invitation in a state that blocks resending
        WHEN:  resend_user_invitation is called
        THEN:  the appropriate guard error is raised
        """
        match mutate:
            case "accepted":
                pending_invitation.status = UserInvitation.Status.ACCEPTED
            case "cancelled":
                pending_invitation.status = UserInvitation.Status.CANCELLED
            case "expired":
                pending_invitation.expires_at = timezone.now() - timedelta(
                    days=1
                )
            case "max_resends":
                pending_invitation.send_count = (
                    settings.INVITATION_MAX_RESENDS + 1
                )
            case "cooldown":
                pending_invitation.last_sent_at = timezone.now()
        pending_invitation.save()

        with pytest.raises(expected_error):
            resend_user_invitation(pending_invitation, fake_request)

    ####################################################################
    #
    def test_resend_increments_send_count(
        self,
        pending_invitation: UserInvitation,
        fake_request,
    ) -> None:
        """
        GIVEN: a valid PENDING invitation past its cooldown
        WHEN:  resend_user_invitation is called
        THEN:  send_count is incremented and last_sent_at is updated
        """
        before = pending_invitation.send_count

        resend_user_invitation(pending_invitation, fake_request)

        pending_invitation.refresh_from_db()
        assert pending_invitation.send_count == before + 1
        assert pending_invitation.last_sent_at is not None

    ####################################################################
    #
    def test_resend_reset_sent_increments_send_count(
        self,
        pending_invitation: UserInvitation,
        fake_request,
    ) -> None:
        """
        GIVEN: a valid RESET_SENT invitation past its cooldown
        WHEN:  resend_user_invitation is called
        THEN:  send_count is incremented (a fresh admin reset email is sent)
        """
        pending_invitation.status = UserInvitation.Status.RESET_SENT
        pending_invitation.save()
        before = pending_invitation.send_count

        resend_user_invitation(pending_invitation, fake_request)

        pending_invitation.refresh_from_db()
        assert pending_invitation.send_count == before + 1

    ####################################################################
    #
    def test_resend_reset_sent_ignores_expiry(
        self,
        pending_invitation: UserInvitation,
        fake_request,
    ) -> None:
        """
        GIVEN: a RESET_SENT invitation whose expires_at is in the past
        WHEN:  resend_user_invitation is called
        THEN:  no InvitationExpiredError is raised (expiry only blocks PENDING)
        """
        pending_invitation.status = UserInvitation.Status.RESET_SENT
        pending_invitation.expires_at = timezone.now() - timedelta(days=1)
        pending_invitation.save()

        # Should not raise.
        resend_user_invitation(pending_invitation, fake_request)


########################################################################
########################################################################
#
class TestAcceptUserInvitation:
    """Tests for accept_user_invitation."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "mutate,expected_error",
        [
            ("accepted", InvitationAlreadyAcceptedError),
            ("cancelled", InvitationCancelledError),
            ("expired", InvitationExpiredError),
            ("reset_sent", InvitationError),
        ],
        ids=["already-accepted", "cancelled", "expired", "reset-sent"],
    )
    def test_accept_raises_when_not_allowed(
        self,
        pending_invitation: UserInvitation,
        fake_request,
        mutate: str,
        expected_error: type,
    ) -> None:
        """
        GIVEN: an invitation that cannot be accepted
        WHEN:  accept_user_invitation is called
        THEN:  the appropriate error is raised
        """
        match mutate:
            case "accepted":
                pending_invitation.status = UserInvitation.Status.ACCEPTED
            case "cancelled":
                pending_invitation.status = UserInvitation.Status.CANCELLED
            case "expired":
                pending_invitation.expires_at = timezone.now() - timedelta(
                    days=1
                )
            case "reset_sent":
                pending_invitation.status = UserInvitation.Status.RESET_SENT
        pending_invitation.save()

        with pytest.raises(expected_error):
            accept_user_invitation(pending_invitation, fake_request)

    ####################################################################
    #
    def test_accept_activates_user_creates_ea_and_marks_accepted(
        self,
        pending_invitation: UserInvitation,
        fake_request,
    ) -> None:
        """
        GIVEN: a valid pending invitation for an inactive placeholder user
        WHEN:  accept_user_invitation is called
        THEN:  the invitee user is activated, a verified primary EmailAddress
               is created, and the invitation is marked accepted with a timestamp
        """
        assert pending_invitation.invitee_user is not None
        user = pending_invitation.invitee_user

        accept_user_invitation(pending_invitation, fake_request)

        user.refresh_from_db()
        pending_invitation.refresh_from_db()

        assert user.is_active
        assert pending_invitation.status == UserInvitation.Status.ACCEPTED
        assert pending_invitation.accepted_at is not None
        assert EmailAddress.objects.filter(
            user=user,
            email=pending_invitation.invitee_email,
            primary=True,
            verified=True,
        ).exists()

    ####################################################################
    #
    def test_accept_already_active_user_marks_accepted(
        self,
        fake_request,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a PENDING invitation linked to an already-active user
              (e.g. created directly rather than via the service layer)
        WHEN:  accept_user_invitation is called
        THEN:  the invitation is marked accepted, the user stays active,
               and a verified EmailAddress record is ensured
        """
        email = faker.email()
        active_user = user_factory(email=email)
        active_user.is_active = True
        active_user.save()

        invitation = UserInvitation.objects.create(
            invited_by=fake_request.user,
            invitee_email=email,
            invitee_user=active_user,
            token=faker.uuid4(),
            status=UserInvitation.Status.PENDING,
            expires_at=timezone.now() + timedelta(days=7),
            send_count=1,
            last_sent_at=timezone.now() - timedelta(hours=2),
        )

        accept_user_invitation(invitation, fake_request)

        active_user.refresh_from_db()
        invitation.refresh_from_db()

        assert active_user.is_active
        assert invitation.status == UserInvitation.Status.ACCEPTED
        assert invitation.accepted_at is not None
        assert EmailAddress.objects.filter(
            user=active_user,
            email=email,
            primary=True,
            verified=True,
        ).exists()
