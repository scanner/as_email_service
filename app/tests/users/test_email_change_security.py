#!/usr/bin/env python
#
"""
Tests for email change security hardening.

Covers PendingEmailChange, EmailChangeCooldown, and the EmailChangeRevokeView
-- all of which are owned by the users app even though the view lives in
as_email.account_views.
"""

# system imports
#
from collections.abc import Callable
from datetime import timedelta

# 3rd party imports
#
import pytest
from allauth.account.models import EmailAddress
from django.core import mail
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from faker import Faker

# Project imports
#
from users.models import EmailChangeCooldown, PendingEmailChange

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestEmailChangeSecurity:
    """Tests for email change security hardening (PendingEmailChange, revocation, cooldown)."""

    ####################################################################
    #
    @pytest.fixture
    def user_with_verified_email(
        self, user_factory: Callable, faker: Faker
    ) -> tuple:
        """User with a verified primary EmailAddress, ready for email change testing."""
        password = faker.pystr(min_chars=8, max_chars=32)
        old_email = faker.email()
        user = user_factory(password=password)
        user.email = old_email
        user.save()
        EmailAddress.objects.create(
            user=user, email=old_email, primary=True, verified=True
        )
        return user, password, old_email

    ####################################################################
    #
    def test_email_change_request_creates_pending_and_notifies(
        self,
        client: Client,
        user_with_verified_email: tuple,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a user with a verified primary email
        WHEN:  they submit a new email address on Account Info
        THEN:  a PendingEmailChange record is created and a pre-confirmation
               notification with a revocation link is sent to the old address
        """
        user, password, old_email = user_with_verified_email
        new_email = "new_" + faker.email()
        client.login(username=user.username, password=password)

        client.post(
            reverse("as_email:account_info"),
            {"email": new_email, "action_add": ""},
        )

        pending = PendingEmailChange.objects.get(user=user)
        assert pending.new_email == new_email

        notification = next((m for m in mail.outbox if old_email in m.to), None)
        assert notification is not None, f"No notification to {old_email!r}"
        revoke_url = reverse(
            "as_email:email_change_revoke", args=[pending.revocation_key]
        )
        assert revoke_url in notification.body

    ####################################################################
    #
    @pytest.mark.parametrize(
        "method,expect_records_present,content_fragment",
        [
            ("get", True, b"Cancel the Email Change"),
            ("post", False, b"cancelled"),
        ],
        ids=["get-shows-confirm", "post-performs-revoke"],
    )
    def test_revoke_valid_key(
        self,
        client: Client,
        user_with_verified_email: tuple,
        faker: Faker,
        method: str,
        expect_records_present: bool,
        content_fragment: bytes,
    ) -> None:
        """
        GIVEN: a valid revocation key for a pending email change
        WHEN:  GET -> renders confirmation page without mutating;
               POST -> deletes PendingEmailChange and pending EmailAddress
        THEN:  200 with appropriate content; records present/absent as expected
        """
        user, _password, _old_email = user_with_verified_email
        new_email = "new_" + faker.email()
        pending = PendingEmailChange.create_for_user(user, new_email)
        EmailAddress.objects.create(
            user=user, email=new_email, primary=False, verified=False
        )

        resp = getattr(client, method)(
            reverse(
                "as_email:email_change_revoke", args=[pending.revocation_key]
            )
        )

        assert resp.status_code == 200
        assert content_fragment in resp.content
        assert (
            PendingEmailChange.objects.filter(user=user).exists()
            == expect_records_present
        )
        assert (
            EmailAddress.objects.filter(
                user=user, email=new_email, verified=False
            ).exists()
            == expect_records_present
        )

    ####################################################################
    #
    @pytest.mark.parametrize("method", ["get", "post"], ids=["get", "post"])
    def test_revoke_invalid_key(self, client: Client, method: str) -> None:
        """
        GIVEN: an invalid or already-used revocation key
        WHEN:  GET or POST to the revocation URL
        THEN:  200 with the "expired or already used" message
        """
        resp = getattr(client, method)(
            reverse("as_email:email_change_revoke", args=["no-such-key"])
        )
        assert resp.status_code == 200
        assert b"expired" in resp.content.lower()

    ####################################################################
    #
    @pytest.mark.parametrize(
        "days_offset,expect_blocked",
        [(5, True), (-1, False)],
        ids=["active-cooldown", "expired-cooldown"],
    )
    def test_cooldown_page_rendering(
        self,
        client: Client,
        user_with_verified_email: tuple,
        days_offset: int,
        expect_blocked: bool,
    ) -> None:
        """
        GIVEN: a user with an active or expired EmailChangeCooldown
        WHEN:  they view Account Info
        THEN:  active -> cooldown notice shown, record still present;
               expired -> notice absent, stale record auto-deleted;
               the current email address is visible either way
        """
        user, password, old_email = user_with_verified_email
        EmailChangeCooldown.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(days=days_offset),
        )
        client.login(username=user.username, password=password)

        resp = client.get(reverse("as_email:account_info"))

        assert resp.status_code == 200
        assert (b"blocked until" in resp.content) == expect_blocked
        assert (
            EmailChangeCooldown.objects.filter(user=user).exists()
            == expect_blocked
        )
        assert old_email.encode() in resp.content

    ####################################################################
    #
    def test_active_cooldown_blocks_post(
        self,
        client: Client,
        user_with_verified_email: tuple,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a user with an active EmailChangeCooldown who bypasses the UI
        WHEN:  they POST a new email to Account Info directly
        THEN:  the server-side guard rejects it and no PendingEmailChange is created
        """
        user, password, _old_email = user_with_verified_email
        EmailChangeCooldown.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(days=5),
        )
        client.login(username=user.username, password=password)

        resp = client.post(
            reverse("as_email:account_info"),
            {"email": "new_" + faker.email(), "action_add": ""},
        )

        assert resp.status_code == 200
        assert b"blocked until" in resp.content
        assert not PendingEmailChange.objects.filter(user=user).exists()
