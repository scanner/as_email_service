#!/usr/bin/env python
#
"""
Tests for the Account Info page, email change flow, password change, and
email change security hardening (PendingEmailChange, revocation, cooldown).
"""

# system imports
#
import re
from collections.abc import Callable
from datetime import timedelta
from urllib.parse import urlparse

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
class TestAccountInfo:
    """Tests for the Account Info page rendering and access control."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "do_login,expected_status",
        [(True, 200), (False, 302)],
        ids=["authenticated", "unauthenticated"],
    )
    def test_page_access(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
        do_login: bool,
        expected_status: int,
    ) -> None:
        """
        GIVEN: an authenticated or unauthenticated visitor
        WHEN:  GET /as_email/account/info/
        THEN:  authenticated -> 200 with username visible;
               unauthenticated -> redirect to login
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        if do_login:
            client.login(username=user.username, password=password)

        resp = client.get(reverse("as_email:account_info"))
        assert resp.status_code == expected_status
        if do_login:
            assert user.username.encode() in resp.content
            assert b"Account Info" in resp.content
        else:
            assert "login" in resp["Location"]


########################################################################
########################################################################
#
class TestEmailChange:
    """Tests for the email change flow via allauth."""

    ####################################################################
    #
    def test_email_change_notification_to_old_address(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a user with an existing email who submits a new email address
        WHEN:  they confirm via the verification link sent to the new address
        THEN:  allauth sends a security notification to the old address that
               includes a link to the contact page
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        old_email = faker.email()
        new_email = "new_" + faker.email()
        user = user_factory(password=password)
        user.email = old_email
        user.save()
        # Create old address as verified+primary so add_new_email's get_new()
        # (which filters on verified=False) does not delete it before confirm.
        EmailAddress.objects.create(
            user=user, email=old_email, primary=True, verified=True
        )
        client.login(username=user.username, password=password)

        # Submit new email; expect 2 outbound messages:
        # 1. our pre-confirmation notification to old address (on_email_added)
        # 2. allauth's verification email to new address
        client.post(
            reverse("as_email:account_info"),
            {"email": new_email, "action_add": ""},
        )
        verification_emails = [m for m in mail.outbox if new_email in m.to]
        assert len(verification_emails) == 1, (
            f"Expected exactly one verification email to {new_email!r}"
        )
        body = str(verification_emails[0].body)
        match = re.search(r"https?://\S+confirm-email/\S+", body)
        assert match, "No confirmation link found in verification email"
        confirm_path = urlparse(match.group(0).rstrip(".")).path

        mail.outbox.clear()

        # POST to the confirmation URL to actually confirm
        # (CONFIRM_EMAIL_ON_GET=False -- GET only renders the prompt page)
        resp = client.post(confirm_path)
        if resp.status_code == 302:
            client.get(resp["Location"])

        # Security notification must have gone to the old address
        notification_emails = [m for m in mail.outbox if old_email in m.to]
        assert notification_emails, (
            f"No email to old address {old_email!r}; outbox: {[m.to for m in mail.outbox]}"
        )
        assert "/as_email/contact/" in notification_emails[0].body


########################################################################
########################################################################
#
class TestAccountInfoPassword:
    """Tests for password change on the Account Info page."""

    ####################################################################
    #
    def test_password_change_succeeds(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a logged-in user with a known password
        WHEN:  they POST valid old+new password to account_info_password_change
        THEN:  they are redirected to Account Info and can log in with the new password
        """
        old_password = faker.pystr(min_chars=8, max_chars=32)
        new_password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=old_password)
        user.save()
        client.login(username=user.username, password=old_password)

        resp = client.post(
            reverse("as_email:account_info_password_change"),
            {
                "oldpassword": old_password,
                "password1": new_password,
                "password2": new_password,
            },
        )

        assert resp.status_code == 302
        assert reverse("as_email:account_info") in resp["Location"]
        # Verify the new password actually works
        client.logout()
        assert client.login(username=user.username, password=new_password)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "has_email,expect_link,expect_message",
        [
            (True, True, False),
            (False, False, True),
        ],
        ids=["with-email", "without-email"],
    )
    def test_forgot_password_display(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
        has_email: bool,
        expect_link: bool,
        expect_message: bool,
    ) -> None:
        """
        GIVEN: a user with or without a registered email address
        WHEN:  they view Account Info
        THEN:  with email -> forgot-password link is shown;
               without email -> explanatory message is shown, no link
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        if has_email:
            user.email = faker.email()
        user.save()
        if has_email:
            EmailAddress.objects.create(
                user=user, email=user.email, primary=True, verified=True
            )
        client.login(username=user.username, password=password)

        resp = client.get(reverse("as_email:account_info"))
        assert resp.status_code == 200

        forgot_url = reverse("account_reset_password").encode()
        no_email_msg = b"Add an email address above to enable it"

        assert (forgot_url in resp.content) == expect_link
        assert (no_email_msg in resp.content) == expect_message


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
               expired -> notice absent, stale record auto-deleted
        """
        user, password, _old_email = user_with_verified_email
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
