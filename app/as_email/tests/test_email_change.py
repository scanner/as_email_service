#!/usr/bin/env python
#
"""
Tests for the Account Info page and email change flow.

Covers: Account Info page rendering, email change via allauth, and the
old-address security notification that fires when an email change is confirmed.
"""

# system imports
#
import re
from collections.abc import Callable
from urllib.parse import urlparse

# 3rd party imports
#
import pytest
from django.core import mail
from django.test import Client
from django.urls import reverse
from faker import Faker

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
        from allauth.account.models import EmailAddress

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

        # Submit new email; allauth sends verification to new address
        client.post(
            reverse("as_email:account_info"),
            {"email": new_email, "action_add": ""},
        )
        assert len(mail.outbox) == 1, (
            "Expected verification email to new address"
        )
        assert new_email in mail.outbox[0].to
        body = str(mail.outbox[0].body)
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
