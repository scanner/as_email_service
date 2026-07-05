#!/usr/bin/env python
#
"""
Tests for allauth-based authentication flows.

Covers login/logout, password change, password reset, and the signup
block that prevents self-registration.
"""

# system imports
#
from collections.abc import Callable

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
class TestLogin:
    """Tests for the allauth login view."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "wrong_password,expected_status",
        [(False, 302), (True, 200)],
        ids=["valid_credentials", "wrong_password"],
    )
    def test_login(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
        wrong_password: bool,
        expected_status: int,
    ) -> None:
        """
        GIVEN: a user posting credentials
        WHEN:  the password is correct or wrong
        THEN:  correct → redirect (302), wrong → form re-rendered (200)
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()

        submitted = "wrongpassword" if wrong_password else password
        url = reverse("account_login")
        resp = client.post(url, {"login": user.username, "password": submitted})
        assert resp.status_code == expected_status

    ####################################################################
    #
    def test_login_without_next_param_redirects_to_home_page(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: a login page visited with no `next` query param
        WHEN:  the login form is rendered and then submitted with valid
               credentials
        THEN:  the hidden `next` field is absent (not the literal string
               "None"), and the login redirect chain lands on the app's
               home page rather than a broken intermediate URL
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()

        url = reverse("account_login")
        get_resp = client.get(url)
        assert b'value="None"' not in get_resp.content

        resp = client.post(
            url,
            {"login": user.username, "password": password},
            follow=True,
        )
        assert resp.status_code == 200
        assert resp.redirect_chain[-1][0] == reverse("as_email:index")


########################################################################
########################################################################
#
class TestLogout:
    """Tests for the allauth logout view."""

    ####################################################################
    #
    def test_logout_page_renders(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: an authenticated user
        WHEN:  GET /accounts/logout/
        THEN:  the logout confirmation template renders without error
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        client.login(username=user.username, password=password)

        resp = client.get(reverse("account_logout"))
        assert resp.status_code == 200
        assert b"Sign Out" in resp.content

    ####################################################################
    #
    def test_logout_clears_session(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: an authenticated user
        WHEN:  POST /accounts/logout/
        THEN:  the session is cleared; a subsequent visit to a protected
               page redirects to login
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        client.login(username=user.username, password=password)

        client.post(reverse("account_logout"))

        resp = client.get(reverse("as_email:index"))
        assert resp.status_code == 302
        assert "login" in resp["Location"]


########################################################################
########################################################################
#
class TestPasswordChange:
    """Tests for the allauth password change view."""

    ####################################################################
    #
    def test_password_change_page_renders(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: an authenticated user
        WHEN:  GET /accounts/password/change/
        THEN:  the password change template renders without error
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        client.login(username=user.username, password=password)

        resp = client.get(reverse("account_change_password"))
        assert resp.status_code == 200
        assert b"Change Password" in resp.content

    ####################################################################
    #
    def test_password_change_success(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
    ) -> None:
        """
        GIVEN: an authenticated user submitting their old and new passwords
        WHEN:  POST /accounts/password/change/
        THEN:  the new password works and the old one does not
        """
        old_password = faker.pystr(min_chars=8, max_chars=32)
        new_password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=old_password)
        user.save()
        client.login(username=user.username, password=old_password)

        client.post(
            reverse("account_change_password"),
            {
                "oldpassword": old_password,
                "password1": new_password,
                "password2": new_password,
            },
        )

        client.logout()
        assert not client.login(username=user.username, password=old_password)
        assert client.login(username=user.username, password=new_password)


########################################################################
########################################################################
#
class TestPasswordReset:
    """Tests for the allauth password reset email flow."""

    ####################################################################
    #
    def test_password_reset_page_renders(self, client: Client) -> None:
        """
        GIVEN: any visitor
        WHEN:  GET /accounts/password/reset/
        THEN:  the password reset template renders without error
        """
        resp = client.get(reverse("account_reset_password"))
        assert resp.status_code == 200
        assert b"Password Reset" in resp.content

    ####################################################################
    #
    def test_password_reset_bad_key_renders(self, client: Client) -> None:
        """
        GIVEN: a malformed or expired reset key in the URL
        WHEN:  GET /accounts/password/reset/key/<junk>/
        THEN:  the token_fail branch of the template renders without error
        """
        resp = client.get(
            reverse(
                "account_reset_password_from_key",
                kwargs={"uidb36": "xx", "key": "bad-key"},
            )
        )
        assert resp.status_code == 200
        assert (
            b"invalid" in resp.content.lower() or b"Bad Token" in resp.content
        )

    ####################################################################
    #
    @pytest.mark.parametrize(
        "user_exists",
        [True, False],
        ids=["known_email", "unknown_email"],
    )
    def test_password_reset_always_sends_email(
        self,
        client: Client,
        user_factory: Callable,
        faker: Faker,
        user_exists: bool,
    ) -> None:
        """
        GIVEN: a POST to the password reset form
        WHEN:  the email belongs to a real account or is unknown
        THEN:  both cases redirect (302) and send exactly 1 email to the
               submitted address — ACCOUNT_PREVENT_ENUMERATION=True (the allauth
               default) means the response is identical either way
        """
        if user_exists:
            user = user_factory()
            user.email = faker.email()
            user.save()
            email_address = user.email
        else:
            email_address = faker.email()

        resp = client.post(
            reverse("account_reset_password"), {"email": email_address}
        )
        assert resp.status_code == 302
        assert len(mail.outbox) == 1
        assert email_address in mail.outbox[0].to


########################################################################
########################################################################
#
class TestSignupBlocked:
    """Tests that self-registration is disabled via NoSignupAccountAdapter."""

    ####################################################################
    #
    def test_signup_url_is_closed(self, client: Client) -> None:
        """
        GIVEN: the NoSignupAccountAdapter returns is_open_for_signup=False
        WHEN:  GET /accounts/signup/
        THEN:  allauth renders the signup-closed page; users cannot register
        """
        resp = client.get(reverse("account_signup"))
        assert resp.status_code == 200
        assert b"closed" in resp.content.lower()
