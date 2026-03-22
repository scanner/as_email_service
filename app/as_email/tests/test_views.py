#!/usr/bin/env python
#
"""
Testing our views. Plain views, webhooks, and the REST interface.
"""

# system imports
#
import json
from urllib.parse import urlencode, urlparse

# 3rd party imports
#
import pytest
from dirty_equals import IsPartialDict
from django.http import JsonResponse
from django.urls import resolve, reverse
from faker import Faker

# Project imports
#
from ..models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
    ImapDelivery,
    LocalDelivery,
    MessageFilterRule,
)
from ..utils import redis_client

pytestmark = pytest.mark.django_db


####################################################################
#
@pytest.fixture
def mock_webhook_provider(mocker):
    """
    Factory fixture for mocking webhook provider backends.

    Returns a function that creates a mocked provider with a specified
    webhook handler method and mocks _get_provider_for_webhook to return it.

    Usage:
        mock_provider = mock_webhook_provider(
            "handle_incoming_webhook",
            JsonResponse({"status": "all good"})
        )
        # mock_provider.backend.handle_incoming_webhook is now set up
    """

    def _mock_provider(webhook_method: str, response):
        """
        Create a mocked provider with the specified webhook handler method.

        Args:
            webhook_method: Name of the webhook handler method to mock
                           (e.g., "handle_incoming_webhook")
            response: The response object to return from the mocked method

        Returns:
            The mock provider object with backend already configured
        """
        mock_provider = mocker.MagicMock()
        mock_provider.provider_name = "dummy"
        mock_backend = mocker.MagicMock()
        mock_provider.backend = mock_backend

        # Set the return value for the specified method
        getattr(mock_backend, webhook_method).return_value = response

        # Mock _get_provider_for_webhook to return our mock provider
        mocker.patch(
            "as_email.views._get_provider_for_webhook",
            return_value=mock_provider,
        )

        return mock_provider

    return _mock_provider


####################################################################
#
def _expected_for_email_account(ea: EmailAccount) -> dict:
    """
    Our tests need to compare a dict retrieved from the REST API with an
    EmailAccount object. This returns a partial dict of the provided
    EmailAccount such that it should match what we get back via the REST API
    when using IsPartialDict.
    """
    return {
        "deactivated": ea.deactivated,
        "deactivated_reason": ea.deactivated_reason,
        "email_address": ea.email_address,
        "enabled": ea.enabled,
        "num_bounces": ea.num_bounces,
        "owner": ea.owner.username,
        "server": ea.server.domain_name,
    }


####################################################################
#
def _expected_for_message_filter_rule(mfr: MessageFilterRule) -> dict:
    """
    Lots of tests see if the results we get back from the endpoint match
    what we expect in the actual mfr object.
    """
    expected = {
        "url": "http://testserver"
        + reverse(
            "as_email:message-filter-rule-detail",
            kwargs={
                "email_account_pk": mfr.email_account.pk,
                "pk": mfr.pk,
            },
        ),
        "email_account": "http://testserver"
        + reverse(
            "as_email:email-account-detail",
            kwargs={"pk": mfr.email_account.pk},
        ),
        "header": mfr.header,
        "pattern": mfr.pattern,
        "action": mfr.action,
        "destination": mfr.destination,
        "order": mfr.order,
    }
    return expected


####################################################################
#
@pytest.mark.parametrize("provider_name", ["postmark"])
def test_get_provider_for_webhook(
    provider_factory, server_factory, provider_name
):
    """
    Test that _get_provider_for_webhook correctly retrieves providers configured
    for a server's receive_providers.
    """
    from django.http import Http404

    from ..views import _get_provider_for_webhook

    # Create a provider with the specified backend name
    #
    provider = provider_factory(backend_name=provider_name)
    provider.save()

    # Create a server with this provider as a receive provider
    #
    server = server_factory(send_provider=provider)
    server.save()
    server.receive_providers.add(provider)

    # Should successfully retrieve the provider
    #
    retrieved_provider = _get_provider_for_webhook(server, provider_name)
    assert retrieved_provider == provider
    assert retrieved_provider.backend_name == provider_name

    # Should raise Http404 if provider is not in receive_providers
    #
    other_provider = provider_factory(backend_name="other_provider")
    other_provider.save()

    with pytest.raises(Http404) as exc_info:
        _get_provider_for_webhook(server, "other_provider")

    assert "not configured as a receive provider" in str(exc_info.value)


####################################################################
#
def test_index(api_client, user_factory, email_account_factory, faker):
    password = faker.pystr(min_chars=8, max_chars=32)
    user = user_factory(password=password)
    user.save()
    eas = []
    for _ in range(5):
        ea = email_account_factory(owner=user)
        ea.save()
        eas.append(ea)

    url = reverse("as_email:index")
    client = api_client()
    resp = client.get(url)
    assert resp.status_code == 302
    assert reverse("login") == urlparse(resp["Location"]).path

    resp = client.login(username=user.username, password=password)
    assert resp
    resp = client.get(url)
    assert resp.status_code == 200


####################################################################
#
def test_incoming_webhook(
    email_account_factory, api_client, faker, mock_webhook_provider
):
    """
    Test that the incoming webhook view correctly calls the provider backend's
    handle_incoming_webhook method with the correct arguments.
    """
    ea = email_account_factory()
    ea.save()
    server = ea.server

    # Mock the provider backend
    #
    expected_response = JsonResponse(
        {"status": "all good", "message": "test message"}
    )
    mock_provider = mock_webhook_provider(
        "handle_incoming_webhook", expected_response
    )

    incoming_message = {
        "OriginalRecipient": ea.email_address,
        "MessageID": "73e6d360-66eb-11e1-8e72-a8904824019b",
        "Date": "Fri, 1 Aug 2014 16:45:32 -04:00",
        "RawEmail": "test email content",
    }

    url = (
        reverse(
            "as_email:hook_incoming",
            kwargs={
                "provider_name": "dummy",
                "domain_name": server.domain_name,
            },
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    client = api_client()
    r = client.post(
        url, json.dumps(incoming_message), content_type="application/json"
    )

    # Verify the view returned the response from the provider backend
    #
    assert r.status_code == 200
    resp_data = r.json()
    assert resp_data["status"] == "all good"

    # Verify the provider backend's method was called with correct arguments
    #
    mock_provider.backend.handle_incoming_webhook.assert_called_once()
    call_args = mock_provider.backend.handle_incoming_webhook.call_args
    assert call_args[0][1] == server  # Second argument should be the server


####################################################################
#
def test_incoming_webhook_no_such_server(
    api_client,
    faker,
):
    domain_name = faker.domain_name()
    api_key = faker.pystr()
    addr = faker.email()
    incoming_message = {
        "OriginalRecipient": addr,
        "MessageID": "73e6d360-66eb-11e1-8e72-a8904824019b",
        "Date": "Fri, 1 Aug 2014 16:45:32 -04:00",
    }

    url = (
        reverse(
            "as_email:hook_incoming",
            kwargs={"provider_name": "dummy", "domain_name": domain_name},
        )
        + "?"
        + urlencode({"api_key": api_key})
    )

    client = api_client()
    r = client.post(
        url, json.dumps(incoming_message), content_type="application/json"
    )
    assert r.status_code == 404


####################################################################
#
def test_incoming_webhook_no_such_provider_backend(
    api_client,
    faker,
):
    domain_name = faker.domain_name()
    api_key = faker.pystr()
    addr = faker.email()
    incoming_message = {
        "OriginalRecipient": addr,
        "MessageID": "73e6d360-66eb-11e1-8e72-a8904824019b",
        "Date": "Fri, 1 Aug 2014 16:45:32 -04:00",
    }

    url = (
        reverse(
            "as_email:hook_incoming",
            kwargs={"provider_name": "foobar", "domain_name": domain_name},
        )
        + "?"
        + urlencode({"api_key": api_key})
    )

    client = api_client()
    r = client.post(
        url, json.dumps(incoming_message), content_type="application/json"
    )
    assert r.status_code == 404


####################################################################
#
def test_bounce_webhook(
    email_account_factory,
    api_client,
    faker,
    mock_webhook_provider,
):
    """
    Test that the bounce webhook view correctly calls the provider backend's
    handle_bounce_webhook method with the correct arguments.
    """
    ea = email_account_factory()
    ea.save()
    server = ea.server

    bounce_data = {
        "ID": 4323372036854775807,
        "Type": "HardBounce",
        "TypeCode": 1,
        "Name": "Hard bounce",
        "Tag": "Test",
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "ServerID": 23,
        "Description": "The server was unable to deliver your message",
        "Details": "Test bounce details",
        "Email": "john@example.com",
        "From": ea.email_address,
        "BouncedAt": "2014-08-01T13:28:10.2735393-04:00",
        "DumpAvailable": True,
        "Inactive": False,
        "CanActivate": True,
        "RecordType": "Bounce",
        "Subject": "Test subject",
    }

    # Mock the provider backend
    #
    expected_response = JsonResponse(
        {
            "status": "all good",
            "message": f"received bounce for {server.domain_name}/{ea.email_address}",
        }
    )
    mock_provider = mock_webhook_provider(
        "handle_bounce_webhook", expected_response
    )

    url = (
        reverse(
            "as_email:hook_bounce",
            kwargs={
                "provider_name": "postmark",
                "domain_name": server.domain_name,
            },
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    client = api_client()
    r = client.post(
        url, json.dumps(bounce_data), content_type="application/json"
    )

    # Verify the view returned the response from the provider backend
    #
    assert r.status_code == 200
    resp_data = r.json()
    assert "status" in resp_data
    assert resp_data["status"] == "all good"

    # Verify the provider backend's method was called with correct arguments
    #
    mock_provider.backend.handle_bounce_webhook.assert_called_once()
    call_args = mock_provider.backend.handle_bounce_webhook.call_args
    assert call_args[0][1] == server  # Second argument should be the server


####################################################################
#
def test_postmark_spam_webhook(
    email_account_factory,
    api_client,
    faker,
    mock_webhook_provider,
):
    """
    Test that the spam webhook view correctly calls the provider backend's
    handle_spam_webhook method with the correct arguments.
    """
    ea = email_account_factory()
    ea.save()
    server = ea.server
    to_addr = faker.email()

    spam_data = {
        "RecordType": "SpamComplaint",
        "MessageStream": "outbound",
        "ID": 42,
        "Type": "SpamComplaint",
        "TypeCode": 512,
        "Name": "Spam complaint",
        "Tag": "Test",
        "MessageID": "00000000-0000-0000-0000-000000000000",
        "Metadata": {"a_key": "a_value", "b_key": "b_value"},
        "ServerID": 1234,
        "Description": "Test spam complaint details",
        "Details": "Test spam complaint details",
        "Email": to_addr,
        "From": ea.email_address,
        "BouncedAt": "2019-11-05T16:33:54.9070259Z",
        "DumpAvailable": True,
        "Inactive": True,
        "CanActivate": False,
        "Subject": "Test subject",
        "Content": "<Abuse report dump>",
    }

    # Mock the provider backend
    #
    expected_response = JsonResponse(
        {
            "status": "all good",
            "message": f"received spam for {server.domain_name}/{ea.email_address}",
        }
    )
    mock_provider = mock_webhook_provider(
        "handle_spam_webhook", expected_response
    )

    url = (
        reverse(
            "as_email:hook_spam",
            kwargs={
                "provider_name": "postmark",
                "domain_name": server.domain_name,
            },
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    client = api_client()
    r = client.post(url, json.dumps(spam_data), content_type="application/json")

    # Verify the view returned the response from the provider backend
    #
    assert r.status_code == 200
    resp_data = r.json()
    assert "status" in resp_data
    assert resp_data["status"] == "all good"

    # Verify the provider backend's method was called with correct arguments
    #
    mock_provider.backend.handle_spam_webhook.assert_called_once()
    call_args = mock_provider.backend.handle_spam_webhook.call_args
    assert call_args[0][1] == server  # Second argument should be the server


########################################################################
########################################################################
#
class TestEmailAccountEndpoints:
    ####################################################################
    #
    @pytest.fixture(autouse=True, scope="function")
    def setup(self, api_client, user_factory, email_account_factory, faker):
        """
        Every test around the EmailAccount REST API needs a user we are
        testing against, several email accounts that belong to that user, and a
        bunch of other email accounts belonging to other users.
        """
        # The user and email account we are testing with..
        #
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        ea = email_account_factory(owner=user)
        ea.save()

        client = api_client()
        resp = client.login(username=user.username, password=password)
        assert resp

        # Other email accounts because we need to make sure the tests only see
        # `user's` email accounts.
        #
        for _ in range(5):
            email_account_factory()

        return {
            "password": password,
            "user": user,
            "email_account": ea,
            "client": client,
        }

    ####################################################################
    #
    def test_list(self, api_client, setup):
        url = reverse("as_email:email-account-list")
        client = api_client()
        resp = client.get(url)
        assert resp.status_code == 403

        ea = setup["email_account"]
        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200
        # There should be only one EmailAccount.
        #
        assert len(resp.data) == 1
        expected = _expected_for_email_account(ea)
        assert resp.data[0] == IsPartialDict(expected)

    ####################################################################
    #
    def test_create(self, api_client, faker, setup):
        """
        The REST API does not support creating users.
        """
        client = api_client()
        # There is no '-create' view. But to create a user one would normally
        # POST to the same url as `list`.
        #
        url = reverse("as_email:email-account-list")

        user = setup["user"]
        password = setup["password"]
        server = setup["email_account"].server

        data = {
            "owner": user.username,
            "server": server.domain_name,
            "email_address": faker.email(),
        }

        resp = client.post(url, data=data)
        assert resp.status_code == 403

        # Even if you authenticate you can not create an EmailAccount.
        #
        resp = client.login(username=user.username, password=password)
        assert resp
        resp = client.post(url, data=data)
        assert resp.status_code == 405

    ####################################################################
    #
    def test_retrieve(self, api_client, setup):
        client = api_client()
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        # Not logged in, no access.
        #
        resp = client.get(url)
        assert resp.status_code == 403

        # Change to logged in client
        #
        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

    ####################################################################
    #
    def test_update(self, setup):
        """
        All EmailAccount fields are read-only via the REST API. A PUT
        returns 200 but the account is unchanged (enabled is admin-only).
        """
        client = setup["client"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        # Attempt to change enabled — should be silently ignored
        #
        resp = client.put(url, data={"enabled": not ea.enabled}, format="json")
        assert resp.status_code == 200
        ea.refresh_from_db()
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

    ####################################################################
    #
    def test_update_readonly_fields(self, faker, setup):
        """
        All EmailAccount fields are read-only via the REST API. Attempting
        to change any of them via PUT should be silently ignored.
        """
        client = setup["client"]
        ea = setup["email_account"]
        orig_ea_data = _expected_for_email_account(ea)
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})
        attempt = {
            "deactivated": True,
            "deactivated_reason": "no reason. haha.",
            "email_address": "boogie@example.com",
            "enabled": not ea.enabled,
            "num_bounces": 2000,
            "owner": "john@example.com",
            "server": "blackhole.example.com",
        }
        resp = client.put(url, data=attempt, format="json")
        assert resp.status_code == 200
        ea.refresh_from_db()
        # All fields should be unchanged
        #
        assert _expected_for_email_account(ea) == orig_ea_data

    ####################################################################
    #
    def test_set_password(self, faker, setup):
        client = setup["client"]
        ea = setup["email_account"]
        new_password = faker.pystr(min_chars=8, max_chars=32)
        url = reverse(
            "as_email:email-account-set-password",
            kwargs={"pk": ea.pk},
        )
        post_data = {"password": new_password}
        resp = client.post(url, data=post_data)
        assert resp.status_code == 200
        ea.refresh_from_db()
        assert ea.check_password(new_password)

    ####################################################################
    #
    def test_partial_update(self, setup):
        """
        All EmailAccount fields are read-only via the REST API. A PATCH
        attempting to change any field should be silently ignored and
        return 200 with the unchanged account data.
        """
        client = setup["client"]
        ea = setup["email_account"]
        orig_ea_data = _expected_for_email_account(ea)
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        # Attempt to change enabled (admin-only) — ignored
        #
        resp = client.patch(
            url, data={"enabled": not ea.enabled}, format="json"
        )
        assert resp.status_code == 200
        ea.refresh_from_db()
        assert _expected_for_email_account(ea) == orig_ea_data

    ####################################################################
    #
    def test_partial_update_ro(
        self, api_client, faker, email_account_factory, setup
    ):
        """
        Make sure read-only fields are read-only.
        """
        client = setup["client"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        ro_fields = {
            "deactivated": not ea.deactivated,
            "deactivated_reason": "foo",
            "email_address": faker.email(),
            "num_bounces": 20,
        }

        for k, v in ro_fields.items():
            patch_data = {k: v}
            resp = client.patch(url, data=patch_data)
            assert resp.status_code == 200
            ea.refresh_from_db()
            assert getattr(ea, k) != v
            assert getattr(ea, k) == resp.data[k]

    ####################################################################
    #
    def test_delete(self, setup):
        """
        Can not delete EmailAccount's
        """
        client = setup["client"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        resp = client.delete(url)
        assert resp.status_code == 405

    ####################################################################
    #
    def test_options(self, setup):
        """
        Make sure that getting `options` for an EmailAccount works.
        """
        client = setup["client"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        resp = client.options(url)
        assert resp.status_code == 200

        # Verify that the `email_address` field is present in PUT options
        # and reported as read-only (all EmailAccount fields are read-only
        # via the API).
        #
        assert resp.data["actions"]["PUT"]["email_address"]["read_only"] is True


########################################################################
########################################################################
#
class TestMessageFilterRuleEndpoints:
    ####################################################################
    #
    @pytest.fixture(autouse=True, scope="function")
    def setup(
        self,
        api_client,
        user_factory,
        email_account_factory,
        message_filter_rule_factory,
        faker,
    ):
        """
        Every test around the EmailAccount REST API needs a user we are
        testing against, several email accounts that belong to that user, and a
        bunch of other email accounts belonging to other users.
        """
        # The user and email account we are testing with..
        #
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        ea = email_account_factory(owner=user)
        ea.save()
        for _ in range(5):
            mfr = message_filter_rule_factory(email_account=ea)
            mfr.save()

        client = api_client()
        resp = client.login(username=user.username, password=password)
        assert resp

        # Other email accounts because we need to make sure the tests only see
        # `user's` email accounts.
        #
        other_eas = []
        for _ in range(2):
            other_ea = email_account_factory()
            other_eas.append(other_ea)
            for _ in range(3):
                mfr = message_filter_rule_factory(email_account=other_ea)
                mfr.save()

        # Also make sure that a specific email account will only see message
        # filter rules that belong to it.
        #
        users_other_eas = []
        for _ in range(2):
            other_ea = email_account_factory(owner=user)
            users_other_eas.append(other_ea)
            for _ in range(3):
                mfr = message_filter_rule_factory(email_account=other_ea)
                mfr.save()

        return {
            "password": password,
            "user": user,
            "email_account": ea,
            "client": client,
            "other_eas": other_eas,
            "users_other_eas": users_other_eas,
        }

    ####################################################################
    #
    def test_list(self, api_client, setup):
        ea = setup["email_account"]
        url = reverse(
            "as_email:message-filter-rule-list",
            kwargs={"email_account_pk": ea.pk},
        )
        client = api_client()
        resp = client.get(url)
        assert resp.status_code == 403

        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200

        # There should be 5 message filter rules
        mfrs = list(ea.message_filter_rules.all())
        assert len(resp.data) == len(mfrs)

        # Since message filter rules are supposed to be ordered by the 'order'
        # field if no other sorting is applied these two lists should be in the
        # same order.
        #
        expected = []
        for mfr in mfrs:
            expected.append(_expected_for_message_filter_rule(mfr))

        for e, r in zip(expected, resp.data):
            r = dict(r)
            assert r == IsPartialDict(e)

    ####################################################################
    #
    def test_retrieve(self, api_client, setup):
        # Test unauthenticated access
        #
        client = api_client()
        ea = setup["email_account"]
        mfr = ea.message_filter_rules.all().first()
        assert mfr.email_account == ea
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )
        resp = client.get(url)
        assert resp.status_code == 403

        # Now work with the authenticated client
        #
        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200
        expected = _expected_for_message_filter_rule(mfr)
        assert resp.data == IsPartialDict(expected)

    ####################################################################
    #
    def test_create(self, setup):
        ea = setup["email_account"]
        url = reverse(
            "as_email:message-filter-rule-list",
            kwargs={"email_account_pk": ea.pk},
        )
        client = setup["client"]
        mfr_data = {
            "header": "from",
            "pattern": "pizzaco@example.com",
            "action": "folder",
            "destination": "orders/pizza",
        }
        resp = client.post(url, data=mfr_data)
        assert resp.status_code == 201

        # We get back a URL that refers to this object. We use `resolve` to
        # determine what the pk of this object is so we can look it up directly
        # via the ORM.Look at
        #     https://docs.djangoproject.com/en/4.2/ref/urlresolvers/#resolve
        # to see how this is used. Basically the 3rd element returned is the
        # kwargs used and in this dict the key "pk" should be the primary key
        # of this object.
        #
        func, args, kwargs = resolve(urlparse(resp.data["url"]).path)
        mfr = MessageFilterRule.objects.get(pk=int(kwargs["pk"]))
        assert mfr.email_account == ea
        assert resp.data == IsPartialDict(
            _expected_for_message_filter_rule(mfr)
        )
        # Also make sure that this logged in user can not create mfr's for
        # email accounts belonging to other users.
        #
        other_ea = setup["other_eas"][0]
        url = reverse(
            "as_email:message-filter-rule-list",
            kwargs={"email_account_pk": other_ea.pk},
        )
        resp = client.post(url, data=mfr_data)
        assert resp.status_code == 403

    ####################################################################
    #
    def test_update(self, setup):
        ea = setup["email_account"]
        mfr = ea.message_filter_rules.all().first()
        assert mfr.email_account == ea
        client = setup["client"]
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )

        mfr_new = {
            "header": "subject",
            "pattern": "foo",
            "action": "folder",
            "destination": "FooStuff",
        }
        resp = client.put(url, data=mfr_new)
        assert resp.status_code == 200
        mfr.refresh_from_db()
        mfr_from_db = _expected_for_message_filter_rule(mfr)

        assert resp.data == IsPartialDict(mfr_from_db)
        assert mfr_from_db == IsPartialDict(mfr_new)

        # Just to make sure.. you can not update anyone else's
        # MessageFilterRule's.
        #
        other_ea = setup["other_eas"][0]
        mfr = other_ea.message_filter_rules.all().first()
        client = setup["client"]
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": other_ea.pk, "pk": mfr.pk},
        )

        mfr_new = {
            "header": "subject",
            "pattern": "foo",
            "action": "folder",
            "destination": "FooStuff",
        }
        resp = client.put(url, data=mfr_new)
        assert resp.status_code == 403

    ####################################################################
    #
    def test_update_ro_fields(self, setup):
        ea = setup["email_account"]
        mfr = ea.message_filter_rules.all().first()
        original_mfr = _expected_for_message_filter_rule(mfr)
        assert mfr.email_account == ea
        client = setup["client"]
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )

        mfr_new = {
            "url": "/here/there",
            "email_address": "/there/here",
            "created_at": "yesterday",
            "modified_at": "today",
            "header": mfr.header,
            "pattern": mfr.pattern,
            "action": mfr.action,
            "destination": mfr.destination,
        }
        resp = client.put(url, data=mfr_new)
        assert resp.status_code == 200
        mfr.refresh_from_db()
        mfr_from_db = _expected_for_message_filter_rule(mfr)
        assert resp.data == IsPartialDict(original_mfr)
        assert resp.data == IsPartialDict(mfr_from_db)

    ####################################################################
    #
    def test_partial_update(self, setup):
        client = setup["client"]
        ea = setup["email_account"]
        mfr = ea.message_filter_rules.all().first()
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )

        patch_data = {
            "header": "subject",
            "pattern": "foo",
            "action": "folder",
            "destination": "FooStuff",
        }
        for k, v in patch_data.items():
            resp = client.patch(url, data={k: v})
            assert resp.status_code == 200
            mfr.refresh_from_db()
            assert getattr(mfr, k) == v

    ####################################################################
    #
    def test_delete(self, setup):
        ea = setup["email_account"]
        url = reverse(
            "as_email:message-filter-rule-list",
            kwargs={"email_account_pk": ea.pk},
        )
        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200
        mfrs = list(ea.message_filter_rules.all())
        assert len(resp.data) == len(mfrs)

        # Delete the first MFR.
        #
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfrs[0].pk},
        )
        resp = client.delete(url)
        assert resp.status_code == 204
        remaining_mfrs = list(ea.message_filter_rules.all())
        assert len(remaining_mfrs) == len(mfrs) - 1
        mfr_pks = [x.pk for x in remaining_mfrs]
        assert mfrs[0].pk not in mfr_pks

        # Make sure you can not delete someone else's mfr.
        #
        other_ea = setup["other_eas"][0]
        other_persons_mfr = other_ea.message_filter_rules.first()
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={
                "email_account_pk": other_ea.pk,
                "pk": other_persons_mfr.pk,
            },
        )
        resp = client.delete(url)
        assert MessageFilterRule.objects.filter(
            pk=other_persons_mfr.pk
        ).exists()
        assert resp.status_code == 403

        # What if you try to delete with bad key data? Should not even see it.
        #
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": other_persons_mfr.pk},
        )
        resp = client.delete(url)
        assert MessageFilterRule.objects.filter(
            pk=other_persons_mfr.pk
        ).exists()
        assert resp.status_code == 404

    ####################################################################
    #
    def test_move(self, setup):
        """
        Test various values for the 'move' method.
        """
        client = setup["client"]
        ea = setup["email_account"]
        mfr = ea.message_filter_rules.all().first()
        assert mfr.email_account == ea
        assert mfr.order == 0
        min_order = MessageFilterRule.objects.all().get_min_order()
        max_order = MessageFilterRule.objects.all().get_max_order()
        url = reverse(
            "as_email:message-filter-rule-move",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )

        resp = client.post(url, data={"command": "down"})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == 1

        resp = client.post(url, data={"command": "up"})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == 0

        resp = client.post(url, data={"command": "bottom"})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == max_order

        resp = client.post(url, data={"command": "top"})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == min_order

        to_loc = max_order - 1
        resp = client.post(url, data={"command": "to", "location": to_loc})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == max_order - 1

        # Moving it below the min order sets it a the min order.
        #
        to_loc = min_order - 1
        resp = client.post(url, data={"command": "to", "location": to_loc})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == min_order

        # Moving it above the max order, sets it to the max order.
        #
        to_loc = max_order + 1
        resp = client.post(url, data={"command": "to", "location": to_loc})
        assert resp.status_code == 200
        mfr.refresh_from_db()
        assert mfr.order == max_order

        # A `to` without a `location` fails.
        #
        resp = client.post(url, data={"command": "to"})
        assert resp.status_code == 400

        # And we can not move anyone else's mfr's.
        #
        other_ea = setup["other_eas"][0]
        other_mfr = other_ea.message_filter_rules.all().first()
        url = reverse(
            "as_email:message-filter-rule-move",
            kwargs={"email_account_pk": other_ea.pk, "pk": other_mfr.pk},
        )
        resp = client.post(url, data={"command": "down"})
        assert resp.status_code == 403

    ####################################################################
    #
    def test_options(self, setup):
        """
        Make sure that getting `options` for an EmailAccount works.
        """
        ea = setup["email_account"]
        client = setup["client"]
        mfr = ea.message_filter_rules.all().first()
        url = reverse(
            "as_email:message-filter-rule-detail",
            kwargs={"email_account_pk": ea.pk, "pk": mfr.pk},
        )
        resp = client.options(url)
        assert resp.status_code == 200


########################################################################
########################################################################
#
class TestDeliveryMethodEndpoints:
    """Tests for the DeliveryMethod REST API endpoints nested under EmailAccount."""

    ####################################################################
    #
    @pytest.fixture(autouse=True, scope="function")
    def setup(
        self,
        api_client,
        user_factory,
        email_account_factory,
        faker,
    ):
        """
        Set up a user with two email accounts:
        - ea: the primary account (has a LocalDelivery created by the factory)
        - ea_other_user: an account owned by a different user (for permission tests)
        """
        password = faker.pystr(min_chars=8, max_chars=32)
        user = user_factory(password=password)
        user.save()
        ea = email_account_factory(owner=user)
        ea.save()

        client = api_client()
        resp = client.login(username=user.username, password=password)
        assert resp

        # A second account owned by a different user for permission checks.
        #
        ea_other_user = email_account_factory()

        return {
            "password": password,
            "user": user,
            "email_account": ea,
            "client": client,
            "ea_other_user": ea_other_user,
        }

    ####################################################################
    #
    def _list_url(self, ea):
        return reverse(
            "as_email:delivery-method-list",
            kwargs={"email_account_pk": ea.pk},
        )

    ####################################################################
    #
    def _detail_url(self, ea, dm):
        return reverse(
            "as_email:delivery-method-detail",
            kwargs={"email_account_pk": ea.pk, "pk": dm.pk},
        )

    ####################################################################
    #
    def _test_imap_url(self, ea):
        return reverse(
            "as_email:delivery-method-test-imap",
            kwargs={"email_account_pk": ea.pk},
        )

    ####################################################################
    #
    def test_list_unauthenticated_is_forbidden(self, api_client, setup):
        """
        GIVEN an unauthenticated client
        WHEN  the delivery-method list endpoint is requested
        THEN  403 is returned
        """
        ea = setup["email_account"]
        client = api_client()
        resp = client.get(self._list_url(ea))
        assert resp.status_code == 403

    ####################################################################
    #
    def test_list_returns_own_delivery_methods(self, setup):
        """
        GIVEN an authenticated user with one LocalDelivery on their account
        WHEN  the delivery-method list endpoint is requested
        THEN  exactly one delivery method is returned for that account
             including LocalDelivery-specific fields (not just base fields)
        """
        ea = setup["email_account"]
        client = setup["client"]
        resp = client.get(self._list_url(ea))
        assert resp.status_code == 200
        assert len(resp.data) == 1
        dm = resp.data[0]
        assert dm["delivery_type"] == "LocalDelivery"
        # Subclass-specific fields must be present so the UI form can
        # display and edit them correctly on first load.
        assert "autofile_spam" in dm
        assert "spam_delivery_folder" in dm
        assert "spam_score_threshold" in dm
        assert "maildir_path" in dm

    ####################################################################
    #
    def test_list_does_not_return_other_users_methods(self, setup):
        """
        GIVEN two accounts owned by different users
        WHEN  the authenticated user lists delivery methods for the other account
        THEN  an empty list is returned — not the other user's methods
        """
        client = setup["client"]
        ea_other = setup["ea_other_user"]
        resp = client.get(self._list_url(ea_other))
        # The filter backend restricts to the requesting user's accounts;
        # querying another user's ea_pk returns an empty list (not 403).
        assert resp.status_code == 200
        assert len(resp.data) == 0

    ####################################################################
    #
    def test_retrieve_local_delivery(self, setup):
        """
        GIVEN an account with a LocalDelivery
        WHEN  the detail endpoint is requested
        THEN  the correct delivery method is returned with expected fields
        """
        ea = setup["email_account"]
        client = setup["client"]
        ld = LocalDelivery.objects.get(email_account=ea)
        resp = client.get(self._detail_url(ea, ld))
        assert resp.status_code == 200
        assert resp.data["delivery_type"] == "LocalDelivery"
        assert resp.data["pk"] == ld.pk
        assert resp.data["enabled"] is True
        assert "maildir_path" in resp.data

    ####################################################################
    #
    def test_retrieve_unauthenticated_is_forbidden(self, api_client, setup):
        """
        GIVEN an unauthenticated client
        WHEN  the delivery-method detail endpoint is requested
        THEN  403 is returned
        """
        ea = setup["email_account"]
        ld = LocalDelivery.objects.get(email_account=ea)
        client = api_client()
        resp = client.get(self._detail_url(ea, ld))
        assert resp.status_code == 403

    ####################################################################
    #
    def test_create_alias_to_delivery(self, email_account_factory, setup):
        """
        GIVEN an account with no alias delivery methods
        WHEN  an AliasToDelivery is created via POST
        THEN  201 is returned and the alias delivery method exists in the DB
        """
        ea = setup["email_account"]
        client = setup["client"]
        ea_target = email_account_factory()
        data = {
            "delivery_type": "AliasToDelivery",
            "target_account": ea_target.email_address,
        }
        resp = client.post(self._list_url(ea), data=data, format="json")
        assert resp.status_code == 201
        assert resp.data["delivery_type"] == "AliasToDelivery"
        assert resp.data["target_account"] == ea_target.email_address
        assert AliasToDelivery.objects.filter(
            email_account=ea, target_account=ea_target
        ).exists()

    ####################################################################
    #
    def test_create_second_local_delivery_is_rejected(self, setup):
        """
        GIVEN an account that already has a LocalDelivery
        WHEN  a second LocalDelivery is POSTed
        THEN  400 is returned with a descriptive error
        """
        ea = setup["email_account"]
        client = setup["client"]
        data = {"delivery_type": "LocalDelivery"}
        resp = client.post(self._list_url(ea), data=data, format="json")
        assert resp.status_code == 400
        assert "LocalDelivery" in str(resp.data)

    ####################################################################
    #
    def test_create_without_delivery_type_is_rejected(self, setup):
        """
        GIVEN a POST body with no delivery_type field
        WHEN  the create endpoint is called
        THEN  400 is returned
        """
        ea = setup["email_account"]
        client = setup["client"]
        resp = client.post(
            self._list_url(ea), data={"enabled": True}, format="json"
        )
        assert resp.status_code == 400
        assert "delivery_type" in resp.data

    ####################################################################
    #
    def test_create_with_invalid_delivery_type_is_rejected(self, setup):
        """
        GIVEN a POST body with an unrecognised delivery_type
        WHEN  the create endpoint is called
        THEN  400 is returned
        """
        ea = setup["email_account"]
        client = setup["client"]
        resp = client.post(
            self._list_url(ea),
            data={"delivery_type": "BogusDelivery"},
            format="json",
        )
        assert resp.status_code == 400

    ####################################################################
    #
    def test_create_for_other_users_account_is_forbidden(
        self, email_account_factory, setup
    ):
        """
        GIVEN a user authenticated as user A
        WHEN  they try to POST a delivery method on user B's account
        THEN  403 is returned
        """
        client = setup["client"]
        ea_other = setup["ea_other_user"]
        ea_target = email_account_factory()
        data = {
            "delivery_type": "AliasToDelivery",
            "target_account": ea_target.email_address,
        }
        resp = client.post(self._list_url(ea_other), data=data, format="json")
        assert resp.status_code == 403

    ####################################################################
    #
    def test_update_local_delivery_spam_settings(self, setup):
        """
        GIVEN a LocalDelivery
        WHEN  autofile_spam and spam_score_threshold are updated via PUT
        THEN  200 is returned and the changes are persisted
        """
        ea = setup["email_account"]
        client = setup["client"]
        ld = LocalDelivery.objects.get(email_account=ea)
        data = {
            "delivery_type": "LocalDelivery",
            "enabled": True,
            "autofile_spam": True,
            "spam_delivery_folder": "Junk",
            "spam_score_threshold": 3,
        }
        resp = client.put(self._detail_url(ea, ld), data=data, format="json")
        assert resp.status_code == 200
        ld.refresh_from_db()
        assert ld.autofile_spam is True
        assert ld.spam_delivery_folder == "Junk"
        assert ld.spam_score_threshold == 3

    ####################################################################
    #
    def test_partial_update_local_delivery(self, setup):
        """
        GIVEN a LocalDelivery
        WHEN  only autofile_spam is patched
        THEN  200 is returned and only that field changes
        """
        ea = setup["email_account"]
        client = setup["client"]
        ld = LocalDelivery.objects.get(email_account=ea)
        original_threshold = ld.spam_score_threshold
        resp = client.patch(
            self._detail_url(ea, ld),
            data={"autofile_spam": True},
            format="json",
        )
        assert resp.status_code == 200
        ld.refresh_from_db()
        assert ld.autofile_spam is True
        assert ld.spam_score_threshold == original_threshold

    ####################################################################
    #
    def test_maildir_path_is_read_only(self, setup):
        """
        GIVEN a LocalDelivery
        WHEN  a PATCH attempt is made to change maildir_path
        THEN  the field is silently ignored (read-only)
        """
        ea = setup["email_account"]
        client = setup["client"]
        ld = LocalDelivery.objects.get(email_account=ea)
        original_path = ld.maildir_path
        resp = client.patch(
            self._detail_url(ea, ld),
            data={"maildir_path": "/tmp/evil_path"},
            format="json",
        )
        assert resp.status_code == 200
        ld.refresh_from_db()
        assert ld.maildir_path == original_path

    ####################################################################
    #
    def test_update_alias_to_delivery(self, email_account_factory, setup):
        """
        GIVEN an AliasToDelivery pointing at target_a
        WHEN  it is updated via PUT to point at target_b
        THEN  200 is returned and the target_account changes
        """
        ea = setup["email_account"]
        client = setup["client"]
        ea_target_a = email_account_factory()
        ea_target_b = email_account_factory()
        atd = AliasToDelivery.objects.create(
            email_account=ea, target_account=ea_target_a
        )
        data = {
            "delivery_type": "AliasToDelivery",
            "enabled": True,
            "target_account": ea_target_b.email_address,
        }
        resp = client.put(self._detail_url(ea, atd), data=data, format="json")
        assert resp.status_code == 200
        atd.refresh_from_db()
        assert atd.target_account == ea_target_b

    ####################################################################
    #
    def test_delete_alias_to_delivery(self, email_account_factory, setup):
        """
        GIVEN an AliasToDelivery
        WHEN  it is deleted via DELETE
        THEN  204 is returned and the object no longer exists in the DB
        """
        ea = setup["email_account"]
        client = setup["client"]
        ea_target = email_account_factory()
        atd = AliasToDelivery.objects.create(
            email_account=ea, target_account=ea_target
        )
        atd_pk = atd.pk
        resp = client.delete(self._detail_url(ea, atd))
        assert resp.status_code == 204
        assert not DeliveryMethod.objects.filter(pk=atd_pk).exists()

    ####################################################################
    #
    def test_delete_local_delivery(self, setup):
        """
        GIVEN an account with a LocalDelivery
        WHEN  the LocalDelivery is deleted via DELETE
        THEN  204 is returned and the object no longer exists
        """
        ea = setup["email_account"]
        client = setup["client"]
        ld = LocalDelivery.objects.get(email_account=ea)
        ld_pk = ld.pk
        resp = client.delete(self._detail_url(ea, ld))
        assert resp.status_code == 204
        assert not DeliveryMethod.objects.filter(pk=ld_pk).exists()

    ####################################################################
    #
    def test_delete_other_users_delivery_method_is_forbidden(self, setup):
        """
        GIVEN a delivery method owned by another user
        WHEN  the current user tries to delete it
        THEN  403 is returned and the method still exists
        """
        client = setup["client"]
        ea_other = setup["ea_other_user"]
        ld_other = LocalDelivery.objects.get(email_account=ea_other)
        resp = client.delete(self._detail_url(ea_other, ld_other))
        assert resp.status_code == 403
        assert DeliveryMethod.objects.filter(pk=ld_other.pk).exists()

    ####################################################################
    #
    @pytest.mark.parametrize(
        "test_result, expected_status",
        [
            pytest.param(
                (True, "Connection successful."),
                200,
                id="success",
            ),
            pytest.param(
                (False, "Authentication failed: bad password"),
                400,
                id="failure",
            ),
        ],
    )
    def test_test_imap_action(
        self, setup, mocker, faker: Faker, test_result, expected_status
    ) -> None:
        """
        GIVEN valid input posted to the test_imap action
        WHEN  test_connection() returns success or failure
        THEN  the response status and body reflect the result
        """
        ea = setup["email_account"]
        client = setup["client"]
        mocker.patch(
            "as_email.models.ImapDelivery.test_connection",
            return_value=test_result,
        )
        resp = client.post(
            self._test_imap_url(ea),
            {
                "imap_host": "imap.example.com",
                "imap_port": 993,
                "username": "user@example.com",
                "password": faker.password(),
            },
            format="json",
        )
        assert resp.status_code == expected_status
        assert resp.data["success"] == test_result[0]
        assert resp.data["message"] == test_result[1]

    ####################################################################
    #
    def test_test_imap_action_missing_field_returns_400(self, setup) -> None:
        """
        GIVEN a POST to test_imap with the required password field missing
        WHEN  the request is processed
        THEN  400 is returned with a validation error for that field
        """
        ea = setup["email_account"]
        client = setup["client"]
        resp = client.post(
            self._test_imap_url(ea),
            {
                "imap_host": "imap.example.com",
                "imap_port": 993,
                "username": "user@example.com",
                # password intentionally omitted
            },
            format="json",
        )
        assert resp.status_code == 400
        assert "password" in resp.data

    ####################################################################
    #
    @pytest.mark.parametrize(
        "test_result, expected_status",
        [
            pytest.param(
                (True, "Connection successful."), 201, id="valid-credentials"
            ),
            pytest.param(
                (False, "Authentication failed: wrong"),
                400,
                id="bad-credentials",
            ),
        ],
    )
    def test_create_imap_delivery_validates_credentials(
        self, setup, mocker, faker: Faker, test_result, expected_status
    ) -> None:
        """
        GIVEN a POST to create an ImapDelivery with a password
        WHEN  test_connection() returns success or failure
        THEN  the create succeeds (201) or is rejected (400) accordingly
        """
        ea = setup["email_account"]
        client = setup["client"]
        mocker.patch(
            "as_email.models.ImapDelivery.test_connection",
            return_value=test_result,
        )
        resp = client.post(
            self._list_url(ea),
            {
                "delivery_type": "ImapDelivery",
                "imap_host": "imap.example.com",
                "imap_port": 993,
                "username": "user@example.com",
                "password": faker.password(),
            },
            format="json",
        )
        assert resp.status_code == expected_status

    ####################################################################
    #
    def test_patch_imap_delivery_with_new_password_triggers_validation(
        self, setup, mocker, faker: Faker
    ) -> None:
        """
        GIVEN an existing ImapDelivery PATCHed with a new password
        WHEN  test_connection() returns failure
        THEN  the PATCH is rejected with 400 and the password is not changed
        """
        ea = setup["email_account"]
        client = setup["client"]
        original_password = faker.password()
        imap_d = ImapDelivery.objects.create(
            email_account=ea,
            imap_host="imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=original_password,
        )
        mocker.patch(
            "as_email.models.ImapDelivery.test_connection",
            return_value=(False, "Authentication failed: wrong password"),
        )
        resp = client.patch(
            self._detail_url(ea, imap_d),
            {"password": faker.password()},
            format="json",
        )
        assert resp.status_code == 400
        imap_d.refresh_from_db()
        assert imap_d.password == original_password

    ####################################################################
    #
    def test_patch_imap_delivery_without_password_skips_validation(
        self, setup, mocker, faker: Faker
    ) -> None:
        """
        GIVEN an existing ImapDelivery PATCHed without a password field
        WHEN  the PATCH is processed
        THEN  test_connection() is not called and the update succeeds
        """
        ea = setup["email_account"]
        client = setup["client"]
        stored_password = faker.password()
        imap_d = ImapDelivery.objects.create(
            email_account=ea,
            imap_host="imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=stored_password,
        )
        mock_test = mocker.patch("as_email.models.ImapDelivery.test_connection")
        resp = client.patch(
            self._detail_url(ea, imap_d),
            {"imap_host": "imap2.example.com"},
            format="json",
        )
        assert resp.status_code == 200
        mock_test.assert_not_called()
        imap_d.refresh_from_db()
        assert imap_d.imap_host == "imap2.example.com"
        assert imap_d.password == stored_password

    ####################################################################
    #
    def test_imap_delivery_password_not_in_response(
        self, setup, faker: Faker
    ) -> None:
        """
        GIVEN an ImapDelivery with a stored password
        WHEN  the detail or list endpoint is fetched
        THEN  the password field is absent from the response
        """
        ea = setup["email_account"]
        client = setup["client"]
        imap_d = ImapDelivery.objects.create(
            email_account=ea,
            imap_host="imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=faker.password(),
        )
        resp = client.get(self._detail_url(ea, imap_d))
        assert resp.status_code == 200
        assert "password" not in resp.data

    ####################################################################
    #
    def test_patch_delivery_method_clears_retry_record(
        self, setup, faker: Faker
    ) -> None:
        """
        GIVEN an ImapDelivery with a delivery_retry Redis record listing its PK
        WHEN  the delivery method is PATCHed (e.g. corrected imap_host)
        THEN  the Redis key is deleted so the next retry run picks it up immediately
        """
        ea = setup["email_account"]
        client = setup["client"]
        imap_d = ImapDelivery.objects.create(
            email_account=ea,
            imap_host="old.imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=faker.password(),
        )

        # Simulate a delivery_retry record that was written when this method
        # previously failed.
        #
        r = redis_client()
        redis_key = "delivery_retry:some-failed-message-stem"
        r.hset(
            redis_key,
            mapping={
                "first_failure": "2026-03-04T10:00:00+00:00",
                "attempt_count": "2",
                "failed_method_pks": json.dumps([imap_d.pk]),
                "next_retry_at": "2026-03-04T10:20:00+00:00",
            },
        )
        assert r.exists(redis_key)

        # PATCH without a password so test_connection is not triggered.
        #
        resp = client.patch(
            self._detail_url(ea, imap_d),
            {"imap_host": "new.imap.example.com"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.data["imap_host"] == "new.imap.example.com"

        # Retry record must be gone so the file is retried without backoff.
        #
        assert not r.exists(redis_key)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "test_result, expected_status, expect_enabled",
        [
            ((True, "Connection successful."), 200, True),
            ((False, "Authentication failed."), 400, False),
        ],
        ids=["valid-credentials", "bad-credentials"],
    )
    def test_reenable_imap_delivery_checks_credentials(
        self,
        setup,
        mocker,
        faker: Faker,
        test_result: tuple[bool, str],
        expected_status: int,
        expect_enabled: bool,
    ) -> None:
        """
        GIVEN a disabled ImapDelivery
        WHEN  it is re-enabled via PATCH
        THEN  test_connection is called with the stored credentials;
              valid credentials allow the enable (200), bad credentials
              are rejected (400) and the method stays disabled
        """
        ea = setup["email_account"]
        client = setup["client"]
        imap_d = ImapDelivery.objects.create(
            email_account=ea,
            imap_host="imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=faker.password(),
            enabled=False,
        )

        mock_test = mocker.patch(
            "as_email.models.ImapDelivery.test_connection",
            return_value=test_result,
        )

        resp = client.patch(
            self._detail_url(ea, imap_d),
            {"enabled": True},
            format="json",
        )
        assert resp.status_code == expected_status
        mock_test.assert_called_once()

        imap_d.refresh_from_db()
        assert imap_d.enabled is expect_enabled
