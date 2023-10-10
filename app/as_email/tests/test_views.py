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
from django.urls import reverse

# Project imports
#
from ..models import EmailAccount

pytestmark = pytest.mark.django_db


####################################################################
#
def _expected_for_email_account(ea: EmailAccount) -> dict:
    """
    Our tests need to compare a dict retrieved from the REST API with an
    EmailAccount object. This returns a partial dict of the provided
    EmailAccount such that it should match what we get back via the REST API
    when using IsPartialDict.
    """
    alias_for = [
        "http://testserver"
        + reverse("as_email:email-account-detail", kwargs={"pk": x.pk})
        for x in ea.alias_for.all()
    ]

    expected = {
        "alias_for": alias_for,
        "autofile_spam": ea.autofile_spam,
        "deactivated": ea.deactivated,
        "deactivated_reason": ea.deactivated_reason,
        "delivery_method": ea.delivery_method,
        "email_address": ea.email_address,
        "forward_to": ea.forward_to,
        "num_bounces": ea.num_bounces,
        "owner": ea.owner.username,
        "server": ea.server.domain_name,
        "spam_delivery_folder": ea.spam_delivery_folder,
        "spam_score_threshold": ea.spam_score_threshold,
    }
    return expected


####################################################################
#
def test_bounce_webhook(
    email_account_factory,
    api_client,
    faker,
    postmark_request,
    postmark_request_bounce,
):
    ea = email_account_factory()
    ea.save()
    server = ea.server
    assert ea.num_bounces == 0

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

    # Make sure when we query postmark for the bounce info it matches what we
    # are expecting here.
    #
    postmark_request_bounce(email_account=ea, **bounce_data)

    url = (
        reverse(
            "as_email:hook_postmark_bounce",
            kwargs={"domain_name": server.domain_name},
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    client = api_client()
    r = client.post(
        url, json.dumps(bounce_data), content_type="application/json"
    )
    assert r.status_code == 200
    resp_data = r.json()
    assert "status" in resp_data
    assert resp_data["status"] == "all good"
    assert (
        resp_data["message"]
        == f"received bounce for {server.domain_name}/{ea.email_address}"
    )
    ea.refresh_from_db()
    assert ea.num_bounces == 1

    # If we get a bounce message from an address that is not covered by our
    # server, we get a different message from the response.
    #
    bounce_data["From"] = faker.email()
    r = client.post(
        url, json.dumps(bounce_data), content_type="application/json"
    )
    assert r.status_code == 200
    resp_data = r.json()
    assert "status" in resp_data
    assert resp_data["status"] == "all good"
    assert (
        resp_data["message"]
        == f"`from` address '{bounce_data['From']}' is not an EmailAccount on server {server.domain_name}. Bounce message ignored."
    )
    ea.refresh_from_db()
    assert ea.num_bounces == 1

    # Requests with bad data return 400 - bad request
    #
    r = client.post(url, "HAHANO", content_type="application/json")
    assert r.status_code == 400
    ea.refresh_from_db()
    assert ea.num_bounces == 1

    # Make sure for requests to servers that do not exist return a 404
    #
    url = (
        reverse(
            "as_email:hook_postmark_bounce",
            kwargs={"domain_name": faker.domain_name()},
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    bounce_data["From"] = faker.email()
    r = client.post(
        url, json.dumps(bounce_data), content_type="application/json"
    )
    assert r.status_code == 404
    ea.refresh_from_db()
    assert ea.num_bounces == 1


####################################################################
#
def test_postmark_spam_webhook(
    email_account_factory,
    api_client,
    faker,
    postmark_request,
    postmark_request_bounce,
):
    ea = email_account_factory()
    ea.save()
    server = ea.server  # noqa: F841
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

    url = (
        reverse(
            "as_email:hook_postmark_spam",
            kwargs={"domain_name": server.domain_name},
        )
        + "?"
        + urlencode({"api_key": server.api_key})
    )

    client = api_client()
    r = client.post(url, json.dumps(spam_data), content_type="application/json")
    assert r.status_code == 200
    resp_data = r.json()
    assert "status" in resp_data
    assert resp_data["status"] == "all good"
    assert (
        resp_data["message"]
        == f"received spam for {server.domain_name}/{ea.email_address}"
    )


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
    def test_retrieve(self, api_client, email_account_factory, setup):
        client = api_client()
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        # Not logged in, no access.
        #
        resp = client.get(url)
        assert resp.status_code == 403

        # Change to logged in client
        #
        user = setup["user"]
        client = setup["client"]
        resp = client.get(url)
        assert resp.status_code == 200
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

        # What if `ea` is an alias for a different email account?
        #
        ea_dest = email_account_factory(owner=user)
        ea_dest.save()
        ea.delivery_method = EmailAccount.ALIAS
        ea.alias_for.add(ea_dest)
        ea.save()

        resp = client.get(url)
        assert resp.status_code == 200
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

    ####################################################################
    #
    def test_update(self, faker, email_account_factory, setup):
        """
        Testing PUT of all writeable fields (and also testing that readonly
        fields are not writeable.)
        """
        client = setup["client"]
        user = setup["user"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        ea_dest = email_account_factory(owner=user)
        ea_dest.save()

        # Try setting the account to be an alias for `ea_dest`
        #
        ea_new = {
            "alias_for": [
                "http://testserver"
                + reverse(
                    "as_email:email-account-detail",
                    kwargs={"pk": ea_dest.pk},
                ),
            ],
            "autofile_spam": False,
            "delivery_method": EmailAccount.ALIAS,
            "forward_to": faker.email(),
            "spam_delivery_folder": "Spam",
            "spam_score_threshold": 10,
        }
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 200
        ea.refresh_from_db()
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

        # Also make sure we can remove alias_for's.
        #
        ea_new = {
            "alias_for": [],
            "autofile_spam": True,
            "delivery_method": EmailAccount.LOCAL_DELIVERY,
            "forward_to": faker.email(),
            "spam_delivery_folder": "Spam",
            "spam_score_threshold": 10,
        }
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 200
        assert resp.data == IsPartialDict(ea_new)
        ea.refresh_from_db()
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)

    ####################################################################
    #
    def test_update_bad_aliases(
        self,
        faker,
        email_account_factory,
        setup,
        message_filter_rule_factory,
    ):
        """
        The `alias_for` attribute is custom `update()` code for the
        EmailAccountViewSet so make sure to test its various failure modes.
        """
        client = setup["client"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})
        orig_ea_data = _expected_for_email_account(ea)

        # Make an EmailAccount that is NOT owned by this user.  (by not
        # specifying `owner` in the creation)
        #
        ea_dest = email_account_factory()
        ea_dest.save()

        # Try setting the account to be an alias for `ea_dest`
        #
        ea_new = {
            "alias_for": [
                "http://testserver"
                + reverse(
                    "as_email:email-account-detail",
                    kwargs={"pk": ea_dest.pk},
                ),
            ],
            "autofile_spam": False,
            "delivery_method": EmailAccount.ALIAS,
            "forward_to": faker.email(),
            "spam_delivery_folder": "Spam",
            "spam_score_threshold": 10,
        }
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 400
        assert (
            resp.data["detail"]
            == "can only alias_for email accounts owned by the same user."
        )

        # And make sure that the EmailAccount was not changed.
        #
        ea.refresh_from_db()
        assert resp.data != IsPartialDict(ea_new)
        assert _expected_for_email_account(ea) == orig_ea_data

        # Let us point at something else entirely.
        #
        mfr = message_filter_rule_factory(email_account=ea)
        ea_new["alias_for"] = [
            "http://testserver"
            + reverse(
                "as_email:message-filter-rule-detail",
                kwargs={"email_account_pk": mfr.email_account.pk, "pk": mfr.pk},
            ),
        ]
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 400
        assert (
            resp.data["detail"] == "All referenced items must be EmailAccounts"
        )

        # And make sure that the EmailAccount was not changed.
        #
        ea.refresh_from_db()
        assert resp.data != IsPartialDict(ea_new)
        assert _expected_for_email_account(ea) == orig_ea_data

        # Also make sure that if we send garbage it also fails as a bad request.
        #
        ea_new["alias_for"] = [
            "http://testserver/foo/bar/bblah/1/",
        ]
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 404

        # And make sure that the EmailAccount was not changed.
        #
        ea.refresh_from_db()
        assert resp.data != IsPartialDict(ea_new)
        assert _expected_for_email_account(ea) == orig_ea_data

        # Also make sure if we point a url somewhere else it also does not work.
        #
        # XXX We should have a better failure for this but this is good enough
        #     for now.
        #
        ea_new["alias_for"] = [
            "https://example.com/foo/bar/bblah/1/",
        ]
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 404

        # And make sure that the EmailAccount was not changed.
        #
        ea.refresh_from_db()
        assert resp.data != IsPartialDict(ea_new)
        assert _expected_for_email_account(ea) == orig_ea_data

    ####################################################################
    #
    def test_update_readonly_fields(self, faker, setup):
        """
        make sure trying to set the read only fields does not update them.
        """
        client = setup["client"]
        ea = setup["email_account"]
        orig_ea_data = _expected_for_email_account(ea)
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})
        ea_new = {
            "alias_for": [],
            "deactivated": True,  # This attribute is read-only.
            "deactivated_reason": "no reason. haha.",
            "email_address": "boogie@example.com",
            "num_bounces": 2000,
            "owner": "john@example.com",
            "server": "blackhole.example.com",
            "autofile_spam": False,
            "delivery_method": EmailAccount.ALIAS,
            "forward_to": faker.email(),
            "spam_delivery_folder": "Spam",
            "spam_score_threshold": 10,
        }
        resp = client.put(url, data=ea_new)
        assert resp.status_code == 200
        ea.refresh_from_db()
        expected = _expected_for_email_account(ea)
        assert resp.data == IsPartialDict(expected)
        # All the read only fields that we tried to change should not be changed
        #
        ro_fields = [
            "deactivated",
            "deactivated_reason",
            "email_address",
            "num_bounces",
            "owner",
            "server",
        ]
        expected_unchanged = {
            k: v for k, v in resp.data.items() if k in ro_fields
        }
        assert orig_ea_data == IsPartialDict(expected_unchanged)

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
    def test_partial_update(
        self, api_client, faker, email_account_factory, setup
    ):
        """
        Test patching a bunch of writeable fields one by one.
        """
        client = setup["client"]
        user = setup["user"]
        ea = setup["email_account"]
        url = reverse("as_email:email-account-detail", kwargs={"pk": ea.pk})

        patch_data = {"autofile_spam": not ea.autofile_spam}
        resp = client.patch(url, data=patch_data)
        assert resp.status_code == 200
        ea.refresh_from_db()
        assert ea.autofile_spam == resp.data["autofile_spam"]

        # set the alias_for to this new account.
        #
        ea_dest = email_account_factory(owner=user)
        ea_dest.save()

        # Try setting the account to be an alias for `ea_dest`
        #
        patch_data = {
            "alias_for": [
                "http://testserver"
                + reverse(
                    "as_email:email-account-detail",
                    kwargs={"pk": ea_dest.pk},
                ),
            ],
        }

        resp = client.patch(url, data=patch_data)
        assert resp.status_code == 200
        ea.refresh_from_db()

        # The URL's for the objects do not have the netloc, strip that off.
        #
        alias_for = [
            urlparse(x.get_absolute_url()).path for x in ea.alias_for.all()
        ]
        assert alias_for == [urlparse(x).path for x in patch_data["alias_for"]]
        assert alias_for == [urlparse(x).path for x in resp.data["alias_for"]]

        # And if we submit an different alias is replaces what we already have
        #
        ea_dest = email_account_factory(owner=user)
        ea_dest.save()

        # Try setting the account to be an alias for `ea_dest`
        #
        patch_data = {
            "alias_for": [
                "http://testserver"
                + reverse(
                    "as_email:email-account-detail",
                    kwargs={"pk": ea_dest.pk},
                ),
            ],
        }

        resp = client.patch(url, data=patch_data)
        assert resp.status_code == 200
        ea.refresh_from_db()

        # The URL's for the objects do not have the netloc, strip that off.
        #
        alias_for = [
            urlparse(x.get_absolute_url()).path for x in ea.alias_for.all()
        ]
        assert alias_for == [urlparse(x).path for x in patch_data["alias_for"]]
        assert alias_for == [urlparse(x).path for x in resp.data["alias_for"]]

        # and submitting an empty string clears the alias_for
        #
        patch_data = {"alias_for": ""}

        resp = client.patch(url, data=patch_data)
        assert resp.status_code == 200
        ea.refresh_from_db()
        assert ea.alias_for.count() == 0
        assert len(resp.data["alias_for"]) == 0
