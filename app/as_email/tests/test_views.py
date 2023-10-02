#!/usr/bin/env python
#
"""
Testing our views. Plain views, webhooks, and the REST interface.
"""
# system imports
#
import json
from urllib.parse import urlencode

# 3rd party imports
#
import pytest
from django.urls import reverse

# Project imports
#

pytestmark = pytest.mark.django_db


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
