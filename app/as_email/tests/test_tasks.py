#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
import email.policy
import json
from datetime import datetime
from pathlib import Path

# 3rd party imports
#
import pytest
from requests import Response

# Project imports
#
from ..models import EmailAccount
from ..tasks import (
    decrement_num_bounces_counter,
    dispatch_incoming_email,
    process_email_bounce,
)
from ..utils import spooled_email
from .test_deliver import assert_email_equal

pytestmark = pytest.mark.django_db


####################################################################
#
def test_dispatch_incoming_email(
    email_account_factory, email_factory, tmp_path
):
    """
    Write a json file that is in the expected format
    """
    ea = email_account_factory()
    ea.save()
    msg = email_factory(to=ea.email_address)
    now = datetime.now()
    message_id = msg["Message-ID"]
    email_file_name = f"{now.isoformat()}-{message_id}.json"
    fname = Path(tmp_path) / email_file_name
    email_msg = spooled_email(msg["To"], message_id, str(now), msg.as_string())
    fname.write_text(json.dumps(email_msg))

    res = dispatch_incoming_email(ea.pk, str(fname))
    res()

    # The message should have been delivered to the inbox since there are no
    # mail filter rules. And it should be the only message in the mailbox.
    #
    mh = ea.MH()
    folder = mh.get_folder("inbox")
    stored_msg = folder.get(1)
    assert_email_equal(msg, stored_msg)


####################################################################
#
def test_decrement_num_bounces_counter(email_account_factory):
    # No accounts.. there should be no errors.
    #
    res = decrement_num_bounces_counter()
    res()

    ea_1 = email_account_factory()
    ea_1.save()
    ea_2 = email_account_factory()
    ea_2.save()

    # 0 bounces.. there should be no changes and no errors.
    #
    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 0
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == 0

    # some bounces
    #
    ea_1.num_bounces = 14
    ea_1.save()
    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 13
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == 0

    # Num bounces at limit, and deactivated
    #
    ea_2.num_bounces = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
    ea_2.deactivated = True
    ea_2.deactivated_reason = EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
    ea_2.save()

    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == 12
    ea_2.refresh_from_db()
    assert ea_2.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 1
    assert ea_2.deactivated is False
    assert ea_2.deactivated_reason is None

    # If deactivated reason is not due to num bounces, then going under the
    # threshold changes nothing.
    #
    ea_1.num_bounces = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
    ea_1.deactivated = True
    ea_1.deactivated_reason = "Sending too much spam"
    ea_1.save()

    res = decrement_num_bounces_counter()
    res()
    ea_1.refresh_from_db()
    assert ea_1.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 1
    assert ea_1.deactivated
    assert ea_1.deactivated_reason == "Sending too much spam"

    ea_2.refresh_from_db()
    assert ea_2.num_bounces == EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    assert ea_2.deactivated is False
    assert ea_2.deactivated_reason is None


####################################################################
#
def test_bounce_deactivated_due_to_inactive(email_account_factory, faker):
    """
    If postmark sets 'Inactive' on its bounce webhook call then it means
    that postmark has deactivated that email address from sending.
    """
    pass


####################################################################
#
def test_too_many_bounces(
    email_account_factory, email_factory, postmark_request
):
    """
    We set up an account that has had 2 less than the bounce limit, and
    that when it crosses that limit it gets deactivated.
    """

    def postmarker_requests(method, url, **kwargs):
        """
        The code we are testing will be making various requests of the
        postmark API. The requests object itself is mocked and this function
        will be called each time a request is made (via mock side-effects.) For
        the request being made we will return a pre-made Response object.
        """
        # The postmark_request is also what is going to be used by the
        # ea.server.client (PostMark client) for mocking requests. So we need
        # to make it return the values we expect to get from calling the
        # postmark API by creating a requests's Response object with the right
        # data.
        #
        print(f"postmarker_requests args: {url}")
        print(f"postmarker_requests kwargs: {kwargs}")
        # A map of responses by the URL being requested.
        #
        responses = {
            "https://api.postmarkapp.com/bounces/4323372036854775807": {
                "ID": 4323372036854775807,
                "Type": "HardBounce",
                "TypeCode": 1,
                "Name": "Hard bounce",
                "Tag": "Invitation",
                "MessageID": "2c1b63fe-43f2-4db5-91b0-8bdfa44a9316",
                "ServerID": 23,
                "MessageStream": "outbound",
                "Description": "The server was unable to deliver your message (ex: unknown user, mailbox not found).",
                "Details": "action: failed\r\n",
                "Email": "anything@blackhole.postmarkapp.com",
                "From": "sender@postmarkapp.com",
                "BouncedAt": "2014-01-15T16:09:19.6421112-05:00",
                "DumpAvailable": True,
                "Inactive": False,
                "CanActivate": True,
                "Subject": "SC API5 Test",
                "Content": "Return-Path: <>\r\nReceived: …",
            },
            "https://api.postmarkapp.com/bounces/4323372036854775807/dump": {
                "Body": "SMTP dump data",
            },
            "https://api.postmarkapp.com/messages/outbound/2c1b63fe-43f2-4db5-91b0-8bdfa44a9316/details": {
                "TextBody": "Thank you for your order...",
                "HtmlBody": "<p>Thank you for your order...</p>",
                "Body": "SMTP dump data",
                "Tag": "product-orders",
                "MessageID": "07311c54-0687-4ab9-b034-b54b5bad88ba",
                "MessageStream": "outbound",
                "To": [{"Email": "john.doe@yahoo.com", "Name": None}],
                "Cc": [],
                "Bcc": [],
                "Recipients": ["john.doe@yahoo.com"],
                "ReceivedAt": "2014-02-14T11:12:54.8054242-05:00",
                "From": '"Joe" <joe@domain.com>',
                "Subject": "Parts Order #5454",
                "Attachments": ["myimage.png", "mypaper.doc"],
                "Status": "Sent",
                "TrackOpens": True,
                "TrackLinks": "HtmlOnly",
                "Metadata": {"color": "blue", "client-id": "12345"},
                "Sandboxed": False,
                "MessageEvents": [
                    {
                        "Recipient": "john.doe@yahoo.com",
                        "Type": "Delivered",
                        "ReceivedAt": "2014-02-14T11:13:10.8054242-05:00",
                        "Details": {
                            "DeliveryMessage": "smtp;250 2.0.0 OK l10si21599969igu.63 - gsmtp",
                            "DestinationServer": "yahoo-smtp-in.l.yahoo.com (433.899.888.26)",
                            "DestinationIP": "173.194.74.256",
                        },
                    },
                    {
                        "Recipient": "john.doe@yahoo.com",
                        "Type": "Transient",
                        "ReceivedAt": "2014-02-14T11:12:10.8054242-05:00",
                        "Details": {
                            "DeliveryMessage": "smtp;400 Server cannot accept messages at this time, please try again later",
                            "DestinationServer": "yahoo-smtp-in.l.yahoo.com (433.899.888.26)",
                            "DestinationIP": "173.194.74.256",
                        },
                    },
                    {
                        "Recipient": "john.doe@yahoo.com",
                        "Type": "Opened",
                        "ReceivedAt": "2014-02-14T11:20:10.8054242-05:00",
                        "Details": {
                            "Summary": "Email opened with Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)"
                        },
                    },
                    {
                        "Recipient": "badrecipient@example.com",
                        "Type": "Bounced",
                        "ReceivedAt": "2014-02-14T11:20:15.8054242-05:00",
                        "Details": {
                            "Summary": "smtp;550 5.1.1 The email account that you tried to reach does not exist. Please try double-checking the recipient's email address for typos or unnecessary spaces.",
                            "BounceID": "374814878",
                        },
                    },
                    {
                        "Recipient": "badrecipient@example.com",
                        "Type": "SubscriptionChanged",
                        "ReceivedAt": "2014-02-14T11:21:15.8054242-05:00",
                        "Details": {
                            "Origin": "Recipient",
                            "SuppressSending": "True",
                        },
                    },
                    {
                        "Recipient": "click-tracked@example.com",
                        "Type": "LinkClicked",
                        "ReceivedAt": "2016-10-05T16:03:56.0000000-04:00",
                        "Details": {
                            "Summary": "Tracked Link 'https://example.com/a/path/to/the/future?queryValue=1&queryValue=2' was clicked from the HTMLBody.",
                            "Link": "https://example.com/a/path/to/the/future?queryValue=1&queryValue=2",
                            "ClickLocation": "HTML",
                        },
                    },
                ],
            },
            "https://api.postmarkapp.com/messages/outbound/07311c54-0687-4ab9-b034-b54b5bad88ba/dump": {
                "Body": email_factory().as_string(policy=email.policy.default)
            },
        }
        resp = Response()
        resp.status_code = 200
        resp._content = bytes(json.dumps(responses[url]), "utf-8")
        return resp

    bounce_start = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    ea = email_account_factory(num_bounces=bounce_start)
    ea.save()
    assert ea.num_bounces == bounce_start

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

    postmark_request.side_effect = postmarker_requests

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 1
    assert ea.deactivated is False
    assert ea.deactivated_reason is None

    # and a second bounce.
    #
    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == bounce_start + 2
    assert ea.deactivated
    assert (
        ea.deactivated_reason == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
    )
