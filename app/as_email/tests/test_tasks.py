#!/usr/bin/env python
#
"""
Test the huey tasks
"""
# system imports
#
import json
from datetime import datetime
from pathlib import Path

# 3rd party imports
#
import pytest

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
    email_account_factory,
    email_factory,
    tmp_path,
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
def test_too_many_bounces(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
):
    """
    We set up an account that has had 2 less than the bounce limit, and
    that when it crosses that limit it gets deactivated.
    """
    bounce_start = EmailAccount.NUM_EMAIL_BOUNCE_LIMIT - 2
    ea = email_account_factory(num_bounces=bounce_start)
    ea.save()
    assert ea.num_bounces == bounce_start
    bounced_msg = email_factory(msg_from=ea.email_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    bounce_data = {
        "ID": bounce_id,
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
        "BouncedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": False,
        "CanActivate": True,
        "RecordType": "Bounce",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

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


####################################################################
#
def test_bounce_inactive(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
    django_outbox,
):
    """
    If postmark flags `inactive` on a bounce then it means that it has
    deactivated that email address, so we will pre-emptively deactivate that
    EmailAccount. Note that this deactivation, unlike the one that comes from
    exceeding the allowable number of bounces in a day, will not be reset
    automatically when the number of bounces decays over time.
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    bounced_msg = email_factory(msg_from=ea.email_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    bounce_data = {
        "ID": bounce_id,
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
        "BouncedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": True,
        "CanActivate": True,
        "RecordType": "Bounce",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert ea.deactivated is True
    assert ea.deactivated_reason == ea.DEACTIVATED_BY_POSTMARK
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email


####################################################################
#
def test_transient_bounce_notifications(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
):
    """
    Some bounce notifcations are transient - these do not cause the num
    bounces for an email account to go up.
    """
    ea = email_account_factory()
    ea.save()
    assert ea.num_bounces == 0
    assert ea.deactivated is False
    bounced_msg = email_factory(msg_from=ea.email_address)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)
    bounce_data = {
        "ID": bounce_id,
        "Type": "Transient",
        "TypeCode": 2,
        "Name": "Transient",
        "Tag": "Test",
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "ServerID": 23,
        "Description": "A transient failure",
        "Details": "Test bounce details",
        "Email": "john@example.com",
        "From": ea.email_address,
        "BouncedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DumpAvailable": False,
        "Inactive": False,
        "CanActivate": True,
        "RecordType": "Transient",
        "Subject": "Test subject",
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 0
    assert ea.deactivated is False


####################################################################
#
def test_bounce_to_forwarded_to_deactivates_emailaccount(
    email_account_factory,
    email_factory,
    postmark_request,
    postmark_request_bounce,
    faker,
    django_outbox,
):
    """
    If you have set a 'forward_to' to an address that causes a hard bounce
    when email is sent to it, then your email account is deactivated (otherwise
    every forwarded message will cause a hard bounce.)
    """
    forward_to = faker.email()
    ea = email_account_factory(
        delivery_method=EmailAccount.FORWARDING,
        forward_to=forward_to,
    )
    ea.save()
    assert ea.num_bounces == 0
    assert ea.deactivated is False

    bounced_msg = email_factory(msg_from=ea.email_address, to=forward_to)
    bounce_id = faker.pyint(1_000_000_000, 9_999_999_999)

    bounce_data = {
        "BouncedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "CanActivate": True,
        "Description": "Invalid email address — The address is not a valid email address.",
        "Details": "Invalid email address",
        "DumpAvailable": False,
        "Email": forward_to,
        "From": ea.email_address,
        "ID": bounce_id,
        "Inactive": False,
        "MessageID": "883953f4-6105-42a2-a16a-77a8eac79483",
        "Name": "Bad email address",
        "RecordType": "BadEmailAddress",
        "ServerID": 23,
        "Subject": "Bad email address",
        "Tag": "Test",
        "Type": "BadEmailAddress",
        "TypeCode": 100000,
    }
    postmark_request_bounce(
        email_account=ea, email_message=bounced_msg, **bounce_data
    )

    res = process_email_bounce(ea.pk, bounce_data)
    res()
    ea.refresh_from_db()
    assert ea.num_bounces == 1
    assert ea.deactivated is True
    assert ea.deactivated_reason == ea.DEACTIVATED_DUE_TO_BAD_FORWARD_TO
    assert len(django_outbox) == 1
    assert django_outbox[0].to[0] == ea.owner.email
