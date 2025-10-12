#!/usr/bin/env python
#
"""
Huey dispatchable (and periodic) tasks.
"""
# system imports
#
import email
import email.policy
import json
import logging
from email.message import EmailMessage
from pathlib import Path
from typing import cast

# 3rd party imports
#
import pytz
from django.conf import settings
from django.core.mail import send_mail
from huey import crontab
from huey.contrib.djhuey import db_periodic_task, db_task, lock_task, task
from postmarker.exceptions import ClientError

# Project imports
#
from .deliver import deliver_message, report_failed_message
from .models import EmailAccount, InactiveEmail, Server
from .utils import (
    BOUNCE_TYPES_BY_TYPE_CODE,
    PWUser,
    read_emailaccount_pwfile,
    write_emailaccount_pwfile,
)

TZ = pytz.timezone(settings.TIME_ZONE)
EST = pytz.timezone("EST")  # Postmark API is in EST! Really!
# How many messages do we try to dispatch during a single run of any of the
# dispatch tasks. Makes sure we do not hog the task queues just sending email.
#
# NOTE: Separate metrics gathering jobs will be used to watch dispatch queue
#       sizes.
#
DISPATCH_NUM_PER_RUN = 100

# How many messages do we attempt to redeliver after failure per run.
#
NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN = 5


logger = logging.getLogger("as_email.tasks")


####################################################################
#
@db_periodic_task(crontab(minute="*/10"))
def retry_failed_incoming_email():
    """
    Go through any messages in the failed incoming spool dir and attempt to
    deliver them again. Logging the exception if it fails.

    To avoid high noise rates stop attempting after a limited number of
    failures
    """
    failing_incoming_dir = Path(settings.FAILED_INCOMING_MSG_DIR)
    if not failing_incoming_dir.exists():
        return

    num_failures = 0
    for email_file in failing_incoming_dir.iterdir():
        try:
            email_msg = json.loads(email_file.read_text())
            email_addr = email_msg["recipient"].strip()
            email_account = EmailAccount.objects.get(email_address=email_addr)
            msg = email.message_from_string(
                email_msg["raw_email"], policy=email.policy.default
            )
            deliver_message(email_account, msg)
            logger.info(
                "Successfully delivered previously failed message '%s' for "
                "email account '%s'",
                email_file,
                email_addr,
            )
            # Since we managed to successfully deliver the email, we can delete
            # it from the FAILED_INCOMING_MSG_DIR.
            #
            email_file.unlink()

        except Exception as e:
            logger.exception(
                "Unable to deliver failed message '%s': %s", email_file, e
            )
            num_failures += 1
            if num_failures >= NUM_DELIVER_FAILURE_ATTEMPTS_PER_RUN:
                logger.error(
                    "Stopping redelivery attempts after %d attempts",
                    num_failures,
                )
                break


####################################################################
#
@db_periodic_task(crontab(minute="*/5"))
def dispatch_spooled_outgoing_email():
    """
    Look for email messages in our outgoing spool folder and attempt to
    send them via the mail provider.  If the attempt fails, try again.

    NOTE: A message failes to be dispatched if our call to the provider
          fail. Not if the provider fails to send the message. This task is
          intended for recovering from provider outages which I expect to be
          few and far between, but still need to account fo rit.

    XXX We need to likely record every attempt and slow down our retries. We
        also need a maximum amount of time we will retry. But I expect this to
        happen so rarely that we will not need to worry about this.
    """
    msg_count = 0
    for server in Server.objects.all():
        if not server.outgoing_spool_dir:
            continue
        outgoing_spool_dir = Path(server.outgoing_spool_dir)
        for spooled_message_file in outgoing_spool_dir.iterdir():
            msg_count += 1
            message = email.message_from_bytes(
                spooled_message_file.read_bytes(),
                policy=email.policy.default,
            )
            rcpt_tos = []
            for hdr in ("To", "Cc", "Bcc"):
                rcpt_tos.extend(message.get_all(hdr, []))

            delete_message = True
            try:
                # Try sending the message again but do not write it to the
                # spool if it fails.
                #
                delete_message = server.send_email_via_smtp(
                    message["From"],
                    rcpt_tos,
                    message,
                    spool_on_retryable=False,
                )
            except Exception as exc:
                # All raised exceptions are a hard fail and the spooled message
                # will be removed.
                #
                delete_message = True
                logger.exception(f"Unable to retry sending email: {exc}")
                failed_message = cast(
                    EmailMessage,
                    email.message_from_bytes(
                        message,
                        policy=email.policy.default,
                    ),
                )

                report_failed_message(
                    failed_message["From"],
                    failed_message,
                    report_text=f"Unable to send email: {str(exc)}",
                    subject=f"Failed to send: {failed_message['Subject']}",
                    action="failed",
                    status="5.1.1",
                    diagnostic=f"smtp; {str(exc)}",
                )

            if delete_message:
                spooled_message_file.unlink(missing_ok=True)

            if msg_count > DISPATCH_NUM_PER_RUN:
                return


####################################################################
#
@db_periodic_task(crontab(day="*", hour="1"))
def decrement_num_bounces_counter():
    """
    EmailAccount.num_bounces decays over time, and this is the task that
    does that decay logic.

    Currently set to decay by one ever 24 hours.
    """
    for ea in EmailAccount.objects.filter(num_bounces__gt=0):
        ea.num_bounces -= 1

        # if the account was deactivated due to number of bounces
        # and we are under the bounce limit, reactivate the account.
        #
        if (
            ea.deactivated
            and ea.deactivated_reason
            == EmailAccount.DEACTIVATED_DUE_TO_BOUNCES_REASON
            and ea.num_bounces < EmailAccount.NUM_EMAIL_BOUNCE_LIMIT
        ):
            ea.deactivated = False
            ea.deactivated_reason = None
            logger.info(
                "decrement_num_bounces_counters: Email Account %s is no longer "
                "deactivated because the number of bounces has decayed to %d",
                ea,
                ea.num_bounces,
            )
            # XXX We need to send email to the account saying that they are
            #     no longer deacivated and can now send emails again.
            #
        ea.save()


####################################################################
#
@db_task()
def dispatch_incoming_email(email_account_pk: int, email_fname: str) -> None:
    """
    This is called after a message has been received by the incoming
    hook. This decides what do with this email based on the configured email
    accounts.

    NOTE: Postmark will POST a message for every recipient of that email being
          handled by postmark. The only race conditions
    """
    email_account = EmailAccount.objects.get(pk=email_account_pk)
    email_file = Path(email_fname)
    email_msg = json.loads(email_file.read_text())
    msg = email.message_from_string(
        email_msg["raw_email"], policy=email.policy.default
    )
    try:
        deliver_message(email_account, msg)
    except Exception:
        try:
            failed_msg_fname = (
                settings.FAILED_INCOMING_MSG_DIR
                / f"{email_msg['recipient'].lower()}-{email_file.name}"
            )
            settings.FAILED_INCOMING_MSG_DIR.mkdir(parents=True, exist_ok=True)
            logger.exception(
                "Failed to deliver message %s to '%s'. Moved to '%s'",
                msg["Message-ID"],
                email_account.email_address,
                failed_msg_fname,
            )
            email_file.rename(failed_msg_fname)
        except Exception as e:
            logger.exception(
                f"Exception moving failed message from '{email_file}' to '{failed_msg_fname}': {e}"
            )
    finally:
        email_file.unlink(missing_ok=True)


####################################################################
#
@db_task(retries=3, retry_delay=15)
def process_email_bounce(email_account_pk: int, bounce: dict):
    """
    We have received an incoming bounce notification from postmark. The web
    front end decoded the bounce message and verified the email account that
    sent the message that generated the bounce and incremented the email
    accounts bounce count. This task handles the rest of the associated work:
      - if the number of bounces has been exceeded deactivate the account
      - send a notification email of the bounce to the account.

    NOTE: We have set huey task retries at 3, with a delay of 15s because we
          have seen the request for the bounce failing with "no such bounce"
          .. only to look for it by id later on and it to work fine.
    """
    # When an email account is deactivated we also send a message with just the
    # report text to the email address attached to the user account that is the
    # owner of the email account. This way if the user is unable to access
    # emails sent to their email account (because they have forwarding turned
    # on!) we will at least try to notify them via their user account that
    # there email account has been deactivated.
    #
    notify_user = False

    ea = EmailAccount.objects.get(pk=email_account_pk)
    client = ea.server.client

    # Get the bounce details if they are available.
    #
    to_addr = bounce["Email"]
    from_addr = bounce["From"]
    try:
        bounce_details = client.bounces.get(int(bounce["ID"]))
    except ClientError:
        logger.warning(
            "Unable to retrieve bounce info for bounce id: %d", bounce["ID"]
        )
        raise

    # We generate the human readable 'report_text' by constructing a list of
    # messages that will concatenated into a single string and passed as the
    # 'report_text' when making the DSN. This lets us stack up several parts of
    # the message and make it all at once instead of having to make several
    # different DSN's depending on the circumstances.
    #
    report_text = [f"Email from {from_addr} to {to_addr} has bounced."]

    # IF this bounce is not a transient bounce, then increment the number of
    # bounces this EmailAccount has generated.
    #
    transient = False
    if bounce_details.TypeCode in BOUNCE_TYPES_BY_TYPE_CODE:
        transient = BOUNCE_TYPES_BY_TYPE_CODE[bounce_details.TypeCode][
            "transient"
        ]
    else:
        logger.warning(
            f"Received bounce type code of {bounce_details.TypeCode}. This is "
            "not one of the recognized type code's. Assuming this is a "
            "non-transient bounce.",
            extra=bounce,
        )

    if not transient:
        ea.num_bounces += 1
        ea.save()
        report_text.append(f"Number of bounced emails: {ea.num_bounces}")
        report_text.append(
            f"Email account will be deactivated from sending emails if this "
            f"number exceeds {ea.NUM_EMAIL_BOUNCE_LIMIT} in a day "
            "(the number of bounces will automatically decrease by 1 each day.)"
        )

    # If `Inactive` is true then this bounce has caused postmark to disable
    # sending to this email address.
    #
    if bounce_details.Inactive:
        inactive, _ = InactiveEmail.objects.get_or_create(
            email_address=bounce_details.Email
        )
        if inactive.can_activate != bounce_details.CanActivate:
            inactive.can_activate = bounce_details.CanActivate
            inactive.save()
        logger.info(
            "Email %s is marked inactive by postmark. Can activate: %s, "
            "sending account: %s: %s",
            bounce_details.Inactive,
            bounce_details.CanActivate,
            ea.email_address,
            bounce_details.Description,
            extra=bounce,
        )

        report_text.append(
            f"Postmark has marked this email address ({bounce_details.Email}) "
            "as inactive and will not send email to this address. Postmark "
            "has marked this address as reactivatable as: "
            f"{bounce_details.CanActivate}. Contact the system adminstrator "
            "to see if this can be resolved."
        )

    # If the emailaccount is forwarding and we got a non-transient bounce when
    # sending email to the forward_to address then the account gets
    # deactivated.
    #
    if (
        ea.delivery_method == ea.FORWARDING
        and not transient
        and bounce_details.Email == ea.forward_to
    ):
        notify_user = True
        ea.deactivated = True
        ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BAD_FORWARD_TO
        # XXX Should we also change the delivery type to local delivery?
        ea.save()
        logger.info(
            "Account %s deactivated due to non-transient bounce to "
            "forward_to address: %s: %s",
            ea,
            ea.forward_to,
            bounce_details.Subject,
            extra=bounce,
        )
        report_text.append(
            f"The account ({from_addr}) has been deactivated from sending "
            f"email due the set `forward_to` ({ea.forward_to}) address "
            "generating a non-transient bounce: "
            f"{bounce_details.Description}\nNOTE: This account can "
            "still receive email. It just can not "
            "send new emails."
        )

    if not ea.deactivated:
        if ea.num_bounces >= ea.NUM_EMAIL_BOUNCE_LIMIT:
            notify_user = True
            ea.deactivated = True
            ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BOUNCES_REASON
            ea.save()
            logger.info(
                "process_email_bounce: Account %s deactivated due to "
                "excessive bounces",
                ea,
            )
            report_text.append(
                f"The account ({from_addr}) has been deactivated from sending "
                "email due to excessive bounced email messages. email account "
                "Will automatically be reactivated after in at most a day. "
                "\nNOTE: This account can still receive email. It just can not "
                "send new emails."
            )

    report_text.append(f"Bounce type: {bounce_details.Type}")
    report_text.append(f"Bounce description: {bounce_details.Description}")
    report_text.append(f"Bounce details: {bounce_details.Details}")
    report_msg = "\n".join(report_text)

    # `notify_user` means we send the report complaint to the user's email
    # address as well (not just the EmailAccount.)
    #
    if notify_user:
        send_mail(
            f"NOTICE: The email account {ea.email_address} has been "
            "deactivated and can not send email",
            report_msg,
            None,
            [ea.owner.email],
            fail_silently=True,
        )

    report_failed_message(
        ea,
        failed_message=bounce_details.Content,
        report_text=report_msg,
        subject="Bounced email: " + bounce_details.Subject,
        action="failed",
        status="5.1.1",
        diagnostic=f"smtp; {bounce_details.Details}",
    )


####################################################################
#
@db_task()
def process_email_spam(email_account_pk: int, spam: dict):
    """
    Our incoming spam complaint webhook was triggered. The view only does
    some curosry work on the data we got. The meat of the work happens in this
    task.

    Spam complaints count as bounces.
    We notify the user that sent the email.
    If `Inactive` is true get/create an InactiveEmail.
    """
    ea = EmailAccount.objects.get(pk=email_account_pk)

    # Get the bounce details if they are available.
    #
    to_addr = spam["Email"]
    from_addr = spam["From"]

    # We generate the human readable 'report_text' by constructing a list of
    # messages that will concatenated into a single string and passed as the
    # 'report_text' when making the DSN. This lets us stack up several parts of
    # the message and make it all at once instead of having to make several
    # different DSN's depending on the circumstances.
    #
    report_text = [
        f"Email marked as spam from {from_addr} to {to_addr}, "
        f"subject: '{spam['Subject']}'"
    ]

    # IF this bounce is not a transient bounce, then increment the number of
    # bounces this EmailAccount has generated.
    #
    notify_user = False
    transient = False
    if spam["TypeCode"] in BOUNCE_TYPES_BY_TYPE_CODE:
        transient = BOUNCE_TYPES_BY_TYPE_CODE[spam["TypeCode"]]["transient"]
    else:
        logger.warning(
            f"Received spam complaint of {spam['TypeCode']}. This is "
            "not one of the recognized type code's.",
            extra=spam,
        )

    if not transient:
        ea.num_bounces += 1
        ea.save()
        report_text.append(f"Number of bounced emails: {ea.num_bounces}")
        report_text.append(
            f"Email account will be deactivated from sending emails if this "
            f"number exceeds {ea.NUM_EMAIL_BOUNCE_LIMIT} in a day "
            "(the number of bounces will automatically decrease by 1 each day.)"
        )

    # If `Inactive` is true then this bounce has caused postmark to disable
    # sending to this email address.
    #
    if spam["Inactive"]:
        inactive, _ = InactiveEmail.objects.get_or_create(
            email_address=spam["Email"]
        )
        if inactive.can_activate != spam["CanActivate"]:
            inactive.can_activate = spam["CanActivate"]
            inactive.save()
        logger.info(
            "Email %s is marked inactive by postmark. Can activate: %s, "
            "sending account: %s: %s",
            spam["Email"],
            spam["CanActivate"],
            ea.email_address,
            spam["Description"],
            extra=spam,
        )

        report_text.append(
            f"Postmark has marked this email address ({spam['Email']}) "
            "as inactive and will not send email to this address. Postmark "
            "has marked this address as reactivatable as: "
            f"{spam['CanActivate']}. Contact the system adminstrator "
            "to see if this can be resolved."
        )

    # If the emailaccount is forwarding and we got a non-transient spam when
    # sending email to the forward_to address then the account gets
    # deactivated.
    #
    if (
        ea.delivery_method == ea.FORWARDING
        and not transient
        and spam["Email"] == ea.forward_to
    ):
        notify_user = True
        ea.deactivated = True
        ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BAD_FORWARD_TO
        # XXX Should we also change the delivery type to local delivery?
        ea.save()
        logger.info(
            "Account %s deactivated due to non-transient spam to "
            "forward_to address: %s: %s",
            ea,
            ea.forward_to,
            spam["Description"],
            extra=spam,
        )
        report_text.append(
            f"The account ({from_addr}) has been deactivated from sending "
            f"email due the set `forward_to` ({ea.forward_to}) address "
            "generating a non-transient spam. NOTE: This account can "
            "still receive email. It just can not send new emails."
        )

    if not ea.deactivated:
        if ea.num_bounces >= ea.NUM_EMAIL_BOUNCE_LIMIT:
            notify_user = True
            ea.deactivated = True
            ea.deactivated_reason = ea.DEACTIVATED_DUE_TO_BOUNCES_REASON
            ea.save()
            logger.info(
                "Account %s deactivated due to excessive spam/bounces",
                ea,
                extra=spam,
            )
            report_text.append(
                f"The account ({from_addr}) has been deactivated from sending "
                "email due to excessive spam email messages. the email account "
                "Will automatically be reactivated after in at most a day. "
                "\nNOTE: This account can still receive email. It just can not "
                "send new emails."
            )

    report_text.append(f"Spam type: {spam['Type']}")
    report_text.append(f"Spam description: {spam['Description']}")
    report_text.append(f"Spam details: {spam['Details']}")
    report_msg = "\n".join(report_text)

    # `notify_user` means we send the report complaint to the user's email
    # address as well (not just the EmailAccount.)
    #
    if notify_user:
        send_mail(
            f"NOTICE: The email account {ea.email_address} has been "
            "deactivated and can not send email",
            report_msg,
            None,
            [ea.owner.email],
            fail_silently=True,
        )

    msg = spam["Content"] if "Content" in spam else spam["Description"]
    report_failed_message(
        ea,
        failed_message=msg,
        report_text=report_msg,
        subject="Message marked as spam: " + spam["Subject"],
        action="failed",
        status="5.1.1",
        diagnostic=f"smtp; {spam['Details']}",
    )


####################################################################
#
@db_task(retries=10, retry_delay=2)
@lock_task("pwfile")
def check_update_pwfile_for_emailaccount(ea_pk: int):
    """
    We are doing a manual retry because normal retries still log exceptions
    and there seem to be a problem with huey and the version of redis we are
    using getting a ZADD error like we are using a priority queue or
    something.. so just do our own retries on failures to look up the email
    account.
    """
    # The password file is at the root of the maildir directory
    #
    write = False
    ea = EmailAccount.objects.get(pk=ea_pk)

    # NOTE: The path to the mail dir is relative to the directory that the
    #       password file is in. In settings the password file is always in
    #       MAIL_DIRS directory.
    #
    ea_mail_dir = Path(ea.mail_dir).relative_to(settings.EXT_PW_FILE.parent)
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    if ea.email_address not in accounts:
        accounts[ea.email_address] = PWUser(
            ea.email_address, ea_mail_dir, ea.password
        )
        write = True
        logger.info("Adding '%s' to external password file", ea.email_address)
    else:
        account = accounts[ea.email_address]
        if account.maildir != ea_mail_dir:
            account.maildir = ea_mail_dir
            logger.info(
                "Updating '%s''s mail dir to: '%s' in external password file",
                ea.email_address,
                ea.mail_dir,
            )
            write = True
        if account.pw_hash != ea.password:
            account.pw_hash = ea.password
            logger.info(
                "Updating '%s''s password hash external password file",
                ea.email_address,
            )
            write = True

    if write:
        write_emailaccount_pwfile(settings.EXT_PW_FILE, accounts)


####################################################################
#
@task(retries=5, retry_delay=5)
@lock_task("pwfile")
def delete_emailaccount_from_pwfile(email_address: str):
    accounts = read_emailaccount_pwfile(settings.EXT_PW_FILE)
    if email_address in accounts:
        logger.info("Deleting '%s' from external password file", email_address)
        del accounts[email_address]
        write_emailaccount_pwfile(settings.EXT_PW_FILE, accounts)
