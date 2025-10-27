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
from .models import EmailAccount, InactiveEmail, Provider, Server
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


########################################################################
########################################################################
#
# Provider Domain and Alias Management Tasks
#
# These tasks handle domain and alias creation/deletion/synchronization
# across multiple email providers (forwardemail, postmark, etc.)
#
########################################################################
########################################################################


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_create_domain(server_pk: int, provider_name: str) -> None:
    """
    Create a domain on the specified provider when a server is configured
    to use that provider.

    This task is triggered when a provider is added to a Server's
    receive_providers or set as send_provider.

    Args:
        server_pk: Primary key of the Server instance
        provider_name: Name of the provider backend (e.g., 'forwardemail', 'postmark')
    """
    from .providers import get_backend

    server = Server.objects.get(pk=server_pk)
    backend = get_backend(provider_name)()

    try:
        backend.create_domain(server)
        logger.info(
            "Created domain '%s' on provider '%s' for server %d",
            server.domain_name,
            provider_name,
            server_pk,
        )
    except Exception as e:
        logger.exception(
            "Failed to create domain '%s' on provider '%s': %s",
            server.domain_name,
            provider_name,
            e,
        )
        raise


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_create_alias(email_account_pk: int, provider_name: str) -> None:
    """
    Create a domain alias on the specified provider for an EmailAccount.

    This task is triggered when an EmailAccount is created and its server
    has the specified provider configured.

    Args:
        email_account_pk: Primary key of the EmailAccount instance
        provider_name: Name of the provider backend (e.g., 'forwardemail', 'postmark')
    """
    from .providers import get_backend

    email_account = EmailAccount.objects.get(pk=email_account_pk)
    backend = get_backend(provider_name)()

    try:
        backend.create_email_account(email_account)
        logger.info(
            "Created alias for '%s' on provider '%s'",
            email_account.email_address,
            provider_name,
        )
    except Exception as e:
        logger.exception(
            "Failed to create alias for '%s' on provider '%s': %s",
            email_account.email_address,
            provider_name,
            e,
        )
        raise


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_delete_alias(
    email_address: str, domain_name: str, provider_name: str
) -> None:
    """
    Delete a domain alias from the specified provider.

    This task is triggered when an EmailAccount is deleted. We pass the
    email_address and domain_name as strings rather than the EmailAccount
    pk because the EmailAccount may no longer exist when this task runs.

    Args:
        email_address: The email address of the alias to delete
        domain_name: The domain name of the server
        provider_name: Name of the provider backend (e.g., 'forwardemail', 'postmark')
    """
    from .providers import get_backend

    backend = get_backend(provider_name)()

    try:
        # We need to look up the server to get provider-specific info
        server = Server.objects.get(domain_name=domain_name)
        backend.delete_email_account_by_address(email_address, server)
        logger.info(
            "Deleted alias for '%s' from provider '%s'",
            email_address,
            provider_name,
        )
    except Server.DoesNotExist:
        logger.warning(
            "Cannot delete alias for '%s': server '%s' no longer exists",
            email_address,
            domain_name,
        )
    except Exception as e:
        logger.exception(
            "Failed to delete alias for '%s' from provider '%s': %s",
            email_address,
            provider_name,
            e,
        )
        raise


####################################################################
#
@db_task(retries=3, retry_delay=10)
def provider_enable_all_aliases(
    server_pk: int, provider_name: str, is_enabled: bool
) -> None:
    """
    Enable or disable all domain aliases for a server on the specified provider.

    This task fetches the current state of all aliases from the provider,
    compares with local EmailAccounts, and only updates aliases that need
    changing. It will also create any missing aliases.

    This task is triggered when:
    - Provider is added to Server's receive_providers (is_enabled=True)
    - Provider is removed from Server's receive_providers (is_enabled=False)

    Args:
        server_pk: Primary key of the Server instance
        provider_name: Name of the provider backend (e.g., 'forwardemail', 'postmark')
        is_enabled: True to enable aliases, False to disable them
    """
    from .providers import get_backend

    server = Server.objects.get(pk=server_pk)
    backend = get_backend(provider_name)()

    # Get all EmailAccounts for this server
    email_accounts = EmailAccount.objects.filter(server=server)
    local_addresses = {ea.email_address: ea for ea in email_accounts}

    # Fetch all existing aliases from the provider
    try:
        remote_aliases = backend.list_email_accounts(server)
    except Exception as e:
        logger.exception(
            "Failed to list aliases for server '%s' on provider '%s': %s",
            server.domain_name,
            provider_name,
            e,
        )
        raise

    # Build a map of remote aliases by email address
    remote_map = {}
    for alias in remote_aliases:
        # Extract email address from alias data
        # Format depends on provider, but typically has 'name' field for mailbox name
        mailbox_name = alias.get("name")
        if mailbox_name:
            email_addr = f"{mailbox_name}@{server.domain_name}"
            remote_map[email_addr] = alias

    created_count = 0
    updated_count = 0
    skipped_count = 0
    error_count = 0

    # Process each local EmailAccount
    for email_addr, email_account in local_addresses.items():
        try:
            if email_addr not in remote_map:
                # Alias doesn't exist on provider, create it
                backend.create_email_account(email_account)
                created_count += 1
                logger.info(
                    "Created missing alias for '%s' on provider '%s'",
                    email_addr,
                    provider_name,
                )
            else:
                # Alias exists, check if is_enabled needs updating
                remote_alias = remote_map[email_addr]
                remote_enabled = remote_alias.get("is_enabled", False)

                if remote_enabled != is_enabled:
                    # Need to update is_enabled flag
                    backend.enable_email_account(
                        email_account, is_enabled=is_enabled
                    )
                    updated_count += 1
                    logger.debug(
                        "Updated is_enabled=%s for alias '%s' on provider '%s'",
                        is_enabled,
                        email_addr,
                        provider_name,
                    )
                else:
                    # Already in correct state, skip
                    skipped_count += 1

        except Exception as e:
            error_count += 1
            logger.exception(
                "Failed to process alias '%s' on provider '%s': %s",
                email_addr,
                provider_name,
                e,
            )

    logger.info(
        "Bulk alias sync for server '%s' on provider '%s': "
        "%d created, %d updated, %d skipped, %d errors (target is_enabled=%s)",
        server.domain_name,
        provider_name,
        created_count,
        updated_count,
        skipped_count,
        error_count,
        is_enabled,
    )


####################################################################
#
@db_periodic_task(crontab(minute="0"))
def provider_sync_aliases() -> None:
    """
    Hourly task to sync alias is_enabled state across all configured providers.

    This ensures that the is_enabled flag for all aliases on each provider
    matches the expected state based on whether that provider is configured
    as a receive provider for each server.
    """
    from .providers import get_backend

    # Process each provider that supports alias management
    for provider in Provider.objects.all():
        try:
            get_backend(provider.backend_name)
        except Exception as e:
            logger.warning(
                "Failed to get backend for provider '%s': %s",
                provider.backend_name,
                e,
            )
            continue

        servers_with_provider = Server.objects.filter(
            receive_providers=provider
        )

        for server in servers_with_provider:
            try:
                # Use the same logic as provider_enable_all_aliases
                # to sync all aliases for this server (target: is_enabled=True)
                provider_enable_all_aliases(
                    server.pk, provider.backend_name, is_enabled=True
                )
            except Exception as e:
                logger.exception(
                    "Failed to sync aliases for server '%s' on provider '%s': %s",
                    server.domain_name,
                    provider.backend_name,
                    e,
                )


####################################################################
#
@db_periodic_task(crontab(day="*", hour="2"))
def provider_report_unused_domains() -> None:
    """
    Daily task to report domains on all providers that have no active aliases.

    This helps identify domains that can potentially be cleaned up manually.
    The report is logged and can be used to inform manual domain deletion.
    """
    from .providers import get_backend

    all_unused = []

    # Process each provider that supports domain management
    for provider in Provider.objects.all():
        try:
            get_backend(provider.backend_name)
        except Exception as e:
            logger.warning(
                "Failed to get backend for provider '%s': %s",
                provider.backend_name,
                e,
            )
            continue

        servers_with_provider = Server.objects.filter(
            receive_providers=provider
        )
        unused_domains = []

        for server in servers_with_provider:
            alias_count = EmailAccount.objects.filter(server=server).count()

            if alias_count == 0:
                unused_domains.append((server.domain_name, 0))
            else:
                # Even if there are EmailAccounts, check if any are actually enabled
                try:
                    backend = get_backend(provider.backend_name)()
                    aliases = backend.list_email_accounts(server)
                    enabled_count = sum(
                        1 for alias in aliases if alias.get("is_enabled")
                    )
                    if enabled_count == 0:
                        unused_domains.append((server.domain_name, alias_count))
                except Exception as e:
                    logger.warning(
                        "Failed to check aliases for domain '%s' on provider '%s': %s",
                        server.domain_name,
                        provider.backend_name,
                        e,
                    )

        if unused_domains:
            all_unused.append((provider.backend_name, unused_domains))

    if all_unused:
        report_lines = ["Provider unused domains report:"]
        for provider_name, domains in all_unused:
            report_lines.append(f"\nProvider '{provider_name}':")
            for domain, count in domains:
                report_lines.append(f"  - {domain}: {count} alias(es)")
        logger.info("\n".join(report_lines))
    else:
        logger.info("No unused domains found across all providers")
