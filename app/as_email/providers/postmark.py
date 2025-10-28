#!/usr/bin/env python
#
"""
Postmark provider backend implementation.

Implements email sending via Postmark's SMTP and API, and webhook handlers
for incoming email, bounces, and spam notifications.
"""
# system imports
#
import email.message
import json
import logging
import smtplib
from typing import TYPE_CHECKING, Any, List

# 3rd party imports
#
from django.http import HttpRequest, HttpResponseBadRequest, JsonResponse
from postmarker.core import PostmarkClient
from postmarker.exceptions import ClientError
from requests import RequestException

# project imports
#
from ..models import EmailAccount
from ..provider_tokens import get_provider_token
from ..tasks import (
    dispatch_incoming_email,
    process_email_bounce,
    process_email_spam,
)
from ..utils import (
    get_smtp_client,
    msg_froms,
    sendmail,
    split_email_mailbox_hash,
    spool_message,
    write_spooled_email,
)
from .base import ProviderBackend

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import Server

logger = logging.getLogger("as_email.providers.postmark")


########################################################################
########################################################################
#
class PostmarkBackend(ProviderBackend):
    """
    Backend implementation for Postmark email service provider.

    Handles sending emails via Postmark's SMTP and API endpoints, and
    processing webhooks for incoming email, bounces, and spam notifications.
    """

    PROVIDER_NAME = "postmark"

    ####################################################################
    #
    def _get_client(self, server: "Server") -> PostmarkClient:
        """
        Get a PostmarkClient instance for the given server.

        Args:
            server: The Server instance to get a client for

        Returns:
            Configured PostmarkClient instance

        Raises:
            KeyError: If server token is not configured
        """
        token = get_provider_token(self.PROVIDER_NAME, server.domain_name)
        if not token:
            raise KeyError(
                f"The token for {self.PROVIDER_NAME} provider on server "
                f"'{server.domain_name}' is not defined in `settings.EMAIL_SERVER_TOKENS`"
            )
        return PostmarkClient(server_token=token)

    ####################################################################
    #
    def send_email_smtp(
        self,
        server: "Server",
        email_from: str,
        rcpt_tos: List[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via Postmark's SMTP service.

        This method connects to Postmark's SMTP server, authenticates with the
        server token, and sends the email. On retryable failures, the message
        is spooled for later retry if spool_on_retryable is True.

        Args:
            server: The Server instance sending the email
            email_from: The email address sending from (must match server domain)
            rcpt_tos: List of recipient email addresses
            msg: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise

        Raises:
            ValueError: If email_from domain doesn't match server domain
            KeyError: If server token is not configured in settings
        """
        if server.domain_name != email_from.split("@")[-1]:
            raise ValueError(
                f"Domain name of {email_from} is not the same "
                f"as the server's: {server.domain_name}"
            )

        token = get_provider_token(self.PROVIDER_NAME, server.domain_name)
        if not token:
            raise KeyError(
                f"The token for {self.PROVIDER_NAME} provider on server "
                f"'{server.domain_name}' is not defined in `settings.EMAIL_SERVER_TOKENS`"
            )

        # Add `X-PM-Message-Stream: outbound` header for postmark. Make sure
        # that there is only ONE `X-PM-Message-Stream` header.
        #
        # NOTE: In the future we might want to support other streams besides
        #       "outbound" and this would likely be set on the Server object.
        #
        del msg["X-PM-Message-Stream"]
        msg["X-PM-Message-Stream"] = "outbound"

        smtp_server, port = server.send_provider.smtp_server.split(":")
        smtp_client = get_smtp_client(smtp_server, int(port))
        try:
            smtp_client.starttls()
            smtp_client.login(token, token)
            sendmail(smtp_client, msg, from_addr=email_from, to_addrs=rcpt_tos)
        except smtplib.SMTPException as exc:
            logger.error(
                "Mail from %s, to: %s, failed with exception: %r",
                email_from,
                rcpt_tos,
                exc,
            )
            if spool_on_retryable:
                spool_message(server.outgoing_spool_dir, msg.as_bytes())
            return False
        finally:
            smtp_client.quit()
        return True

    ####################################################################
    #
    def send_email_api(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via Postmark's web API.

        Uses the postmarker library to send emails via Postmark's REST API.
        On retryable failures (network issues, rate limits, maintenance), the
        message is spooled for later retry if spool_on_retryable is True.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        client = self._get_client(server)
        try:
            client.emails.send(message)
        except RequestException as exc:
            logger.error(
                "Failed to send email: %r. Spooling for retransmission", exc
            )
            if spool_on_retryable:
                spool_message(server.outgoing_spool_dir, message.as_bytes())
            return False
        except ClientError as exc:
            # For certain error codes we spool for retry. For everything else
            # it will fail here and now.
            #
            if exc.error_code in (
                100,  # Maintenance
                405,  # Account has run out of credits
                429,  # Rate limit exceeded
            ):
                if spool_on_retryable:
                    spool_message(server.outgoing_spool_dir, message.as_bytes())
                    logger.warning("Spooling message for retry (%r)", exc)
                else:
                    logger.warning("Message retry failed: (%r)", exc)
                return False
            else:
                logger.error("Failed to send email: %r", exc)
                raise
        return True

    ####################################################################
    #
    def handle_incoming_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle incoming email webhook from Postmark.

        When emails arrive, Postmark POSTs to this webhook once for each
        recipient address. The `OriginalRecipient` field contains the specific
        email address this POST is for.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        try:
            incoming_msg = json.loads(request.body)
        except json.JSONDecodeError as exc:
            logger.warning(
                "Incoming web hook for %s: %r", server.domain_name, exc
            )
            return HttpResponseBadRequest(f"invalid json: {exc}")

        message_id = incoming_msg.get("MessageID")
        from_addr = incoming_msg.get("From", "<unknown>")

        if "OriginalRecipient" not in incoming_msg:
            logger.warning(
                "email received from postmark without `OriginalRecipient`, "
                "message id: %s",
                message_id,
            )
            return JsonResponse(
                {
                    "status": "all good",
                    "message": "no original recipient",
                }
            )

        # Find out who this email is being sent to, and validate that there is
        # an EmailAccount for that address. If it is not one we serve, we need
        # to log/record metrics about that but otherwise drop it on the floor.
        #
        # This is wasteful but not wasteful.. we look up all the EmailAccounts
        # that this email will be delivered to, and if it is zero we just stop
        # right here. Wasteful in that we do this lookup again inside the huey
        # task.. but that is probably still better than all the work to write
        # the email to the spool dir and invoke the huey task only for it to do
        # nothing.
        #
        addr, _ = split_email_mailbox_hash(incoming_msg["OriginalRecipient"])
        try:
            email_account = EmailAccount.objects.get(email_address=addr)
        except EmailAccount.DoesNotExist:
            logger.info(
                "Received email for EmailAccount that does not exist: %s, from: %s",
                addr,
                from_addr,
            )
            # XXX here we would log metrics for getting email that no one is
            #     going to receive.
            #
            return JsonResponse(
                {
                    "status": "all good",
                    "message": f"no such email account '{addr}'",
                },
            )

        spooled_msg_path = write_spooled_email(
            incoming_msg["OriginalRecipient"],
            server.incoming_spool_dir,
            incoming_msg["RawEmail"],
            msg_id=message_id,
            msg_date=incoming_msg.get("Date"),
        )

        # Fire off async huey task to dispatch the email we just wrote to the
        # spool directory.
        #
        dispatch_incoming_email(email_account.pk, str(spooled_msg_path))

        msg = email.message_from_string(
            incoming_msg["RawEmail"], policy=email.policy.default
        )
        msg_id = msg.get("Message-ID", "unknown")
        msg_from = msg_froms(msg)
        logger.info(
            "deliver_email_locally: Queued delivery for '%s', message %s, from %s",
            incoming_msg["OriginalRecipient"],
            msg_id,
            msg_from,
        )

        return JsonResponse(
            {"status": "all good", "message": str(spooled_msg_path)}
        )

    ####################################################################
    #
    def handle_bounce_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle bounce notification webhook from Postmark.

        Postmark sends bounce notifications when sent emails fail to deliver.
        After initial validation, the bulk of the processing is handled in
        an async Huey task.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        try:
            bounce = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning(
                "Bad json from caller: %r", exc, extra={"body": request.body}
            )
            return HttpResponseBadRequest(f"invalid json: {exc}")

        # Make sure the json message from postmark contains at least the keys
        # we expect.
        #
        if not all(
            [
                x in bounce
                for x in ("From", "Type", "ID", "Email", "Description")
            ]
        ):
            return HttpResponseBadRequest(
                "submitted json missing expected keys"
            )

        logger.info(
            "postmark bounce hook: message from %s to %s: %s",
            bounce["From"],
            bounce["Email"],
            bounce["Description"],
        )

        try:
            ea = EmailAccount.objects.get(email_address=bounce["From"])
        except EmailAccount.DoesNotExist:
            logger.warning(
                "%s from email address that does not belong "
                "to any EmailAccount: %s, server: %s, bounce id: %d, to: %s, "
                "description: %s",
                bounce["Type"],
                bounce["From"],
                server,
                bounce["ID"],
                bounce["Email"],
                bounce["Description"],
                extra=bounce,
            )
            # NOTE: This does not return an error. Not their fault unless they are
            #       buggeed, but we should log it. Maybe we just deleted that
            #       EmailAccount. Hmm.. maybe we should send the bounce message
            #       to the django support email address.
            #
            return JsonResponse(
                {
                    "status": "all good",
                    "message": f"`from` address '{bounce['From']}' is not an "
                    f"EmailAccount on server {server.domain_name}. "
                    "Bounce message ignored.",
                }
            )

        # We do the rest of the processing in an async huey task (this will involve
        # querying postmark's bounce API, and sending a notification email to the
        # email account in question.)
        #
        process_email_bounce(ea.pk, bounce)

        return JsonResponse(
            {
                "status": "all good",
                "message": f"received bounce for {server}/{ea.email_address}",
            }
        )

    ####################################################################
    #
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle spam complaint webhook from Postmark.

        When Postmark receives a spam complaint, the destination email address
        becomes "inactive" and can no longer receive email from us. After initial
        validation, processing is handled in an async Huey task.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            JsonResponse indicating success or failure
        """
        try:
            spam = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning(
                "Bad json from caller: %r", exc, extra={"body": request.body}
            )
            return HttpResponseBadRequest(f"invalid json: {exc}")

        # Make sure the json message from postmark contains at least the keys
        # we expect.
        #
        if not all(
            [
                x in spam
                for x in (
                    "From",
                    "Type",
                    "TypeCode",
                    "Details",
                    "Subject",
                    "ID",
                    "Email",
                    "Description",
                )
            ]
        ):
            logger.warning(
                "submitted json missing expected keys, message: %r", spam
            )
            return HttpResponseBadRequest(
                "submitted json missing expected keys"
            )

        # Just to be safe, try to make sure that the TypeCode is an integer.
        #
        try:
            spam["TypeCode"] = int(spam["TypeCode"])
        except ValueError:
            logger.error(
                "From: %s, to %s, ID: %s - TypeCode is not an integer: '%s'",
                spam["From"],
                spam["Email"],
                spam["ID"],
                spam["TypeCode"],
                extra=spam,
            )
            spam["TypeCode"] = 2048  # Mark it as 'unknown'

        logger.warning(
            "message from %s to %s. Message ID: %s, Postmark ID: %s: %s",
            spam["From"],
            spam["Email"],
            spam["MessageID"],
            spam["ID"],
            spam["Description"],
            extra=spam,
        )

        try:
            ea = EmailAccount.objects.get(email_address=spam["From"])
        except EmailAccount.DoesNotExist:
            logger.warning(
                "%s from email address that does not belong "
                "to any EmailAccount: %s, server: %s, Postmark id: %d, to: %s, "
                "description: %s",
                spam["Type"],
                spam["From"],
                server,
                spam["ID"],
                spam["Email"],
                spam["Description"],
                extra=spam,
            )
            # NOTE: This does not return an error. Not their fault unless they are
            #       buggeed, but we should log it. Maybe we just deleted that
            #       EmailAccount. Hmm.. maybe we should send the spam message
            #       to the django support email address.
            #
            return JsonResponse(
                {
                    "status": "all good",
                    "message": f"`from` address '{spam['From']}' is not an "
                    f"EmailAccount on server {server.domain_name}. "
                    "Spam message ignored.",
                }
            )

        # We do the rest of the processing in an async huey task (this will involve
        # querying postmark's spam API, and sending a notification email to the
        # email account in question.)
        #
        process_email_spam(ea.pk, spam)

        return JsonResponse(
            {
                "status": "all good",
                "message": f"received spam for {server.domain_name}/{ea.email_address}",
            }
        )

    ####################################################################
    #
    # Domain and Alias Management Methods (Stubs for future implementation)
    #
    ####################################################################

    ####################################################################
    #
    def create_domain(self, server: "Server") -> None:
        """
        Create a domain (server) on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future GH-180 implementation. Currently, Postmark
        servers must be created manually through their web interface.

        Args:
            server: The Server instance representing the domain
        """
        logger.info(
            "Postmark domain creation not yet implemented for %s (GH-180)",
            server.domain_name,
        )

    ####################################################################
    #
    def create_email_account(self, email_account: "EmailAccount") -> None:
        """
        Create an alias for an EmailAccount on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future implementation. Postmark doesn't have a
        concept of per-address aliases like forwardemail.net does.

        Args:
            email_account: The EmailAccount to create an alias for
        """
        logger.debug(
            "Postmark does not require alias creation for %s",
            email_account.email_address,
        )

    ####################################################################
    #
    def delete_email_account(self, email_account: "EmailAccount") -> None:
        """
        Delete an alias for an EmailAccount on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future implementation. Postmark doesn't have a
        concept of per-address aliases like forwardemail.net does.

        Args:
            email_account: The EmailAccount whose alias to delete
        """
        logger.debug(
            "Postmark does not require alias deletion for %s",
            email_account.email_address,
        )

    ####################################################################
    #
    def delete_email_account_by_address(
        self, email_address: str, server: "Server"
    ) -> None:
        """
        Delete an alias by email address on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future implementation. Postmark doesn't have a
        concept of per-address aliases like forwardemail.net does.

        Args:
            email_address: The email address of the alias to delete
            server: The Server instance for this domain
        """
        logger.debug(
            "Postmark does not require alias deletion for %s",
            email_address,
        )

    ####################################################################
    #
    def enable_email_account(
        self, email_account: "EmailAccount", is_enabled: bool = True
    ) -> None:
        """
        Enable or disable an alias on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future implementation. Postmark doesn't have a
        concept of enabling/disabling individual aliases.

        Args:
            email_account: The EmailAccount to enable/disable
            is_enabled: True to enable, False to disable
        """
        logger.debug(
            "Postmark does not support enable/disable for %s",
            email_account.email_address,
        )

    ####################################################################
    #
    def list_email_accounts(self, server: "Server") -> list[dict[str, Any]]:
        """
        List all aliases for a server on Postmark - NOT YET IMPLEMENTED.

        This is a stub for future implementation. Postmark doesn't have a
        concept of per-address aliases like forwardemail.net does.

        Args:
            server: The Server instance to list aliases for

        Returns:
            Empty list (no aliases to list)
        """
        logger.debug(
            "Postmark does not have aliases to list for %s",
            server.domain_name,
        )
        return []
