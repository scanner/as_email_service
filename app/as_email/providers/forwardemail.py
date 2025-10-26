#!/usr/bin/env python
#
"""
ForwardEmail provider backend implementation.

Implements webhook handler for incoming email from forwardemail.net.
This is a receive-only provider - it does not support sending email.

References:
- API Documentation: https://forwardemail.net/en/email-api
- Webhook Documentation: https://forwardemail.net/en/faq#do-you-support-webhooks
- SMTP Integration Guide: https://forwardemail.net/en/guides/smtp-integration#python-integration
"""
# system imports
#
import email.message
import json
import logging
from typing import TYPE_CHECKING

# 3rd party imports
#
from django.http import HttpRequest, HttpResponseBadRequest, JsonResponse

# project imports
#
from ..models import EmailAccount
from ..tasks import dispatch_incoming_email
from ..utils import split_email_mailbox_hash, write_spooled_email
from .base import ProviderBackend

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import Server

logger = logging.getLogger("as_email.providers.forwardemail")


########################################################################
########################################################################
#
class ForwardEmailBackend(ProviderBackend):
    """
    Backend implementation for ForwardEmail.net email service provider.

    This is a receive-only provider. It handles incoming email webhooks
    from forwardemail.net but does not support sending email.

    References:
    - API Documentation: https://forwardemail.net/en/email-api
    - Webhook Documentation: https://forwardemail.net/en/faq#do-you-support-webhooks
    - SMTP Integration: https://forwardemail.net/en/guides/smtp-integration#python-integration
    """

    PROVIDER_NAME = "forwardemail"

    ####################################################################
    #
    def send_email_smtp(
        self,
        server: "Server",
        email_from: str,
        rcpt_tos: list[str],
        msg: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via SMTP - NOT SUPPORTED.

        ForwardEmail is a receive-only provider and does not support
        sending email.

        Raises:
            NotImplementedError: This provider does not support sending
        """
        raise NotImplementedError(
            f"{self.PROVIDER_NAME} is a receive-only provider and does not "
            "support sending email"
        )

    ####################################################################
    #
    def send_email_api(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via API - NOT SUPPORTED.

        ForwardEmail is a receive-only provider and does not support
        sending email.

        Raises:
            NotImplementedError: This provider does not support sending
        """
        raise NotImplementedError(
            f"{self.PROVIDER_NAME} is a receive-only provider and does not "
            "support sending email"
        )

    ####################################################################
    #
    def handle_incoming_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle incoming email webhook from ForwardEmail.net.

        ForwardEmail POSTs a JSON payload containing the raw email message
        and recipient information. The `recipients` field is an array that
        may contain multiple local addresses that should receive this message.

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
                "Incoming webhook for %s: %r", server.domain_name, exc
            )
            return HttpResponseBadRequest(f"invalid json: {exc}")

        # Extract key fields from the forwardemail webhook
        #
        message_id = incoming_msg.get("messageId", "<unknown>")
        from_addr = incoming_msg.get("from", {})
        if isinstance(from_addr, dict):
            from_addr_str = from_addr.get("text", "<unknown>")
        else:
            from_addr_str = str(from_addr)

        # Get the raw email message - this is the complete RFC822 message
        #
        if "raw" not in incoming_msg:
            logger.warning(
                "Email received from forwardemail without `raw` field, "
                "message id: %s",
                message_id,
            )
            return JsonResponse(
                {
                    "status": "error",
                    "message": "missing raw email content",
                }
            )

        raw_email = incoming_msg["raw"]

        # Get the recipients list - forwardemail may deliver to multiple
        # local addresses in a single webhook
        #
        recipients = incoming_msg.get("recipients", [])
        if not recipients:
            logger.warning(
                "Email received from forwardemail without recipients, "
                "message id: %s",
                message_id,
            )
            return JsonResponse(
                {
                    "status": "all good",
                    "message": "no recipients",
                }
            )

        # Process each recipient - dispatch delivery for each local address
        #
        delivered_count = 0
        failed_recipients = []

        for recipient in recipients:
            # Handle potential +hash addressing
            #
            addr, _ = split_email_mailbox_hash(recipient)

            try:
                email_account = EmailAccount.objects.get(email_address=addr)
            except EmailAccount.DoesNotExist:
                logger.info(
                    "Received email for EmailAccount that does not exist: %s, from: %s",
                    addr,
                    from_addr_str,
                )
                failed_recipients.append(addr)
                # XXX: Track metrics for email to non-existent accounts
                continue

            # Write the email to the spool directory
            #
            spooled_msg_path = write_spooled_email(
                recipient,
                server.incoming_spool_dir,
                raw_email,
                msg_id=message_id,
                msg_date=incoming_msg.get("date"),
            )

            # Fire off async huey task to dispatch the email
            #
            dispatch_incoming_email(email_account.pk, str(spooled_msg_path))
            delivered_count += 1

            logger.info(
                "deliver_email_locally: Queued delivery for '%s', message %s, from %s",
                recipient,
                message_id,
                from_addr_str,
            )

        # Return status indicating how many recipients were processed
        #
        if delivered_count == 0:
            return JsonResponse(
                {
                    "status": "all good",
                    "message": f"no valid recipients among {len(recipients)} provided",
                    "failed_recipients": failed_recipients,
                }
            )

        return JsonResponse(
            {
                "status": "all good",
                "message": f"queued delivery for {delivered_count} of {len(recipients)} recipients",
                "delivered": delivered_count,
                "failed_recipients": failed_recipients,
            }
        )

    ####################################################################
    #
    def handle_bounce_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle bounce notification webhook - NOT SUPPORTED.

        ForwardEmail is a receive-only provider and does not send email,
        so bounce notifications are not applicable.

        Returns:
            JsonResponse indicating this webhook is not supported
        """
        logger.warning(
            "Received bounce webhook for receive-only provider %s on server %s",
            self.PROVIDER_NAME,
            server.domain_name,
        )
        return JsonResponse(
            {
                "status": "not supported",
                "message": f"{self.PROVIDER_NAME} is a receive-only provider",
            }
        )

    ####################################################################
    #
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> JsonResponse:
        """
        Handle spam complaint webhook - NOT SUPPORTED.

        ForwardEmail is a receive-only provider and does not send email,
        so spam complaints are not applicable.

        Returns:
            JsonResponse indicating this webhook is not supported
        """
        logger.warning(
            "Received spam webhook for receive-only provider %s on server %s",
            self.PROVIDER_NAME,
            server.domain_name,
        )
        return JsonResponse(
            {
                "status": "not supported",
                "message": f"{self.PROVIDER_NAME} is a receive-only provider",
            }
        )
