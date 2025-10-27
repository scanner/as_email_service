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
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from io import BytesIO
from typing import TYPE_CHECKING, Any, Optional
from urllib.error import HTTPError
from urllib.parse import urljoin

# 3rd party imports
#
import requests
from django.conf import settings
from django.http import HttpRequest, HttpResponseBadRequest, JsonResponse
from django.urls import reverse

# project imports
#
from ..models import EmailAccount
from ..provider_tokens import get_provider_token
from ..tasks import dispatch_incoming_email
from ..utils import (
    now_str_datetime,
    redis_client,
    split_email_mailbox_hash,
    utc_now_str,
    write_spooled_email,
)
from .base import ProviderBackend

if TYPE_CHECKING:
    from redis import StrictRedis

    from ..models import EmailAccount, Server

logger = logging.getLogger("as_email.providers.forwardemail")


########################################################################
########################################################################
#
class HTTPMethod(StrEnum):
    PUT = "put"
    POST = "post"
    GET = "GET"
    DEL = "DEL"


########################################################################
########################################################################
#
class ObjType(StrEnum):
    DOMAIN = "domain"
    ALIAS = "alias"


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
    API_ENDPOINT = "https://api.forwardemail.net/"

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

    ####################################################################
    #
    @classmethod
    def _req(cls, method: HTTPMethod, url: str, data=None) -> requests.Response:
        """
        Construct the url from the api endpoint + relative URL provided.
        """
        u = urljoin(cls.API_ENDPOINT, url)
        token = get_provider_token(cls.PROVIDER_NAME, "account_api_key")
        r = requests.request(str(method), u, auth=(token, ""), data=data)
        if r.status_code != 200:
            raw = BytesIO(r.text)
            raise HTTPError(u, r.status_code, r.reason, r.headers, raw)
        return r

    ####################################################################
    #
    @classmethod
    def _redis_key(cls, obj_type: ObjType, key: str) -> str:
        return f"{cls.PROVIDER_NAME}:{obj_type}:{key}"

    ####################################################################
    #
    def list_domains(self) -> dict[str, dict[str, Any]]:
        """
        List all the domains we have configured on our forwardemail.net
        provider. Store a mapping from the domain name to the id in redis.
        Return a dict. Each key in the dict is a domain name configured on the
        forwardemail.net provider, its value is the dict response for that
        domain name info from forwardemail.net. We also store a key in redis
        based on the domain name that stores as its value the id.
        """
        # XXX when we hit 1,000 domain names we will need to support paging
        #     through the results.
        #
        r = self._req(HTTPMethod.GET, "v1/domains")
        redis = redis_client()
        domains = r.json()
        result = {}
        for domain_info in domains:
            domain_name = domain_info["name"]
            domain_id = domain_info["id"]
            result[domain_name] = domain_info
            redis_key = self._redis_key(ObjType.DOMAIN, domain_name)
            redis.set(redis_key, domain_id)

        # Set a key indicating we got the list of domains.
        #
        redis_key = self._redis_key(ObjType.DOMAIN, "all_domains")
        redis.set(redis_key, utc_now_str())

        return result

    ####################################################################
    #
    @classmethod
    def update_domains(cls, redis: Optional["StrictRedis"] = None) -> None:
        """
        Refresh the domain mapping from forwardemail.net if it's stale.

        Checks the timestamp of the last domain list refresh. If it's more than
        one hour old or doesn't exist, calls list_domains() to refresh the
        domain-to-id mapping in Redis.
        """
        redis = redis() if redis is None else redis
        redis_key = cls._redis_key(ObjType.DOMAIN, "all_domains")
        last_update_str = redis.get(redis_key)

        # If we've never fetched domains, fetch them now
        #
        if last_update_str is None:
            logger.info(
                "Domain mapping not found in Redis, fetching from forwardemail.net"
            )
            cls().list_domains()
            return

        # Parse the timestamp and check if it's stale
        #
        last_update = now_str_datetime(last_update_str.decode())
        age = datetime.now(UTC) - last_update

        if age > timedelta(hours=1):
            logger.info(
                "Domain mapping is %s old (>1 hour), refreshing from forwardemail.net",
                age,
            )
            cls().list_domains()
        else:
            logger.debug(
                "Domain mapping is %s old (<1 hour), skipping refresh", age
            )

    ####################################################################
    #
    def create_domain(self, server: "Server") -> dict[str, Any]:
        """
        Create a domain in forwardemail.net. Right now we are only doing
        "receive only" support for forwardemail.net so the domain we setup is
        very simple. All of the values are pretty much going to be hardcoded.

        If the domain already exists, we update its id in redis.

        XXX We are hardcoding the plan to "enhanced_protection" because that is
            what we have paid for. We should add suport for at least "free" as
            well.
        """
        redis = redis_client()
        self.update_domains(redis=redis)

        # If the domain already exists, then do nothing.
        #
        if (
            redis.get(self._redis_key(ObjType.DOMAIN, server.domain_name))
            is not None
        ):
            return

        data = {
            "domain": server.domain_name,
            "plan": "enhanced_protection",
            "has_catchall": False,
            "has_delivery_logs": True,  # XXX only while making sure it works
            "has_phishing_protection": True,
            "has_executable_protection": True,
            "has_virus_protection": True,
        }
        r = self._req(HTTPMethod.POST, "v1/domains", data=data)
        domain = r.json()
        redis.set(domain["name"], domain["id"])

    ####################################################################
    #
    def delete_domain(self, server: "Server") -> None:
        pass

    ####################################################################
    #
    def _get_domain_id(
        self, domain_name: str, redis: Optional["StrictRedis"] = None
    ) -> Optional[str]:
        """
        Get the domain ID for a given domain name from Redis.

        Args:
            domain_name: The domain name to look up
            redis: Optional Redis client to reuse

        Returns:
            The domain ID string, or None if not found
        """
        redis = redis_client() if redis is None else redis
        redis_key = self._redis_key(ObjType.DOMAIN, domain_name)
        domain_id = redis.get(redis_key)
        return domain_id.decode() if domain_id else None

    ####################################################################
    #
    def _get_webhook_url(self, email_account: "EmailAccount") -> str:
        """
        Construct the incoming webhook URL for an email account.

        Args:
            email_account: The EmailAccount to get the webhook URL for

        Returns:
            The full webhook URL with api_key query parameter
        """
        # Get the base incoming webhook URL for this provider
        #
        webhook_path = reverse(
            "as_email:hook_incoming",
            kwargs={
                "provider_name": self.PROVIDER_NAME,
                "domain_name": email_account.server.domain_name,
            },
        )

        # Construct full URL with api_key parameter using settings.SITE_NAME
        #
        base_url = f"https://{settings.SITE_NAME}"
        webhook_url_base = urljoin(base_url, webhook_path)
        webhook_url = (
            f"{webhook_url_base}?api_key={email_account.server.api_key}"
        )

        return webhook_url

    ####################################################################
    #
    def list_email_accounts(
        self, server: "Server", redis: Optional["StrictRedis"] = None
    ) -> dict[str, dict[str, Any]]:
        """
        List all domain aliases (email accounts) for a server's domain.

        Args:
            server: The Server whose aliases to list
            redis: Optional Redis client to reuse

        Returns:
            Dict mapping email addresses to their alias info from forwardemail.net
        """
        redis = redis_client() if redis is None else redis

        # Ensure domain mapping is up to date
        #
        self.update_domains(redis=redis)

        domain_id = self._get_domain_id(server.domain_name, redis=redis)
        if domain_id is None:
            logger.warning(
                "Cannot list aliases for domain %s: domain ID not found",
                server.domain_name,
            )
            return {}

        # XXX when we hit 1,000 aliases we will need to support paging
        #
        r = self._req(HTTPMethod.GET, f"v1/domains/{domain_id}/aliases")
        aliases = r.json()
        result = {}

        for alias_info in aliases:
            alias_name = alias_info["name"]
            alias_id = alias_info["id"]
            email_address = f"{alias_name}@{server.domain_name}"
            result[email_address] = alias_info

            # Store alias ID in Redis for quick lookup
            #
            redis_key = self._redis_key(ObjType.ALIAS, email_address)
            redis.set(redis_key, alias_id)

        return result

    ####################################################################
    #
    def create_email_account(
        self,
        email_account: "EmailAccount",
        redis: Optional["StrictRedis"] = None,
    ) -> None:
        """
        Create a domain alias on forwardemail.net for an EmailAccount.

        Args:
            email_account: The EmailAccount to create an alias for
            redis: Optional Redis client to reuse
        """
        redis = redis_client() if redis is None else redis

        # Ensure domain exists and mapping is up to date
        #
        self.update_domains(redis=redis)

        domain_id = self._get_domain_id(
            email_account.server.domain_name, redis=redis
        )
        if domain_id is None:
            logger.error(
                "Cannot create alias for %s: domain ID not found for %s",
                email_account.email_address,
                email_account.server.domain_name,
            )
            return

        # Extract mailbox name from email address
        #
        mailbox_name = email_account.email_address.split("@")[0]

        # Construct webhook URL for this email account
        #
        webhook_url = self._get_webhook_url(email_account)

        # Prepare alias data
        #
        alias_data = {
            "name": mailbox_name,
            "recipients": webhook_url,
            "description": "",
            "labels": "",
            "has_recipient_verification": False,
            "is_enabled": True,
            "has_imap": False,
            "has_pgp": False,
        }

        # Create the alias
        #
        r = self._req(
            HTTPMethod.POST, f"v1/domains/{domain_id}/aliases", data=alias_data
        )
        alias_info = r.json()

        # Store alias ID in Redis
        #
        redis_key = self._redis_key(ObjType.ALIAS, email_account.email_address)
        redis.set(redis_key, alias_info["id"])

        logger.info(
            "Created forwardemail.net alias for %s (ID: %s)",
            email_account.email_address,
            alias_info["id"],
        )

    ####################################################################
    #
    def delete_email_account(
        self,
        email_account: "EmailAccount",
        redis: Optional["StrictRedis"] = None,
    ) -> None:
        """
        Delete a domain alias from forwardemail.net.

        Args:
            email_account: The EmailAccount whose alias to delete
            redis: Optional Redis client to reuse
        """
        redis = redis_client() if redis is None else redis

        # Get domain and alias IDs
        #
        domain_id = self._get_domain_id(
            email_account.server.domain_name, redis=redis
        )
        if domain_id is None:
            logger.warning(
                "Cannot delete alias for %s: domain ID not found",
                email_account.email_address,
            )
            return

        redis_key = self._redis_key(ObjType.ALIAS, email_account.email_address)
        alias_id = redis.get(redis_key)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not found in Redis",
                email_account.email_address,
            )
            return

        alias_id = alias_id.decode()

        # Delete the alias
        #
        self._req(HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}")

        # Remove from Redis
        #
        redis.delete(redis_key)

        logger.info(
            "Deleted forwardemail.net alias for %s (ID: %s)",
            email_account.email_address,
            alias_id,
        )

    ####################################################################
    #
    def enable_email_account(
        self,
        email_account: "EmailAccount",
        enable: bool = True,
        redis: Optional["StrictRedis"] = None,
    ) -> None:
        """
        Enable or disable a domain alias on forwardemail.net.

        Args:
            email_account: The EmailAccount whose alias to enable/disable
            enable: True to enable, False to disable
            redis: Optional Redis client to reuse
        """
        redis = redis_client() if redis is None else redis

        # Get domain and alias IDs
        #
        domain_id = self._get_domain_id(
            email_account.server.domain_name, redis=redis
        )
        if domain_id is None:
            logger.warning(
                "Cannot update alias for %s: domain ID not found",
                email_account.email_address,
            )
            return

        redis_key = self._redis_key(ObjType.ALIAS, email_account.email_address)
        alias_id = redis.get(redis_key)

        if alias_id is None:
            logger.warning(
                "Cannot update alias for %s: alias ID not found in Redis",
                email_account.email_address,
            )
            return

        alias_id = alias_id.decode()

        # Update the alias is_enabled field
        #
        update_data = {"is_enabled": enable}
        self._req(
            HTTPMethod.PUT,
            f"v1/domains/{domain_id}/aliases/{alias_id}",
            data=update_data,
        )

        logger.info(
            "%s forwardemail.net alias for %s (ID: %s)",
            "Enabled" if enable else "Disabled",
            email_account.email_address,
            alias_id,
        )

    ####################################################################
    #
    def delete_email_account_by_address(
        self,
        email_address: str,
        server: "Server",
        redis: Optional["StrictRedis"] = None,
    ) -> None:
        """
        Delete a domain alias from forwardemail.net by email address.

        This variant is used when the EmailAccount object no longer exists
        (e.g., during post-delete cleanup).

        Args:
            email_address: The email address of the alias to delete
            server: The Server instance for this domain
            redis: Optional Redis client to reuse
        """
        redis = redis_client() if redis is None else redis

        # Get domain ID
        #
        domain_id = self._get_domain_id(server.domain_name, redis=redis)
        if domain_id is None:
            logger.warning(
                "Cannot delete alias for %s: domain ID not found",
                email_address,
            )
            return

        redis_key = self._redis_key(ObjType.ALIAS, email_address)
        alias_id = redis.get(redis_key)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not found in Redis",
                email_address,
            )
            return

        alias_id = alias_id.decode()

        # Delete the alias
        #
        self._req(HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}")

        # Remove from Redis
        #
        redis.delete(redis_key)

        logger.info(
            "Deleted forwardemail.net alias for %s (ID: %s)",
            email_address,
            alias_id,
        )
