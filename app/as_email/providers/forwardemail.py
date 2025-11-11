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
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from io import BytesIO
from threading import Lock
from typing import TYPE_CHECKING, Any, Iterator, Optional
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
from as_email.models import EmailAccount
from as_email.provider_tokens import get_provider_token
from as_email.tasks import dispatch_incoming_email
from as_email.utils import (
    now_str_datetime,
    redis_client,
    split_email_mailbox_hash,
    utc_now_str,
    write_spooled_email,
)

from .base import ProviderBackend

if TYPE_CHECKING:
    from as_email.models import Server

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
@dataclass
class RateLimitInfo:
    """
    Store rate limit information. Fancier then we will ever need for our
    use, but they have info about rate limiting in their API so I felt
    obligated to code for it.
    """

    remaining: int
    reset_timestamp: int
    limit: int
    last_updated: float

    @property
    def percent_remaining(self) -> float:
        return (self.remaining / self.limit) * 100 if self.limit else 100

    @property
    def is_expired(self) -> bool:
        return time.time() > self.reset_timestamp

    @property
    def seconds_until_reset(self) -> float:
        return max(0, self.reset_timestamp - time.time())


########################################################################
########################################################################
#
class APIClient:
    """
    Overkill for our use here, but I could not help myself
    """

    API_ENDPOINT = "https://api.forwardemail.net/"

    ####################################################################
    #
    def __init__(
        self,
        rate_limit_threshold_percent: float = 10.0,
        min_requests_reserved: int = 5,
    ):
        # Rate limiting state
        self._rate_limit: Optional[RateLimitInfo] = None
        self._lock = Lock()  # Thread safety

        self.rate_limit_threshold_percent = rate_limit_threshold_percent
        # Always keep some requests in reserve
        #
        self.min_requests_reserved = min_requests_reserved
        self.logger = logging.getLogger(__name__)

    ####################################################################
    #
    def _calculate_sleep_time(self) -> float:
        """Calculate optimal sleep time based on remaining requests and time."""
        if not self._rate_limit or self._rate_limit.is_expired:
            return 0

        # If we're below minimum reserved requests, wait until reset
        if self._rate_limit.remaining <= self.min_requests_reserved:
            return self._rate_limit.seconds_until_reset

        # Calculate requests per second we can safely make
        seconds_until_reset = self._rate_limit.seconds_until_reset
        if seconds_until_reset <= 0:
            return 0

        # Reserve some requests
        available_requests = (
            self._rate_limit.remaining - self.min_requests_reserved
        )
        if available_requests <= 0:
            return seconds_until_reset

        # Spread remaining requests evenly over remaining time
        seconds_between_requests = seconds_until_reset / available_requests

        # Don't sleep too long (max 5 seconds)
        return min(seconds_between_requests, 5.0)

    ####################################################################
    #
    def _should_throttle(self) -> bool:
        """Check if we should throttle based on rate limit."""
        with self._lock:
            if not self._rate_limit:
                return False

            # If rate limit period has expired, we're good
            if self._rate_limit.is_expired:
                return False

            # Check if we're below threshold
            threshold = self._rate_limit.limit * (
                self.rate_limit_threshold_percent / 100
            )
            return self._rate_limit.remaining <= threshold

    ####################################################################
    #
    def _wait_if_needed(self):
        """Sleep if we're approaching rate limit."""
        if self._should_throttle():
            sleep_time = self._calculate_sleep_time()

            if sleep_time > 0:
                with self._lock:
                    if self._rate_limit:
                        self.logger.info(
                            f"Rate limiting: {self._rate_limit.remaining}/{self._rate_limit.limit} "
                            f"requests remaining ({self._rate_limit.percent_remaining:.1f}%). "
                            f"Sleeping {sleep_time:.1f}s"
                        )

                time.sleep(sleep_time)

    ####################################################################
    #
    def _update_rate_limit_from_headers(self, headers: dict[str, str]):
        """Update rate limit state from response headers."""
        try:
            # Only update if all headers are present
            if all(
                h in headers
                for h in [
                    "X-RateLimit-Remaining",
                    "X-RateLimit-Reset",
                    "X-RateLimit-Limit",
                ]
            ):
                with self._lock:
                    self._rate_limit = RateLimitInfo(
                        remaining=int(headers["X-RateLimit-Remaining"]),
                        reset_timestamp=int(headers["X-RateLimit-Reset"]),
                        limit=int(headers["X-RateLimit-Limit"]),
                        last_updated=time.time(),
                    )

                    # Log if we're getting low
                    if self._rate_limit.percent_remaining < 20:
                        self.logger.warning(
                            f"Rate limit warning: {self._rate_limit.remaining}/{self._rate_limit.limit} "
                            f"requests remaining ({self._rate_limit.percent_remaining:.1f}%)"
                        )

        except (ValueError, TypeError) as e:
            self.logger.error(f"Failed to parse rate limit headers: {e}")

    ####################################################################
    #
    def req(self, method: HTTPMethod, url: str, data=None) -> requests.Response:
        """
        Construct the url from the api endpoint + relative URL provided.
        Implements rate limiting with automatic throttling.
        """
        # Check if we need to throttle before making request
        self._wait_if_needed()

        u = urljoin(self.API_ENDPOINT, url)
        token = get_provider_token(self.PROVIDER_NAME, "account_api_key")
        assert token

        # Make the request
        start_time = time.time()
        r = requests.request(str(method), u, auth=(token, ""), data=data)
        request_time = time.time() - start_time

        # Update rate limit state from response headers
        self._update_rate_limit_from_headers(r.headers)

        # Log slow requests
        if request_time > 5.0:
            self.logger.warning(
                f"Slow request: {method} {url} took {request_time:.1f}s"
            )

        if r.status_code != 200:
            raw = BytesIO(r.content)
            raise HTTPError(u, r.status_code, r.reason, r.headers, raw)

        return r

    ####################################################################
    #
    def get_rate_limit_info(self) -> Optional[dict[str, Any]]:
        """Get current rate limit information."""
        with self._lock:
            if not self._rate_limit:
                return None

            return {
                "remaining": self._rate_limit.remaining,
                "limit": self._rate_limit.limit,
                "percent_remaining": self._rate_limit.percent_remaining,
                "reset_timestamp": self._rate_limit.reset_timestamp,
                "reset_datetime": datetime.fromtimestamp(
                    self._rate_limit.reset_timestamp
                ),
                "seconds_until_reset": self._rate_limit.seconds_until_reset,
                "is_expired": self._rate_limit.is_expired,
                "is_throttling": self._should_throttle(),
            }


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
    def __init__(self, *args, **kwargs) -> None:
        super(self).__init__(*args, **kwargs)
        self.api = APIClient()
        self.r = redis_client()

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
    def paginated_request(self, url: str) -> Iterator[dict]:
        """
        Get all the results from a paginated endpoint in forwardemail.net's API

        Pagination is determined by these headers:
          X-Page-Count: Total page count.
          X-Page-Current: Current page number.
          X-Page-Size: Number of items on the current page.
          X-Item-Count: Total number of items across all pages.
          Link: Navigation links (prev, next, first, last).

        For the purposes of this method we only pay attention to the "Link"
        header, and its format is:

           <https://api.forwardemail.net/v1/domains?page=2>; rel="next",
           <https://api.forwardemail.net/v1/domains?page=2)>; rel="last",
           <https://api.forwardemail.net/v1/domains?page=1)>; rel="first"

        """
        next_url: str | None = url

        while next_url:
            response = self.api.req(HTTPMethod.GET, next_url)
            response.raise_for_status()

            for item in response.json():
                yield item

            # The header 'Link' gets the next page of results.
            #
            link_header = response.headers.get("Link", "")
            match = re.search(r'<([^>]+)>\s*;\s*rel="next"', link_header)
            next_url = match.group(1) if match else None

    ####################################################################
    #
    @classmethod
    def _redis_key(cls, obj_type: ObjType, key: str) -> str:
        return f"{cls.PROVIDER_NAME}:{obj_type}:{key}"

    ####################################################################
    #
    def set_domain_info(self, domain_info: dict) -> None:
        domain_name = domain_info["name"]
        domain_id = domain_info["id"]
        redis_key = self._redis_key(ObjType.DOMAIN, domain_name)
        self.r.set(redis_key, domain_id)

    ####################################################################
    #
    def set_alias_info(self, alias_info: dict, domain_name: str) -> None:
        """
        Store alias information in Redis.

        Args:
            alias_info: The alias info dict from forwardemail.net API
            domain_name: The domain name the alias belongs to
        """
        alias_name = alias_info["name"]
        alias_id = alias_info["id"]
        email_address = f"{alias_name}@{domain_name}"
        redis_key = self._redis_key(ObjType.ALIAS, email_address)
        self.r.set(redis_key, alias_id)

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
        result = {}
        for domain_info in self.paginated_request("v1/domains"):
            domain_name = domain_info["name"]
            domain_id = domain_info["id"]
            result[domain_name] = domain_info
            redis_key = self._redis_key(ObjType.DOMAIN, domain_name)
            self.r.set(redis_key, domain_id)

        # Set a key indicating we got the list of domains.
        #
        redis_key = self._redis_key(ObjType.DOMAIN, "all_domains")
        self.r.set(redis_key, utc_now_str())

        return result

    ####################################################################
    #
    def update_domains(self, force: bool | None = False) -> bool:
        """
        Refresh the domain mapping from forwardemail.net if it's stale.

        Checks the timestamp of the last domain list refresh. If it's more than
        one hour old or doesn't exist, call list_domains() to refresh the
        domain-to-id mapping in Redis.

        If `force` is set, then we update the domain list whether or not we
        updated it in the last hour.

        Returns True if we did fetch the domains, False if we did not because
        our cache ttl has not expired yet.
        """

        # We store under the "all_domains" key the last timestamp, as a string
        # of when we fetched the domains. So even if we have them loaded in to
        # redis, if it has been more than an hour fetch them again.
        #
        redis_key = self._redis_key(ObjType.DOMAIN, "all_domains")
        last_update_str = self.r.get(redis_key)
        if last_update_str is None:
            self.list_domains()
            logger.info("Fetching domains from forwardemail.net")
            return True

        # Parse the timestamp and check if it's stale
        #
        age = datetime.now(UTC) - now_str_datetime(last_update_str)
        if age > timedelta(hours=1) or force:
            self.list_domains()
            logger.info(
                "Domain mapping is %s old, refreshing from forwardemail.net",
                age,
            )
            return True

        logger.debug(
            "Domain mapping is %s old (<1 hour), skipping refresh", age
        )
        return False

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
        # See if the domain already exists. If it does, return its info.
        #
        try:
            r = self.api.req(HTTPMethod.GET, f"v1/domains/{server.domain_name}")
            domain_info = r.json()
            self.set_domain_info(domain_info)
            return domain_info

        except HTTPError as e:
            # If it fails with anyting but a 404, raise the
            # exception. Otherwise fall through to the create because this
            # means it does not exist.
            #
            if e.status_code != 404:
                raise

        # The domain does not exist, create it.
        #
        data = {
            "domain": server.domain_name,
            "plan": "enhanced_protection",
            "has_catchall": False,
            "has_delivery_logs": True,  # XXX only while making sure it works
            "has_phishing_protection": True,
            "has_executable_protection": True,
            "has_virus_protection": True,
        }
        r = self.api.req(HTTPMethod.POST, "v1/domains", data=data)
        domain_info = r.json()
        self.set_domain_info(domain_info)
        return domain_info

    ####################################################################
    #
    def delete_domain(self, server: "Server") -> None:
        """
        Delete a domain from forwardemail.net.

        Args:
            server: The Server instance whose domain should be deleted

        Raises:
            Exception: If the domain ID cannot be found or the deletion fails
        """
        domain_id = self.get_domain_id(server.domain_name)
        self.api.req(HTTPMethod.DEL, f"v1/domains/{domain_id}")

        redis_key = self._redis_key(ObjType.DOMAIN, server.domain_name)
        self.r.delete(redis_key)

        logger.info(
            "Deleted forwardemail.net domain '%s' (ID: %s)",
            server.domain_name,
            domain_id,
        )

    ####################################################################
    #
    def get_domain_id(self, domain_name: str) -> Optional[str]:
        """
        Get the domain ID for a given domain name from Redis if
        possible. If not in redis, then fetch it from their API and store it in
        redis.

        Args:
            domain_name: The domain name to look up

        Returns:
            The domain ID string, or None if not found
        """
        redis_key = self._redis_key(ObjType.DOMAIN, domain_name)
        domain_id = self.r.get(redis_key)

        if domain_id is None:
            res = self.api.req(HTTPMethod.GET, f"v1/domains/{domain_name}")
            domain_info = res.json()
            self.set_domain_info(domain_info)
            domain_id = domain_info["id"]

        return domain_id

    ####################################################################
    #
    def get_alias_id(self, domain_id: str, email_address: str) -> str:
        """
        Get the domain alias ID from redis if possible. If not in redis
        then fetch it from the forwardemail.net API and store it in redis.

        Args:
            domain_id: the domain id the alias is inside.
            email_address: The email address. We only look at the mailbox part
                           of the email address

        Returns:
           The domain alias id
        """
        redis_key = self._redis_key(ObjType.ALIAS, email_address)
        alias_id = self.r.get(redis_key)
        if alias_id is None:
            mailbox = email_address.split("@")[0]
            domain_name = email_address.split("@")[1]
            url = f"v1/domains/{domain_id}/{mailbox}"
            res = self.api.req(HTTPMethod.GET, url)
            alias_info = res.json()
            self.set_alias_info(alias_info, domain_name)
            alias_id = alias_info["id"]

        return alias_id

    ####################################################################
    #
    def get_webhook_url(self, email_account: "EmailAccount") -> str:
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
        self, server: "Server"
    ) -> dict[str, dict[str, Any]]:
        """
        List all domain aliases (email accounts) for a server's domain.

        Args:
            server: The Server whose aliases to list
            redis: Optional Redis client to reuse

        Returns:
            Dict mapping email addresses to their alias info from
            forwardemail.net
        """
        domain_id = self.get_domain_id(server.domain_name)

        result = {}
        url = f"v1/domains/{domain_id}/aliases"
        for alias_info in self.paginated_request(url):
            alias_name = alias_info["name"]
            alias_id = alias_info["id"]
            email_address = f"{alias_name}@{server.domain_name}"
            result[email_address] = alias_info

            # Store alias ID in Redis for quick lookup
            #
            redis_key = self._redis_key(ObjType.ALIAS, email_address)
            self.r.set(redis_key, alias_id)

        return result

    ####################################################################
    #
    def create_update_email_account(
        self,
        email_account: "EmailAccount",
    ) -> None:
        """
        On forwardemail.net the email addresses within a domain are called
        'domain aliases.'

        Create a domain alias on forwardemail.net for an EmailAccount, or
        update it with our settings if it already exists.

        Args:
            email_account: The EmailAccount to create or update an alias for
        """
        # This will raise an error if the domain does not exist
        #
        domain_id = self.get_domain_id(email_account.server.domain_name)

        # Extract mailbox name from email address
        #
        mailbox_name = email_account.email_address.split("@")[0]

        # Construct webhook URL for this email account
        #
        webhook_url = self.get_webhook_url(email_account)

        # Prepare alias data
        #
        alias_data = {
            "name": mailbox_name,
            "recipients": [webhook_url],
            "description": f"Email account for {email_account.owner.name}",
            "labels": "",
            "has_recipient_verification": False,
            "is_enabled": True,
            "has_imap": False,
            "has_pgp": False,
        }

        # Check if the alias already exists by trying to get it
        #
        try:
            r = self.api.req(
                HTTPMethod.GET, f"v1/domains/{domain_id}/aliases/{mailbox_name}"
            )
            alias_info = r.json()
            alias_id = alias_info["id"]

            # Alias exists - update it using PUT
            #
            r = self.api.req(
                HTTPMethod.PUT,
                f"v1/domains/{domain_id}/aliases/{alias_id}",
                data=alias_data,
            )
            alias_info = r.json()

            # Store alias ID in Redis
            #
            self.set_alias_info(alias_info, email_account.server.domain_name)

            logger.info(
                "Updated forwardemail.net alias for %s (ID: %s), webhook: %s",
                email_account.email_address,
                alias_id,
                webhook_url,
            )

        except HTTPError as e:
            # If it fails with anything but a 404, raise the exception.
            # Otherwise fall through to create because it doesn't exist.
            #
            if e.status_code != 404:
                raise

            # Alias doesn't exist - create it using POST
            #
            r = self.api.req(
                HTTPMethod.POST, f"v1/domains/{domain_id}/aliases", data=alias_data
            )
            alias_info = r.json()

            # Store alias ID in Redis
            #
            self.set_alias_info(alias_info, email_account.server.domain_name)

            logger.info(
                "Created forwardemail.net alias for %s (ID: %s), webhook: %s",
                email_account.email_address,
                alias_info["id"],
                webhook_url,
            )

    ####################################################################
    #
    def create_update_email_account(
        self,
        email_account: "EmailAccount",
        redis: Optional["StrictRedis"] = None,
    ) -> None:
        """
        Create or update a domain alias on forwardemail.net for an EmailAccount.

        This method intelligently handles both create and update operations:
        - If the alias doesn't exist, it creates a new one using POST
        - If the alias already exists, it updates it using PUT

        Args:
            email_account: The EmailAccount to create or update an alias for
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
                "Cannot create/update alias for %s: domain ID not found for %s",
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
            "recipients": [webhook_url],
            "description": "",
            "labels": "",
            "has_recipient_verification": False,
            "is_enabled": True,
            "has_imap": False,
            "has_pgp": False,
        }

        # Check if alias already exists by looking up its ID in Redis
        #
        redis_key = self._redis_key(ObjType.ALIAS, email_account.email_address)
        alias_id = redis.get(redis_key)

        # If not in Redis, refresh the alias list to make sure we have current data
        #
        if alias_id is None:
            self.list_email_accounts(email_account.server, redis=redis)
            alias_id = redis.get(redis_key)

        if alias_id is None:
            # Alias doesn't exist - create it using POST
            #
            r = self._req(
                HTTPMethod.POST,
                f"v1/domains/{domain_id}/aliases",
                data=alias_data,
            )
            alias_info = r.json()

            # Store alias ID in Redis
            #
            redis.set(redis_key, alias_info["id"])

            logger.info(
                "Created forwardemail.net alias for %s (ID: %s)",
                email_account.email_address,
                alias_info["id"],
            )
        else:
            # Alias exists - update it using PUT
            #
            self._req(
                HTTPMethod.PUT,
                f"v1/domains/{domain_id}/aliases/{alias_id}",
                data=alias_data,
            )

            logger.info(
                "Updated forwardemail.net alias for %s (ID: %s)",
                email_account.email_address,
                alias_id,
            )

    ####################################################################
    #
    def delete_email_account(
        self,
        email_account: "EmailAccount",
    ) -> None:
        """
        Delete a domain alias from forwardemail.net.

        Args:
            email_account: The EmailAccount whose alias to delete
        """
        domain_id = self.get_domain_id(email_account.server.domain_name)
        redis_key = self._redis_key(ObjType.ALIAS, email_account.email_address)
        alias_id = self.r.get(redis_key)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not found in Redis",
                email_account.email_address,
            )
            return

        # Delete the alias
        #
        self.api.req(
            HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}"
        )

        # Remove from Redis
        #
        self.r.delete(redis_key)

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
    ) -> None:
        """
        Enable or disable a domain alias on forwardemail.net.

        Args:
            email_account: The EmailAccount whose alias to enable/disable
            enable: True to enable, False to disable
            redis: Optional Redis client to reuse
        """
        # Get domain and alias IDs
        #
        domain_id = self.get_domain_id(email_account.server.domain_name)
        assert domain_id
        alias_id = self.get_alias_id(domain_id, email_account.email_address)

        if alias_id is None:
            logger.warning(
                "Cannot update alias for %s: alias ID not found in Redis",
                email_account.email_address,
            )
            return

        # Update the alias is_enabled field
        #
        update_data = {"is_enabled": enable}
        self.api.req(
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
    ) -> None:
        """
        Delete a domain alias from forwardemail.net by email address.

        This variant is used when the EmailAccount object no longer exists
        (e.g., during post-delete cleanup).

        Args:
            email_address: The email address of the alias to delete
            server: The Server instance for this domain
        """
        # Get domain ID
        #
        domain_id = self.get_domain_id(server.domain_name)
        if domain_id is None:
            logger.warning(
                "Cannot delete alias for %s: domain ID not found",
                email_address,
            )
            return

        redis_key = self._redis_key(ObjType.ALIAS, email_address)
        alias_id = self.r.get(redis_key)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not found in Redis",
                email_address,
            )
            return

        # Delete the alias
        #
        self.api.req(
            HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}"
        )

        # Remove from Redis
        #
        self.r.delete(redis_key)

        logger.info(
            "Deleted forwardemail.net alias for %s (ID: %s)",
            email_address,
            alias_id,
        )
