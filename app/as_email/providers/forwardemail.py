#!/usr/bin/env python
#
"""
ForwardEmail provider backend implementation.

Handles both inbound and outbound email via the forwardemail.net REST API.

**Incoming mail architecture**

forwardemail.net routes incoming mail through per-alias webhook URLs, which
is fundamentally different from a domain-level webhook (like Postmark).  The
flow is:

1. forwardemail.net receives an inbound message for a domain it manages.
2. It looks up the destination alias record for the recipient address.
3. It POSTs the raw message to the webhook URL stored on that alias.
4. Our ``handle_incoming_webhook`` handler processes the POST and dispatches
   delivery to the local EmailAccount.

Because the webhook URL is stored per-alias, ``create_update_email_account``
always includes it when creating or updating an alias via the API.

**Outbound mail**

Outbound email is sent via the ``/v1/emails`` REST API endpoint using the
account-level API key.  The raw RFC 2822 message is posted as the ``raw``
field.  Transient failures (408, 429, 5xx) result in the message being
spooled for retry.  SMTP sending (per-alias passwords) is supported by the
provider but deferred pending a credential-storage strategy.

**Bounce handling**

forwardemail.net delivers bounce notifications (including spam complaints)
to a single domain-level webhook URL (``bounce_webhook`` domain setting).
Both hard bounces and spam complaints arrive at ``handle_bounce_webhook``;
the ``bounce["bounce"]["category"]`` field distinguishes them.  There is no
separate spam webhook - ``handle_spam_webhook`` returns a "not applicable"
response and explains this.

**Domain and alias ID caching**

The forwardemail.net API identifies domains and aliases by opaque ID strings.
Most API calls (update alias, delete alias, list aliases) require those IDs.
To avoid a lookup roundtrip on every operation, ``ForwardEmailCache`` stores
the IDs in Redis keyed by domain name and email address respectively.  On a
cache miss the cache falls back to the API and populates itself for future
calls.  See ``ForwardEmailCache`` for the full Redis key schema.

**Rate limiting**

``APIClient`` implements header-driven throttling.  After each response it
reads ``X-RateLimit-Remaining``, ``X-RateLimit-Reset``, and
``X-RateLimit-Limit`` and updates a thread-safe ``RateLimitInfo`` dataclass.
Before each request it checks whether the remaining capacity has fallen below
``rate_limit_threshold_percent`` (default 10 %).  When throttling is needed it
sleeps for ``min(seconds_until_reset / available_requests, 5.0)`` seconds,
always keeping ``min_requests_reserved`` (default 5) requests in reserve so
that urgent calls can still go through.

References:
- API Documentation: https://forwardemail.net/en/email-api
- Webhook Documentation: https://forwardemail.net/en/faq#do-you-support-webhooks
- SMTP Integration Guide: https://forwardemail.net/en/guides/smtp-integration#python-integration
"""
# system imports
#
import email.message
import email.policy
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from io import BytesIO
from threading import Lock
from typing import TYPE_CHECKING, Any, Iterator, Optional
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin

# 3rd party imports
#
import requests
from django.conf import settings
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
)
from django.urls import reverse

# project imports
#
from as_email.models import EmailAccount
from as_email.provider_tokens import get_provider_token
from as_email.tasks import dispatch_incoming_email, process_bounce
from as_email.utils import (
    now_str_datetime,
    redis_client,
    split_email_mailbox_hash,
    spool_message,
    utc_now_str,
    write_spooled_email,
)

from .base import (
    BounceEvent,
    BounceType,
    Capability,
    EmailAccountInfo,
    ProviderBackend,
)

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

    from as_email.models import Server

logger = logging.getLogger("as_email.providers.forwardemail")


########################################################################
########################################################################
#
class HTTPMethod(StrEnum):
    PUT = "put"
    POST = "post"
    GET = "get"
    DEL = "delete"


########################################################################
########################################################################
#
class ObjType(StrEnum):
    """
    Namespace tokens used to partition Redis keys by object type.

    Used by ForwardEmailCache._key() to build keys of the form
    ``forwardemail:<obj_type>:<name>``, keeping domain entries and alias
    entries in separate keyspaces so there is no collision between a
    domain name and an email address that happen to share a string.
    """

    DOMAIN = "domain"
    ALIAS = "alias"
    ALIAS_DATA = "alias_data"


########################################################################
########################################################################
#
class RetryableHTTPStatus(IntEnum):
    """
    HTTP status codes from the ForwardEmail API that indicate a transient
    failure worth retrying rather than a permanent error.

    408 REQUEST_TIMEOUT      - server timed out waiting for the request
    429 TOO_MANY_REQUESTS    - rate-limit hit; back off and retry
    500 INTERNAL_SERVER_ERROR - provider-side bug or transient fault
    502 BAD_GATEWAY          - upstream dependency temporarily unavailable
    503 SERVICE_UNAVAILABLE  - provider in maintenance or overloaded
    504 GATEWAY_TIMEOUT      - upstream dependency timed out
    """

    REQUEST_TIMEOUT = 408
    TOO_MANY_REQUESTS = 429
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


# Frozenset to make checking against the return error code easier.
#
RETRYABLE_STATUS_CODES: frozenset[int] = frozenset(RetryableHTTPStatus)


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
    Thin HTTP client for the forwardemail.net REST API with rate-limit
    throttling.

    After each response the client reads ``X-RateLimit-Remaining``,
    ``X-RateLimit-Reset``, and ``X-RateLimit-Limit`` headers into a
    thread-safe ``RateLimitInfo`` dataclass.  Before each request it checks
    whether remaining capacity has fallen below ``rate_limit_threshold_percent``
    (default 10 %).  When throttling is needed it sleeps for at most 5 seconds,
    always keeping ``min_requests_reserved`` (default 5) requests in reserve.

    Non-200 responses are raised as ``urllib.error.HTTPError``.
    """

    API_ENDPOINT = "https://api.forwardemail.net/"

    ####################################################################
    #
    def __init__(
        self,
        provider_name: str,
        rate_limit_threshold_percent: float = 10.0,
        min_requests_reserved: int = 5,
    ):
        # Rate limiting state
        self._rate_limit: Optional[RateLimitInfo] = None
        self._lock = Lock()  # Thread safety

        self.provider_name = provider_name
        self.rate_limit_threshold_percent = rate_limit_threshold_percent
        # Always keep some requests in reserve
        #
        self.min_requests_reserved = min_requests_reserved
        self.logger = logging.getLogger(__name__)

    ####################################################################
    #
    def _calculate_sleep_time(self) -> float:
        """
        Calculate optimal sleep time based on remaining requests and time.
        """
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
        token = get_provider_token(self.provider_name, "account_api_key")
        assert token

        # Make the request
        start_time = time.time()
        r = requests.request(str(method), u, auth=(token, ""), json=data)
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
#
def _owner_display_name(owner: "AbstractBaseUser") -> str:
    """
    Return a human-readable display string for an email account owner.

    Uses full name when available: "Jane Smith (jsmith)".
    Falls back to username alone if get_full_name() is empty or raises.

    Args:
        owner: A Django User instance.

    Returns:
        A display string for use in provider-side descriptions.
    """
    try:
        full_name = owner.get_full_name()
    except Exception:
        full_name = ""
    if full_name:
        return f"{full_name} ({owner.username})"
    return owner.username


########################################################################
########################################################################
#
class ForwardEmailCache:
    """
    Redis-backed cache for forwardemail.net domain and alias ID lookups.

    On a cache miss the methods fall back to the forwardemail.net API,
    populate the cache, and return the result - the caller never needs to
    know whether the value came from Redis or from a live API call.

    **Alias ↔ EmailAccount mapping**

    In forwardemail.net terminology an *alias* is what this service calls
    an *EmailAccount*: a single deliverable address within a domain.  Every
    EmailAccount that uses a forwardemail.net receive-provider has exactly
    one corresponding alias on that provider, and vice-versa.  The cache
    stores the provider's opaque alias ID so that subsequent create/update/
    delete operations can reference it without a lookup roundtrip.

    **Redis key schema**

    All keys are prefixed ``forwardemail:`` (KEY_PREFIX) followed by an
    ObjType namespace token and the identifying name, separated by colons:

    +--------------------------------------------------------+------------------+
    | Key                                                    | Value            |
    +========================================================+==================+
    | ``forwardemail:domain:<domain_name>``                  | domain ID str    |
    +--------------------------------------------------------+------------------+
    | ``forwardemail:alias:<email_address>``                 | alias ID str     |
    +--------------------------------------------------------+------------------+
    | ``forwardemail:alias_data:<email_address>``            | alias JSON str   |
    +--------------------------------------------------------+------------------+
    | ``forwardemail:domain:all_domains``                    | UTC timestamp    |
    +--------------------------------------------------------+------------------+

    ``alias_data`` entries store the full raw API alias dict (JSON-encoded).
    They are populated by ``set_alias`` whenever a full alias dict is
    available (list, get, create, update) and consumed by
    ``create_update_email_account`` to avoid a redundant GET when the data
    was already fetched during ``list_email_accounts``.

    All values are plain UTF-8 strings stored with no TTL (they are
    invalidated explicitly when the corresponding object is deleted or the
    domain list is refreshed).

    **Single-provider limitation**

    The KEY_PREFIX is a class-level constant (``"forwardemail"``), which
    means all ForwardEmailCache instances share the same Redis keyspace.
    The current implementation assumes there is only one active forwardemail
    provider account at a time.  Supporting multiple independent forwardemail
    accounts (each with different API credentials) would require a
    per-instance prefix derived from, e.g., the provider's database PK.
    """

    KEY_PREFIX = "forwardemail"

    # TTLs (seconds).  All cache entries expire naturally as a safety net
    # against stale data from manual API changes or missed invalidations.
    # The hourly sync task refreshes alias and domain data well within these
    # windows, so normal operation never hits a cold cache mid-cycle.
    #
    DOMAIN_ID_TTL: int = 24 * 3600  # 24 h - domain IDs change very rarely
    ALIAS_ID_TTL: int = 24 * 3600  # 24 h - alias IDs are stable
    ALIAS_DATA_TTL: int = 2 * 3600  # 2 h  - refreshed each hourly sync cycle
    ALL_DOMAINS_TTL: int = 2 * 3600  # 2 h  - mirrors the 1-hour stale check

    ####################################################################
    #
    def __init__(self, r: Any, api: "APIClient") -> None:
        self.r = r
        self.api = api

    ####################################################################
    #
    def _key(self, obj_type: ObjType, key: str) -> str:
        return f"{self.KEY_PREFIX}:{obj_type}:{key}"

    ####################################################################
    #
    def set_domain(self, domain_info: dict) -> None:
        """Cache the domain ID from a domain info response dict."""
        domain_name = domain_info["name"]
        domain_id = domain_info["id"]
        self.r.set(
            self._key(ObjType.DOMAIN, domain_name),
            domain_id,
            ex=self.DOMAIN_ID_TTL,
        )

    ####################################################################
    #
    def set_alias(self, alias_info: dict, domain_name: str) -> None:
        """Cache the alias ID and full alias data from an alias info response dict."""
        alias_name = alias_info["name"]
        alias_id = alias_info["id"]
        email_address = f"{alias_name}@{domain_name}"
        self.r.set(
            self._key(ObjType.ALIAS, email_address),
            alias_id,
            ex=self.ALIAS_ID_TTL,
        )
        self.r.set(
            self._key(ObjType.ALIAS_DATA, email_address),
            json.dumps(alias_info),
            ex=self.ALIAS_DATA_TTL,
        )

    ####################################################################
    #
    def get_alias_data(self, email_address: str) -> Optional[dict]:
        """
        Return the cached full alias dict for email_address, or None on miss.

        Populated by set_alias() (called from list_email_accounts,
        get_alias_id fallback, and create_update_email_account).
        """
        val = self.r.get(self._key(ObjType.ALIAS_DATA, email_address))
        return json.loads(val.decode("utf-8")) if val is not None else None

    ####################################################################
    #
    def delete_alias_data(self, email_address: str) -> None:
        """Remove only the cached alias data, leaving the alias ID intact."""
        self.r.delete(self._key(ObjType.ALIAS_DATA, email_address))

    ####################################################################
    #
    def delete_domain(self, domain_name: str) -> None:
        """Remove a domain's cached ID."""
        self.r.delete(self._key(ObjType.DOMAIN, domain_name))

    ####################################################################
    #
    def delete_alias(self, email_address: str) -> None:
        """Remove an alias's cached ID and alias data (full cleanup on delete)."""
        self.r.delete(self._key(ObjType.ALIAS, email_address))
        self.r.delete(self._key(ObjType.ALIAS_DATA, email_address))

    ####################################################################
    #
    def set_all_domains_fetched(self) -> None:
        """Record the current time as the last full domain-list refresh."""
        self.r.set(
            self._key(ObjType.DOMAIN, "all_domains"),
            utc_now_str(),
            ex=self.ALL_DOMAINS_TTL,
        )

    ####################################################################
    #
    def get_all_domains_fetched(self) -> Optional[str]:
        """Return the timestamp of the last full domain-list refresh, or None."""
        val = self.r.get(self._key(ObjType.DOMAIN, "all_domains"))
        return val.decode("utf-8") if val is not None else None

    ####################################################################
    #
    def get_cached_domain_id(self, domain_name: str) -> Optional[str]:
        """Return the cached domain ID without falling back to the API."""
        val = self.r.get(self._key(ObjType.DOMAIN, domain_name))
        return val.decode("utf-8") if val is not None else None

    ####################################################################
    #
    def get_cached_alias_id(self, email_address: str) -> Optional[str]:
        """Return the cached alias ID without falling back to the API."""
        val = self.r.get(self._key(ObjType.ALIAS, email_address))
        return val.decode("utf-8") if val is not None else None

    ####################################################################
    #
    def get_domain_id(self, domain_name: str) -> str:
        """
        Return the domain ID for domain_name, using the Redis cache when
        possible and falling back to the API on a miss.

        Args:
            domain_name: The domain name to look up

        Returns:
            The forwardemail.net domain ID string

        Raises:
            KeyError: If the domain does not exist on forwardemail.net
            HTTPError: If the API returns a non-404 error
        """
        cached = self.get_cached_domain_id(domain_name)
        if cached is not None:
            return cached

        try:
            res = self.api.req(HTTPMethod.GET, f"v1/domains/{domain_name}")
            domain_info = res.json()
            self.set_domain(domain_info)
            return domain_info["id"]
        except HTTPError as e:
            if e.code == 404:
                raise KeyError(
                    f"Domain '{domain_name}' does not exist on forwardemail.net"
                )
            raise

    ####################################################################
    #
    def get_alias_id(self, domain_id: str, email_address: str) -> str:
        """
        Return the alias ID for email_address, using the Redis cache when
        possible and falling back to the API on a miss.

        In forwardemail.net terms an alias is the same concept as an
        EmailAccount in this service: one deliverable address within a domain.

        Args:
            domain_id: The domain ID the alias belongs to
            email_address: The full email address of the alias (EmailAccount)

        Returns:
            The forwardemail.net alias ID string

        Raises:
            KeyError: If the alias does not exist on forwardemail.net
            HTTPError: If the API returns a non-404 error
        """
        cached = self.get_cached_alias_id(email_address)
        if cached is not None:
            return cached

        mailbox = email_address.split("@")[0]
        domain_name = email_address.split("@")[1]
        url = f"v1/domains/{domain_id}/{mailbox}"
        try:
            res = self.api.req(HTTPMethod.GET, url)
            alias_info = res.json()
            self.set_alias(alias_info, domain_name)
            return alias_info["id"]
        except HTTPError as e:
            if e.code == 404:
                raise KeyError(
                    f"Alias '{email_address}' does not exist on forwardemail.net"
                )
            raise


########################################################################
########################################################################
#
class ForwardEmailBackend(ProviderBackend):
    """
    Backend implementation for ForwardEmail.net email service provider.

    Supports inbound email via per-alias webhooks, outbound email via the
    ``/v1/emails`` REST API, and bounce notification handling via a
    domain-level bounce webhook.

    References:
    - API Documentation: https://forwardemail.net/en/email-api
    - Webhook Documentation: https://forwardemail.net/en/faq#do-you-support-webhooks
    - SMTP Integration: https://forwardemail.net/en/guides/smtp-integration#python-integration
    """

    PROVIDER_NAME = "forwardemail"
    CAPABILITIES: frozenset[Capability] = frozenset(
        {Capability.MANAGES_EMAIL_ACCOUNTS}
    )

    # Desired settings applied to every domain we manage.  These are
    # compared against the live domain on every create_update_domain call
    # and a PUT is issued for any field that has drifted.
    #
    # Protection notes (all protections hard-reject with SMTP 554 -- no tagging):
    #   has_phishing_protection    -- blocks phishing and malware links; keep True
    #   has_virus_protection       -- blocks virus attachments; keep True
    #   has_adult_content_protection -- sub-case of phishing; only fires when
    #                                  has_phishing_protection is also True; False
    #                                  because a hard 554 reject is too aggressive
    #   has_executable_protection  -- rejects executable attachments; False because
    #                                  legitimate mail sometimes carries executables
    #   retention_days             -- outbound SMTP log retention (0–30 days);
    #                                  relevant once we add sending support
    #
    # NOTE: `plan` is intentionally excluded -- it is managed via the
    #       forwardemail.net website and must never be overwritten by code.
    # NOTE: `catchall` is intentionally excluded -- it is only accepted at
    #       domain creation time (POST), not on updates (PUT).  It is passed
    #       separately in create_update_domain() when creating a new domain.
    #
    DEFAULT_DOMAIN_SETTINGS: dict[str, Any] = {
        "has_adult_content_protection": False,
        "has_phishing_protection": True,
        "has_executable_protection": False,
        "has_virus_protection": True,
        "has_delivery_logs": True,
        "retention_days": 7,
    }

    # Desired settings applied to every alias we manage.  These are
    # compared against the live alias on every create_update_email_account
    # call and a PUT is issued for any field that has drifted.
    #
    # NOTE: Per-account fields (`name`, `recipients`, `description`) are
    #       handled separately and are not listed here.
    #
    # Field notes:
    #   has_recipient_verification -- False; we never want delivery held
    #                                pending a click-through verification
    #   has_imap                 -- False; mail arrives via webhook, not IMAP
    #   has_pgp                  -- False; no PGP encryption at the provider
    #
    # NOTE: `is_enabled` is not here - it is per-account and set from
    #       EmailAccount.enabled in create_update_email_account.
    #
    DEFAULT_ALIAS_SETTINGS: dict[str, Any] = {
        "has_recipient_verification": False,
        "has_imap": False,
        "has_pgp": False,
    }

    ####################################################################
    #
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.api = APIClient(self.PROVIDER_NAME)
        self.cache = ForwardEmailCache(redis_client(), self.api)

    ####################################################################
    #
    def send_email_smtp(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via SMTP — not supported by ForwardEmail.

        ForwardEmail does not support SMTP relay; use ``send_email()``
        instead, which routes to the REST API.

        Raises:
            NotImplementedError: Always — use send_email() instead
        """
        raise NotImplementedError(
            f"{self.PROVIDER_NAME} does not support SMTP relay; "
            "use send_email() instead"
        )

    ####################################################################
    #
    def send_email_api(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via the ForwardEmail.net outbound REST API.

        Posts the RFC 2822 message to ``/v1/emails`` as the ``raw`` field.
        Transient server-side failures (408, 429, 5xx) are retryable: the
        message is spooled when ``spool_on_retryable`` is True.  All other
        provider errors are re-raised.

        NOTE: ``email_from`` and ``rcpt_tos`` are accepted for interface
        consistency but unused — the ForwardEmail API extracts recipients
        from the raw message headers.

        Args:
            server: The Server instance sending the email
            message: The email message to send
            email_from: Unused (accepted for interface consistency)
            rcpt_tos: Unused (accepted for interface consistency)
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the provider accepted the message, False on retryable failure

        Raises:
            HTTPError: For non-retryable provider errors (e.g. 400, 422)
        """
        data = {"raw": message.as_string(policy=email.policy.SMTP)}
        try:
            self.api.req(HTTPMethod.POST, "v1/emails", data=data)
            return True
        except HTTPError as exc:
            if exc.code in RETRYABLE_STATUS_CODES:
                logger.warning(
                    "Transient error sending email via %s (%d %s). %s.",
                    self.PROVIDER_NAME,
                    exc.code,
                    exc.reason,
                    (
                        "Spooling for retry"
                        if spool_on_retryable
                        else "Not spooling"
                    ),
                )
                if spool_on_retryable:
                    spool_message(server.outgoing_spool_dir, message.as_bytes())
                return False
            logger.error(
                "Failed to send email via %s: %d %s",
                self.PROVIDER_NAME,
                exc.code,
                exc.reason,
            )
            raise

    ####################################################################
    #
    def send_email(
        self,
        server: "Server",
        message: email.message.EmailMessage,
        email_from: str | None = None,
        rcpt_tos: list[str] | None = None,
        spool_on_retryable: bool = True,
    ) -> bool:
        """
        Send email via our preferred transport for ForwardEmail (REST API).

        Delegates to send_email_api().

        Args:
            server: The Server instance sending the email
            message: The email message to send
            email_from: Passed through to send_email_api (unused by API)
            rcpt_tos: Passed through to send_email_api (unused by API)
            spool_on_retryable: If True, spool message on retryable failures

        Returns:
            True if the email was sent successfully, False otherwise
        """
        return self.send_email_api(
            server, message, email_from, rcpt_tos, spool_on_retryable
        )

    ####################################################################
    #
    def handle_incoming_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> HttpResponse:
        """
        Handle incoming email webhook from ForwardEmail.net.

        ForwardEmail POSTs a JSON payload containing the raw email message
        and recipient information. The `recipients` field is an array that
        may contain multiple local addresses that should receive this message.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            HttpResponse indicating success or failure
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

            if not email_account.enabled:
                logger.info(
                    "Received email for disabled EmailAccount: %s, from: %s",
                    addr,
                    from_addr_str,
                )
                failed_recipients.append(addr)
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
    ) -> HttpResponse:
        """
        Handle bounce and spam complaint notifications from forwardemail.net.

        ForwardEmail delivers both hard bounces and spam complaints to this
        single domain-level webhook URL (the ``bounce_webhook`` field on the
        domain).  Spam complaints are distinguished by
        ``bounce["bounce"]["category"] == "spam"``; transient failures by
        ``bounce["bounce"]["action"] == "defer"``.

        After validation the payload is normalized to a BounceEvent and
        dispatched to the provider-agnostic process_bounce Huey task.

        Args:
            request: The Django HTTP request containing the webhook payload
            server: The Server instance this webhook is for

        Returns:
            HttpResponse indicating success or failure
        """
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning(
                "Bad JSON in bounce webhook from forwardemail.net: %r", exc
            )
            return HttpResponseBadRequest(f"invalid json: {exc}")

        if not all(k in payload for k in ("email_id", "recipient", "bounce")):
            return HttpResponseBadRequest(
                "submitted json missing expected keys"
            )

        bounce_info = payload["bounce"]
        if "action" not in bounce_info:
            return HttpResponseBadRequest(
                "submitted json bounce object missing 'action' key"
            )

        # The From address identifies the sending EmailAccount.
        #
        from_addr = payload.get("headers", {}).get("from", "")
        if not from_addr:
            logger.warning(
                "ForwardEmail bounce webhook missing From header "
                "(email_id=%s, server=%s)",
                payload["email_id"],
                server.domain_name,
            )
            return HttpResponseBadRequest(
                "missing From address in bounce headers"
            )

        action = bounce_info["action"]
        category = bounce_info.get("category", "")
        # ForwardEmail currently uses "spam" as the only non-delivery category.
        # When GH-223 migrates Postmark, additional BounceType values (e.g.
        # UNSUBSCRIBE) will be added and this mapping will grow accordingly.
        bounce_type = (
            BounceType.SPAM if category == "spam" else BounceType.BOUNCE
        )
        is_transient = action == "defer"

        logger.info(
            "forwardemail bounce hook: from=%s to=%s action=%s category=%s "
            "server=%s",
            from_addr,
            payload["recipient"],
            action,
            category,
            server.domain_name,
        )

        try:
            ea = EmailAccount.objects.get(email_address=from_addr)
        except EmailAccount.DoesNotExist:
            logger.warning(
                "ForwardEmail %s for unrecognized From address '%s' "
                "(server=%s, email_id=%s, to=%s) - ignored",
                bounce_type,
                from_addr,
                server.domain_name,
                payload["email_id"],
                payload["recipient"],
            )
            return JsonResponse(
                {
                    "status": "all good",
                    "message": (
                        f"From address '{from_addr}' is not an EmailAccount "
                        f"on server {server.domain_name}. Bounce ignored."
                    ),
                }
            )

        description = bounce_info.get("message", payload.get("message", ""))
        status_code = bounce_info.get("status", "")

        event = BounceEvent(
            email_from=from_addr,
            email_to=payload["recipient"],
            subject="",
            transient=is_transient,
            bounce_type=bounce_type,
            description=description,
            details=status_code,
            # ForwardEmail has no "inactive recipient" concept and does not
            # provide the original message body in the bounce payload.
        )
        process_bounce(ea.pk, event)

        event_label = bounce_type
        return JsonResponse(
            {
                "status": "all good",
                "message": (
                    f"received {event_label} for "
                    f"{server.domain_name}/{ea.email_address}"
                ),
            }
        )

    ####################################################################
    #
    def handle_spam_webhook(
        self, request: HttpRequest, server: "Server"
    ) -> HttpResponse:
        """
        Handle spam complaint webhook - NOT APPLICABLE for ForwardEmail.

        ForwardEmail delivers spam complaints via the bounce webhook
        (``bounce["bounce"]["category"] == "spam"``), not a dedicated spam
        endpoint.  This handler should never be called in production; it
        exists only to satisfy the ProviderBackend interface.

        Returns:
            JsonResponse indicating this endpoint is not applicable
        """
        logger.warning(
            "Received spam webhook request for %s on server %s - "
            "ForwardEmail delivers spam via the bounce webhook, not here",
            self.PROVIDER_NAME,
            server.domain_name,
        )
        return JsonResponse(
            {
                "status": "not applicable",
                "message": (
                    "ForwardEmail delivers spam complaints via the bounce "
                    "webhook (bounce.category=spam), not a dedicated spam "
                    "endpoint."
                ),
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
    def list_domains(self) -> dict[str, dict[str, Any]]:
        """
        List all the domains configured on our forwardemail.net provider.

        Populates the cache with every domain ID returned and records the
        refresh timestamp.  Returns a dict keyed by domain name whose values
        are the raw domain info dicts from the forwardemail.net API.
        """
        result = {}
        for domain_info in self.paginated_request("v1/domains"):
            domain_name = domain_info["name"]
            result[domain_name] = domain_info
            self.cache.set_domain(domain_info)

        self.cache.set_all_domains_fetched()
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
        last_update_str = self.cache.get_all_domains_fetched()
        if last_update_str is None:
            self.list_domains()
            logger.info("Fetching domains from forwardemail.net")
            return True

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
    def create_update_domain(
        self, server: "Server", dry_run: bool = False
    ) -> bool:
        """
        Create or update a domain in forwardemail.net.

        If the domain does not yet exist it is created with the desired
        settings.  If it already exists its live settings are fetched and
        compared; any settings that differ are updated with a single PUT
        request.

        The desired settings are ``DEFAULT_DOMAIN_SETTINGS`` plus the
        server-specific ``bounce_webhook`` URL, which is computed here
        because it depends on the server's domain name.

        Args:
            server: The Server instance whose domain to create or update
            dry_run: If True, log what would change but skip API writes.

        Returns:
            True if changes were made (or would be made in dry_run),
            False if already correct.
        """
        # Merge static defaults with the server-specific bounce webhook URL.
        #
        desired = {
            **self.DEFAULT_DOMAIN_SETTINGS,
            "bounce_webhook": self.get_bounce_webhook_url(server),
        }

        try:
            domain_id = self.cache.get_domain_id(server.domain_name)

            # Domain exists -- fetch current settings and apply any updates
            r = self.api.req(HTTPMethod.GET, f"v1/domains/{domain_id}")
            domain_info = r.json()

            to_update = {
                k: v for k, v in desired.items() if domain_info.get(k) != v
            }

            if to_update:
                if dry_run:
                    logger.info(
                        "Domain '%s' would be updated (dry run): %r",
                        server.domain_name,
                        to_update,
                    )
                else:
                    logger.info(
                        "Domain '%s' settings updated: %r",
                        server.domain_name,
                        to_update,
                    )
                    self.api.req(
                        HTTPMethod.PUT,
                        f"v1/domains/{domain_id}",
                        data=to_update,
                    )
                return True

            logger.debug(
                "Domain '%s' already up to date on forwardemail.net (ID: %s)",
                server.domain_name,
                domain_id,
            )
            return False

        except KeyError:
            # Domain doesn't exist, create it
            pass

        if dry_run:
            logger.info(
                "Domain '%s' would be created on forwardemail.net (dry run)",
                server.domain_name,
            )
            return True

        # Create the domain with our desired settings.
        # NOTE: `catchall` is a create-only field; it cannot be set via PUT.
        #
        data = {
            "domain": server.domain_name,
            "catchall": False,
            **desired,
        }
        r = self.api.req(HTTPMethod.POST, "v1/domains", data=data)
        domain_info = r.json()
        self.cache.set_domain(domain_info)

        logger.info(
            "Created forwardemail.net domain '%s' (ID: %s)",
            server.domain_name,
            domain_info["id"],
        )

        return True

    ####################################################################
    #
    def delete_domain(self, server: "Server") -> None:
        """
        Delete a domain from forwardemail.net.

        If the domain doesn't exist on forwardemail.net, this is a no-op.

        Args:
            server: The Server instance whose domain should be deleted
        """
        try:
            domain_id = self.cache.get_domain_id(server.domain_name)
        except KeyError:
            # Domain doesn't exist, nothing to delete
            logger.info(
                "Domain '%s' does not exist on forwardemail.net, nothing to delete",
                server.domain_name,
            )
            return

        self.api.req(HTTPMethod.DEL, f"v1/domains/{domain_id}")

        self.cache.delete_domain(server.domain_name)

        logger.info(
            "Deleted forwardemail.net domain '%s' (ID: %s)",
            server.domain_name,
            domain_id,
        )

    ####################################################################
    #
    def get_bounce_webhook_url(self, server: "Server") -> str:
        """
        Construct the domain-level bounce webhook URL for a server.

        This URL is registered on the forwardemail.net domain as the
        ``bounce_webhook`` field so that both delivery bounces and spam
        complaints are POSTed here.

        Args:
            server: The Server instance to get the bounce webhook URL for

        Returns:
            The full bounce webhook URL
        """
        webhook_path = reverse(
            "as_email:hook_bounce",
            kwargs={
                "provider_name": self.PROVIDER_NAME,
                "domain_name": server.domain_name,
            },
        )
        base_url = f"https://{settings.SITE_NAME}"
        webhook_url_base = urljoin(base_url, webhook_path)
        return f"{webhook_url_base}?{urlencode({'api_key': server.api_key})}"

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
            f"{webhook_url_base}?"
            f"{urlencode({'api_key': email_account.server.api_key})}"
        )

        return webhook_url

    ####################################################################
    #
    def list_email_accounts(self, server: "Server") -> list[EmailAccountInfo]:
        """
        List all domain aliases (email accounts) for a server's domain.

        Args:
            server: The Server whose aliases to list

        Returns:
            List of EmailAccountInfo objects containing alias information
        """
        domain_id = self.cache.get_domain_id(server.domain_name)

        result = []
        url = f"v1/domains/{domain_id}/aliases"
        for alias_info in self.paginated_request(url):
            alias_name = alias_info["name"]
            alias_id = alias_info["id"]
            email_address = f"{alias_name}@{server.domain_name}"

            # Create EmailAccountInfo object. Store the full raw API dict in
            # extra_data so sync_email_account() can compare without a GET.
            account_info = EmailAccountInfo(
                id=alias_id,
                email=email_address,
                domain=server.domain_name,
                enabled=alias_info.get("is_enabled", False),
                name=alias_name,
                extra_data=alias_info,
            )
            result.append(account_info)
            self.cache.set_alias(alias_info, server.domain_name)

        return result

    ####################################################################
    #
    def create_email_account(self, email_account: "EmailAccount") -> None:
        """
        Create a domain alias on forwardemail.net for an EmailAccount.

        This method delegates to create_update_email_account which will
        create the alias if it doesn't exist or update it if it does.

        Args:
            email_account: The EmailAccount to create an alias for
        """
        self.create_update_email_account(email_account)

    ####################################################################
    #
    def create_update_email_account(
        self,
        email_account: "EmailAccount",
    ) -> bool:
        """
        On forwardemail.net the email addresses within a domain are called
        'domain aliases.'

        Create a domain alias on forwardemail.net for an EmailAccount, or
        update it with our settings if it already exists.

        When the alias exists, the current settings are taken from the Redis
        alias-data cache if available (populated by list_email_accounts or a
        prior call), avoiding a redundant GET.  On a cache miss the settings
        are fetched from the API.  A PUT is issued only when something differs
        from the desired state.

        Args:
            email_account: The EmailAccount to create or update an alias for

        Returns:
            True if the alias was created or if existing settings were updated,
            False if the alias already existed with all correct settings.
        """
        # This will raise KeyError if the domain does not exist
        #
        domain_id = self.cache.get_domain_id(email_account.server.domain_name)

        mailbox_name = email_account.email_address.split("@")[0]
        webhook_url = self.get_webhook_url(email_account)

        # The full desired state for this alias: static defaults plus the
        # per-account fields that may change over time.
        #
        wanted = {
            **self.DEFAULT_ALIAS_SETTINGS,
            "is_enabled": email_account.enabled,
            "recipients": [webhook_url],
            "description": f"Email account for {_owner_display_name(email_account.owner)}",
        }

        try:
            alias_id = self.cache.get_alias_id(
                domain_id, email_account.email_address
            )

            # Alias exists -- use cached settings when available to avoid a
            # redundant GET (cache is warmed by list_email_accounts).
            #
            alias_info = self.cache.get_alias_data(email_account.email_address)
            if alias_info is None:
                r = self.api.req(
                    HTTPMethod.GET,
                    f"v1/domains/{domain_id}/aliases/{alias_id}",
                )
                alias_info = r.json()
                self.cache.set_alias(
                    alias_info, email_account.server.domain_name
                )

            to_update = {
                k: v for k, v in wanted.items() if alias_info.get(k) != v
            }

            if to_update:
                logger.info(
                    "Alias '%s' settings updated: %r",
                    email_account.email_address,
                    to_update,
                )
                # Send the full `wanted` dict, not just the diff: ForwardEmail
                # treats PUT as a full replacement and clears any field omitted
                # from the payload.
                #
                self.api.req(
                    HTTPMethod.PUT,
                    f"v1/domains/{domain_id}/aliases/{alias_id}",
                    data=wanted,
                )
                # Invalidate the cache so the next call fetches fresh state
                # from the provider rather than using stale pre-PUT data.
                #
                self.cache.delete_alias_data(email_account.email_address)
                return True
            else:
                logger.debug(
                    "Alias '%s' already exists with correct settings (ID: %s)",
                    email_account.email_address,
                    alias_id,
                )
                return False

        except KeyError:
            # Alias doesn't exist - create it.
            #
            r = self.api.req(
                HTTPMethod.POST,
                f"v1/domains/{domain_id}/aliases",
                data={"name": mailbox_name, **wanted},
            )
            alias_info = r.json()
            self.cache.set_alias(alias_info, email_account.server.domain_name)

            logger.info(
                "Created forwardemail.net alias for %s (ID: %s), webhook: %s",
                email_account.email_address,
                alias_info["id"],
                webhook_url,
            )
            return True

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
        domain_id = self.cache.get_domain_id(email_account.server.domain_name)
        alias_id = self.cache.get_cached_alias_id(email_account.email_address)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not in cache, skipping",
                email_account.email_address,
            )
            return

        # Delete the alias
        #
        self.api.req(
            HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}"
        )
        self.cache.delete_alias(email_account.email_address)

        logger.info(
            "Deleted forwardemail.net alias for %s (ID: %s)",
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
        # Get domain ID; if the domain doesn't exist there's nothing to delete
        #
        try:
            domain_id = self.cache.get_domain_id(server.domain_name)
        except KeyError:
            logger.warning(
                "Cannot delete alias for %s: domain '%s' not found",
                email_address,
                server.domain_name,
            )
            return

        alias_id = self.cache.get_cached_alias_id(email_address)

        if alias_id is None:
            logger.warning(
                "Cannot delete alias for %s: alias ID not in cache, skipping",
                email_address,
            )
            return

        # Delete the alias
        #
        self.api.req(
            HTTPMethod.DEL, f"v1/domains/{domain_id}/aliases/{alias_id}"
        )
        self.cache.delete_alias(email_address)

        logger.info(
            "Deleted forwardemail.net alias for %s (ID: %s)",
            email_address,
            alias_id,
        )
