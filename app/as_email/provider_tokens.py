#!/usr/bin/env python
#
"""
Utilities for managing provider API tokens/credentials.

Handles the EMAIL_SERVER_TOKENS setting which stores API keys for email
providers on a per-server basis.

Format: {"provider_name": {"domain.com": "token"}}
"""
# system imports
#
from typing import Optional

# 3rd party imports
#
from django.conf import settings


########################################################################
#
def get_provider_token(provider_name: str, domain_name: str) -> Optional[str]:
    """
    Get the API token for a specific provider and domain.

    NOTE: Each provider also has an "account_api_key" token which is for
          account level API access, not just domain level. This is stored under
          the key "account_api_key" So use the value "account_api_key" instead
          of the domain name to get the account api key.

    Args:
        provider_name: The provider backend name (e.g., "postmark")
        domain_name: The server's domain name

    Returns:
        The API token/key for this provider+domain combination, or None if not found

    Example:
        >>> EMAIL_SERVER_TOKENS = {
        ...     "postmark": {"example.com": "pm-token-123"},
        ...     "forwardemail": {"example.com": "fe-token-456"}
        ... }
        >>> get_provider_token("postmark", "example.com")
        'pm-token-123'
    """
    tokens = settings.EMAIL_SERVER_TOKENS

    if provider_name not in tokens:
        return None

    provider_tokens = tokens[provider_name]
    if not isinstance(provider_tokens, dict):
        return None

    return provider_tokens.get(domain_name)


########################################################################
#
def has_provider_token(provider_name: str, domain_name: str) -> bool:
    """
    Check if a token exists for the given provider and domain.

    Args:
        provider_name: The provider backend name
        domain_name: The server's domain name

    Returns:
        True if a token is configured, False otherwise
    """
    return get_provider_token(provider_name, domain_name) is not None
