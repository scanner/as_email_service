"""
Custom allauth adapters for as_email_service.
"""

# 3rd party imports
#
from allauth.account.adapter import DefaultAccountAdapter
from django.http import HttpRequest


class NoSignupAccountAdapter(DefaultAccountAdapter):
    """
    Account adapter that disables self-registration.

    Users are created exclusively through the Django admin. This blocks
    the /accounts/signup/ URL so opportunistic registrations are not
    possible.
    """

    def is_open_for_signup(self, request: HttpRequest) -> bool:
        return False
