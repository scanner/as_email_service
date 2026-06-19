#!/usr/bin/env python
#
"""
Password strength validator using zxcvbn.
"""

# system imports
#
from typing import Any

# 3rd party imports
#
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from zxcvbn import zxcvbn


########################################################################
########################################################################
#
class ZxcvbnPasswordValidator:
    """
    Reject passwords scoring below ZXCVBN_MIN_SCORE on the zxcvbn scale.

    Reads ZXCVBN_MIN_SCORE from Django settings (default 2). Can be
    overridden per-entry in AUTH_PASSWORD_VALIDATORS via OPTIONS.
    """

    ####################################################################
    #
    def __init__(self, min_score: int | None = None) -> None:
        if min_score is None:
            min_score = getattr(settings, "ZXCVBN_MIN_SCORE", 2)
        self.min_score = min_score

    ####################################################################
    #
    def validate(self, password: str, user: Any = None) -> None:
        """
        Raise ValidationError if the password scores below min_score.

        Args:
            password: The password to validate.
            user: Optional user object; username and email are passed as
                user_inputs to penalise trivially guessable passwords.

        Raises:
            ValidationError: If zxcvbn rates the password too weak.
        """
        user_inputs: list[str] = []
        if user is not None:
            user_inputs = [
                v
                for v in [
                    getattr(user, "username", None),
                    getattr(user, "email", None),
                ]
                if v
            ]
        result = zxcvbn(password, user_inputs=user_inputs)
        if result["score"] < self.min_score:
            fb = result.get("feedback", {})
            error_messages: list[str] = []
            if fb.get("warning"):
                error_messages.append(fb["warning"])
            error_messages.extend(fb.get("suggestions", []))
            if not error_messages:
                error_messages = [_("Password is too weak.")]
            raise ValidationError(error_messages)

    ####################################################################
    #
    def get_help_text(self) -> str:
        """Return help text describing the strength requirement."""
        return _(
            "Your password must score at least %(min_score)s out of 4"
            " on the zxcvbn strength scale."
        ) % {"min_score": self.min_score}
