#!/usr/bin/env python
#
"""Tests for users.validators.ZxcvbnPasswordValidator."""

# system imports
#
from types import SimpleNamespace

# 3rd party imports
#
import pytest
from django.core.exceptions import ValidationError

# Project imports
#
from users.validators import ZxcvbnPasswordValidator


########################################################################
########################################################################
#
class TestZxcvbnPasswordValidator:
    """Tests for ZxcvbnPasswordValidator."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "password",
        ["password", "123456", "qwerty", "abc123"],
        ids=["password", "123456", "qwerty", "abc123"],
    )
    def test_weak_passwords_rejected(self, password: str) -> None:
        """
        GIVEN: a weak password (zxcvbn score < 2)
        WHEN:  validate() is called
        THEN:  ValidationError is raised
        """
        validator = ZxcvbnPasswordValidator(min_score=2)
        with pytest.raises(ValidationError):
            validator.validate(password)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "password",
        [
            "correct horse battery staple",
            "Tr0ub4dor&3!xQ9",
            "mY$up3rS3cr3tP@ss!",
        ],
        ids=["passphrase", "mixed-complex", "long-mixed"],
    )
    def test_strong_passwords_accepted(self, password: str) -> None:
        """
        GIVEN: a strong password (zxcvbn score >= 2)
        WHEN:  validate() is called
        THEN:  no exception is raised
        """
        validator = ZxcvbnPasswordValidator(min_score=2)
        validator.validate(password)  # must not raise

    ####################################################################
    #
    def test_user_inputs_penalise_guessable_password(self) -> None:
        """
        GIVEN: a password identical to the user's username
        WHEN:  validate() is called with the user object
        THEN:  ValidationError is raised -- the username is passed as a
               user_input so zxcvbn penalises trivially guessable passwords
        """
        user = SimpleNamespace(
            username="johndoe1234", email="other@example.com"
        )
        validator = ZxcvbnPasswordValidator(min_score=2)
        with pytest.raises(ValidationError):
            validator.validate("johndoe1234", user=user)

    ####################################################################
    #
    def test_settings_min_score_controls_acceptance(self, settings) -> None:
        """
        GIVEN: ZXCVBN_MIN_SCORE is overridden to 0 in Django settings
        WHEN:  ZxcvbnPasswordValidator() is constructed with no arguments
               and validate() is called with a weak password
        THEN:  no exception is raised -- proves settings are read and the
               threshold value actually controls acceptance
        """
        settings.ZXCVBN_MIN_SCORE = 0
        validator = ZxcvbnPasswordValidator()
        validator.validate("password")  # must not raise at floor threshold
