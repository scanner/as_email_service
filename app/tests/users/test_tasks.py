#!/usr/bin/env python
#
"""Tests for users app periodic tasks."""

# system imports
#
from collections.abc import Callable
from datetime import timedelta
from typing import Any

# 3rd party imports
#
import pytest
from django.utils import timezone
from faker import Faker

# Project imports
#
from users.models import EmailChangeCooldown, PendingEmailChange
from users.tasks import cleanup_expired_email_change_records

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestCleanupExpiredEmailChangeRecords:
    """Tests for the cleanup_expired_email_change_records periodic task."""

    ####################################################################
    #
    @pytest.fixture
    def two_users(self, user_factory: Callable, faker: Faker) -> tuple:
        """Two distinct users for testing expired vs. active records."""
        u1 = user_factory()
        u1.save()
        u2 = user_factory()
        u2.save()
        return u1, u2

    ####################################################################
    #
    @pytest.mark.parametrize(
        "model_cls",
        [PendingEmailChange, EmailChangeCooldown],
        ids=["PendingEmailChange", "EmailChangeCooldown"],
    )
    def test_expired_records_deleted_active_preserved(
        self,
        two_users: tuple,
        faker: Faker,
        model_cls: type[PendingEmailChange] | type[EmailChangeCooldown],
    ) -> None:
        """
        GIVEN: one expired and one still-active record of the same model type
        WHEN:  cleanup_expired_email_change_records runs
        THEN:  the expired record is deleted; the active one is preserved
        """
        now = timezone.now()
        user_expired, user_active = two_users

        kwargs_expired: dict[str, Any] = {
            "user": user_expired,
            "expires_at": now - timedelta(days=1),
        }
        kwargs_active: dict[str, Any] = {
            "user": user_active,
            "expires_at": now + timedelta(days=3),
        }

        if model_cls is PendingEmailChange:
            kwargs_expired["new_email"] = faker.email()
            kwargs_expired["revocation_key"] = faker.uuid4()
            kwargs_active["new_email"] = faker.email()
            kwargs_active["revocation_key"] = faker.uuid4()

        model_cls.objects.create(**kwargs_expired)
        model_cls.objects.create(**kwargs_active)

        cleanup_expired_email_change_records()

        assert not model_cls.objects.filter(user=user_expired).exists()
        assert model_cls.objects.filter(user=user_active).exists()
