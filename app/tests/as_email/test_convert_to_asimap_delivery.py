#!/usr/bin/env python
#
"""Test the convert_to_asimap_delivery management command."""

# system imports
#
from collections.abc import Callable
from io import StringIO

# 3rd party imports
#
import pytest
import pytest_check as check
from django.conf import LazySettings
from django.core.management import call_command
from django.core.management.base import CommandError

# Project imports
#
from as_email.models import (
    ASIMAPDelivery,
    EmailAccount,
    LocalDelivery,
    MHDelivery,
    local_deliveries,
)

pytestmark = pytest.mark.django_db


####################################################################
#
@pytest.fixture
def mh_accounts(
    email_account_factory: Callable[..., EmailAccount],
) -> list[EmailAccount]:
    """
    Three email accounts, each with the MHDelivery the factory gives it. The
    first one's spam settings are changed from the defaults so a conversion
    can be seen to keep them.
    """
    eas = [email_account_factory() for _ in range(3)]
    mh = MHDelivery.objects.get(email_account=eas[0])
    mh.spam_delivery_folder = "Spam"
    mh.spam_score_threshold = 12
    mh.save()
    return eas


####################################################################
#
@pytest.fixture
def run_command() -> Callable[..., tuple[str, str]]:
    """Run the command with the given arguments; return (stdout, stderr)."""

    def _run(*args: str) -> tuple[str, str]:
        out, err = StringIO(), StringIO()
        call_command(
            "convert_to_asimap_delivery", *args, stdout=out, stderr=err
        )
        return out.getvalue(), err.getvalue()

    return _run


####################################################################
#
def local_delivery_type(ea: EmailAccount) -> type[LocalDelivery]:
    """Return the concrete type of the account's local delivery."""
    return type(local_deliveries().get(email_account=ea))


########################################################################
########################################################################
#
class TestConvertToASIMAPDelivery:
    """Tests for the convert_to_asimap_delivery command."""

    ####################################################################
    #
    def test_all_converts_every_account_keeping_pk_and_settings(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
    ) -> None:
        """
        GIVEN accounts that each have an MHDelivery
        WHEN  the command is run with --all
        THEN  every one is an ASIMAPDelivery with the same pk and settings
        """
        before = {
            ea.pk: local_deliveries().get(email_account=ea).pk
            for ea in mh_accounts
        }

        out, _ = run_command("--all")

        for ea in mh_accounts:
            delivery = local_deliveries().get(email_account=ea)
            check.is_instance(delivery, ASIMAPDelivery, ea.email_address)
            check.equal(delivery.pk, before[ea.pk], "keeps its pk")
        converted = ASIMAPDelivery.objects.get(email_account=mh_accounts[0])
        check.equal(converted.spam_delivery_folder, "Spam")
        check.equal(converted.spam_score_threshold, 12)
        check.is_in("Converted 3 delivery method(s)", out)

    ####################################################################
    #
    def test_listed_addresses_only(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
    ) -> None:
        """
        GIVEN accounts that each have an MHDelivery
        WHEN  the command is given one of their addresses and an unknown one
        THEN  only the listed account is converted and the unknown address
              is reported
        """
        listed, *others = mh_accounts

        _, err = run_command(listed.email_address, "nobody@example.com")

        check.equal(local_delivery_type(listed), ASIMAPDelivery)
        for ea in others:
            check.equal(local_delivery_type(ea), MHDelivery, ea.email_address)
        check.is_in("nobody@example.com: no MHDelivery to convert", err)

    ####################################################################
    #
    def test_revert(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
    ) -> None:
        """
        GIVEN accounts converted to ASIMAPDelivery
        WHEN  the command is run with --revert --all
        THEN  every one is an MHDelivery again and keeps its settings
        """
        run_command("--all")

        run_command("--revert", "--all")

        for ea in mh_accounts:
            check.equal(local_delivery_type(ea), MHDelivery, ea.email_address)
        check.is_false(ASIMAPDelivery.objects.exists())
        reverted = MHDelivery.objects.get(email_account=mh_accounts[0])
        check.equal(reverted.spam_delivery_folder, "Spam")

    ####################################################################
    #
    def test_skips_sa_training_account(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
        settings: LazySettings,
    ) -> None:
        """
        GIVEN one of the accounts is the SPAM_TRAINING_ADDRESS
        WHEN  the command is run with --all
        THEN  that account keeps its MHDelivery, is reported as skipped,
              and the others are converted
        """
        training, *others = mh_accounts
        settings.SPAM_TRAINING_ADDRESS = training.email_address

        _, err = run_command("--all")

        check.equal(local_delivery_type(training), MHDelivery)
        for ea in others:
            check.equal(
                local_delivery_type(ea), ASIMAPDelivery, ea.email_address
            )
        check.is_in(f"{training.email_address}: skipped", err)

    ####################################################################
    #
    def test_dry_run_changes_nothing(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
    ) -> None:
        """
        GIVEN accounts that each have an MHDelivery
        WHEN  the command is run with --all --dry-run
        THEN  it reports what it would convert and converts nothing
        """
        out, _ = run_command("--all", "--dry-run")

        check.is_false(ASIMAPDelivery.objects.exists())
        check.is_in("Would convert 3 delivery method(s)", out)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "args", [(), ("--all", "someone@example.com")], ids=["none", "both"]
    )
    def test_requires_all_or_addresses(
        self,
        run_command: Callable[..., tuple[str, str]],
        args: tuple[str, ...],
    ) -> None:
        """
        GIVEN neither --all nor addresses, or both
        WHEN  the command is run
        THEN  it refuses with a CommandError
        """
        with pytest.raises(
            CommandError, match="--all or a list of email addresses"
        ):
            run_command(*args)
