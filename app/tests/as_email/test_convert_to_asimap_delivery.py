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
    def test_all_with_exclude_leaves_excluded_alone(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
    ) -> None:
        """
        GIVEN accounts that each have an MHDelivery
        WHEN  the command is run with --all and one of them --exclude'd
        THEN  that account keeps its MHDelivery and is reported as
              excluded, and the others are converted
        """
        kept, *others = mh_accounts

        _, err = run_command("--all", "--exclude", kept.email_address)

        check.equal(local_delivery_type(kept), MHDelivery)
        for ea in others:
            check.equal(
                local_delivery_type(ea), ASIMAPDelivery, ea.email_address
            )
        check.is_in(f"{kept.email_address}: excluded", err)

    ####################################################################
    #
    @pytest.mark.parametrize(
        "listed,expected_out,expected_err",
        [
            (
                [],
                [
                    "ASIMAPDelivery  {asimap}",
                    "MHDelivery      {disabled}  (disabled)",
                    "2 MHDelivery, 1 ASIMAPDelivery",
                ],
                [],
            ),
            (
                ["{asimap}", "nobody@example.com"],
                ["ASIMAPDelivery  {asimap}", "0 MHDelivery, 1 ASIMAPDelivery"],
                ["nobody@example.com: no local delivery"],
            ),
        ],
        ids=["all", "given-addresses"],
    )
    def test_list(
        self,
        mh_accounts: list[EmailAccount],
        run_command: Callable[..., tuple[str, str]],
        listed: list[str],
        expected_out: list[str],
        expected_err: list[str],
    ) -> None:
        """
        GIVEN one account converted to ASIMAPDelivery and one MHDelivery
              disabled
        WHEN  the command is run with --list, alone or with addresses
        THEN  each listed account is shown with its type, a disabled one is
              marked, the counts cover what was listed, an address with no
              local delivery is reported, and nothing is converted
        """
        asimap, disabled, _ = mh_accounts
        run_command(asimap.email_address)
        MHDelivery.objects.filter(email_account=disabled).update(enabled=False)
        names = {
            "asimap": asimap.email_address,
            "disabled": disabled.email_address,
        }

        out, err = run_command("--list", *(a.format(**names) for a in listed))

        for line in expected_out:
            check.is_in(line.format(**names), out)
        for line in expected_err:
            check.is_in(line.format(**names), err)
        check.equal(local_delivery_type(disabled), MHDelivery, "not converted")

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
        "args,match",
        [
            ((), "--all or a list of email addresses"),
            (("--all", "a@example.com"), "--all or a list of email addresses"),
            (("a@example.com", "--exclude", "b@example.com"), "only works"),
            (("--all", "--exclude", "nobody@example.com"), "No email account"),
            (("--list", "--all"), "--list takes only"),
        ],
        ids=["none", "both", "exclude-without-all", "unknown-exclude", "list"],
    )
    def test_rejects_bad_arguments(
        self,
        run_command: Callable[..., tuple[str, str]],
        args: tuple[str, ...],
        match: str,
    ) -> None:
        """
        GIVEN arguments that do not say clearly what to convert: neither or
              both of --all and addresses, --exclude without --all, an
              --exclude address with no account, or --list with --all
        WHEN  the command is run
        THEN  it refuses with a CommandError before changing anything
        """
        with pytest.raises(CommandError, match=match):
            run_command(*args)
