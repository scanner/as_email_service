#!/usr/bin/env python
#
"""
Convert email accounts' MHDelivery methods to ASIMAPDelivery, or back.

A conversion replaces the delivery method's MHDelivery row with an
ASIMAPDelivery row (or the reverse) and changes its polymorphic type. The
delivery method keeps its pk and all of its settings.

Run this only once every asimap that serves these mail stores can import
from the delivery spool (asimap 2.7.0 or later).

asimap imports spooled mail only while the user's IMAP server process is
running. The spam and ham training accounts (SPAM_TRAINING_ADDRESS and
NOT_SPAM_TRAINING_ADDRESS) are read straight from their MH inbox by SA
training, so they are never converted.

Usage::

    manage.py convert_to_asimap_delivery --list
    manage.py convert_to_asimap_delivery --all --exclude bucket@example.com
    manage.py convert_to_asimap_delivery user@example.com other@example.com
    manage.py convert_to_asimap_delivery --revert user@example.com
"""

# system imports
#
from collections import Counter
from typing import Any

# 3rd party imports
#
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import QuerySet

# Project imports
#
from as_email.models import (
    ASIMAPDelivery,
    DeliveryMethod,
    EmailAccount,
    LocalDelivery,
    MHDelivery,
    local_deliveries,
)


####################################################################
#
def convert_local_delivery(
    delivery: LocalDelivery, to_type: type[LocalDelivery]
) -> None:
    """
    Turn a local delivery into one of another local delivery type, keeping
    its pk and settings.

    Both types are children of the same DeliveryMethod row. The delivery's
    own row is deleted, a row of `to_type` with the same field values is
    inserted, and the DeliveryMethod's polymorphic type is switched.
    """
    converted = to_type(
        **{
            f.attname: getattr(delivery, f.attname)
            for f in type(delivery)._meta.concrete_fields
        }
    )
    to_ct = ContentType.objects.get_for_model(to_type)
    pk = delivery.pk
    with transaction.atomic():
        delivery.delete(keep_parents=True)
        # `raw` saves only the new type's table, not the DeliveryMethod row.
        #
        converted.save_base(raw=True, force_insert=True)
        DeliveryMethod.objects.filter(pk=pk).update(polymorphic_ctype=to_ct)


########################################################################
########################################################################
#
class Command(BaseCommand):
    """Convert MHDelivery methods to ASIMAPDelivery, or back."""

    help = (
        "Convert the MHDelivery of the given email accounts (or of every "
        "account, with --all, less any --exclude) to ASIMAPDelivery. With "
        "--revert, convert ASIMAPDelivery back to MHDelivery. With --list, "
        "show each account's local delivery type instead."
    )

    ####################################################################
    #
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "email_addresses",
            nargs="*",
            help="Email addresses of the accounts to convert (or list).",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Convert every account instead of the listed ones.",
        )
        parser.add_argument(
            "--exclude",
            action="append",
            default=[],
            metavar="ADDRESS",
            help=(
                "With --all, leave this account alone. Repeat for more. "
                "Every excluded address must be an existing email account."
            ),
        )
        parser.add_argument(
            "--list",
            action="store_true",
            help=(
                "List each account with a local delivery and its type (only "
                "the given addresses, if any) and convert nothing."
            ),
        )
        parser.add_argument(
            "--revert",
            action="store_true",
            help="Convert ASIMAPDelivery back to MHDelivery.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be converted without changing anything.",
        )

    ####################################################################
    #
    def handle(self, *args: Any, **options: Any) -> None:
        addresses = [a.lower() for a in options["email_addresses"]]
        excluded = [a.lower() for a in options["exclude"]]

        if options["list"]:
            if options["all"] or options["revert"] or excluded:
                raise CommandError(
                    "--list takes only email addresses, not --all, "
                    "--revert or --exclude."
                )
            self.list_local_deliveries(addresses)
            return

        if options["all"] == bool(addresses):
            raise CommandError(
                "Give --all or a list of email addresses, but not both."
            )
        if excluded and not options["all"]:
            raise CommandError("--exclude only works with --all.")
        unknown = set(excluded) - set(
            EmailAccount.objects.filter(email_address__in=excluded).values_list(
                "email_address", flat=True
            )
        )
        if unknown:
            raise CommandError(
                "No email account for --exclude "
                f"{', '.join(sorted(unknown))}; nothing converted."
            )

        self.convert(addresses, excluded, options["revert"], options["dry_run"])

    ####################################################################
    #
    def list_local_deliveries(self, addresses: list[str]) -> None:
        """
        Print each account's local delivery type, then a count per type.

        Args:
            addresses: Only list these accounts; all of them when empty.
        """
        deliveries = local_deliveries().select_related("email_account")
        if addresses:
            deliveries = deliveries.filter(
                email_account__email_address__in=addresses
            )
        counts: Counter[str] = Counter()
        for delivery in deliveries.order_by("email_account__email_address"):
            type_name = type(delivery).__name__
            counts[type_name] += 1
            disabled = "" if delivery.enabled else "  (disabled)"
            self.stdout.write(
                f"{type_name:<15} {delivery.email_account.email_address}"
                f"{disabled}"
            )
        listed = set(
            deliveries.values_list("email_account__email_address", flat=True)
        )
        for address in sorted(set(addresses) - listed):
            self.stderr.write(f"{address}: no local delivery")
        self.stdout.write(
            ", ".join(
                f"{counts[t.__name__]} {t.__name__}"
                for t in (MHDelivery, ASIMAPDelivery)
            )
        )

    ####################################################################
    #
    def convert(
        self,
        addresses: list[str],
        excluded: list[str],
        revert: bool,
        dry_run: bool,
    ) -> None:
        """
        Convert the selected local deliveries and report what was done.

        Args:
            addresses: Only convert these accounts; every account when empty.
            excluded: Accounts to leave alone.
            revert: Convert ASIMAPDelivery to MHDelivery instead.
            dry_run: Report without changing anything.
        """
        source: type[LocalDelivery] = MHDelivery
        target: type[LocalDelivery] = ASIMAPDelivery
        if revert:
            source, target = target, source

        deliveries: QuerySet = source.objects.all()
        if addresses:
            deliveries = deliveries.filter(
                email_account__email_address__in=addresses
            )
        deliveries = deliveries.exclude(
            email_account__email_address__in=excluded
        )

        skipped: list[str] = []
        if not revert:
            training = [
                a.lower()
                for a in (
                    settings.SPAM_TRAINING_ADDRESS,
                    settings.NOT_SPAM_TRAINING_ADDRESS,
                )
                if a
            ]
            skipped = sorted(
                deliveries.filter(
                    email_account__email_address__in=training
                ).values_list("email_account__email_address", flat=True)
            )
            deliveries = deliveries.exclude(
                email_account__email_address__in=training
            )

        deliveries = deliveries.select_related("email_account").order_by(
            "email_account__email_address"
        )

        converted = set()
        for delivery in deliveries:
            address = delivery.email_account.email_address
            if not dry_run:
                convert_local_delivery(delivery, target)
            converted.add(address)
            verb = "Would convert" if dry_run else "Converted"
            self.stdout.write(f"{verb} {address} to {target.__name__}")

        for address in sorted(excluded):
            self.stderr.write(f"{address}: excluded")
        for address in skipped:
            self.stderr.write(
                f"{address}: skipped, SA training reads its MH inbox directly"
            )
        for address in sorted(set(addresses) - converted - set(skipped)):
            self.stderr.write(f"{address}: no {source.__name__} to convert")

        verb = "Would convert" if dry_run else "Converted"
        self.stdout.write(f"{verb} {len(converted)} delivery method(s)")
