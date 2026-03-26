#!/usr/bin/env python
#
"""
Process spam/ham training submissions and stage extracted messages for
SpamAssassin ``sa-learn``.

Usage::

    manage.py as_email_sa_training /path/to/training/dir
"""

# system imports
#
from pathlib import Path
from typing import Any

# 3rd party imports
#
from django.core.management.base import BaseCommand

# Project imports
#
from as_email.sa_training import process_training_inbox


class Command(BaseCommand):
    """Process SA training inbox and stage messages for sa-learn."""

    help = (
        "Process spam/ham training submissions from the training inbox "
        "and stage extracted messages for SpamAssassin sa-learn."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "training_dir",
            type=str,
            help=(
                "Base directory for SA training output. "
                "spam/ and ham/ subdirectories are created within it."
            ),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        training_dir = Path(options["training_dir"])
        result = process_training_inbox(training_dir, stdout=self.stdout)
        self.stdout.write(
            f"Processed: {result.spam_count} spam, "
            f"{result.ham_count} ham, "
            f"{result.skipped_invalid_sender} invalid sender, "
            f"{result.skipped_no_classification} unclassifiable, "
            f"{result.errors} errors"
        )
