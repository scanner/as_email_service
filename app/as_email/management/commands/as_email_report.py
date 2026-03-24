#!/usr/bin/env python
#
"""
Run a named report and print the output to stdout.

Usage::

    manage.py report email-usage
    manage.py report unused-servers
    manage.py report --list
"""

# system imports
#
from typing import Any

# 3rd party imports
#
from django.core.management.base import BaseCommand, CommandError

# Project imports
#
from as_email.reports import REPORTS


class Command(BaseCommand):
    """Run a report by name and print the result to stdout."""

    help = (
        "Run a named report and print the output. "
        "Use --list to see available reports."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "report_name",
            nargs="?",
            help="Name of the report to run.",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            dest="list_reports",
            help="List all available reports and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["list_reports"]:
            self.stdout.write("Available reports:\n")
            for name, defn in sorted(REPORTS.items()):
                self.stdout.write(
                    f"  {name:<20s} [{defn.schedule.value}]  {defn.description}"
                )
            return

        report_name = options["report_name"]
        if not report_name:
            raise CommandError(
                "Provide a report name or use --list to see available reports."
            )

        if report_name not in REPORTS:
            available = ", ".join(sorted(REPORTS.keys()))
            raise CommandError(
                f"Unknown report '{report_name}'. "
                f"Available reports: {available}"
            )

        report_def = REPORTS[report_name]
        output = report_def.generate()
        if output:
            self.stdout.write(output)
        else:
            self.stdout.write(f"Report '{report_name}' returned no data.")
