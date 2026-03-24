#!/usr/bin/env python
#
"""
Report registry for AS Email Service.

Each report has a name, description, schedule, and a generate function
that returns the report body as a string.  The registry is used by
management commands and periodic tasks to discover and run reports.
"""

# system imports
#
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

# Project imports
#
from .email_usage import generate_email_usage_report
from .unused_servers import generate_unused_servers_report


########################################################################
#
class ReportSchedule(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"


########################################################################
#
@dataclass(frozen=True)
class ReportDefinition:
    name: str
    description: str
    schedule: ReportSchedule
    generate: Callable[[], str]
    subject: str


# The canonical registry of all reports.  Keys are the report names
# used on the command line and in task scheduling.
#
REPORTS: dict[str, ReportDefinition] = {
    "unused-servers": ReportDefinition(
        name="unused-servers",
        description=("Servers on providers that have no active email accounts"),
        schedule=ReportSchedule.DAILY,
        generate=generate_unused_servers_report,
        subject="AS Email Service: {count} unused server(s) detected",
    ),
    "email-usage": ReportDefinition(
        name="email-usage",
        description=("Mailbox usage and orphaned mail directories"),
        schedule=ReportSchedule.WEEKLY,
        generate=generate_email_usage_report,
        subject="AS Email Service: Weekly email usage report",
    ),
}


########################################################################
#
def get_reports_by_schedule(
    schedule: ReportSchedule,
) -> list[ReportDefinition]:
    """Return all reports matching the given schedule."""
    return [r for r in REPORTS.values() if r.schedule == schedule]
