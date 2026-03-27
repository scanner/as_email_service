#!/usr/bin/env python
#
"""
Tests for the report framework: individual report generators, the
run_report task, and the as_email_report management command.
"""

# system imports
#
import mailbox
from collections.abc import Callable
from pathlib import Path
from typing import Any

# 3rd party imports
#
import pytest
from django.conf import LazySettings
from django.core.management import call_command
from django.core.management.base import CommandError

# Project imports
#
from ..models import EmailAccount, LocalDelivery, Server
from ..reports import REPORTS, ReportSchedule, get_reports_by_schedule
from ..reports.email_usage import generate_email_usage_report
from ..tasks import run_report

pytestmark = pytest.mark.django_db


########################################################################
#
def _create_mh_messages(maildir_path: Path, folder: str, count: int) -> None:
    """Create `count` MH messages in the given folder."""
    mh = mailbox.MH(str(maildir_path), create=True)
    sub = mh.add_folder(folder)
    for i in range(count):
        msg = mailbox.MHMessage(f"Subject: test {i}\n\nBody {i}")
        sub.add(msg)
    sub.close()
    mh.close()


########################################################################
#
class TestReportRegistry:
    """Tests for the report registry in as_email.reports."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "report_name,expected_schedule",
        [
            ("email-usage", ReportSchedule.WEEKLY),
            ("unused-servers", ReportSchedule.DAILY),
        ],
    )
    def test_report_registered_with_correct_schedule(
        self, report_name: str, expected_schedule: ReportSchedule
    ) -> None:
        """
        Given the report registry
        When we look up a report by name
        Then it exists and has the expected schedule, and
             get_reports_by_schedule returns it
        """
        assert report_name in REPORTS
        assert REPORTS[report_name].schedule == expected_schedule

        scheduled = get_reports_by_schedule(expected_schedule)
        assert any(r.name == report_name for r in scheduled)


########################################################################
#
class TestEmailUsageReport:
    """Tests for generate_email_usage_report."""

    ####################################################################
    #
    def test_no_local_deliveries(self) -> None:
        """
        Given no LocalDelivery instances
        When generate_email_usage_report is called
        Then the report indicates no accounts found
        """
        report = generate_email_usage_report()
        assert "No local delivery accounts found" in report

    ####################################################################
    #
    def test_active_account_listed(
        self,
        settings: LazySettings,
        email_account_factory: Callable[..., EmailAccount],
        server_factory: Callable[..., Server],
        django_capture_on_commit_callbacks: Callable,
    ) -> None:
        """
        Given an email account with LocalDelivery and some messages
        When generate_email_usage_report is called
        Then the account appears in the report with message counts
        """
        with django_capture_on_commit_callbacks(execute=True):
            server = server_factory()
            ea = email_account_factory(server=server)

        ld = LocalDelivery.objects.get(email_account=ea)
        assert ld.maildir_path is not None
        _create_mh_messages(Path(ld.maildir_path), "inbox", 3)

        report = generate_email_usage_report()
        assert ea.email_address in report
        assert server.domain_name in report
        assert "3 messages" in report

    ####################################################################
    #
    def test_orphaned_account_directory(
        self,
        settings: LazySettings,
        server_factory: Callable[..., Server],
    ) -> None:
        """
        Given a mail directory for an account with no LocalDelivery
        When generate_email_usage_report is called
        Then the orphaned directory is listed
        """
        server = server_factory()
        orphan_dir = (
            settings.MAIL_DIRS / server.domain_name / "ghost@example.com"
        )
        orphan_dir.mkdir(parents=True, exist_ok=True)
        (orphan_dir / "testfile").write_text("data")

        report = generate_email_usage_report()
        assert "Orphaned account directories" in report
        assert "ghost@example.com" in report

    ####################################################################
    #
    def test_orphaned_domain_directory(
        self,
        settings: LazySettings,
    ) -> None:
        """
        Given a domain directory in MAIL_DIRS with no matching Server
        When generate_email_usage_report is called
        Then the orphaned domain directory is listed
        """
        orphan_domain = settings.MAIL_DIRS / "no-such-domain.example"
        orphan_domain.mkdir(parents=True, exist_ok=True)
        (orphan_domain / "somefile").write_text("leftover")

        report = generate_email_usage_report()
        assert "Orphaned domain directories" in report
        assert "no-such-domain.example" in report

    ####################################################################
    #
    def test_no_orphans_when_clean(
        self,
        settings: LazySettings,
        email_account_factory: Callable[..., EmailAccount],
        server_factory: Callable[..., Server],
        django_capture_on_commit_callbacks: Callable,
    ) -> None:
        """
        Given all mail directories match existing LocalDelivery instances
        When generate_email_usage_report is called
        Then no orphan sections appear
        """
        with django_capture_on_commit_callbacks(execute=True):
            server = server_factory()
            email_account_factory(server=server)

        report = generate_email_usage_report()
        assert "Orphaned" not in report


########################################################################
#
class TestRunReportTask:
    """Tests for the run_report task."""

    ####################################################################
    #
    def test_run_report_sends_email(
        self,
        settings: LazySettings,
        django_outbox: list[Any],
    ) -> None:
        """
        Given the run_report task is called with 'email-usage'
        When there are no accounts (simple case)
        Then an email is sent to ADMINISTRATIVE_EMAIL_ADDRESS
        """
        res = run_report("email-usage")
        res()

        assert len(django_outbox) == 1
        msg = django_outbox[0]
        assert "usage report" in msg.subject.lower()
        assert msg.to == [settings.ADMINISTRATIVE_EMAIL_ADDRESS]
        assert "Email Account Usage Report" in msg.body

    ####################################################################
    #
    def test_run_report_unknown_name(
        self,
        django_outbox: list[Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        Given a report name that does not exist
        When run_report is called
        Then it logs an error and sends no email
        """
        res = run_report("no-such-report")
        res()

        assert len(django_outbox) == 0
        assert "Unknown report name" in caplog.text


########################################################################
#
class TestAsEmailReportCommand:
    """Tests for the as_email_report management command."""

    ####################################################################
    #
    def test_command_output(self, capsys: pytest.CaptureFixture) -> None:
        """
        Given the management command is invoked with 'email-usage'
        When there are no accounts
        Then the report is written to stdout
        """
        call_command("as_email_report", "email-usage")
        captured = capsys.readouterr()
        assert "Email Account Usage Report" in captured.out

    ####################################################################
    #
    def test_list_reports(self, capsys: pytest.CaptureFixture) -> None:
        """
        Given the --list flag is passed
        When the command runs
        Then all available reports are listed
        """
        call_command("as_email_report", "--list")
        captured = capsys.readouterr()
        assert "email-usage" in captured.out
        assert "unused-servers" in captured.out

    ####################################################################
    #
    def test_unknown_report(self) -> None:
        """
        Given an unknown report name
        When the command runs
        Then a CommandError is raised
        """
        with pytest.raises(CommandError, match="Unknown report"):
            call_command("as_email_report", "bogus")

    ####################################################################
    #
    def test_no_args(self) -> None:
        """
        Given no report name and no --list flag
        When the command runs
        Then a CommandError is raised
        """
        with pytest.raises(CommandError, match="Provide a report name"):
            call_command("as_email_report")
