#!/usr/bin/env python
#
"""
Tests for the SpamAssassin training message processor and management
command.
"""

# system imports
#
from collections.abc import Callable
from email.message import EmailMessage
from email.mime.message import MIMEMessage
from pathlib import Path
from typing import Any, cast

# 3rd party imports
#
import pytest
from django.conf import LazySettings
from django.core.management import call_command
from django.core.management.base import CommandError

# Project imports
#
from ..models import EmailAccount, LocalDelivery
from ..sa_training import (
    TrainingResult,
    determine_classification,
    find_training_local_delivery,
    process_training_inbox,
    validate_sender,
)

pytestmark = pytest.mark.django_db


########################################################################
#
def _make_forwarded_msg(
    msg_from: str,
    msg_to: str,
    inner_msg: EmailMessage | None = None,
) -> EmailMessage:
    """
    Build a forwarded message envelope.

    If ``inner_msg`` is provided it is attached as ``message/rfc822``.
    Otherwise the envelope is a plain inline-forward message.
    """
    outer = EmailMessage()
    outer["From"] = msg_from
    outer["To"] = msg_to
    outer["Delivered-To"] = msg_to
    outer["Subject"] = "Fwd: suspicious email"

    if inner_msg is not None:
        outer.set_content("See attached message.")
        # EmailMessage.add_attachment does not support message/rfc822
        # directly, so build the MIME part manually.
        #
        outer.make_mixed()
        attachment = MIMEMessage(inner_msg)
        outer.attach(cast(EmailMessage, attachment))
    else:
        outer.set_content("---------- Forwarded message ----------\nspam body")

    return outer


########################################################################
#
def _make_inner_msg() -> EmailMessage:
    """Create a simple message to use as the forwarded original."""
    msg = EmailMessage()
    msg["From"] = "spammer@evil.example"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "You have won a prize"
    msg.set_content("Click here to claim your prize.")
    return msg


########################################################################
#
def _deposit_message(local_delivery: LocalDelivery, msg: EmailMessage) -> str:
    """
    Add a message to the inbox of the given LocalDelivery's MH
    mailbox.  Returns the MH key as a string.
    """
    mh = local_delivery.MH()
    inbox = mh.get_folder("inbox")
    key = inbox.add(msg.as_bytes())
    inbox.close()
    mh.close()
    return str(key)


########################################################################
#
@pytest.fixture
def training_accounts(
    settings: LazySettings,
    email_account_factory: Callable[..., EmailAccount],
    django_capture_on_commit_callbacks: Callable,
) -> dict[str, Any]:
    """
    Create the spam and not-spam training EmailAccounts with
    LocalDelivery and configure the settings.
    """
    with django_capture_on_commit_callbacks(execute=True):
        spam_ea = email_account_factory(
            email_address="spam@srvr0.example.com",
        )
    not_spam_ea = EmailAccount.objects.create(
        owner=spam_ea.owner,
        server=spam_ea.server,
        email_address="not-spam@srvr0.example.com",
    )

    settings.SPAM_TRAINING_ADDRESS = spam_ea.email_address
    settings.NOT_SPAM_TRAINING_ADDRESS = not_spam_ea.email_address

    ld = LocalDelivery.objects.get(email_account=spam_ea)

    return {
        "spam_ea": spam_ea,
        "not_spam_ea": not_spam_ea,
        "local_delivery": ld,
        "server": spam_ea.server,
    }


########################################################################
#
class TestValidateSender:
    """Tests for validate_sender edge cases."""

    ####################################################################
    #
    def test_disabled_sender(self, training_accounts: dict[str, Any]) -> None:
        """
        Given a message from a disabled EmailAccount
        When validate_sender is called
        Then it returns False
        """
        ea = training_accounts["spam_ea"]
        ea.enabled = False
        ea.save()

        msg = EmailMessage()
        msg["From"] = ea.email_address
        assert validate_sender(msg) is False

    ####################################################################
    #
    def test_no_from_header(self) -> None:
        """
        Given a message with no From header
        When validate_sender is called
        Then it returns False
        """
        msg = EmailMessage()
        assert validate_sender(msg) is False


########################################################################
#
class TestDetermineClassification:
    """Tests for determine_classification."""

    SPAM_ADDR = "spam@example.com"
    NOT_SPAM_ADDR = "not-spam@example.com"

    ####################################################################
    #
    @pytest.mark.parametrize(
        "header_name,header_value,expected",
        [
            ("Delivered-To", "spam@example.com", "spam"),
            ("Delivered-To", "not-spam@example.com", "ham"),
            ("X-Original-To", "spam@example.com", "spam"),
            ("To", "not-spam@example.com", "ham"),
            ("To", "someone-else@example.com", None),
            ("Delivered-To", "SPAM@Example.COM", "spam"),
        ],
        ids=[
            "delivered-to-spam",
            "delivered-to-ham",
            "x-original-to-spam",
            "to-ham",
            "no-match",
            "case-insensitive",
        ],
    )
    def test_classification_from_header(
        self,
        header_name: str,
        header_value: str,
        expected: str | None,
    ) -> None:
        """
        Given a message with a recipient header
        When determine_classification is called
        Then it returns the correct classification based on which
             training address was matched
        """
        msg = EmailMessage()
        msg[header_name] = header_value
        result = determine_classification(
            msg, self.SPAM_ADDR, self.NOT_SPAM_ADDR
        )
        assert result == expected


########################################################################
#
class TestFindTrainingLocalDelivery:
    """Tests for find_training_local_delivery edge cases."""

    ####################################################################
    #
    def test_finds_via_not_spam_address(
        self,
        settings: LazySettings,
        training_accounts: dict[str, Any],
    ) -> None:
        """
        Given only NOT_SPAM_TRAINING_ADDRESS has a LocalDelivery
        When find_training_local_delivery is called
        Then it returns that LocalDelivery
        """
        ld = training_accounts["local_delivery"]
        ld.delete()
        new_ld = LocalDelivery.objects.create(
            email_account=training_accounts["not_spam_ea"]
        )

        found = find_training_local_delivery()
        assert found.pk == new_ld.pk

    ####################################################################
    #
    def test_no_local_delivery_raises(
        self,
        settings: LazySettings,
        training_accounts: dict[str, Any],
    ) -> None:
        """
        Given the training accounts exist but have no LocalDelivery
        When find_training_local_delivery is called
        Then CommandError is raised
        """
        LocalDelivery.objects.filter(
            email_account=training_accounts["spam_ea"]
        ).delete()

        with pytest.raises(CommandError, match="No enabled LocalDelivery"):
            find_training_local_delivery()


########################################################################
#
class TestProcessTrainingInbox:
    """Integration tests for process_training_inbox."""

    ####################################################################
    #
    @pytest.mark.parametrize(
        "classification",
        ["spam", "ham"],
        ids=["forward-to-spam", "forward-to-not-spam"],
    )
    def test_message_processed(
        self,
        classification: str,
        training_accounts: dict[str, Any],
        tmp_path: Path,
        email_account_factory: Callable[..., EmailAccount],
        django_capture_on_commit_callbacks: Callable,
    ) -> None:
        """
        Given a valid forwarded message in the training inbox
        When process_training_inbox is called
        Then the extracted message appears in the correct training
             subdirectory and the original is removed from the inbox
        """
        with django_capture_on_commit_callbacks(execute=True):
            sender = email_account_factory(
                server=training_accounts["server"],
            )

        ld = training_accounts["local_delivery"]
        target_key = "spam_ea" if classification == "spam" else "not_spam_ea"
        target_addr = training_accounts[target_key].email_address

        inner = _make_inner_msg()
        outer = _make_forwarded_msg(
            sender.email_address, target_addr, inner_msg=inner
        )
        _deposit_message(ld, outer)

        training_dir = tmp_path / "sa_training"
        result = process_training_inbox(training_dir)

        assert getattr(result, f"{classification}_count") == 1
        other = "ham" if classification == "spam" else "spam"
        assert getattr(result, f"{other}_count") == 0

        output_files = list((training_dir / classification).iterdir())
        assert len(output_files) == 1

        mh = ld.MH(create=False)
        inbox = mh.get_folder("inbox")
        assert len(inbox.keys()) == 0

    ####################################################################
    #
    def test_invalid_sender_tossed(
        self,
        training_accounts: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """
        Given a message from an untrusted sender
        When process_training_inbox is called
        Then the message is discarded and the counter incremented
        """
        ld = training_accounts["local_delivery"]
        outer = _make_forwarded_msg(
            "stranger@nowhere.example",
            training_accounts["spam_ea"].email_address,
            inner_msg=_make_inner_msg(),
        )
        _deposit_message(ld, outer)

        training_dir = tmp_path / "sa_training"
        result = process_training_inbox(training_dir)

        assert result.skipped_invalid_sender == 1
        assert result.spam_count == 0
        assert result.ham_count == 0

        mh = ld.MH(create=False)
        inbox = mh.get_folder("inbox")
        assert len(inbox.keys()) == 0

    ####################################################################
    #
    def test_empty_inbox(
        self,
        training_accounts: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """
        Given an empty training inbox
        When process_training_inbox is called
        Then all counters are zero
        """
        training_dir = tmp_path / "sa_training"
        result = process_training_inbox(training_dir)
        assert result == TrainingResult()

    ####################################################################
    #
    def test_inline_forward_processed(
        self,
        training_accounts: dict[str, Any],
        tmp_path: Path,
        email_account_factory: Callable[..., EmailAccount],
        django_capture_on_commit_callbacks: Callable,
    ) -> None:
        """
        Given a message forwarded inline (no message/rfc822 attachment)
        When process_training_inbox is called
        Then the full message is saved to the training directory
        """
        with django_capture_on_commit_callbacks(execute=True):
            sender = email_account_factory(
                server=training_accounts["server"],
            )

        ld = training_accounts["local_delivery"]
        outer = _make_forwarded_msg(
            sender.email_address,
            training_accounts["spam_ea"].email_address,
            inner_msg=None,
        )
        _deposit_message(ld, outer)

        training_dir = tmp_path / "sa_training"
        result = process_training_inbox(training_dir)

        assert result.spam_count == 1
        spam_files = list((training_dir / "spam").iterdir())
        assert len(spam_files) == 1


########################################################################
#
class TestAsEmailSaTrainingCommand:
    """Tests for the as_email_sa_training management command."""

    ####################################################################
    #
    def test_command_runs(
        self,
        training_accounts: dict[str, Any],
        tmp_path: Path,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """
        Given valid configuration
        When the management command is invoked
        Then it runs without error and prints a summary
        """
        training_dir = tmp_path / "sa_training"
        call_command("as_email_sa_training", str(training_dir))
        captured = capsys.readouterr()
        assert "Processed:" in captured.out

    ####################################################################
    #
    def test_command_missing_settings(
        self,
        settings: LazySettings,
        tmp_path: Path,
    ) -> None:
        """
        Given neither training address is configured
        When the management command is invoked
        Then a CommandError is raised
        """
        settings.SPAM_TRAINING_ADDRESS = None
        settings.NOT_SPAM_TRAINING_ADDRESS = None

        with pytest.raises(CommandError):
            call_command("as_email_sa_training", str(tmp_path))
