#!/usr/bin/env python
#
"""
Tests for LocalDelivery, AliasToDelivery, and ImapDelivery model behaviour.

Delivery integration tests (loops, hop limits, alias chains) live in
test_deliver.py.  This file covers model-level properties — maildir creation,
spam routing, enabled/disabled dispatch, and multi-method fan-out.
"""

# system imports
#
import socket
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path

# 3rd party imports
#
import pytest
from faker import Faker
from pytest_mock import MockerFixture

# Project imports
#
from ..models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
    ImapDelivery,
    LocalDelivery,
)

pytestmark = pytest.mark.django_db


########################################################################
########################################################################
#
class TestLocalDeliveryModel:
    """Tests for LocalDelivery model properties and delivery behaviour."""

    ####################################################################
    #
    def test_maildir_path_auto_filled(
        self, email_account_factory: Callable[..., EmailAccount]
    ) -> None:
        """
        GIVEN a LocalDelivery created without an explicit maildir_path
        WHEN  it is saved
        THEN  maildir_path is auto-populated from the account's email address
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        assert ld.maildir_path
        assert ea.email_address in ld.maildir_path
        assert ea.server.domain_name in ld.maildir_path

    ####################################################################
    #
    def test_maildir_path_preserved_when_set(
        self,
        email_account_factory: Callable[..., EmailAccount],
        settings,
    ) -> None:
        """
        GIVEN a LocalDelivery created with an explicit maildir_path
        WHEN  it is saved
        THEN  the explicit path is preserved
        """
        ea = email_account_factory(local_delivery=False)
        custom = str(settings.MAIL_DIRS / "custom_dir")
        Path(custom).mkdir(parents=True, exist_ok=True)
        ld = LocalDelivery.objects.create(email_account=ea, maildir_path=custom)
        ld.refresh_from_db()
        assert ld.maildir_path == custom

    ####################################################################
    #
    def test_mh_creates_mailbox_directory(
        self,
        email_account_factory: Callable[..., EmailAccount],
        settings,
    ) -> None:
        """
        GIVEN a LocalDelivery
        WHEN  MH() is called
        THEN  the maildir path exists on disk and default folders are created
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        assert ld.maildir_path is not None
        assert Path(ld.maildir_path).is_dir()
        mh = ld.MH(create=False)
        for folder in settings.DEFAULT_FOLDERS:
            mh.get_folder(folder)  # raises NoSuchMailboxError if missing

    ####################################################################
    #
    def test_deliver_locally_puts_message_in_inbox(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN a LocalDelivery with no filter rules
        WHEN  a message is delivered
        THEN  the message ends up in the inbox folder
        """
        ea = email_account_factory()
        msg = email_factory(to=ea.email_address)
        ea.deliver(msg)

        ld = LocalDelivery.objects.get(email_account=ea)
        folder = ld.MH().get_folder("inbox")
        assert folder.get("1") is not None

    ####################################################################
    #
    def test_disabled_local_delivery_skips_delivery(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN a LocalDelivery with enabled=False
        WHEN  a message is delivered to the account
        THEN  no message is stored in the mailbox
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        ld.enabled = False
        ld.save()

        msg = email_factory(to=ea.email_address)
        ea.deliver(msg)

        folder = ld.MH().get_folder("inbox")
        assert len(list(folder.values())) == 0

    ####################################################################
    #
    def test_spam_above_threshold_goes_to_spam_folder(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN a LocalDelivery with autofile_spam=True and threshold=5
        WHEN  a message with X-Spam-Status score above the threshold arrives
        THEN  it is filed in spam_delivery_folder, not inbox
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        ld.autofile_spam = True
        ld.spam_score_threshold = 5
        ld.spam_delivery_folder = "Junk"
        ld.save()

        msg = email_factory(to=ea.email_address)
        msg["X-Spam-Status"] = "Yes, score=8.0 required=5.0 tests=NONE"
        ea.deliver(msg)

        mh = ld.MH()
        inbox = mh.get_folder("inbox")
        junk = mh.get_folder("Junk")
        assert len(list(inbox.values())) == 0
        assert len(list(junk.values())) == 1

    ####################################################################
    #
    def test_spam_below_threshold_goes_to_inbox(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN a LocalDelivery with autofile_spam=True and threshold=10
        WHEN  a message with X-Spam-Status score below the threshold arrives
        THEN  it is delivered to inbox normally
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        ld.autofile_spam = True
        ld.spam_score_threshold = 10
        ld.save()

        msg = email_factory(to=ea.email_address)
        msg["X-Spam-Status"] = "No, score=4.2 required=5.0 tests=NONE"
        ea.deliver(msg)

        mh = ld.MH()
        inbox = mh.get_folder("inbox")
        assert len(list(inbox.values())) == 1

    ####################################################################
    #
    def test_autofile_spam_disabled_delivers_to_inbox(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN a LocalDelivery with autofile_spam=False
        WHEN  a high-scoring spam message arrives
        THEN  it is delivered to inbox (spam filtering disabled)
        """
        ea = email_account_factory()
        ld = LocalDelivery.objects.get(email_account=ea)
        ld.autofile_spam = False
        ld.spam_score_threshold = 1
        ld.save()

        msg = email_factory(to=ea.email_address)
        msg["X-Spam-Status"] = "Yes, score=99.0 required=5.0 tests=NONE"
        ea.deliver(msg)

        mh = ld.MH()
        inbox = mh.get_folder("inbox")
        assert len(list(inbox.values())) == 1


########################################################################
########################################################################
#
class TestAliasToDeliveryModel:
    """Tests for AliasToDelivery model properties and delivery behaviour."""

    ####################################################################
    #
    def test_alias_delivers_to_target(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN an account with one AliasToDelivery pointing to a second account
        WHEN  a message is delivered to the first account
        THEN  it appears in the second account's inbox
        """
        ea_src = email_account_factory(local_delivery=False)
        ea_dst = email_account_factory()
        AliasToDelivery.objects.create(
            email_account=ea_src, target_account=ea_dst
        )

        msg = email_factory(to=ea_src.email_address)
        ea_src.deliver(msg)

        ld = LocalDelivery.objects.get(email_account=ea_dst)
        folder = ld.MH().get_folder("inbox")
        assert folder.get("1") is not None

    ####################################################################
    #
    def test_disabled_alias_is_skipped(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN an AliasToDelivery with enabled=False
        WHEN  a message is delivered to the source account
        THEN  nothing reaches the target account
        """
        ea_src = email_account_factory(local_delivery=False)
        ea_dst = email_account_factory()
        atd = AliasToDelivery.objects.create(
            email_account=ea_src, target_account=ea_dst, enabled=False
        )
        assert not atd.enabled

        msg = email_factory(to=ea_src.email_address)
        ea_src.deliver(msg)

        ld = LocalDelivery.objects.get(email_account=ea_dst)
        folder = ld.MH().get_folder("inbox")
        assert len(list(folder.values())) == 0

    ####################################################################
    #
    def test_str_representation(
        self, email_account_factory: Callable[..., EmailAccount]
    ) -> None:
        """
        GIVEN an AliasToDelivery
        WHEN  str() is called
        THEN  it includes the target account address
        """
        ea_src = email_account_factory(local_delivery=False)
        ea_dst = email_account_factory()
        atd = AliasToDelivery.objects.create(
            email_account=ea_src, target_account=ea_dst
        )
        assert ea_dst.email_address in str(atd)


########################################################################
########################################################################
#
class TestMultipleDeliveryMethods:
    """Tests for an EmailAccount that has more than one delivery method."""

    ####################################################################
    #
    def test_local_and_alias_both_deliver(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN an account with both a LocalDelivery and an AliasToDelivery
        WHEN  a message is delivered
        THEN  it reaches both the local mailbox and the alias target
        """
        ea_main = email_account_factory()  # has LocalDelivery
        ea_alias_target = email_account_factory()
        AliasToDelivery.objects.create(
            email_account=ea_main, target_account=ea_alias_target
        )

        msg = email_factory(to=ea_main.email_address)
        ea_main.deliver(msg)

        # Local copy
        ld_main = LocalDelivery.objects.get(email_account=ea_main)
        assert len(list(ld_main.MH().get_folder("inbox").values())) == 1

        # Aliased copy
        ld_target = LocalDelivery.objects.get(email_account=ea_alias_target)
        assert len(list(ld_target.MH().get_folder("inbox").values())) == 1

    ####################################################################
    #
    def test_multiple_aliases_all_receive(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN an account with three AliasToDelivery methods
        WHEN  a message is delivered
        THEN  all three targets receive the message
        """
        ea_src = email_account_factory(local_delivery=False)
        targets = [email_account_factory() for _ in range(3)]
        for ea_tgt in targets:
            AliasToDelivery.objects.create(
                email_account=ea_src, target_account=ea_tgt
            )

        msg = email_factory(to=ea_src.email_address)
        ea_src.deliver(msg)

        for ea_tgt in targets:
            ld = LocalDelivery.objects.get(email_account=ea_tgt)
            assert len(list(ld.MH().get_folder("inbox").values())) == 1

    ####################################################################
    #
    def test_only_enabled_methods_are_used(
        self,
        email_account_factory: Callable[..., EmailAccount],
        email_factory: Callable[..., EmailMessage],
    ) -> None:
        """
        GIVEN an account with one enabled and one disabled AliasToDelivery
        WHEN  a message is delivered
        THEN  only the enabled target receives the message
        """
        ea_src = email_account_factory(local_delivery=False)
        ea_enabled = email_account_factory()
        ea_disabled = email_account_factory()
        AliasToDelivery.objects.create(
            email_account=ea_src, target_account=ea_enabled, enabled=True
        )
        AliasToDelivery.objects.create(
            email_account=ea_src, target_account=ea_disabled, enabled=False
        )

        msg = email_factory(to=ea_src.email_address)
        ea_src.deliver(msg)

        ld_enabled = LocalDelivery.objects.get(email_account=ea_enabled)
        assert len(list(ld_enabled.MH().get_folder("inbox").values())) == 1

        ld_disabled = LocalDelivery.objects.get(email_account=ea_disabled)
        assert len(list(ld_disabled.MH().get_folder("inbox").values())) == 0

    ####################################################################
    #
    def test_delivery_method_queryset_filters_to_account(
        self, email_account_factory: Callable[..., EmailAccount]
    ) -> None:
        """
        GIVEN two accounts each with a LocalDelivery
        WHEN  delivery_methods is queried on one account
        THEN  only that account's methods are returned
        """
        ea1 = email_account_factory()
        ea2 = email_account_factory()

        assert DeliveryMethod.objects.filter(email_account=ea1).count() == 1
        assert DeliveryMethod.objects.filter(email_account=ea2).count() == 1
        dm = DeliveryMethod.objects.filter(email_account=ea1).first()
        assert dm is not None
        assert dm.email_account_id == ea1.pk


########################################################################
########################################################################
#
@pytest.fixture
def imap_delivery_factory(
    email_account_factory: Callable[..., EmailAccount],
    faker: Faker,
) -> Callable[..., ImapDelivery]:
    """Return a factory that creates an ImapDelivery attached to a fresh account."""

    def make(**kwargs) -> ImapDelivery:
        ea = email_account_factory(local_delivery=False)
        return ImapDelivery.objects.create(
            email_account=ea,
            imap_host="imap.example.com",
            imap_port=993,
            username="user@example.com",
            password=faker.password(),
            **kwargs,
        )

    return make


########################################################################
########################################################################
#
class TestImapDeliveryModel:
    """Tests for ImapDelivery model delivery behaviour.

    imapclient.IMAPClient is mocked in every test so no real IMAP
    connection is attempted.  The mock is set up via mocker.patch on the
    symbol ``as_email.models.imapclient.IMAPClient``.  The pattern::

        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value

    gives us the object that the ``with`` block binds to ``client``.
    """

    ####################################################################
    #
    def test_deliver_normal_message_to_inbox(
        self,
        imap_delivery_factory: Callable[..., ImapDelivery],
        email_factory: Callable[..., EmailMessage],
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN an ImapDelivery and a message with no spam header
        WHEN  deliver() is called
        THEN  the message is appended to INBOX
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value

        imap_d = imap_delivery_factory()
        msg = email_factory()
        imap_d.deliver(msg, set())

        mock_cls.assert_called_once_with(
            host="imap.example.com", port=993, ssl=True
        )
        mock_client.login.assert_called_once_with(
            "user@example.com", imap_d.password
        )
        mock_client.append.assert_called_once()
        folder_used = mock_client.append.call_args[0][0]
        assert folder_used == "INBOX"

    ####################################################################
    #
    @pytest.mark.parametrize(
        "list_folders_result, folder_exists_result, expected_folder",
        [
            pytest.param(
                [((r"\Junk",), "/", "Junk Mail")],
                False,
                "Junk Mail",
                id="special-use-Junk",
            ),
            pytest.param(
                [((r"\HasNoChildren",), "/", "INBOX")],
                True,
                "Junk",
                id="literal-Junk-exists",
            ),
            pytest.param(
                [],
                False,
                "INBOX",
                id="inbox-fallback",
            ),
        ],
    )
    def test_spam_routed_to_correct_junk_folder(
        self,
        imap_delivery_factory: Callable[..., ImapDelivery],
        email_factory: Callable[..., EmailMessage],
        mocker: MockerFixture,
        list_folders_result: list,
        folder_exists_result: bool,
        expected_folder: str,
    ) -> None:
        """
        GIVEN an ImapDelivery with autofile_spam=True and threshold=5
          AND the server's folder layout varies by parameter
        WHEN  a spam message (score >= threshold) is delivered
        THEN  it is appended to the correct junk folder:
              - \\Junk SPECIAL-USE folder when advertised (RFC 6154)
              - literal "Junk" folder when it exists
              - INBOX as a last resort
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value
        mock_client.list_folders.return_value = list_folders_result
        mock_client.folder_exists.return_value = folder_exists_result

        imap_d = imap_delivery_factory(
            autofile_spam=True, spam_score_threshold=5
        )
        msg = email_factory()
        msg["X-Spam-Status"] = "Yes, score=8.0 required=5.0 tests=NONE"
        imap_d.deliver(msg, set())

        folder_used = mock_client.append.call_args[0][0]
        assert folder_used == expected_folder

    ####################################################################
    #
    def test_autofile_spam_disabled_delivers_spam_to_inbox(
        self,
        imap_delivery_factory: Callable[..., ImapDelivery],
        email_factory: Callable[..., EmailMessage],
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN an ImapDelivery with autofile_spam=False
        WHEN  a high-scoring spam message is delivered
        THEN  it is appended to INBOX (spam filtering disabled)
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value

        imap_d = imap_delivery_factory(
            autofile_spam=False, spam_score_threshold=1
        )
        msg = email_factory()
        msg["X-Spam-Status"] = "Yes, score=99.0 required=5.0 tests=NONE"
        imap_d.deliver(msg, set())

        folder_used = mock_client.append.call_args[0][0]
        assert folder_used == "INBOX"
        mock_client.list_folders.assert_not_called()

    ####################################################################
    #
    def test_deliver_exception_propagates(
        self,
        imap_delivery_factory: Callable[..., ImapDelivery],
        email_factory: Callable[..., EmailMessage],
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN an ImapDelivery whose IMAPClient raises on login
        WHEN  deliver() is called
        THEN  the exception propagates out (caller moves mail to failed dir)
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value
        mock_client.login.side_effect = Exception("auth failure")

        imap_d = imap_delivery_factory()
        msg = email_factory()

        with pytest.raises(Exception, match="auth failure"):
            imap_d.deliver(msg, set())

        mock_client.append.assert_not_called()

    ####################################################################
    #
    def test_test_connection_success(self, mocker: MockerFixture) -> None:
        """
        GIVEN valid credentials and a reachable IMAP server
        WHEN  test_connection() is called
        THEN  (True, "Connection successful.") is returned
        """
        mocker.patch("as_email.models.imapclient.IMAPClient")
        ok, msg = ImapDelivery.test_connection(
            "imap.example.com", 993, "user@example.com", "s3cr3t"
        )
        assert ok is True
        assert "successful" in msg.lower()

    ####################################################################
    #
    @pytest.mark.parametrize(
        "exc_location, exception, expected_fragment",
        [
            pytest.param(
                "cls",
                socket.gaierror(8, "Name or service not known"),
                "not found",
                id="bad-hostname",
            ),
            pytest.param(
                "cls",
                ConnectionRefusedError(),
                "refused",
                id="connection-refused",
            ),
            pytest.param(
                "cls",
                TimeoutError(),
                "timed out",
                id="timeout",
            ),
            pytest.param(
                "cls",
                ssl.SSLError(1, "CERTIFICATE_VERIFY_FAILED"),
                "SSL/TLS error",
                id="ssl-error",
            ),
            pytest.param(
                "cls",
                Exception("something unexpected"),
                "Connection failed",
                id="generic-exception",
            ),
            pytest.param(
                "login",
                Exception(b"\"No such user 'user@example.com'\""),
                "Authentication failed: No such user",
                id="auth-failure-bytes",
            ),
            pytest.param(
                "login",
                Exception("b\"'bad!'\""),
                "Authentication failed: 'bad!'",
                id="auth-failure-bytes-repr",
            ),
        ],
    )
    def test_test_connection_failures(
        self,
        mocker: MockerFixture,
        exc_location: str,
        exception: Exception,
        expected_fragment: str,
    ) -> None:
        """
        GIVEN an IMAP server that raises a specific exception
        WHEN  test_connection() is called
        THEN  (False, message) is returned with a user-friendly description
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value
        if exc_location == "cls":
            mock_cls.side_effect = exception
        else:
            mock_client.login.side_effect = exception

        ok, msg = ImapDelivery.test_connection(
            "imap.example.com", 993, "user@example.com", "s3cr3t"
        )
        assert ok is False
        assert expected_fragment in msg

    ####################################################################
    #
    def test_deliver_non_ascii_message(
        self,
        imap_delivery_factory: Callable[..., ImapDelivery],
        malformed_non_ascii_email: EmailMessage,
        mocker: MockerFixture,
    ) -> None:
        """
        GIVEN a malformed email with non-ASCII characters in the subject
              and body but no charset declaration (common in spam)
        WHEN  deliver() is called
        THEN  the message is serialized and appended without raising
              UnicodeEncodeError
        """
        mock_cls = mocker.patch("as_email.models.imapclient.IMAPClient")
        mock_client = mock_cls.return_value.__enter__.return_value

        imap_d = imap_delivery_factory()
        imap_d.deliver(malformed_non_ascii_email, set())

        mock_client.append.assert_called_once()
        appended_bytes = mock_client.append.call_args[0][1]
        assert isinstance(appended_bytes, bytes)
