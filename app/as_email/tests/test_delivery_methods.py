#!/usr/bin/env python
#
"""
Tests for LocalDelivery and AliasToDelivery model behaviour.

Delivery integration tests (loops, hop limits, alias chains) live in
test_deliver.py.  This file covers model-level properties — maildir creation,
spam routing, enabled/disabled dispatch, and multi-method fan-out.
"""
from email.message import EmailMessage

# system imports
#
from pathlib import Path
from typing import Callable

# 3rd party imports
#
import pytest

# Project imports
#
from ..models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
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
        assert (
            DeliveryMethod.objects.filter(email_account=ea1)
            .first()
            .email_account_id
            == ea1.pk
        )
