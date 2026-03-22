#!/usr/bin/env python
#
"""
Tests for migrations 0009–0011 (the multiple-delivery-methods feature).

0009 – schema: creates DeliveryMethod, LocalDelivery, AliasToDelivery tables
        and adds EmailAccount.enabled.
0010 – data: populates DeliveryMethod rows from legacy EmailAccount fields.
0011 – schema: removes legacy delivery fields and the Alias through-model.

Each migration is tested forward-only, plus reverse paths for the two
data/schema migrations that are new and non-trivial (0010 and 0011).
"""

# 3rd party imports
#
import pytest
from django.utils import timezone


########################################################################
########################################################################
#
@pytest.fixture
def make_migration_context():
    """
    Factory fixture that creates the prerequisite objects for migration tests.

    Returns a callable: make_migration_context(apps_state, domain_name)
    which returns a dict with 'server', 'user', and 'EmailAccount' (the
    historical model class from that migration state).
    """

    def _factory(apps, domain_name: str):
        Provider = apps.get_model("as_email", "Provider")
        Server = apps.get_model("as_email", "Server")

        provider = Provider.objects.create(
            name="test provider",
            backend_name="dummy",
        )
        server = Server.objects.create(
            domain_name=domain_name,
            api_key="secret",
            send_provider=provider,
        )
        # Use the historical User model from the migration state rather than
        # get_user_model()/create_user() so we work with the schema as it
        # exists at this migration step.  auth/0005 (which makes last_login
        # nullable) may not have been applied yet, so set it explicitly.
        #
        User = apps.get_model("auth", "User")
        user = User.objects.create(
            username=f"user_{domain_name}",
            password="unusable",
            last_login=timezone.now(),
            is_active=True,
            is_staff=False,
            is_superuser=False,
            email="",
            first_name="",
            last_name="",
        )
        return {
            "server": server,
            "user": user,
            "EmailAccount": apps.get_model("as_email", "EmailAccount"),
        }

    return _factory


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0009_creates_delivery_method_tables(migrator_factory) -> None:
    """
    GIVEN  the database at migration 0008
    WHEN   migration 0009 is applied
    THEN   the DeliveryMethod, LocalDelivery, and AliasToDelivery tables
           exist and EmailAccount gains an 'enabled' column
    """
    migrator = migrator_factory()
    migrator.apply_initial_migration(
        ("as_email", "0008_alter_emailaccount_server")
    )
    new_state = migrator.apply_tested_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    DeliveryMethod = new_state.apps.get_model("as_email", "DeliveryMethod")
    LocalDelivery = new_state.apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = new_state.apps.get_model("as_email", "AliasToDelivery")
    EmailAccount = new_state.apps.get_model("as_email", "EmailAccount")

    # Tables exist (no exception raised) and the new 'enabled' field is present.
    #
    assert not DeliveryMethod.objects.exists()
    assert not LocalDelivery.objects.exists()
    assert not AliasToDelivery.objects.exists()
    ea_field_names = {f.name for f in EmailAccount._meta.get_fields()}
    assert "enabled" in ea_field_names


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_local_delivery_account_gets_local_delivery(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an EmailAccount with delivery_method='LD' at migration 0009
    WHEN   migration 0010 is applied
    THEN   a LocalDelivery row is created for that account with the right maildir_path
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10ld.example.com")
    ea = ctx["EmailAccount"].objects.create(
        email_address="local@m10ld.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
        mail_dir="/tmp/maildir/local",
    )

    new_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    LocalDelivery = new_state.apps.get_model("as_email", "LocalDelivery")
    ld = LocalDelivery.objects.filter(email_account_id=ea.pk).first()
    assert ld is not None
    assert ld.maildir_path == ea.mail_dir


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_forwarding_account_gets_local_delivery(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an EmailAccount with delivery_method='FW' at migration 0009
    WHEN   migration 0010 is applied
    THEN   a LocalDelivery row is created (forwarding falls back to local)
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10fw.example.com")
    ea = ctx["EmailAccount"].objects.create(
        email_address="fwd@m10fw.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="FW",
        mail_dir="/tmp/maildir/fwd",
    )

    new_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    LocalDelivery = new_state.apps.get_model("as_email", "LocalDelivery")
    assert LocalDelivery.objects.filter(email_account_id=ea.pk).exists()


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_alias_account_gets_alias_to_delivery(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an EmailAccount with delivery_method='AL' and one alias_for target
    WHEN   migration 0010 is applied
    THEN   an AliasToDelivery row is created pointing at that target
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10al.example.com")
    EmailAccount = ctx["EmailAccount"]
    ea_src = EmailAccount.objects.create(
        email_address="alias@m10al.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="AL",
    )
    ea_dst = EmailAccount.objects.create(
        email_address="target@m10al.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
    )
    ea_src.alias_for.add(ea_dst)

    new_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    AliasToDelivery = new_state.apps.get_model("as_email", "AliasToDelivery")
    atd = AliasToDelivery.objects.filter(email_account_id=ea_src.pk).first()
    assert atd is not None
    assert atd.target_account_id == ea_dst.pk


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_alias_with_no_targets_falls_back_to_local(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an EmailAccount with delivery_method='AL' but no alias_for entries
    WHEN   migration 0010 is applied
    THEN   a LocalDelivery is created as a fallback (not an AliasToDelivery)
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10alfb.example.com")
    ea = ctx["EmailAccount"].objects.create(
        email_address="noalias@m10alfb.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="AL",
        mail_dir="/tmp/maildir/noalias",
    )
    # No alias_for targets — empty M2M.

    new_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    LocalDelivery = new_state.apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = new_state.apps.get_model("as_email", "AliasToDelivery")
    assert LocalDelivery.objects.filter(email_account_id=ea.pk).exists()
    assert not AliasToDelivery.objects.filter(email_account_id=ea.pk).exists()


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_skips_accounts_with_existing_delivery_methods(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an EmailAccount that already has a DeliveryMethod row at 0009
    WHEN   migration 0010 is applied
    THEN   no additional DeliveryMethod is created for that account
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10skip.example.com")
    LocalDelivery = old_state.apps.get_model("as_email", "LocalDelivery")
    ea = ctx["EmailAccount"].objects.create(
        email_address="existing@m10skip.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
    )
    # Pre-create a delivery method row (simulates an already-migrated account).
    LocalDelivery.objects.create(
        email_account=ea,
        maildir_path="/tmp/already_migrated",
    )

    new_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    LocalDelivery2 = new_state.apps.get_model("as_email", "LocalDelivery")
    assert LocalDelivery2.objects.filter(email_account_id=ea.pk).count() == 1


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0010_reverse_removes_delivery_methods(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  migration 0010 has been applied (with delivery method rows)
    WHEN   migration 0010 is reversed (back to 0009)
    THEN   all DeliveryMethod rows are deleted
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m10rev.example.com")
    ctx["EmailAccount"].objects.create(
        email_address="rev@m10rev.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
    )

    migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )
    reversed_state = migrator.apply_tested_migration(
        ("as_email", "0009_add_delivery_methods")
    )

    DeliveryMethod = reversed_state.apps.get_model("as_email", "DeliveryMethod")
    assert not DeliveryMethod.objects.exists()


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0011_removes_legacy_fields(migrator_factory) -> None:
    """
    GIVEN  the database at migration 0010
    WHEN   migration 0011 is applied
    THEN   EmailAccount no longer has delivery_method, mail_dir,
           autofile_spam, spam_delivery_folder, spam_score_threshold,
           forward_to, or alias_for fields, and the Alias model is gone
    """
    migrator = migrator_factory()
    migrator.apply_initial_migration(
        ("as_email", "0010_populate_delivery_methods")
    )
    new_state = migrator.apply_tested_migration(
        ("as_email", "0011_remove_legacy_delivery_fields")
    )

    EmailAccount = new_state.apps.get_model("as_email", "EmailAccount")

    removed_fields = [
        "delivery_method",
        "mail_dir",
        "autofile_spam",
        "spam_delivery_folder",
        "spam_score_threshold",
        "forward_to",
        "alias_for",
    ]
    ea_field_names = {f.name for f in EmailAccount._meta.get_fields()}
    for field_name in removed_fields:
        assert field_name not in ea_field_names, (
            f"Field '{field_name}' should have been removed from EmailAccount"
        )

    # The Alias through-model should no longer exist.
    #
    with pytest.raises(LookupError):
        new_state.apps.get_model("as_email", "Alias")


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0011_reverse_restores_local_delivery_fields(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an account with a LocalDelivery row at migration 0010
    WHEN   migration 0011 is applied then reversed
    THEN   EmailAccount.delivery_method, mail_dir, and spam fields
           are restored from the LocalDelivery row
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m11revld.example.com")
    LocalDelivery = old_state.apps.get_model("as_email", "LocalDelivery")

    ea = ctx["EmailAccount"].objects.create(
        email_address="local@m11revld.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
        mail_dir="/tmp/rev11_maildir",
        autofile_spam=True,
        spam_delivery_folder="Junk",
        spam_score_threshold=7,
    )
    LocalDelivery.objects.create(
        email_account=ea,
        maildir_path="/tmp/rev11_maildir",
        autofile_spam=True,
        spam_delivery_folder="Junk",
        spam_score_threshold=7,
    )

    # Apply 0011 (removes legacy fields).
    migrator.apply_tested_migration(
        ("as_email", "0011_remove_legacy_delivery_fields")
    )

    # Reverse back to 0010 (restore_legacy_fields runs).
    reversed_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    EmailAccount2 = reversed_state.apps.get_model("as_email", "EmailAccount")
    ea_rev = EmailAccount2.objects.get(pk=ea.pk)
    assert ea_rev.delivery_method == "LD"
    assert ea_rev.mail_dir == "/tmp/rev11_maildir"
    assert ea_rev.autofile_spam is True
    assert ea_rev.spam_delivery_folder == "Junk"
    assert ea_rev.spam_score_threshold == 7


########################################################################
########################################################################
#
@pytest.mark.django_db(transaction=True)
def test_0011_reverse_restores_alias_delivery_fields(
    migrator_factory, make_migration_context
) -> None:
    """
    GIVEN  an account with an AliasToDelivery row at migration 0010
    WHEN   migration 0011 is applied then reversed
    THEN   EmailAccount.delivery_method is 'AL' and alias_for contains the target
    """
    migrator = migrator_factory()
    old_state = migrator.apply_initial_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    ctx = make_migration_context(old_state.apps, "m11revalias.example.com")
    EmailAccount = ctx["EmailAccount"]
    LocalDelivery = old_state.apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = old_state.apps.get_model("as_email", "AliasToDelivery")

    ea_target = EmailAccount.objects.create(
        email_address="target@m11revalias.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="LD",
    )
    LocalDelivery.objects.create(
        email_account=ea_target,
        maildir_path="/tmp/target_maildir",
    )

    ea_alias = EmailAccount.objects.create(
        email_address="alias@m11revalias.example.com",
        server=ctx["server"],
        owner=ctx["user"],
        delivery_method="AL",
    )
    AliasToDelivery.objects.create(
        email_account=ea_alias,
        target_account=ea_target,
    )

    # Apply 0011 (removes legacy fields).
    migrator.apply_tested_migration(
        ("as_email", "0011_remove_legacy_delivery_fields")
    )

    # Reverse back to 0010 (restore_legacy_fields runs).
    reversed_state = migrator.apply_tested_migration(
        ("as_email", "0010_populate_delivery_methods")
    )

    EmailAccount2 = reversed_state.apps.get_model("as_email", "EmailAccount")
    ea_rev = EmailAccount2.objects.get(pk=ea_alias.pk)
    assert ea_rev.delivery_method == "AL"
    assert ea_rev.alias_for.filter(pk=ea_target.pk).exists()
