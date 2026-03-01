#!/usr/bin/env python
#
"""
Stage 3: remove legacy delivery fields from EmailAccount and drop the Alias
through model.

The forward migration is a no-op at the data level (everything was already
migrated to DeliveryMethod rows in 0010); it just drops the columns.

The reverse migration restores the legacy fields from each account's *first*
DeliveryMethod:
  - LocalDelivery  → delivery_method="LD", mail_dir, spam fields
  - AliasToDelivery → delivery_method="AL", alias_for M2M target
"""
# system imports
#
from django.db import migrations


####################################################################
#
def noop(apps, schema_editor):
    pass


####################################################################
#
def restore_legacy_fields(apps, schema_editor):
    """
    Reverse migration: restore legacy fields on EmailAccount from the first
    DeliveryMethod for each account (LocalDelivery takes precedence).
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    LocalDelivery = apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = apps.get_model("as_email", "AliasToDelivery")

    for ea in EmailAccount.objects.all():
        # LocalDelivery takes precedence when both types exist.
        ld = LocalDelivery.objects.filter(email_account=ea).first()
        if ld:
            ea.delivery_method = "LD"
            ea.mail_dir = ld.maildir_path or ""
            ea.autofile_spam = ld.autofile_spam
            ea.spam_delivery_folder = ld.spam_delivery_folder
            ea.spam_score_threshold = ld.spam_score_threshold
            ea.save()
            continue

        atd = AliasToDelivery.objects.filter(email_account=ea).first()
        if atd:
            ea.delivery_method = "AL"
            ea.save()
            ea.alias_for.add(atd.target_account)


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0010_populate_delivery_methods"),
    ]

    operations = [
        # RunPython comes first so that, on reversal, it runs last — after all
        # removed fields have been added back by the reversed RemoveField /
        # DeleteModel operations below.
        migrations.RunPython(noop, reverse_code=restore_legacy_fields),
        # Drop the Alias model's constraints before removing its FK columns.
        # SQLite recreates the full table when dropping a column; if the
        # constraints still reference the column being dropped the CREATE TABLE
        # statement will be invalid.
        migrations.RemoveConstraint(
            model_name="alias",
            name="as_email_alias_unique_relationships",
        ),
        migrations.RemoveConstraint(
            model_name="alias",
            name="as_email_alias_prevent_self_alias",
        ),
        migrations.RemoveField(
            model_name="alias",
            name="from_email_account",
        ),
        migrations.RemoveField(
            model_name="alias",
            name="to_email_account",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="alias_for",
        ),
        migrations.AlterModelOptions(
            name="emailaccount",
            options={"ordering": ("server", "email_address")},
        ),
        migrations.RemoveIndex(
            model_name="emailaccount",
            name="as_email_em_forward_136d4b_idx",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="autofile_spam",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="delivery_method",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="forward_to",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="mail_dir",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="spam_delivery_folder",
        ),
        migrations.RemoveField(
            model_name="emailaccount",
            name="spam_score_threshold",
        ),
        migrations.DeleteModel(
            name="Alias",
        ),
    ]
