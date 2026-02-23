#!/usr/bin/env python
#
"""
Data migration: create DeliveryMethod instances for existing EmailAccounts
based on their legacy `delivery_method` field.

- LOCAL_DELIVERY (LD) → LocalDelivery with maildir_path from mail_dir
- ALIAS (AL)          → AliasToDelivery for each entry in alias_for
- FORWARDING (FW)     → LocalDelivery (forwarding is removed; fall back to local)

Accounts that already have at least one DeliveryMethod are left untouched.
"""
# system imports
#
from django.db import migrations


####################################################################
#
def create_delivery_methods(apps, schema_editor):
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    LocalDelivery = apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = apps.get_model("as_email", "AliasToDelivery")

    for ea in EmailAccount.objects.all():
        # Skip accounts that already have delivery methods.
        #
        if ea.delivery_methods.exists():
            continue

        delivery_method = ea.delivery_method

        if delivery_method in ("LD", "FW"):
            # Local delivery (and forwarding fallback).
            LocalDelivery.objects.create(
                email_account=ea,
                maildir_path=ea.mail_dir or "",
                autofile_spam=ea.autofile_spam,
                spam_delivery_folder=ea.spam_delivery_folder,
                spam_score_threshold=ea.spam_score_threshold,
            )
        elif delivery_method == "AL":
            # Alias — create an AliasToDelivery for each alias_for target.
            for target in ea.alias_for.all():
                AliasToDelivery.objects.create(
                    email_account=ea,
                    target_account=target,
                )
            # If no alias targets exist, fall back to local delivery so the
            # account still has at least one delivery method.
            if not ea.alias_for.exists():
                LocalDelivery.objects.create(
                    email_account=ea,
                    maildir_path=ea.mail_dir or "",
                    autofile_spam=ea.autofile_spam,
                    spam_delivery_folder=ea.spam_delivery_folder,
                    spam_score_threshold=ea.spam_score_threshold,
                )


####################################################################
#
def remove_delivery_methods(apps, schema_editor):
    """
    Reverse migration: remove all DeliveryMethod instances. The legacy fields
    on EmailAccount remain untouched, so rolling back to 0009 is safe.
    """
    DeliveryMethod = apps.get_model("as_email", "DeliveryMethod")
    DeliveryMethod.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0009_add_delivery_methods"),
    ]

    operations = [
        migrations.RunPython(
            create_delivery_methods,
            reverse_code=remove_delivery_methods,
        ),
    ]
