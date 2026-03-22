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
from django.apps import apps as real_apps
from django.contrib.contenttypes.management import create_contenttypes
from django.db import migrations


####################################################################
#
def create_delivery_methods(apps, schema_editor):
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    LocalDelivery = apps.get_model("as_email", "LocalDelivery")
    AliasToDelivery = apps.get_model("as_email", "AliasToDelivery")
    ContentType = apps.get_model("contenttypes", "ContentType")
    # NOTE: apps.get_model() bypasses the polymorphic model's save(), so
    # polymorphic_ctype_id is NOT set automatically. We must set it explicitly
    # on every create() call, otherwise all rows are left with a NULL
    # polymorphic_ctype_id and django-polymorphic raises PolymorphicTypeUndefined
    # when it tries to resolve the concrete subtype.
    #
    # NOTE: Django's post_migrate signal normally populates content type rows,
    # but it fires after ALL migrations complete — so at the point this data
    # migration runs during test setup, the rows for our concrete subtypes don't
    # exist yet. We call create_contenttypes() explicitly to seed them first;
    # in production where they already exist, create_contenttypes() is a no-op.
    # We use apps.get_model("contenttypes", "ContentType") (the historical model)
    # rather than the real ContentType class so that FK assignment type-checks
    # pass when Django validates the historical model graph.
    #
    create_contenttypes(real_apps.get_app_config("as_email"), verbosity=0)

    local_ct = ContentType.objects.get(
        app_label="as_email", model="localdelivery"
    )
    alias_ct = ContentType.objects.get(
        app_label="as_email", model="aliastodelivery"
    )

    for ea in EmailAccount.objects.all():
        # Skip accounts that already have delivery methods.
        #
        if ea.delivery_methods.exists():
            continue

        delivery_method = ea.delivery_method

        if delivery_method in ("LD", "FW"):
            # Local delivery (and forwarding fallback).
            LocalDelivery.objects.create(
                polymorphic_ctype=local_ct,
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
                    polymorphic_ctype=alias_ct,
                    email_account=ea,
                    target_account=target,
                )
            # If no alias targets exist, fall back to local delivery so the
            # account still has at least one delivery method.
            if not ea.alias_for.exists():
                LocalDelivery.objects.create(
                    polymorphic_ctype=local_ct,
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
