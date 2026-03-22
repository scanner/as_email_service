#!/usr/bin/env python
#
"""
Data migration: backfill polymorphic_ctype_id on DeliveryMethod rows that
were created by migration 0010 before it was fixed to set the field explicitly.

django-polymorphic requires polymorphic_ctype_id to be non-NULL on every row;
apps.get_model() bypasses the model's save() method, so the original 0010
migration left all rows with NULL.  This migration repairs those rows using
raw SQL so it does not depend on the ORM's polymorphic machinery.
"""

# system imports
#
from django.db import migrations


####################################################################
#
def backfill_polymorphic_ctype(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")

    local_ct = ContentType.objects.get(
        app_label="as_email", model="localdelivery"
    )
    alias_ct = ContentType.objects.get(
        app_label="as_email", model="aliastodelivery"
    )

    db = schema_editor.connection
    with db.cursor() as cursor:
        # Fix LocalDelivery rows: base rows whose id appears in the
        # as_email_localdelivery sub-table.
        cursor.execute(
            """
            UPDATE as_email_deliverymethod
               SET polymorphic_ctype_id = %s
             WHERE polymorphic_ctype_id IS NULL
               AND id IN (SELECT deliverymethod_ptr_id
                            FROM as_email_localdelivery)
            """,
            [local_ct.pk],
        )

        # Fix AliasToDelivery rows: base rows whose id appears in the
        # as_email_aliastodelivery sub-table.
        cursor.execute(
            """
            UPDATE as_email_deliverymethod
               SET polymorphic_ctype_id = %s
             WHERE polymorphic_ctype_id IS NULL
               AND id IN (SELECT deliverymethod_ptr_id
                            FROM as_email_aliastodelivery)
            """,
            [alias_ct.pk],
        )


####################################################################
#
def noop(apps, schema_editor):
    """Reverse is a no-op: we cannot safely un-set ctype values."""
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0011_remove_legacy_delivery_fields"),
    ]

    operations = [
        migrations.RunPython(
            backfill_polymorphic_ctype,
            reverse_code=noop,
        ),
    ]
