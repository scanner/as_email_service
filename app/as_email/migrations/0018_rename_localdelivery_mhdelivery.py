#!/usr/bin/env python
#
"""
Rename LocalDelivery to MHDelivery and rename its ContentType to match, so
existing rows keep resolving to their concrete type through
`polymorphic_ctype`.
"""

# system imports
#
from django.db import migrations


####################################################################
#
def rename_content_type(apps, schema_editor):
    """
    Point the 'localdelivery' ContentType at 'mhdelivery'.

    `migrate` normally does this itself after a RenameModel; this covers a
    run with the migrate signals muted. It does nothing when the rename has
    already happened.
    """
    ContentType = apps.get_model("contenttypes", "ContentType")
    if ContentType.objects.filter(
        app_label="as_email", model="mhdelivery"
    ).exists():
        return
    ContentType.objects.filter(
        app_label="as_email", model="localdelivery"
    ).update(model="mhdelivery")


####################################################################
#
def unrename_content_type(apps, schema_editor):
    """Point the 'mhdelivery' ContentType back at 'localdelivery'."""
    ContentType = apps.get_model("contenttypes", "ContentType")
    if ContentType.objects.filter(
        app_label="as_email", model="localdelivery"
    ).exists():
        return
    ContentType.objects.filter(app_label="as_email", model="mhdelivery").update(
        model="localdelivery"
    )


########################################################################
########################################################################
#
class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0017_server_mail_hostname"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.RenameModel(old_name="LocalDelivery", new_name="MHDelivery"),
        migrations.AlterModelOptions(
            name="mhdelivery",
            options={
                "verbose_name": "MH Delivery",
                "verbose_name_plural": "MH Deliveries",
            },
        ),
        migrations.RunPython(rename_content_type, unrename_content_type),
    ]
