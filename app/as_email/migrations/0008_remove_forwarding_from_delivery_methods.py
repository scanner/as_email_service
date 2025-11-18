# Data migration to remove FORWARDING from delivery_methods

from django.db import migrations


def remove_forwarding_from_delivery_methods(apps, schema_editor):
    """
    Remove "FW" (FORWARDING) from any EmailAccount delivery_methods lists.
    FORWARDING is no longer a valid delivery method - forwarding is now
    handled solely via the forward_to field.

    If an account only had FORWARDING, set delivery_methods to empty list
    which will default to LOCAL_DELIVERY.
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")

    updated_count = 0
    for account in EmailAccount.objects.all():
        if not account.delivery_methods:
            continue

        if "FW" in account.delivery_methods:
            # Remove FW from the list
            account.delivery_methods = [
                method for method in account.delivery_methods if method != "FW"
            ]
            account.save(update_fields=["delivery_methods"])
            updated_count += 1

    if updated_count > 0:
        print(
            f"Removed FORWARDING from {updated_count} EmailAccount(s). "
            f"Forwarding is now handled via the forward_to field only."
        )


def reverse_migration(apps, schema_editor):
    """
    Reverse is a no-op since we can't reliably restore which accounts
    had FORWARDING as a delivery method.
    """
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0007_add_multiple_delivery_methods"),
    ]

    operations = [
        migrations.RunPython(
            remove_forwarding_from_delivery_methods,
            reverse_code=reverse_migration,
        ),
    ]
