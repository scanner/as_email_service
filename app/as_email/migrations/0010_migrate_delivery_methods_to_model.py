# Data migration to create default DeliveryMethod instances
#
from django.db import migrations


def create_default_delivery_methods(apps, schema_editor):
    """
    Create default DeliveryMethod instances for existing EmailAccounts.

    For each EmailAccount:
    - Create a LOCAL_DELIVERY DeliveryMethod as the default
    - If the account has alias_for relationships, also create ALIAS DeliveryMethods
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    DeliveryMethod = apps.get_model("as_email", "DeliveryMethod")
    Alias = apps.get_model("as_email", "Alias")

    for account in EmailAccount.objects.all():
        order = 0

        # Create default LOCAL_DELIVERY method
        DeliveryMethod.objects.create(
            email_account=account,
            delivery_type="LD",
            config={},
            order=order,
            enabled=True,
        )
        order += 1

        # Create ALIAS DeliveryMethods for existing alias_for relationships
        alias_relationships = Alias.objects.filter(from_email_account=account)
        for alias_rel in alias_relationships:
            DeliveryMethod.objects.create(
                email_account=account,
                delivery_type="AL",
                config={
                    "target_email_account_id": alias_rel.to_email_account.pk
                },
                order=order,
                enabled=True,
            )
            order += 1


def reverse_migration(apps, schema_editor):
    """
    Delete all DeliveryMethod instances.
    """
    DeliveryMethod = apps.get_model("as_email", "DeliveryMethod")
    DeliveryMethod.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0009_create_delivery_method_model"),
    ]

    operations = [
        migrations.RunPython(
            create_default_delivery_methods, reverse_migration
        ),
    ]
