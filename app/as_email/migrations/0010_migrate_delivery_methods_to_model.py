# Data migration to convert EmailAccount.delivery_methods to DeliveryMethod model
#
from django.db import migrations


def migrate_delivery_methods_to_model(apps, schema_editor):
    """
    Convert EmailAccount.delivery_methods (list of strings) to
    DeliveryMethod model instances.

    For each EmailAccount:
    - If delivery_methods is empty/None, create LOCAL_DELIVERY method
    - For each "LD" in the list, create one LOCAL_DELIVERY DeliveryMethod
    - For each "AL" in the list, create one DeliveryMethod per alias_for relationship
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    DeliveryMethod = apps.get_model("as_email", "DeliveryMethod")
    Alias = apps.get_model("as_email", "Alias")

    for account in EmailAccount.objects.all():
        methods = account.delivery_methods or []

        # If no methods, create default LOCAL_DELIVERY
        if not methods:
            DeliveryMethod.objects.create(
                email_account=account,
                delivery_type="LD",
                config={},
                order=0,
                enabled=True,
            )
            continue

        # Track which order we're at
        order = 0

        # Process each method type
        for method_type in methods:
            if method_type == "LD":
                # Local delivery needs no config
                DeliveryMethod.objects.create(
                    email_account=account,
                    delivery_type="LD",
                    config={},
                    order=order,
                    enabled=True,
                )
                order += 1

            elif method_type == "AL":
                # Create one DeliveryMethod for each alias_for relationship
                alias_relationships = Alias.objects.filter(
                    from_email_account=account
                )

                if not alias_relationships.exists():
                    # No alias targets - skip this method
                    print(
                        f"WARNING: {account.email_address} has ALIAS delivery "
                        f"but no alias_for relationships, skipping"
                    )
                    continue

                # Create a DeliveryMethod for each alias target
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

            elif method_type == "IM":
                # IMAP not implemented yet - skip
                print(
                    f"INFO: {account.email_address} has IMAP delivery "
                    f"but IMAP is not yet implemented, skipping"
                )
                continue

            else:
                # Unknown method type
                print(
                    f"WARNING: {account.email_address} has unknown delivery "
                    f"method type '{method_type}', skipping"
                )


def reverse_migration(apps, schema_editor):
    """
    Convert DeliveryMethod instances back to delivery_methods list.

    This is for rolling back the migration if needed.
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    DeliveryMethod = apps.get_model("as_email", "DeliveryMethod")

    for account in EmailAccount.objects.all():
        # Collect unique delivery types from enabled DeliveryMethods
        methods_set = set()
        for dm in DeliveryMethod.objects.filter(
            email_account=account, enabled=True
        ):
            methods_set.add(dm.delivery_type)

        # Convert to list (loses order information)
        account.delivery_methods = list(methods_set)
        account.save(update_fields=["delivery_methods"])


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0009_create_delivery_method_model"),
    ]

    operations = [
        migrations.RunPython(
            migrate_delivery_methods_to_model, reverse_migration
        ),
    ]
