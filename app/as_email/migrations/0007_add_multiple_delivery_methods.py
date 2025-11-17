# Generated manually for multiple delivery methods feature

from django.db import migrations, models


def convert_delivery_method_to_list(apps, schema_editor):
    """
    Convert existing single delivery_method values to the new
    delivery_methods list format.
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    for account in EmailAccount.objects.all():
        if hasattr(account, "delivery_method") and account.delivery_method:
            # Convert the single value to a list with one element
            account.delivery_methods = [account.delivery_method]
            account.save(update_fields=["delivery_methods"])
        else:
            # Default to LOCAL_DELIVERY
            account.delivery_methods = ["LD"]
            account.save(update_fields=["delivery_methods"])


def convert_delivery_methods_to_single(apps, schema_editor):
    """
    Reverse migration: convert delivery_methods list back to single value.
    Takes the first value from the list.
    """
    EmailAccount = apps.get_model("as_email", "EmailAccount")
    for account in EmailAccount.objects.all():
        if account.delivery_methods and len(account.delivery_methods) > 0:
            account.delivery_method = account.delivery_methods[0]
        else:
            account.delivery_method = "LD"  # LOCAL_DELIVERY
        account.save(update_fields=["delivery_method"])


class Migration(migrations.Migration):

    dependencies = [
        ("as_email", "0006_remove_old_provider_field"),
    ]

    operations = [
        # Step 1: Add the new delivery_methods field (nullable initially)
        migrations.AddField(
            model_name="emailaccount",
            name="delivery_methods",
            field=models.JSONField(
                default=list,
                help_text=(
                    "Delivery methods indicate how email for this account is "
                    "delivered. Multiple delivery methods can be selected, allowing "
                    "email to be delivered via multiple mechanisms simultaneously "
                    "(e.g., local delivery AND forwarding). Options include: delivery "
                    "to a local mailbox, delivery to an IMAP mailbox, an alias to "
                    "another email account on this system, or forwarding to an email "
                    "address by encapsulating the message or rewriting the headers. "
                    "If empty, defaults to local delivery only."
                ),
            ),
        ),
        # Step 2: Migrate data from delivery_method to delivery_methods
        migrations.RunPython(
            convert_delivery_method_to_list,
            reverse_code=convert_delivery_methods_to_single,
        ),
        # Step 3: Remove the old delivery_method field
        migrations.RemoveField(
            model_name="emailaccount",
            name="delivery_method",
        ),
    ]
