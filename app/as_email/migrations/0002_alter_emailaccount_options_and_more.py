# Generated by Django 4.2.6 on 2023-11-12 09:32

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0001_initial"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="emailaccount",
            options={
                "ordering": ("server", "email_address"),
                "permissions": [
                    ("can_have_foreign_aliases", "Can have foriegn aliases")
                ],
            },
        ),
        migrations.AlterField(
            model_name="emailaccount",
            name="autofile_spam",
            field=models.BooleanField(
                default=True,
                help_text="When incoming mail exceeds the threshold set in `spam_score_threshold` then this email will automatically be filed in the `spam_delivery_folder` mailbox if delivery method is `Local Delivery` or `IMAP`. This option has no effect if the delivery method is `Alias` or `Forwarding`.",
            ),
        ),
        migrations.AlterField(
            model_name="emailaccount",
            name="spam_delivery_folder",
            field=models.CharField(
                default="Junk",
                help_text="For delivery methods of `Local Delivery` and `IMAP`, if this message is considered spam it and `Autofile Spam` is set then this message will be delivered to this folder, overriding and message filter rules.",
                max_length=1024,
            ),
        ),
        migrations.AlterField(
            model_name="emailaccount",
            name="spam_score_threshold",
            field=models.IntegerField(
                default=15,
                help_text="This is the value at which an incoming message is considered spam or not. The higher the value the more tolerant the rules. 15 is a good default. Lower may cause more false positives. If the delivery method is `Local delivery` or `IMAP` then incoming spam will be filed in the `spam delivery folder`. If the delivery method is `Forwrding` then instead of just re-sending the email to the forwarding address the message will be encapsulated and attached as a `message/rfc822` when being forwarded.",
            ),
        ),
    ]
