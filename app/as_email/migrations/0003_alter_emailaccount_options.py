# Generated by Django 4.2.6 on 2023-11-12 09:34

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0002_alter_emailaccount_options_and_more"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="emailaccount",
            options={
                "ordering": ("server", "email_address"),
                "permissions": [
                    ("can_have_foreign_aliases", "Can have foreign aliases")
                ],
            },
        ),
    ]
