# Generated by Django 4.2.6 on 2023-10-07 00:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0010_inactiveemail"),
    ]

    operations = [
        migrations.AlterField(
            model_name="messagefilterrule",
            name="email_account",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="message_filter_rule",
                to="as_email.emailaccount",
            ),
        ),
    ]