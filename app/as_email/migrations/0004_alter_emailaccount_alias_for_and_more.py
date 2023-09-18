# Generated by Django 4.2.4 on 2023-09-06 17:55

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0003_alter_emailaccount_deactivated"),
    ]

    operations = [
        migrations.AlterField(
            model_name="emailaccount",
            name="alias_for",
            field=models.ManyToManyField(
                help_text="If the account type is `Alias` this is a list of the email accounts that the email will be delivered to instead of this email account. You are declaring that this account is an `alias for` these other accounts. So, say `root@example.com` is an alias for `admin@example.com`, or `thetwoofus@example.com` is an alis for `me@example.com` and `you@example.com`. NOTE: you can only alias to email accounts that are managed by this system. If you want to have email forwarded to a email address not managed by this system you need to choose the account type `Forwarding` and properly specify the destination address in the `forward_to` field. NOTE: `alias_for` is only relevant when the account type is `Alias`. The field is otherwise ignored.",
                related_name="aliases",
                related_query_name="alias",
                through="as_email.Alias",
                to="as_email.emailaccount",
            ),
        ),
        migrations.AlterField(
            model_name="emailaccount",
            name="forward_to",
            field=models.EmailField(
                blank=True,
                help_text="When the email account account type is set to `Forwarding` this is the email address that this email is forwarded to. NOTE: `forward_to` is only relevant when the account type is `Forwarding`. The field is otherwise ignored.",
                max_length=254,
                null=True,
            ),
        ),
    ]