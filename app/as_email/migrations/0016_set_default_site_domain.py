"""
Seed the default django.contrib.sites Site row from settings.SITE_NAME,
but only if it is still at the Django-seeded default of "example.com".

Allauth builds password-reset links from Site.objects.get(id=1).domain, so
leaving it as "example.com" breaks those links. This migration is a no-op on
any environment that has already set the site domain (e.g. via the admin).
"""

# 3rd party imports
#
from django.conf import settings
from django.db import migrations

_DJANGO_DEFAULT_DOMAIN = "example.com"


def set_site_domain(apps, schema_editor):
    Site = apps.get_model("sites", "Site")
    site_name = settings.SITE_NAME
    # sites.0001_initial only creates the table; the pk=1 row is normally
    # inserted by Django's post_migrate signal (create_default_site), which
    # fires after all migrations complete. On a fresh install the row won't
    # exist yet when this migration runs, so we create it. On an existing
    # install we only update if the domain is still at Django's seeded default.
    if not Site.objects.filter(pk=1).exists():
        Site.objects.create(pk=1, domain=site_name, name=site_name)
    else:
        Site.objects.filter(pk=1, domain=_DJANGO_DEFAULT_DOMAIN).update(
            domain=site_name, name=site_name
        )


class Migration(migrations.Migration):
    dependencies = [
        ("as_email", "0015_alter_imapdelivery_autofile_spam_and_more"),
        ("sites", "0002_alter_domain_unique"),
    ]

    operations = [
        migrations.RunPython(set_site_domain, migrations.RunPython.noop),
    ]
