from django.apps import AppConfig


####################################################################
#
class AsEmailConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "as_email"

    ####################################################################
    #
    def ready(self):
        # recommended place to make sure our signals are wired up.
        import as_email.signals  # noqa: F401
