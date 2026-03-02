"""
Custom static file finders and compatibility shims.
"""

# 3rd party imports
from django.conf import settings
from django.contrib.staticfiles.finders import get_finder
from django.core.files.storage import FileSystemStorage
from django_simple_bulma.finders import SimpleBulmaFinder as _SimpleBulmaFinder
from django_simple_bulma.utils import simple_bulma_path


########################################################################
#
class SimpleBulmaFinder(_SimpleBulmaFinder):
    """
    Compatibility shim for django-simple-bulma with Django 5.1+.

    Django 5.1 renamed the ``all`` parameter in the finder ``find()``
    method to ``find_all``. django-simple-bulma 2.6.0 still uses the
    old ``all`` name, causing a TypeError at runtime.

    Additionally, the upstream ``__init__`` hardcodes the string
    ``"django_simple_bulma.finders.SimpleBulmaFinder"`` when removing
    itself from the finders list to build ``other_finders``. Since
    settings now references this shim class instead, that remove()
    raises a ValueError. We override __init__ to use our own path.

    This subclass corrects both issues until upstream fixes them.
    See: https://docs.djangoproject.com/en/5.1/releases/5.1/
    Fixes: AS-EMAIL-SERVICE-36
    """

    # The dotted path as it appears in STATICFILES_FINDERS in settings.
    _FINDER_PATH = "config.finders.SimpleBulmaFinder"

    def __init__(self) -> None:
        """Initialize with the corrected STATICFILES_FINDERS reference."""
        try:
            self.bulma_settings = settings.BULMA_SETTINGS
        except AttributeError:
            self.bulma_settings = {}

        self.bulma_submodule_path = simple_bulma_path / "bulma" / "sass"
        self.custom_scss = self.bulma_settings.get("custom_scss", [])
        self.variables = self.bulma_settings.get("variables", {})
        self.output_style = self.bulma_settings.get("output_style", "nested")
        self.storage = FileSystemStorage(simple_bulma_path)

        # Make a list of all the finders except this one.
        # NOTE: remove our own path, not the upstream hardcoded string.
        other_finders = settings.STATICFILES_FINDERS.copy()
        other_finders.remove(self._FINDER_PATH)
        self.other_finders = [get_finder(finder) for finder in other_finders]

    def find(self, path: str, find_all: bool = False) -> list[str] | str:
        """
        Given a relative file path, find an absolute file path.

        If ``find_all`` is False (default) return only the first found
        file path; if True, return a list of all found file paths.
        """
        return super().find(path, all=find_all)
