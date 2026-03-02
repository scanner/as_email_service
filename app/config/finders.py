"""
Custom static file finders and compatibility shims.
"""

# 3rd party imports
from django_simple_bulma.finders import SimpleBulmaFinder as _SimpleBulmaFinder


########################################################################
#
class SimpleBulmaFinder(_SimpleBulmaFinder):
    """
    Compatibility shim for django-simple-bulma with Django 5.1+.

    Django 5.1 renamed the ``all`` parameter in the finder ``find()``
    method to ``find_all``. django-simple-bulma 2.6.0 still uses the
    old ``all`` name, causing a TypeError at runtime.

    This subclass corrects the signature until upstream fixes it.
    See: https://docs.djangoproject.com/en/5.1/releases/5.1/
    Fixes: AS-EMAIL-SERVICE-36
    """

    def find(self, path: str, find_all: bool = False) -> list[str] | str:
        """
        Given a relative file path, find an absolute file path.

        If ``find_all`` is False (default) return only the first found
        file path; if True, return a list of all found file paths.
        """
        return super().find(path, all=find_all)
