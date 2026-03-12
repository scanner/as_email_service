"""
Template tags for the AS Email project that do not belong in the `as_email`
app itself.

Like a template tag that produces the <script> includes for 3rd party utilities
like django-simple-bulma so we can wrap those in django_compressor's compress
tag.
"""

# 3rd party imports
#
from django import template
from django.contrib.auth.models import AnonymousUser, User
from django.templatetags.static import static
from django.utils.safestring import SafeString, mark_safe
from django_simple_bulma.utils import get_js_files, logger, themes

register = template.Library()


####################################################################
#
@register.filter
def is_in_group(user: User | AnonymousUser, group_name: str) -> bool:
    """Return True if the user is a member of the named group.

    Args:
        user: The user to check.
        group_name: The name of the group to check membership in.

    Returns:
        True if the user is in the group, False otherwise.
    """
    if not user.is_authenticated:
        return False
    return user.groups.filter(name=group_name).exists()


####################################################################
#
@register.simple_tag
def project_third_party_js() -> SafeString:
    html = []
    for js_file in map(static, get_js_files()):
        html.append(
            f'<script defer type="text/javascript" src="{js_file}"></script>'
        )
    return mark_safe("\n".join(html))


####################################################################
#
@register.simple_tag
def project_bulma_css(theme: str = "") -> SafeString:
    """Build static files required for Bulma.

    Parameters:
        theme:
            CSS theme to load. If the given theme can not be found, a warning
            will be logged and the library will fall back to the default theme.

    """
    if theme and theme not in themes:
        logger.warning(
            f"Theme '{theme}' does not match any of the detected themes: {', '.join(themes)}. "
            "Using default theme instead."
        )
        theme = ""

    # Build the html to include the stylesheet
    css = static(f"css/{theme + '_' if theme else ''}bulma.css")
    stylesheet_id = f"bulma-css-{theme}" if theme else "bulma-css"

    html = [
        f'<link rel="preload" href="{css}" as="style">',
        f'<link rel="stylesheet" href="{css}" id="{stylesheet_id}">',
    ]

    return mark_safe("\n".join(html))
