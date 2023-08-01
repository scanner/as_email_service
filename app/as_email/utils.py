#!/usr/bin/env python
#
"""
Utilitities used by our app. We want to separate them from views and models
so we can use them in other modules without running the code in app.
"""
# system imports
#
from hashlib import sha256


####################################################################
#
def short_hash_email(email: dict) -> str:
    """
    Generate a short hash of the email message. We do not know necessarily
    what parts of the message exist so try `RawEmail`, `HTMLBody`, `TextBody`,
    and `MessageID` in that order.
    """
    # Generate a sha256 for the email message
    if "RawEmail" in email:
        text_to_hash = email["RawEmail"]
    elif "HtmlBody" in email:
        text_to_hash = email["HtmlBody"]
    elif "TextBody" in email:
        text_to_hash = email["TextBody"]
    else:
        text_to_hash = email["MessageID"]

    short_hash = sha256(text_to_hash.encode("utf-8")).hexdigest()[:8]
    return short_hash
