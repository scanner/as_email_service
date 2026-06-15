#!/usr/bin/env python
#
"""Admin registrations for the users app."""

# 3rd party imports
#
from django.contrib import admin

# Project imports
#
from .models import EmailChangeCooldown, PendingEmailChange


########################################################################
########################################################################
#
@admin.register(PendingEmailChange)
class PendingEmailChangeAdmin(admin.ModelAdmin):
    list_display = ("user", "new_email", "expires_at")
    readonly_fields = ("revocation_key",)


########################################################################
########################################################################
#
@admin.register(EmailChangeCooldown)
class EmailChangeCooldownAdmin(admin.ModelAdmin):
    list_display = ("user", "expires_at")
