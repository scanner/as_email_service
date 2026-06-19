#!/usr/bin/env python
#
"""Admin registrations for the users app."""

# system imports
#
import logging
from typing import Any

# 3rd party imports
#
from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.forms import ModelForm
from django.http import HttpRequest
from django.utils.html import format_html

# Project imports
#
from .invitation import (
    InvitationError,
    cancel_user_invitation,
    create_user_invitation,
    resend_user_invitation,
    window_count,
)
from .models import EmailChangeCooldown, PendingEmailChange, UserInvitation

logger = logging.getLogger("users.admin")
User = get_user_model()


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


########################################################################
########################################################################
#
class UserInvitationAdminForm(forms.ModelForm):
    """
    Form used only when creating a new invitation.

    Validates the rolling window cap and, when a username is provided for a
    new account, that the username is not already taken.
    """

    invitee_email = forms.EmailField(
        label="Invitee email address",
        help_text="The email address to send the invitation to.",
    )
    username = forms.CharField(
        label="Username",
        required=False,
        help_text=(
            "Username for the new account. Leave blank to auto-derive from "
            "the email address. Ignored when the address belongs to an "
            "existing account."
        ),
        max_length=150,
    )

    ####################################################################
    #
    class Meta:
        model = UserInvitation
        fields = ("invitee_email",)

    ####################################################################
    #
    def clean_invitee_email(self) -> str:
        email = self.cleaned_data["invitee_email"].strip().lower()
        count = window_count(email)
        if count >= settings.INVITATION_MAX_PER_WINDOW:
            raise forms.ValidationError(
                f"Too many invitations to this address in the last "
                f"{settings.INVITATION_WINDOW_DAYS} days "
                f"(limit: {settings.INVITATION_MAX_PER_WINDOW}, current: {count})."
            )
        return email

    ####################################################################
    #
    def clean_username(self) -> str:
        username = self.cleaned_data.get("username", "").strip()
        if not username:
            return username

        # Skip uniqueness check when inviting an existing account -- the
        # username field is ignored by the service layer in that case.
        invitee_email = self.cleaned_data.get("invitee_email", "")
        if (
            invitee_email
            and User.objects.filter(email__iexact=invitee_email).exists()
        ):
            return username

        if User.objects.filter(username=username).exists():
            raise forms.ValidationError(
                f"The username {username!r} is already taken."
            )
        return username


########################################################################
########################################################################
#
@admin.register(UserInvitation)
class UserInvitationAdmin(admin.ModelAdmin):
    list_display = (
        "invitee_email",
        "status",
        "invited_by",
        "send_count",
        "created_at",
        "expires_at",
    )
    list_filter = ("status",)
    search_fields = ("invitee_email",)
    readonly_fields = (
        "invited_by",
        "invitee_user",
        "token",
        "status",
        "expires_at",
        "accepted_at",
        "cancelled_at",
        "send_count",
        "last_sent_at",
        "created_at",
        "invitation_link",
    )
    actions = ["resend_invitation", "cancel_invitation"]

    ####################################################################
    #
    def get_form(
        self,
        request: HttpRequest,
        obj: Any | None = None,
        change: bool = False,
        **kwargs: Any,
    ) -> type[ModelForm]:
        if obj is None:
            # Creating a new invitation -- use the constrained form.
            kwargs["form"] = UserInvitationAdminForm
        return super().get_form(request, obj, **kwargs)

    ####################################################################
    #
    def get_fields(self, request, obj=None):
        if obj is None:
            return ("invitee_email", "username")
        return (
            "invitee_email",
            "status",
            "invited_by",
            "invitee_user",
            "invitation_link",
            "send_count",
            "last_sent_at",
            "expires_at",
            "accepted_at",
            "cancelled_at",
            "created_at",
        )

    ####################################################################
    #
    def save_model(self, request, obj, form, change):
        if not change:
            # Creating -- delegate entirely to the service layer.
            try:
                create_user_invitation(
                    invited_by=request.user,
                    invitee_email=form.cleaned_data["invitee_email"],
                    request=request,
                    username=form.cleaned_data.get("username") or None,
                )
                self.message_user(
                    request,
                    f"Invitation sent to {form.cleaned_data['invitee_email']!r}.",
                    level=messages.SUCCESS,
                )
            except InvitationError as e:
                self.message_user(request, str(e), level=messages.ERROR)
        # No direct save for existing invitations -- all mutations go through
        # the service (resend/cancel actions below).

    ####################################################################
    #
    def has_delete_permission(self, request, obj=None) -> bool:
        return False

    ####################################################################
    #
    @admin.display(description="Invitation link")
    def invitation_link(self, obj: UserInvitation):
        from django.urls import reverse as url_reverse

        url = url_reverse("users:accept_invitation", args=[obj.token])
        return format_html('<a href="{}">{}</a>', url, url)

    ####################################################################
    #
    @admin.action(description="Resend selected invitations")
    def resend_invitation(self, request, queryset):
        success = 0
        for inv in queryset:
            try:
                resend_user_invitation(inv, request)
                success += 1
            except InvitationError as e:
                self.message_user(
                    request,
                    f"{inv.invitee_email}: {e}",
                    level=messages.WARNING,
                )
        if success:
            self.message_user(
                request,
                f"Resent {success} invitation(s).",
                level=messages.SUCCESS,
            )

    ####################################################################
    #
    @admin.action(description="Cancel selected invitations")
    def cancel_invitation(self, request, queryset):
        success = 0
        for inv in queryset:
            try:
                cancel_user_invitation(inv)
                success += 1
            except InvitationError as e:
                self.message_user(
                    request,
                    f"{inv.invitee_email}: {e}",
                    level=messages.WARNING,
                )
        if success:
            self.message_user(
                request,
                f"Cancelled {success} invitation(s).",
                level=messages.SUCCESS,
            )
