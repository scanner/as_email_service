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

    If the username already exists, a RESET_SENT invitation is created
    and an admin-initiated password-reset email is sent immediately.
    If the username does not exist, a new inactive account is created
    using the provided email address and a standard invitation is sent.
    """

    username = forms.CharField(
        label="Username",
        required=True,
        help_text=(
            "Username of the account to invite. If this user already exists, "
            "a password-reset email is sent to their registered address "
            "immediately -- no acceptance link is required. If they do not "
            "exist, a new account is created and a standard invitation is "
            "sent to the email address below."
        ),
        max_length=150,
    )
    invitee_email = forms.EmailField(
        label="Email address",
        required=False,
        help_text=(
            "Required when the username does not yet exist. "
            "Ignored when the username already belongs to an existing account."
        ),
    )

    ####################################################################
    #
    class Meta:
        model = UserInvitation
        fields = ("invitee_email",)

    ####################################################################
    #
    def clean_username(self) -> str:
        return self.cleaned_data.get("username", "").strip()

    ####################################################################
    #
    def clean_invitee_email(self) -> str:
        email = self.cleaned_data.get("invitee_email", "")
        return email.strip().lower() if email else ""

    ####################################################################
    #
    def clean(self):
        cleaned = super().clean()
        if cleaned is None:
            return cleaned
        username = cleaned.get("username", "").strip()
        email = cleaned.get("invitee_email", "")

        if not username:
            return cleaned

        existing_user = User.objects.filter(username=username).first()
        if existing_user:
            effective_email = existing_user.email.lower()
        else:
            if not email:
                self.add_error(
                    "invitee_email",
                    "An email address is required when creating a new account.",
                )
                return cleaned
            effective_email = email

        count = window_count(effective_email)
        if count >= settings.INVITATION_MAX_PER_WINDOW:
            raise forms.ValidationError(
                f"Too many invitations to this address in the last "
                f"{settings.INVITATION_WINDOW_DAYS} days "
                f"(limit: {settings.INVITATION_MAX_PER_WINDOW}, current: {count})."
            )

        return cleaned


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
            return ("username", "invitee_email")
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
                inv = create_user_invitation(
                    invited_by=request.user,
                    username=form.cleaned_data["username"],
                    request=request,
                    invitee_email=form.cleaned_data.get("invitee_email")
                    or None,
                )
                verb = (
                    "Password reset sent"
                    if inv.status == UserInvitation.Status.RESET_SENT
                    else "Invitation sent"
                )
                self.message_user(
                    request,
                    f"{verb} to {inv.invitee_email!r} "
                    f"(username: {form.cleaned_data['username']!r}).",
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
