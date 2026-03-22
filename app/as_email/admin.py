# 3rd party imports
#
from django import forms
from django.contrib import admin
from ordered_model.admin import OrderedModelAdmin
from polymorphic.admin import (
    PolymorphicChildModelAdmin,
    PolymorphicChildModelFilter,
    PolymorphicParentModelAdmin,
)

# Project imports
#
from .models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
    InactiveEmail,
    LocalDelivery,
    MessageFilterRule,
    Provider,
    Server,
)
from .providers import ProviderName


####################################################################
#
class ProviderAdminForm(forms.ModelForm):
    """
    Custom form for Provider admin.

    Renders backend_name as a dropdown derived from the registered
    provider backends, and splits smtp_server into separate host and
    port inputs so the format is unambiguous.
    """

    backend_name = forms.ChoiceField(
        choices=sorted([(p.value, p.value) for p in ProviderName]),
        help_text="Provider backend implementation to use.",
    )
    smtp_host = forms.CharField(
        required=False,
        label="SMTP Host",
        help_text=(
            "Hostname for outgoing SMTP (e.g., smtp.postmarkapp.com). "
            "Leave blank for receive-only providers."
        ),
    )
    smtp_port = forms.IntegerField(
        required=False,
        label="SMTP Port",
        initial=25,
        min_value=1,
        max_value=65535,
        help_text=(
            "Common ports: 25 (standard SMTP), "
            "587 (STARTTLS submission), "
            "465 (SSL/TLS). Any valid port number is accepted."
        ),
    )

    ################################################################
    #
    class Meta:
        model = Provider
        exclude = ("smtp_server",)

    ################################################################
    #
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Pre-populate the split fields from the stored smtp_server value.
        if self.instance.pk and self.instance.smtp_server:
            raw = self.instance.smtp_server
            if ":" in raw:
                host, port = raw.split(":", 1)
            else:
                host, port = raw, "25"
            self.initial["smtp_host"] = host
            self.initial["smtp_port"] = port

    ################################################################
    #
    def clean(self) -> dict:
        cleaned_data = super().clean()
        if cleaned_data is None:
            return {}
        provider_type = cleaned_data.get("provider_type")
        smtp_host = (cleaned_data.get("smtp_host") or "").strip()
        smtp_port = cleaned_data.get("smtp_port") or 25

        if provider_type != Provider.ProviderType.RECEIVE and not smtp_host:
            self.add_error(
                "smtp_host",
                "SMTP host is required for providers that send email.",
            )

        cleaned_data["smtp_server"] = (
            f"{smtp_host}:{smtp_port}" if smtp_host else ""
        )
        return cleaned_data

    ################################################################
    #
    def save(self, commit: bool = True) -> Provider:
        instance = super().save(commit=False)
        instance.smtp_server = self.cleaned_data.get("smtp_server", "")
        if commit:
            instance.save()
        return instance


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    form = ProviderAdminForm
    list_display = (
        "id",
        "name",
        "backend_name",
        "provider_type",
        "created_at",
        "modified_at",
    )
    list_filter = ("backend_name", "provider_type", "created_at", "modified_at")
    search_fields = ("name", "backend_name")
    date_hierarchy = "created_at"
    fieldsets = (
        (
            None,
            {
                "fields": ("name", "backend_name", "provider_type"),
            },
        ),
        (
            "SMTP Configuration",
            {
                "description": (
                    "Required for providers that send email. "
                    "Leave blank for receive-only providers."
                ),
                "fields": ("smtp_host", "smtp_port"),
            },
        ),
    )


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "domain_name",
        "send_provider",
        "api_key",
        "incoming_spool_dir",
        "outgoing_spool_dir",
        "mail_dir_parent",
        "created_at",
        "modified_at",
    )
    search_fields = ("domain_name",)
    list_filter = ("send_provider", "created_at", "modified_at")
    filter_horizontal = ("receive_providers",)
    date_hierarchy = "created_at"


@admin.register(LocalDelivery)
class LocalDeliveryAdmin(PolymorphicChildModelAdmin):
    base_model = LocalDelivery
    list_display = (
        "id",
        "email_account",
        "enabled",
        "maildir_path",
        "autofile_spam",
        "spam_score_threshold",
        "created_at",
    )
    list_filter = ("enabled", "autofile_spam")


@admin.register(AliasToDelivery)
class AliasToDeliveryAdmin(PolymorphicChildModelAdmin):
    base_model = AliasToDelivery
    list_display = (
        "id",
        "email_account",
        "enabled",
        "target_account",
        "created_at",
    )
    list_filter = ("enabled",)


@admin.register(DeliveryMethod)
class DeliveryMethodAdmin(PolymorphicParentModelAdmin):
    base_model = DeliveryMethod
    child_models = [LocalDelivery, AliasToDelivery]
    list_display = (
        "id",
        "email_account",
        "enabled",
        "polymorphic_ctype",
        "created_at",
    )
    list_filter = (PolymorphicChildModelFilter, "enabled")


class DeliveryMethodInline(admin.TabularInline):
    model = DeliveryMethod
    fields = ("polymorphic_ctype", "enabled")
    readonly_fields = ("polymorphic_ctype",)
    extra = 0


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "owner",
        "server",
        "email_address",
        "enabled",
        "password",
        "deactivated",
        "num_bounces",
        "deactivated_reason",
        "created_at",
        "modified_at",
    )
    list_filter = (
        "owner",
        "server",
        "enabled",
        "deactivated",
        "created_at",
        "modified_at",
    )
    search_fields = (
        "owner__username",
        "owner__email",
        "owner__first_name",
        "owner__last_name",
        "email_address",
    )
    inlines = [
        DeliveryMethodInline,
    ]
    date_hierarchy = "created_at"


@admin.register(MessageFilterRule)
class MessageFilterRuleAdmin(OrderedModelAdmin):
    list_display = (
        "id",
        "order",
        "email_account",
        "header",
        "pattern",
        "action",
        "destination",
        "created_at",
        "modified_at",
        "move_up_down_links",
    )
    list_filter = ("email_account", "created_at", "modified_at")
    search_fields = ("pattern", "destination")
    date_hierarchy = "created_at"


@admin.register(InactiveEmail)
class InactiveEmailAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "email_address",
        "can_activate",
        "created_at",
        "modified_at",
    )
    search_fields = ("email_address",)
    list_filter = ("created_at", "modified_at", "can_activate")
    date_hierarchy = "created_at"
