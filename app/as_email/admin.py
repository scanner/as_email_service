# 3rd party imports
#
from django.contrib import admin
from ordered_model.admin import OrderedModelAdmin

# Project imports
#
from .models import (
    DeliveryMethod,
    EmailAccount,
    InactiveEmail,
    MessageFilterRule,
    Provider,
    Server,
)


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
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


class AliasForInline(admin.TabularInline):
    model = EmailAccount.alias_for.through
    fk_name = "from_email_account"
    extra = 1
    verbose_name = "alias for"
    verbose_name_plural = "aliases for"


class AliasesInline(admin.TabularInline):
    model = EmailAccount.alias_for.through
    fk_name = "to_email_account"
    extra = 1
    verbose_name = "alias"
    verbose_name_plural = "aliases"


class DeliveryMethodInline(admin.TabularInline):
    """Inline admin for managing delivery methods."""

    model = DeliveryMethod
    extra = 1
    fields = ("delivery_type", "config", "order", "enabled", "config_summary")
    readonly_fields = ("config_summary",)

    def config_summary(self, obj):
        """Display a human-readable summary of the configuration."""
        if obj.pk:
            try:
                return obj.backend.get_display_summary(obj.config)
            except Exception as e:
                return f"Error: {e}"
        return "-"

    config_summary.short_description = "Configuration Summary"


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "owner",
        "server",
        "email_address",
        "mail_dir",
        "password",
        "autofile_spam",
        "spam_delivery_folder",
        "spam_score_threshold",
        "forward_to",
        "deactivated",
        "num_bounces",
        "deactivated_reason",
        "created_at",
        "modified_at",
    )
    list_filter = (
        "owner",
        "server",
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
        AliasForInline,
        AliasesInline,
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
