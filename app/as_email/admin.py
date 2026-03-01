# 3rd party imports
#
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
    child_models = (LocalDelivery, AliasToDelivery)
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
