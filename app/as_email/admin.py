# 3rd party imports
#
from django.contrib import admin
from ordered_model.admin import OrderedModelAdmin

# Project imports
#
from .models import EmailAccount, MessageFilterRule, Provider, Server


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "created_at", "modified_at")
    list_filter = ("created_at", "modified_at")
    search_fields = ("name",)
    date_hierarchy = "created_at"


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "domain_name",
        "provider",
        "api_key",
        "incoming_spool_dir",
        "outgoing_spool_dir",
        "mail_dir_parent",
        "created_at",
        "modified_at",
    )
    search_fields = ("domain_name",)
    list_filter = ("provider", "created_at", "modified_at")
    date_hierarchy = "created_at"


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "owner",
        "server",
        "email_address",
        "delivery_method",
        "mail_dir",
        "password",
        "autofile_spam",
        "spam_delivery_folder",
        "spam_assassin_score_threshold",
        "forward_to",
        "forward_style",
        "deactivated",
        "num_bounces",
        "deactivated_reason",
        "created_at",
        "modified_at",
    )
    list_filter = (
        "owner",
        "server",
        "delivery_method",
        "deactivated",
        "created_at",
        "modified_at",
    )
    search_fields = (
        "owner",
        "email_address",
    )
    raw_id_fields = ("alias_for",)
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
    )
    list_filter = ("email_account", "created_at", "modified_at")
    search_fields = ("pattern", "destination")
    date_hierarchy = "created_at"
