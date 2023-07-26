# 3rd party imports
#
from django.contrib import admin
from ordered_model.admin import OrderedModelAdmin

# Project imports
#
from .models import (
    BlockedMessage,
    EmailAccount,
    MessageFilterRule,
    Provider,
    Server,
)


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
        "user",
        "server",
        "email_address",
        "account_type",
        "mail_dir",
        "password",
        "handle_blocked_messages",
        "blocked_messages_delivery_folder",
        "forward_to",
        "deactivated",
        "num_bounces",
        "deactivated_reason",
        "created_at",
        "modified_at",
    )
    list_filter = (
        "user",
        "server",
        "account_type",
        "deactivated",
        "created_at",
        "modified_at",
    )
    search_fields = (
        "user",
        "email_address",
    )
    raw_id_fields = ("alias_for",)
    date_hierarchy = "created_at"


@admin.register(BlockedMessage)
class BlockedMessageAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "email_account",
        "message_id",
        "status",
        "from_address",
        "subject",
        "cc",
        "blocked_reason",
        "created_at",
        "modified_at",
    )
    list_filter = ("email_account", "status", "created_at", "modified_at")
    search_fields = ("blocked_reason", "from_address", "cc", "email_account")
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
