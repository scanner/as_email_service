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
    pass


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    pass


@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    pass


@admin.register(BlockedMessage)
class BlockedMessageAdmin(admin.ModelAdmin):
    pass


@admin.register(MessageFilterRule)
class MessageFilterRuleAdmin(OrderedModelAdmin):
    list_display = (
        "move_up_down_links",
        "email_account",
        "header",
        "pattern",
        "action",
        "destination",
    )
