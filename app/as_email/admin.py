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
    Account,
    Address,
    Alias,
    BlockedMessage,
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


@admin.register(Address)
class AddressAdmin(PolymorphicParentModelAdmin):
    base_model = Address
    child_models = (Account, Alias)
    list_filter = (PolymorphicChildModelFilter,)


@admin.register(Account)
class AccountAdmin(PolymorphicChildModelAdmin):
    base_model = Address


@admin.register(Alias)
class AliasAdmin(PolymorphicChildModelAdmin):
    base_model = Address


@admin.register(BlockedMessage)
class BlockedMessageAdmin(admin.ModelAdmin):
    pass


@admin.register(MessageFilterRule)
class MessageFilterRuleAdmin(OrderedModelAdmin):
    list_display = (
        "move_up_down_links",
        "account",
        "header",
        "pattern",
        "action",
        "folder",
    )
