# System imports
#

# Project imports
#
from as_email.models import (
    Account,
    Address,
    Alias,
    BlockedMessage,
    Forward,
    Provider,
    Server,
)

# 3rd party imports
#
from django.contrib import admin
from polymorphic.admin import (
    PolymorphicChildModelAdmin,
    PolymorphicChildModelFilter,
    PolymorphicParentModelAdmin,
)

# Register your models here.


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    pass


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    pass


@admin.register(Address)
class AddressAdmin(PolymorphicParentModelAdmin):
    base_model = Address
    child_models = (Account, Alias, Forward)
    list_filter = (PolymorphicChildModelFilter,)


@admin.register(Account)
class AccountAdmin(PolymorphicChildModelAdmin):
    base_model = Address


@admin.register(Alias)
class AliasAdmin(PolymorphicChildModelAdmin):
    base_model = Address


@admin.register(Forward)
class ForwardAdmin(PolymorphicChildModelAdmin):
    base_model = Address


@admin.register(BlockedMessage)
class BlockedMessageAdmin(admin.ModelAdmin):
    pass
