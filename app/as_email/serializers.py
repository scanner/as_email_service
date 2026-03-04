#!/usr/bin/env python
#
"""
Serializers for the rest framework of our models
"""
# 3rd party imports
#
from rest_framework import serializers
from rest_framework_nested.relations import (
    NestedHyperlinkedIdentityField,
    NestedHyperlinkedRelatedField,
)
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

# Project imports
#
from .models import (
    AliasToDelivery,
    DeliveryMethod,
    EmailAccount,
    ImapDelivery,
    InactiveEmail,
    LocalDelivery,
    MessageFilterRule,
)


########################################################################
########################################################################
#
class PasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint on the EmailAccount.
    """

    class Meta:
        model = EmailAccount
        fields = ["password"]

    password = serializers.CharField(required=True)


########################################################################
########################################################################
#
class MoveOrderSerializer(serializers.Serializer):
    """
    Models that use the "ordered" feature need to expose via the REST API
    methods for changing their ordering. This is done via the "move" method
    added to the REST API for that model which takes this serializer
    """

    UP = "up"
    DOWN = "down"
    TO = "to"
    BOTTOM = "bottom"
    TOP = "top"
    COMMANDS = [UP, DOWN, TO, BOTTOM, TOP]

    class Meta:
        model = MessageFilterRule
        fields = ["command", "location"]

    command = serializers.ChoiceField(required=True, choices=COMMANDS)
    # Only required if command is "to"
    location = serializers.IntegerField(required=False)


########################################################################
########################################################################
#
class EmailAccountSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="as_email:email-account-detail", read_only=True
    )
    server = serializers.StringRelatedField(read_only=True)
    owner = serializers.StringRelatedField(read_only=True)
    message_filter_rules = NestedHyperlinkedIdentityField(
        view_name="as_email:message-filter-rule-list",
        lookup_url_kwarg="email_account_pk",
    )
    aliased_from = serializers.SerializerMethodField()

    def get_aliased_from(self, obj: EmailAccount) -> list[dict]:
        return [
            {"email": atd.email_account.email_address, "enabled": atd.enabled}
            for atd in obj.aliased_from.all()
        ]

    class Meta:
        model = EmailAccount
        fields = [
            "pk",
            "aliased_from",
            "created_at",
            "deactivated",
            "deactivated_reason",
            "email_address",
            "enabled",
            "message_filter_rules",
            "modified_at",
            "num_bounces",
            "owner",
            "scan_incoming_spam",
            "server",
            "url",
        ]
        read_only_fields = [
            "pk",
            "aliased_from",
            "created_at",
            "deactivated",
            "deactivated_reason",
            "email_address",
            "enabled",
            "message_filter_rules",
            "modified_at",
            "num_bounces",
            "owner",
            "server",
            "url",
        ]


########################################################################
########################################################################
#
class MessageFilterRuleSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    url = NestedHyperlinkedIdentityField(
        view_name="as_email:message-filter-rule-detail",
        lookup_field="pk",
        parent_lookup_kwargs={"email_account_pk": "email_account__pk"},
    )
    email_account = NestedHyperlinkedRelatedField(
        view_name="as_email:email-account-detail",
        parent_lookup_kwargs={"email_account_pk": "email_account__pk"},
        read_only=True,
    )

    class Meta:
        model = MessageFilterRule
        fields = [
            "url",
            "email_account",
            "header",
            "pattern",
            "action",
            "destination",
            "order",
            "created_at",
            "modified_at",
        ]

        read_only_fields = [
            "email_address",
            "order",
            "url",
            "created_at",
            "modified_at",
        ]


########################################################################
########################################################################
#
class InactiveEmailSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="as_email:inactive_email-detail", read_only=True
    )

    class Meta:
        model = InactiveEmail
        fields = [
            "url",
            "email_address",
            "can_activate",
            "created_at",
            "modified_at",
            "order",
        ]

        read_only_fields = [
            "url",
            "email_address",
            "can_activate",
            "created_at",
            "modified_at",
            "order",
        ]


########################################################################
########################################################################
#
class DeliveryMethodSerializer(NestedHyperlinkedModelSerializer):
    """
    Base serializer for DeliveryMethod. The `delivery_type` field exposes the
    concrete subclass name so clients can distinguish LocalDelivery from
    AliasToDelivery.
    """

    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    url = NestedHyperlinkedIdentityField(
        view_name="as_email:delivery-method-detail",
        lookup_field="pk",
        parent_lookup_kwargs={"email_account_pk": "email_account__pk"},
    )
    delivery_type = serializers.SerializerMethodField()

    ####################################################################
    #
    def get_delivery_type(self, obj: DeliveryMethod) -> str:
        return obj.__class__.__name__

    class Meta:
        model = DeliveryMethod
        fields = [
            "url",
            "pk",
            "delivery_type",
            "enabled",
            "created_at",
            "modified_at",
        ]
        read_only_fields = [
            "url",
            "pk",
            "delivery_type",
            "created_at",
            "modified_at",
        ]


########################################################################
########################################################################
#
class LocalDeliverySerializer(DeliveryMethodSerializer):
    class Meta(DeliveryMethodSerializer.Meta):
        model = LocalDelivery
        fields = DeliveryMethodSerializer.Meta.fields + [
            "maildir_path",
            "autofile_spam",
            "spam_delivery_folder",
            "spam_score_threshold",
        ]
        read_only_fields = DeliveryMethodSerializer.Meta.read_only_fields + [
            "maildir_path",
        ]


########################################################################
########################################################################
#
class AliasToDeliverySerializer(DeliveryMethodSerializer):
    target_account = serializers.SlugRelatedField(
        slug_field="email_address",
        queryset=EmailAccount.objects.all(),
        help_text=AliasToDelivery.target_account.field.help_text,
    )

    class Meta(DeliveryMethodSerializer.Meta):
        model = AliasToDelivery
        fields = DeliveryMethodSerializer.Meta.fields + [
            "target_account",
        ]


########################################################################
########################################################################
#
class ImapDeliverySerializer(DeliveryMethodSerializer):
    """
    Serializer for ImapDelivery. The `password` field is write-only — it is
    accepted on create and update but never returned in GET responses. On
    PATCH, omitting `password` leaves the stored value unchanged.
    """

    password = serializers.CharField(
        write_only=True,
        required=False,
        style={"input_type": "password"},
        help_text=ImapDelivery.password.field.help_text,
    )

    class Meta(DeliveryMethodSerializer.Meta):
        model = ImapDelivery
        fields = DeliveryMethodSerializer.Meta.fields + [
            "imap_host",
            "imap_port",
            "username",
            "password",
            "autofile_spam",
            "spam_score_threshold",
        ]

    ####################################################################
    #
    def update(
        self, instance: ImapDelivery, validated_data: dict
    ) -> ImapDelivery:
        """
        Remove `password` from validated_data when it is absent so a PATCH
        without a password field does not overwrite the stored credential.
        """
        if "password" not in self.initial_data:
            validated_data.pop("password", None)
        return super().update(instance, validated_data)
