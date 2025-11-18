#!/usr/bin/env python
#
"""
Serializers for the rest framework of our models
"""
# system imports
#

# 3rd party imports
#
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_nested.relations import (
    NestedHyperlinkedIdentityField,
    NestedHyperlinkedRelatedField,
)
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

# Project imports
#
from .models import (
    DeliveryMethod,
    EmailAccount,
    InactiveEmail,
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
class EmailAccountRelatedField(serializers.SlugRelatedField):
    """
    Override `get_queryset` to provide the limit queryset of only valid
    EmailAccounts.
    """

    ####################################################################
    #
    def get_queryset(self):
        """
        Replace the generic provided queryset with one that only returns
        the valid related email accounts.

        This field we know is only used by the `EmailAccountSerializer` and we
        also know that this will **always** be a `many=True` field. Because of
        this we can safely access `self.parent.parent.instance`. When you make
        a related field that is `many=True` drf: "Relationships with
        `many=True` transparently get coerced into instead being a
        ManyRelatedField with a child relationship."

        See: https://github.com/encode/django-rest-framework/blob/f56b85b7dd7e4f786e0769bba6b7609d4507da83/rest_framework/relations.py#L471

        This lets us access the EmailAccount instance that this serializer is
        for, which lets us create a QuerySet that only shows to the REST API
        view the EmailAccounts that this EmailAccount is allowed to have for
        `aliases` and `alias_for`.
        """
        # The pre-populated list of valid EmailAccount's for `aliases` and
        # `for_alias` are EmailAccounts that have the same owner _except_ for
        # the EmailAccount being serialized (you can not alias to yourself.)
        #
        # NOTE: Unless the owner has the permission
        #       `as_email.can_have_foreign_aliases` in which case they can
        #       alias to any email account.
        #
        if self.parent.parent.instance is None:
            queryset = EmailAccount.objects.none()
        else:
            owner = self.parent.parent.instance.owner
            if not owner.has_perms(["as_email.can_have_foreign_aliases"]):
                queryset = EmailAccount.objects.filter(owner=owner).exclude(
                    pk=self.parent.parent.instance.pk
                )
            else:
                queryset = EmailAccount.objects.exclude(
                    pk=self.parent.parent.instance.pk
                )
        return queryset


########################################################################
########################################################################
#
class DeliveryMethodSerializer(serializers.ModelSerializer):
    """Serializer for DeliveryMethod model."""

    delivery_type_display = serializers.CharField(
        source="get_delivery_type_display", read_only=True
    )
    config_summary = serializers.SerializerMethodField()

    class Meta:
        model = DeliveryMethod
        fields = [
            "id",
            "delivery_type",
            "delivery_type_display",
            "config",
            "config_summary",
            "order",
            "enabled",
            "created_at",
            "modified_at",
        ]
        read_only_fields = ["id", "created_at", "modified_at"]

    def get_config_summary(self, obj):
        """Return human-readable summary of configuration."""
        try:
            return obj.backend.get_display_summary(obj.config)
        except Exception as e:
            return f"Error: {str(e)}"


########################################################################
########################################################################
#
class EmailAccountSerializer(serializers.HyperlinkedModelSerializer):
    # Nested delivery methods
    delivery_methods = DeliveryMethodSerializer(many=True, read_only=True)

    url = serializers.HyperlinkedIdentityField(
        view_name="as_email:email-account-detail", read_only=True
    )
    server = serializers.StringRelatedField(read_only=True)
    owner = serializers.StringRelatedField(read_only=True)
    message_filter_rules = NestedHyperlinkedIdentityField(
        view_name="as_email:message-filter-rule-list",
        lookup_url_kwarg="email_account_pk",
    )

    # The `EmailAccountRelatedField` makes sure that the queryset for
    # presenting valid EmailAccount's is limited to the EmailAccount's a user
    # is permitted to see.
    #
    alias_for = EmailAccountRelatedField(
        many=True,
        slug_field="email_address",
        required=False,
        help_text=EmailAccount.alias_for.field.help_text,
    )
    aliases = EmailAccountRelatedField(
        many=True,
        slug_field="email_address",
        required=False,
        help_text=_(
            "This is the reverse part of the `alias_for` relationship. It "
            "lists all the EmailAccounts that are an alias for this "
            "EmailAccount. NOTE: Adding and removing entries from this field "
            "updates `alias_for` on the added or removed EmailAccount."
        ),
    )

    class Meta:
        model = EmailAccount
        fields = [
            "pk",
            "aliases",
            "alias_for",
            "autofile_spam",
            "created_at",
            "deactivated",
            "deactivated_reason",
            "delivery_methods",
            "email_address",
            "forward_to",
            "message_filter_rules",
            "modified_at",
            "num_bounces",
            "owner",
            "server",
            "spam_delivery_folder",
            "spam_score_threshold",
            "url",
        ]
        read_only_fields = [
            "pk",
            "created_at",
            "deactivated",
            "deactivated_reason",
            "email_address",
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
