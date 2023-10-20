#!/usr/bin/env python
#
"""
Serializers for the rest framework of our models
"""
# system imports
#

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
from .models import EmailAccount, InactiveEmail, MessageFilterRule


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
    alias_for = serializers.SlugRelatedField(
        many=True,
        slug_field="email_address",
        queryset=EmailAccount.objects.all(),
        required=False,
        html_cutoff=0,
        html_cutoff_text="",
    )
    aliases = serializers.SlugRelatedField(
        many=True,
        slug_field="email_address",
        queryset=EmailAccount.objects.all(),
        required=False,
        html_cutoff=0,
        html_cutoff_text="",
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
            "delivery_method",
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
