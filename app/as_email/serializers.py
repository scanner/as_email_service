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
    alias_for = serializers.HyperlinkedIdentityField(
        view_name="as_email:email-account-detail",
        many=True,
    )

    class Meta:
        model = EmailAccount
        fields = [
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
