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
from rest_framework_nested.relations import (  # NestedHyperlinkedIdentityField,
    NestedHyperlinkedRelatedField,
)
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

# Project imports
#
from .models import EmailAccount, InactiveEmail, MessageFilterRule


########################################################################
########################################################################
#
class EmailAccountSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="as_email:email_accounts-detail", read_only=True
    )
    server = serializers.StringRelatedField(read_only=True)

    # message_filter_rules = serializers.RelatedField(
    #     view_name="as_email:message_filter_rules-list",
    #     read_only=True,
    #     many=True,
    # )
    class Meta:
        model = EmailAccount
        fields = [
            "url",
            "server",
            "email_address",
            "delivery_method",
            "autofile_spam",
            "spam_delivery_folder",
            "spam_score_threshold",
            "alias_for",
            "forward_to",
            "deactivated",
            "num_bounces",
            "deactivated_reason",
            # "message_filter_rules",
            "created_at",
            "modified_at",
        ]
        read_only_fields = [
            "owner",
            "url",
            "email_address",
            "deactivated",
            "num_bounces",
            "deactivated_reason",
            # "message_filter_rules",
            "created_at",
            "modified_at",
            "server",
        ]


########################################################################
########################################################################
#
class MessageFilterRuleSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    # url = NestedHyperlinkedIdentityField(
    #     view_name="as_email:message_filter_rules-detail", read_only=True,
    #     parent_lookup_kwargs={'email_account_pk': 'email_account__pk'},
    # )
    email_account = NestedHyperlinkedRelatedField(
        view_name="as_email:email_accounts-detail",
        parent_lookup_kwargs={"email_account_pk": "email_account__pk"},
        read_only=True,
    )

    class Meta:
        model = MessageFilterRule
        fields = [
            # "url",
            "email_account",
            "header",
            "pattern",
            "action",
            "destination",
            "order",
            "created_at",
            "modified_at",
        ]

        read_only_fields = ["url", "email_account", "created_at", "modified_at"]


########################################################################
########################################################################
#
class InactiveEmailSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = InactiveEmail
        fields = [
            "url",
            "email_address",
            "can_activate",
            "created_at",
            "modified_at",
        ]

        read_only_fields = [
            "url",
            "email_address",
            "can_activate",
            "created_at",
            "modified_at",
        ]
