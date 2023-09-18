#!/usr/bin/env python
#
"""
Serializers for the rest framework of our models
"""
# system imports
#

# 3rd party imports
#
from rest_framework.serializers import HyperlinkedModelSerializer
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

# Project imports
#
from .models import EmailAccount, MessageFilterRule


########################################################################
########################################################################
#
class EmailAccountSerializer(HyperlinkedModelSerializer):
    class Meta:
        model = EmailAccount
        fields = [
            "url",
            "owner",
            "server",
            "email_address",
            "delivery_method",
            "autofile_spam",
            "spam_delivery_folder",
            "spam_score_threshold",
            "alias_for",
            "forward_to",
            "forward_style",
            "deactivated",
            "num_bounces",
            "deactivated_reason",
            "message_filter_rules",
            "created_at",
            "modified_at",
        ]


########################################################################
########################################################################
#
class MessageFilterRuleSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    class Meta:
        model = MessageFilterRule
        fields = [
            "email_account",
            "header",
            "pattern",
            "action",
            "destination",
            "order",
        ]
