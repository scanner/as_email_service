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
from .models import BlockedMessage, EmailAccount, MessageFilterRule


########################################################################
########################################################################
#
class EmailAccountSerializer(HyperlinkedModelSerializer):
    class Meta:
        model = EmailAccount
        fields = [
            "url",
            "email_address",
            "account_type",
            "handle_blocked_messages",
            "blocked_message_delivery_folder",
            "alias_for",
            "forward_to",
            "deactivated",
            "blocked_messages",
            "message_filter_rules",
        ]


########################################################################
########################################################################
#
class BlockedMessageSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    class Meta:
        model = BlockedMessage
        fields = [
            "status",
            "from_address",
            "subject",
            "cc",
            "blocked_reason",
            "created_at",
        ]


########################################################################
########################################################################
#
class MessageFilterRuleSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"email_account_pk": "email_account__pk"}

    class Meta:
        model = MessageFilterRule
        fields = ["header", "pattern", "action", "destination", "order"]
