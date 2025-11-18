#!/usr/bin/env python
#
"""
Local delivery backend implementation.

Implements delivery to local mailboxes using the mailbox module.
"""
# system imports
#
import logging
from email.message import EmailMessage
from typing import TYPE_CHECKING, Any, Dict

# 3rd party imports
#
from django import forms
from django.core.exceptions import ValidationError

# project imports
#
from .base import DeliveryTypeBackend

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import DeliveryMethod, EmailAccount

logger = logging.getLogger("as_email.delivery_backends.local")


########################################################################
########################################################################
#
class LocalBackend(DeliveryTypeBackend):
    """
    Backend for local mailbox delivery.

    Delivers messages to the EmailAccount's local mailbox directory using
    the existing deliver_message_locally() function.
    """

    ####################################################################
    #
    def deliver(
        self,
        delivery_method: "DeliveryMethod",
        msg: EmailMessage,
        depth: int = 1,
    ) -> bool:
        """
        Deliver to local mailbox using existing logic.

        Args:
            delivery_method: The DeliveryMethod instance
            msg: The email message to deliver
            depth: Recursion depth (not used for local delivery)

        Returns:
            True if delivery succeeded

        Raises:
            Exception: If delivery fails
        """
        from ..deliver import deliver_message_locally

        deliver_message_locally(delivery_method.email_account, msg)
        logger.info(
            "Delivered message %s to local mailbox for %s",
            msg.get("Message-ID", "unknown"),
            delivery_method.email_account.email_address,
        )
        return True

    ####################################################################
    #
    def validate_config(
        self, config: Dict[str, Any], email_account: "EmailAccount"
    ) -> None:
        """
        Local delivery needs no additional config.

        Args:
            config: The configuration dictionary
            email_account: The EmailAccount context

        Raises:
            ValidationError: If config contains unexpected data
        """
        # Local delivery doesn't need any configuration
        # The mail_dir is already on the EmailAccount
        if config and len(config) > 0:
            raise ValidationError(
                "Local delivery does not accept configuration"
            )

    ####################################################################
    #
    def get_config_form(
        self,
        email_account: "EmailAccount",
        initial_config: Dict[str, Any] = None,
    ) -> forms.Form:
        """
        Return an empty form - no config needed for local delivery.

        Args:
            email_account: The EmailAccount context
            initial_config: Initial configuration values (ignored)

        Returns:
            Empty Django Form instance
        """

        class LocalDeliveryForm(forms.Form):
            """Empty form for local delivery - no configuration needed."""

            pass

        return LocalDeliveryForm(initial=initial_config or {})

    ####################################################################
    #
    def get_display_summary(self, config: Dict[str, Any]) -> str:
        """
        Display summary for local delivery.

        Args:
            config: The configuration dictionary

        Returns:
            String summary
        """
        return "Deliver to local mailbox"
