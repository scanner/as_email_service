#!/usr/bin/env python
#
"""
Alias delivery backend implementation.

Implements delivery to aliased email accounts.
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

logger = logging.getLogger("as_email.delivery_backends.alias")


########################################################################
########################################################################
#
class AliasBackend(DeliveryTypeBackend):
    """
    Backend for alias delivery.

    Delivers messages to a target EmailAccount specified in the configuration.
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
        Deliver to aliased account.

        Args:
            delivery_method: The DeliveryMethod instance with config
            msg: The email message to deliver
            depth: Recursion depth for alias chains

        Returns:
            True if delivery succeeded

        Raises:
            ValueError: If configuration is invalid
            Exception: If delivery fails
        """
        from ..deliver import deliver_message
        from ..models import EmailAccount

        config = delivery_method.config
        target_id = config.get("target_email_account_id")

        if not target_id:
            raise ValueError(
                "Alias delivery method missing target_email_account_id in config"
            )

        try:
            target_account = EmailAccount.objects.get(pk=target_id)
        except EmailAccount.DoesNotExist:
            raise ValueError(
                f"Target EmailAccount {target_id} does not exist for alias delivery"
            )

        logger.info(
            "Delivering message %s from %s to aliased account %s",
            msg.get("Message-ID", "unknown"),
            delivery_method.email_account.email_address,
            target_account.email_address,
        )

        deliver_message(target_account, msg, depth + 1)
        return True

    ####################################################################
    #
    def validate_config(
        self, config: Dict[str, Any], email_account: "EmailAccount"
    ) -> None:
        """
        Validate alias configuration.

        Args:
            config: The configuration dictionary
            email_account: The EmailAccount this belongs to

        Raises:
            ValidationError: If configuration is invalid
        """
        from ..models import EmailAccount

        if "target_email_account_id" not in config:
            raise ValidationError(
                "Alias delivery requires 'target_email_account_id' in config"
            )

        target_id = config["target_email_account_id"]

        # Ensure target_id is an integer
        if not isinstance(target_id, int):
            raise ValidationError("target_email_account_id must be an integer")

        try:
            target = EmailAccount.objects.get(pk=target_id)
        except EmailAccount.DoesNotExist:
            raise ValidationError(
                f"Target EmailAccount with id {target_id} does not exist"
            )

        # Prevent self-aliasing
        if target.pk == email_account.pk:
            raise ValidationError("Cannot alias to yourself")

    ####################################################################
    #
    def get_config_form(
        self,
        email_account: "EmailAccount",
        initial_config: Dict[str, Any] = None,
    ) -> forms.Form:
        """
        Return form for alias configuration.

        Args:
            email_account: The EmailAccount context
            initial_config: Initial configuration values

        Returns:
            Django Form instance for alias configuration
        """
        from ..models import EmailAccount

        class AliasConfigForm(forms.Form):
            """Form for configuring alias delivery."""

            target_email_account_id = forms.ModelChoiceField(
                queryset=EmailAccount.objects.exclude(pk=email_account.pk),
                label="Target Email Account",
                help_text="Email account to deliver messages to",
                to_field_name="id",
            )

        return AliasConfigForm(initial=initial_config or {})

    ####################################################################
    #
    def get_display_summary(self, config: Dict[str, Any]) -> str:
        """
        Display summary for alias delivery.

        Args:
            config: The configuration dictionary

        Returns:
            String summary showing target account
        """
        from ..models import EmailAccount

        target_id = config.get("target_email_account_id")
        if target_id:
            try:
                target = EmailAccount.objects.get(pk=target_id)
                return f"Alias to: {target.email_address}"
            except EmailAccount.DoesNotExist:
                return f"Alias to: [EmailAccount {target_id} not found]"
        return "Alias (not configured)"
