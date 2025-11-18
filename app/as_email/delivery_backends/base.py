#!/usr/bin/env python
#
"""
Base abstract class for delivery method type backends.

Defines the interface that all delivery type backends must implement for
delivering messages, validating configuration, and providing UI forms.
"""
# system imports
#
from abc import ABC, abstractmethod
from email.message import EmailMessage
from typing import TYPE_CHECKING, Any, Dict

# 3rd party imports
#
from django import forms

# Avoid circular imports
#
if TYPE_CHECKING:
    from ..models import DeliveryMethod, EmailAccount


########################################################################
########################################################################
#
class DeliveryTypeBackend(ABC):
    """
    Abstract base class for delivery method type backends.

    Each delivery type (Local, Alias, IMAP, etc.) implements this interface
    to provide delivery logic, configuration validation, and UI forms.
    """

    ####################################################################
    #
    @abstractmethod
    def deliver(
        self,
        delivery_method: "DeliveryMethod",
        msg: EmailMessage,
        depth: int = 1,
    ) -> bool:
        """
        Deliver a message using this delivery method.

        Args:
            delivery_method: The DeliveryMethod instance with config
            msg: The email message to deliver
            depth: Recursion depth for alias chains

        Returns:
            True if delivery succeeded, False otherwise

        Raises:
            Exception: If delivery fails unrecoverably
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def validate_config(
        self, config: Dict[str, Any], email_account: "EmailAccount"
    ) -> None:
        """
        Validate the configuration dict for this delivery type.

        Args:
            config: The configuration dictionary to validate
            email_account: The EmailAccount this belongs to

        Raises:
            ValidationError: If configuration is invalid
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def get_config_form(
        self,
        email_account: "EmailAccount",
        initial_config: Dict[str, Any] = None,
    ) -> forms.Form:
        """
        Return a Django form for editing this delivery type's configuration.

        Args:
            email_account: The EmailAccount context
            initial_config: Initial configuration values

        Returns:
            Django Form instance for this delivery type
        """
        pass

    ####################################################################
    #
    @abstractmethod
    def get_display_summary(self, config: Dict[str, Any]) -> str:
        """
        Return a human-readable summary of the configuration.

        Args:
            config: The configuration dictionary

        Returns:
            String summary for display in admin/UI
        """
        pass
