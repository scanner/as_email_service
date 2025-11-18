#!/usr/bin/env python
#
"""
Delivery type backends for different delivery methods.

Each delivery backend implements the logic for delivering messages via a
specific method (e.g., local mailbox, alias, IMAP).
"""
# system imports
#
import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import DeliveryTypeBackend

# Mapping of delivery type codes to backend module names
BACKEND_MAP = {
    "LD": "local",
    "AL": "alias",
    # Future: 'IM': 'imap',
}


########################################################################
#
def get_delivery_backend(delivery_type: str) -> "DeliveryTypeBackend":
    """
    Dynamically load and instantiate a delivery backend by type code.

    This function attempts to import a module named <backend_name>.py from
    the delivery_backends package and instantiate its backend class. The
    backend class name should be <BackendName>Backend (e.g., LocalBackend).

    Args:
        delivery_type: The delivery type code (e.g., 'LD', 'AL')

    Returns:
        An instance of the delivery backend

    Raises:
        ValueError: If delivery type is not recognized
        ImportError: If backend module cannot be loaded
        AttributeError: If backend class is not found in the module
    """
    if delivery_type not in BACKEND_MAP:
        raise ValueError(f"Unknown delivery type: {delivery_type}")

    module_name = BACKEND_MAP[delivery_type]

    try:
        module = importlib.import_module(
            f".{module_name}", package="as_email.delivery_backends"
        )
    except ImportError as exc:
        raise ImportError(
            f"Failed to import delivery backend '{module_name}': {exc}"
        )

    # Class naming convention: LocalBackend, AliasBackend, etc.
    class_name = f"{module_name.capitalize()}Backend"

    try:
        backend_class = getattr(module, class_name)
    except AttributeError:
        raise AttributeError(
            f"Module '{module_name}' does not have class '{class_name}'"
        )

    return backend_class()


__all__ = ["get_delivery_backend", "BACKEND_MAP"]
