#!/usr/bin/env python
#
"""
Provider backends for different email service providers.

Each provider backend implements the logic for sending emails and handling
webhooks for a specific email service provider (e.g., Postmark, ForwardEmail).
"""
# system imports
#
import importlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import ProviderBackend


########################################################################
#
def get_backend(backend_name: str) -> "ProviderBackend":
    """
    Dynamically import and instantiate a provider backend by name.

    This function attempts to import a module named <backend_name>.py from
    the providers package and instantiate its backend class. The backend
    class name should be <BackendName>Backend (e.g., PostmarkBackend).

    Args:
        backend_name: The name of the backend (e.g., "postmark", "forwardemail")

    Returns:
        An instance of the provider backend

    Raises:
        ImportError: If the backend module does not exist
        AttributeError: If the backend class is not found in the module
    """
    # Verify the backend module file exists
    #
    backend_file = Path(__file__).parent / f"{backend_name}.py"
    if not backend_file.exists():
        raise ImportError(f"Provider backend '{backend_name}' not found")

    # Dynamically import the backend module
    #
    try:
        module = importlib.import_module(
            f".{backend_name}", package="as_email.providers"
        )
    except ImportError as exc:
        raise ImportError(
            f"Failed to import provider backend '{backend_name}': {exc}"
        )

    # Construct the expected class name (e.g., "postmark" -> "PostmarkBackend")
    #
    class_name = f"{backend_name.capitalize()}Backend"

    # Get the backend class from the module
    #
    try:
        backend_class = getattr(module, class_name)
    except AttributeError:
        raise AttributeError(
            f"Provider module '{backend_name}' does not have a '{class_name}' class"
        )

    # Instantiate and return the backend
    #
    return backend_class()


__all__ = ["get_backend"]
