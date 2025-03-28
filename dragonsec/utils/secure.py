"""Secure utilities for handling sensitive data."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def secure(api_key: Optional[str]) -> Optional[str]:
    """Securely handle API key.

    Args:
        api_key: The API key to secure

    Returns:
        The secured API key
    """
    if not api_key:
        logger.warning("No API key provided")
        return None

    # Remove any whitespace
    api_key = api_key.strip()

    # Basic validation
    if len(api_key) < 8:
        logger.warning("API key seems too short")
        return None

    return api_key 