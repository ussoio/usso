"""
Text utility functions for code generation and encoding.

This module provides utilities for generating human-readable codes and
base64url encoding/decoding.
"""

import base64
import secrets
import string

HUMAN_READABLE_CHARS = list(set(string.ascii_letters + string.digits) - set("oO0Il1"))


def generate_human_readable_code(length: int = 6) -> str:
    """
    Generate a human-readable random code.

    Uses characters that are easily distinguishable (excludes o, O, 0, I, l, 1)
    to avoid confusion in user-facing codes.

    Args:
        length: Length of the code to generate (default: 6).

    Returns:
        Random string of the specified length using human-readable characters.

    """
    return "".join(secrets.choice(HUMAN_READABLE_CHARS) for _ in range(length))


def base64url_encode(value: bytes) -> str:
    """
    Encode bytes to base64url string.

    Base64url encoding uses URL-safe characters and omits padding.

    Args:
        value: Bytes to encode.

    Returns:
        Base64url-encoded string without padding.

    """
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    """
    Decode base64url string to bytes.

    Adds padding if necessary before decoding.

    Args:
        value: Base64url-encoded string to decode.

    Returns:
        Decoded bytes.

    """
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
