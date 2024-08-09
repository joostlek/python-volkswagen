"""Utility functions for the aiovolkswagen library."""

import hashlib
import secrets
import string
from base64 import b64encode


def get_random_string() -> str:
    """Generate a random string."""
    chars = string.ascii_letters + string.digits
    text = "".join(secrets.choice(chars) for _ in range(10))
    sha256 = hashlib.sha256()
    sha256.update(text.encode())
    return b64encode(sha256.digest()).decode("utf-8")[:-1]
