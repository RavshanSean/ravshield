from __future__ import annotations

import re

from ravshield.intel.email.normalize import normalize_email


EMAIL_PATTERN = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    flags=re.IGNORECASE,
)


def validate_email(email: str) -> bool:
    """
    Return True when a value is a structurally valid email address.
    """

    if not isinstance(email, str):
        return False

    try:
        normalized = normalize_email(email)
    except (TypeError, ValueError):
        return False

    if len(normalized) > 254:
        return False

    local_part, separator, domain = normalized.rpartition("@")

    if not separator:
        return False

    if not local_part or not domain:
        return False

    if len(local_part) > 64:
        return False

    if local_part.startswith(".") or local_part.endswith("."):
        return False

    if ".." in local_part:
        return False

    return bool(EMAIL_PATTERN.fullmatch(normalized))