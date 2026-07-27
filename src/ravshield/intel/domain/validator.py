from __future__ import annotations

import ipaddress
import re

from ravshield.intel.domain.normalize import normalize_domain


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:"
    r"[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"\."
    r")+"
    r"[a-z]{2,63}$",
    flags=re.IGNORECASE,
)


def validate_domain(domain: str) -> bool:
    """
    Return True when a value is a valid public-style domain name.

    IP addresses, localhost values, malformed labels, and unsupported
    values are rejected.
    """

    if not isinstance(domain, str):
        return False

    normalized = normalize_domain(domain)

    if not normalized:
        return False

    if normalized == "localhost":
        return False

    try:
        ipaddress.ip_address(normalized)
        return False
    except ValueError:
        pass

    if ".." in normalized:
        return False

    labels = normalized.split(".")

    if any(len(label) > 63 for label in labels):
        return False

    if any(
        label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        return False

    return bool(DOMAIN_PATTERN.fullmatch(normalized))