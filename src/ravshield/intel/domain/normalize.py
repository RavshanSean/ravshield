from __future__ import annotations


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain into RavShield's canonical format.

    Examples:
        Example.COM -> example.com
        example.com. -> example.com
        HTTPS://Example.COM/login -> example.com
    """

    normalized = domain.strip().lower()

    if "://" in normalized:
        from urllib.parse import urlparse

        parsed = urlparse(normalized)
        normalized = parsed.hostname or ""

    normalized = normalized.rstrip(".")

    return normalized