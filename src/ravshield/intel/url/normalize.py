from __future__ import annotations

from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)


DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def normalize_url(url: str) -> str:
    """
    Convert a URL into a consistent canonical form.

    Normalization helps RavShield treat equivalent URLs
    as the same target during reputation checks.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    candidate = url.strip()

    if not candidate:
        raise ValueError("URL cannot be empty.")

    parsed = urlsplit(candidate)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    if not scheme:
        raise ValueError("URL must include a scheme.")

    if not hostname:
        raise ValueError("URL must include a hostname.")

    port = parsed.port

    if port == DEFAULT_PORTS.get(scheme):
        port = None

    netloc = hostname

    if parsed.username:
        netloc = parsed.username

        if parsed.password:
            netloc += f":{parsed.password}"

        netloc += f"@{hostname}"

    if port is not None:
        netloc += f":{port}"

    path = parsed.path or "/"

    query_pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    normalized_query = urlencode(
        sorted(query_pairs),
        doseq=True,
    )

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            normalized_query,
            "",
        )
    )