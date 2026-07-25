from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit


SUSPICIOUS_KEYWORDS = {
    "account",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}


@dataclass(slots=True)
class URLHeuristicResult:
    url: str
    signals: set[str] = field(default_factory=set)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def analyze_url_heuristics(url: str) -> URLHeuristicResult:
    """
    Inspect a URL for suspicious structural characteristics.

    This function does not decide whether a URL is malicious.
    It only reports observable warning signals.
    """

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    decoded_url = unquote(url).lower()

    signals: set[str] = set()
    details: dict[str, object] = {}

    labels = hostname.split(".") if hostname else []

    if parsed.username or parsed.password:
        signals.add("embedded_credentials")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        signals.add("punycode_hostname")

    if len(labels) > 4:
        signals.add("excessive_subdomains")
        details["subdomain_count"] = max(len(labels) - 2, 0)

    if len(hostname) > 60:
        signals.add("long_hostname")
        details["hostname_length"] = len(hostname)

    if len(url) > 150:
        signals.add("long_url")
        details["url_length"] = len(url)

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in decoded_url
    )

    if matched_keywords:
        signals.add("suspicious_keywords")
        details["matched_keywords"] = matched_keywords

    if "%" in url:
        signals.add("encoded_characters")

    return URLHeuristicResult(
        url=url,
        signals=signals,
        details=details,
    )