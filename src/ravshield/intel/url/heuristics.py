from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit
import re

from ravshield.intel.text_match import keyword_matches


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


def _has_suspicious_encoding(url: str) -> tuple[bool, dict[str, object]]:
    """
    Detect obfuscating percent-encoding rather than normal escapes.

    Normal encoding of spaces or reserved query characters is ignored.
    Encoding unreserved characters (e.g. ``%76`` for ``v``) is treated
    as obfuscation commonly used in phishing URLs.
    """

    details: dict[str, object] = {}

    if "%25" in url.lower():
        details["double_encoding"] = True
        return True, details

    obfuscation_tokens = {
        "%40",  # @
        "%2f",  # /
        "%5c",  # \
        "%2e",  # .
        "%00",
    }

    lowered = url.lower()
    matched_tokens = sorted(
        token
        for token in obfuscation_tokens
        if token in lowered
    )

    if matched_tokens:
        details["obfuscation_tokens"] = matched_tokens
        return True, details

    encoded_unreserved: list[str] = []

    for match in re.finditer(r"%([0-9A-Fa-f]{2})", url):
        raw = match.group(0)
        decoded_char = chr(int(match.group(1), 16))

        if decoded_char.isalnum() or decoded_char in "-._~":
            encoded_unreserved.append(raw.lower())

    if encoded_unreserved:
        details["encoded_unreserved"] = sorted(
            set(encoded_unreserved)
        )
        return True, details

    if "%" not in url:
        return False, details

    decoded = unquote(url)
    encoded_keywords = keyword_matches(decoded, SUSPICIOUS_KEYWORDS)
    raw_keywords = keyword_matches(url, SUSPICIOUS_KEYWORDS)

    revealed = sorted(set(encoded_keywords) - set(raw_keywords))

    if revealed:
        details["decoded_keywords"] = revealed
        return True, details

    return False, details


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

    matched_keywords = keyword_matches(decoded_url, SUSPICIOUS_KEYWORDS)

    if matched_keywords:
        signals.add("suspicious_keywords")
        details["matched_keywords"] = matched_keywords

    suspicious_encoding, encoding_details = _has_suspicious_encoding(url)

    if suspicious_encoding:
        signals.add("suspicious_encoding")
        details.update(encoding_details)

    return URLHeuristicResult(
        url=url,
        signals=signals,
        details=details,
    )
