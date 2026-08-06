from __future__ import annotations

from dataclasses import dataclass, field

from ravshield.intel.email.normalize import normalize_email


DISPOSABLE_EMAIL_DOMAINS = {
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "temp-mail.org",
    "tempmail.com",
    "throwawaymail.com",
    "yopmail.com",
}

SUSPICIOUS_LOCAL_KEYWORDS = {
    "admin",
    "billing",
    "helpdesk",
    "login",
    "payment",
    "security",
    "support",
    "verify",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
}


@dataclass(slots=True)
class EmailHeuristicResult:
    """
    Structural warning signals found in an email address.
    """

    email: str
    signals: set[str] = field(default_factory=set)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def analyze_email_heuristics(
    email: str,
) -> EmailHeuristicResult:
    """
    Inspect an email address for suspicious characteristics.

    This function does not prove that an address is malicious.
    It only reports observable warning signals.
    """

    normalized = normalize_email(email)
    local_part, domain = normalized.rsplit("@", 1)

    signals: set[str] = set()
    details: dict[str, object] = {}

    if domain in DISPOSABLE_EMAIL_DOMAINS:
        signals.add("disposable_provider")
        details["provider"] = domain

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_LOCAL_KEYWORDS
        if keyword in local_part
    )

    if matched_keywords:
        signals.add("suspicious_local_keywords")
        details["matched_keywords"] = matched_keywords

    digit_count = sum(
        character.isdigit()
        for character in local_part
    )

    if local_part:
        digit_ratio = digit_count / len(local_part)
    else:
        digit_ratio = 0.0

    details["digit_ratio"] = round(digit_ratio, 2)

    if len(local_part) >= 8 and digit_ratio >= 0.60:
        signals.add("numeric_heavy_local_part")

    if len(local_part) > 40:
        signals.add("long_local_part")
        details["local_part_length"] = len(local_part)

    if domain.startswith("xn--") or ".xn--" in domain:
        signals.add("punycode_domain")

    if domain in FREE_EMAIL_DOMAINS:
        details["free_email_provider"] = True

    return EmailHeuristicResult(
        email=normalized,
        signals=signals,
        details=details,
    )