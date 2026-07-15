import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ravshield.engines.hash_engine import normalize_hash, validate_hash
from ravshield.enums import Severity


SUPPORTED_IOC_TYPES = frozenset(
    {
        "sha256",
        "sha1",
        "md5",
        "ip",
        "domain",
        "url",
        "email",
        "cve",
    }
)


def normalize_indicator_type(indicator_type: str) -> str:
    """
    Convert an IOC type into the canonical format used by RavShield.
    """

    return indicator_type.strip().lower()


def normalize_indicator_value(
    indicator_type: str,
    value: str,
) -> str:
    """
    Normalize an IOC value according to its type.
    """

    normalized_type = normalize_indicator_type(indicator_type)
    normalized_value = value.strip()

    if normalized_type in {"sha256", "sha1", "md5"}:
        return normalize_hash(normalized_value)

    if normalized_type == "ip":
        return str(ipaddress.ip_address(normalized_value))

    if normalized_type == "domain":
        return normalized_value.lower().rstrip(".")

    if normalized_type == "url":
        parsed = urlparse(normalized_value)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""

        normalized_url = f"{scheme}://{hostname}{port}{parsed.path or ''}"

        if parsed.query:
            normalized_url += f"?{parsed.query}"

        return normalized_url

    if normalized_type in {"email", "cve"}:
        return normalized_value.lower()

    return normalized_value


def is_valid_indicator(
    indicator_type: str,
    value: str,
) -> bool:
    """
    Validate an IOC value before it enters the intelligence store.
    """

    normalized_type = normalize_indicator_type(indicator_type)

    if normalized_type not in SUPPORTED_IOC_TYPES:
        return False

    if not value or not value.strip():
        return False

    normalized_value = value.strip()

    if normalized_type in {"sha256", "sha1", "md5"}:
        return validate_hash(normalized_value, normalized_type)

    if normalized_type == "ip":
        try:
            ipaddress.ip_address(normalized_value)
            return True
        except ValueError:
            return False

    if normalized_type == "domain":
        domain_pattern = re.compile(
            r"^(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,63}$"
        )
        return bool(domain_pattern.fullmatch(normalized_value.rstrip(".")))

    if normalized_type == "url":
        parsed = urlparse(normalized_value)

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )

    if normalized_type == "email":
        email_pattern = re.compile(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        )
        return bool(email_pattern.fullmatch(normalized_value))

    if normalized_type == "cve":
        return bool(
            re.fullmatch(
                r"CVE-\d{4}-\d{4,}",
                normalized_value,
                flags=re.IGNORECASE,
            )
        )

    return False


@dataclass(slots=True, frozen=True)
class IOC:
    value: str
    indicator_type: str
    severity: Severity
    source: str
    confidence: int

    def __post_init__(self) -> None:
        normalized_type = normalize_indicator_type(
            self.indicator_type
        )

        if normalized_type not in SUPPORTED_IOC_TYPES:
            raise ValueError(
                f"Unsupported IOC type: {self.indicator_type}"
            )

        if not is_valid_indicator(
            normalized_type,
            self.value,
        ):
            raise ValueError(
                f"Invalid {normalized_type} IOC value: "
                f"{self.value}"
            )

        if not 0 <= self.confidence <= 100:
            raise ValueError(
                "IOC confidence must be between 0 and 100."
            )

        normalized_value = normalize_indicator_value(
            normalized_type,
            self.value,
        )

        object.__setattr__(
            self,
            "indicator_type",
            normalized_type,
        )
        object.__setattr__(
            self,
            "value",
            normalized_value,
        )
        object.__setattr__(
            self,
            "source",
            self.source.strip(),
        )