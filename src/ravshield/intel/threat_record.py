from dataclasses import dataclass
from datetime import datetime

from ravshield.enums import Severity, Verdict
from ravshield.intel.ioc import (
    is_valid_indicator,
    normalize_indicator_type,
    normalize_indicator_value,
)


@dataclass(slots=True, frozen=True)
class ThreatRecord:
    indicator_type: str
    value: str
    verdict: Verdict
    severity: Severity
    confidence: int
    source: str
    first_seen: datetime
    last_seen: datetime
    malware_family: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        normalized_type = normalize_indicator_type(
            self.indicator_type
        )

        if not is_valid_indicator(
            normalized_type,
            self.value,
        ):
            raise ValueError(
                f"Invalid {normalized_type} threat indicator: "
                f"{self.value}"
            )

        if not 0 <= self.confidence <= 100:
            raise ValueError(
                "Threat confidence must be between 0 and 100."
            )

        if not self.source.strip():
            raise ValueError(
                "Threat intelligence source cannot be empty."
            )

        if self.first_seen.tzinfo is None:
            raise ValueError(
                "first_seen must include timezone information."
            )

        if self.last_seen.tzinfo is None:
            raise ValueError(
                "last_seen must include timezone information."
            )

        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen cannot be earlier than first_seen."
            )

        normalized_value = normalize_indicator_value(
            normalized_type,
            self.value,
        )

        normalized_tags = tuple(
            dict.fromkeys(
                tag.strip().lower()
                for tag in self.tags
                if tag.strip()
            )
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
        object.__setattr__(
            self,
            "tags",
            normalized_tags,
        )