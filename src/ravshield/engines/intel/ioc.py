from dataclasses import dataclass

from ravshield.enums import Severity


@dataclass(slots=True, frozen=True)
class IOC:
    value: str
    indicator_type: str
    severity: Severity
    source: str
    confidence: int
    