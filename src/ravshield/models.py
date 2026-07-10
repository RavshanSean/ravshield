from dataclasses import dataclass, field
from typing import Any

from ravshield.enums import Severity


@dataclass(slots=True)
class DetectionFinding:
    code: str
    title: str
    description: str
    severity: Severity
    confidence: int
    evidence: dict[str, Any] = field(default_factory=dict)