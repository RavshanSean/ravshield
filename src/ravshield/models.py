from dataclasses import dataclass, field
from typing import Any
from ravshield.enums import Severity, Verdict
from ravshield.enums import Severity

@dataclass(slots=True)
class DetectionFinding:
    code: str
    title: str
    description: str
    severity: Severity
    confidence: int
    evidence: dict[str, Any] = field(default_factory=dict)
    
@dataclass(slots=True)
class Evidence:
    source: str
    key: str
    value: Any
    description: str | None = None
    
@dataclass(slots=True)
class AnalysisResult:
    verdict: Verdict
    severity: Severity
    risk_score: int
    confidence: int
    findings: list[DetectionFinding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    recommended_action: str | None = None
    engine_version: str = "0.1.0"
    analysis_modules: list[str] = field(default_factory=list)