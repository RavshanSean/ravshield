from ravshield.enums import Severity
from ravshield.models import DetectionFinding
from ravshield.scoring import clamp_score, severity_from_score


SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


def correlate_findings(
    findings: list[DetectionFinding],
) -> tuple[int, Severity]:
    risk_score = 0
    seen_codes: set[str] = set()

    for finding in findings:
        if finding.code in seen_codes:
            continue

        seen_codes.add(finding.code)
        risk_score += SEVERITY_WEIGHTS[finding.severity]

    risk_score = clamp_score(risk_score)
    severity = severity_from_score(risk_score)

    return risk_score, severity