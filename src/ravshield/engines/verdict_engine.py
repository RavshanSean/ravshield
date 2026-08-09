"""
Multi-Signal Verdict Engine.

This module combines findings produced by different RavShield
intelligence modules and converts them into one final AnalysisResult.
"""

from ravshield.engines.correlation_engine import correlate_findings
from ravshield.enums import Severity, Verdict
from ravshield.models import AnalysisResult, DetectionFinding, Evidence
from ravshield.scoring import calculate_confidence


# Finding codes that represent confirmed malicious intelligence.
# Heuristic / behavioral codes must NEVER appear here.
STRONG_SIGNAL_CODES = {
    "ioc_match",
    "reputation_malicious",
    "URL_REPUTATION_MALICIOUS",
    "DOMAIN_REPUTATION_MALICIOUS",
    "EMAIL_REPUTATION_MALICIOUS",
    "IP_REPUTATION_MALICIOUS",
    "HASH_REPUTATION_MALICIOUS",
    "FILE_HASH_IOC_MATCH",
    "ENRICHMENT_MALICIOUS_TAG",
}

# Finding codes that explicitly describe a trusted or safe indicator.
SAFE_SIGNAL_CODES = {
    "reputation_safe",
    "URL_REPUTATION_KNOWN",
    "DOMAIN_REPUTATION_KNOWN",
    "EMAIL_REPUTATION_KNOWN",
    "IP_REPUTATION_KNOWN",
    "HASH_REPUTATION_CLEAN",
}


def is_strong_malicious_code(code: str) -> bool:
    return code in STRONG_SIGNAL_CODES


def is_safe_signal_code(code: str) -> bool:
    return code in SAFE_SIGNAL_CODES


def verdict_from_signals(
    findings: list[DetectionFinding],
    risk_score: int,
) -> Verdict:
    """
    Determine the final verdict from correlated findings.

    Rules:

    1. No findings means RavShield does not have enough evidence.
    2. Confirmed malicious intelligence (IOC / reputation) → MALICIOUS.
    3. Heuristics and behavioral signals alone never escalate past
       SUSPICIOUS, even when the stacked risk score is high.
    4. An explicit trusted signal with no threat signals → SAFE.
    5. Otherwise the result remains UNKNOWN.
    """

    if not findings:
        return Verdict.UNKNOWN

    finding_codes = {
        finding.code
        for finding in findings
    }

    has_strong_malicious_signal = any(
        is_strong_malicious_code(code)
        for code in finding_codes
    )

    has_safe_signal = any(
        is_safe_signal_code(code)
        for code in finding_codes
    )

    has_threat_signal = any(
        finding.severity
        in {
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        }
        for finding in findings
        if not is_safe_signal_code(finding.code)
    )

    if has_strong_malicious_signal:
        return Verdict.MALICIOUS

    if has_threat_signal or risk_score > 0:
        return Verdict.SUSPICIOUS

    if has_safe_signal and not has_threat_signal:
        return Verdict.SAFE

    return Verdict.UNKNOWN


def recommended_action_from_verdict(
    verdict: Verdict,
) -> str:
    """
    Return a human-readable recommendation for the final verdict.
    """

    recommendations = {
        Verdict.MALICIOUS: (
            "Block or quarantine the indicator and begin "
            "incident-response investigation."
        ),
        Verdict.SUSPICIOUS: (
            "Investigate the indicator further before allowing "
            "or trusting it. Heuristic signals alone are not "
            "sufficient for an automatic block."
        ),
        Verdict.SAFE: (
            "No immediate threat response is required, but normal "
            "security monitoring should continue."
        ),
        Verdict.UNKNOWN: (
            "Not enough evidence is available. Collect additional "
            "intelligence before making a security decision."
        ),
    }

    return recommendations[verdict]


def build_evidence(
    findings: list[DetectionFinding],
) -> list[Evidence]:
    """
    Convert finding evidence dictionaries into Evidence objects.

    Each key-value pair stored inside a finding becomes one structured
    Evidence item in the final AnalysisResult.
    """

    evidence_items: list[Evidence] = []

    for finding in findings:
        for key, value in finding.evidence.items():
            evidence_items.append(
                Evidence(
                    source=finding.code,
                    key=key,
                    value=value,
                    description=(
                        f"Evidence collected from: {finding.title}"
                    ),
                )
            )

    return evidence_items


class MultiSignalVerdictEngine:
    """
    Combine findings from several RavShield modules.

    The engine does not perform IOC lookup or reputation lookup itself.
    Those modules produce DetectionFinding objects first.

    This engine receives those findings and makes the final decision.
    """

    VERSION = "0.2.0"

    def analyze(
        self,
        findings: list[DetectionFinding],
        *,
        analysis_modules: list[str] | None = None,
    ) -> AnalysisResult:
        """
        Produce one final AnalysisResult from multiple findings.

        Args:
            findings:
                Findings returned by IOC matching, threat intelligence,
                history analysis, malware intelligence, or future
                RavShield modules.

            analysis_modules:
                Names of modules that participated in the analysis.

        Returns:
            A complete AnalysisResult containing verdict, severity,
            risk score, confidence, findings, and evidence.
        """

        modules = list(
            dict.fromkeys(analysis_modules or [])
        )

        # Combine all unique findings into a risk score and severity.
        risk_score, severity = correlate_findings(findings)

        finding_codes = {
            finding.code
            for finding in findings
        }

        strong_signal_count = sum(
            is_strong_malicious_code(finding.code)
            or finding.severity
            in {
                Severity.HIGH,
                Severity.CRITICAL,
            }
            for finding in findings
        )

        has_safe_signal = any(
            is_safe_signal_code(code)
            for code in finding_codes
        )

        has_threat_signal = any(
            not is_safe_signal_code(finding.code)
            and finding.severity != Severity.INFO
            for finding in findings
        )

        contradictory_signal_count = int(
            has_safe_signal and has_threat_signal
        )

        confidence = calculate_confidence(
            evidence_count=len(findings),
            strong_signal_count=strong_signal_count,
            contradictory_signal_count=(
                contradictory_signal_count
            ),
        )

        verdict = verdict_from_signals(
            findings=findings,
            risk_score=risk_score,
        )

        evidence = build_evidence(findings)

        return AnalysisResult(
            verdict=verdict,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            findings=list(findings),
            evidence=evidence,
            recommended_action=(
                recommended_action_from_verdict(verdict)
            ),
            engine_version=self.VERSION,
            analysis_modules=modules,
        )
