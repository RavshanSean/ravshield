from ravshield.engines import MultiSignalVerdictEngine
from ravshield.enums import Severity, Verdict
from ravshield.models import DetectionFinding


def make_finding(
    *,
    code: str,
    severity: Severity,
    confidence: int = 80,
    evidence: dict | None = None,
) -> DetectionFinding:
    return DetectionFinding(
        code=code,
        title=code.replace("_", " ").title(),
        description=f"Test finding for {code}.",
        severity=severity,
        confidence=confidence,
        evidence=evidence or {},
    )


def test_empty_findings_return_unknown() -> None:
    engine = MultiSignalVerdictEngine()

    result = engine.analyze([])

    assert result.verdict is Verdict.UNKNOWN
    assert result.severity is Severity.INFO
    assert result.risk_score == 0
    assert result.confidence == 20
    assert result.findings == []
    assert result.evidence == []


def test_safe_reputation_returns_safe() -> None:
    engine = MultiSignalVerdictEngine()

    finding = make_finding(
        code="reputation_safe",
        severity=Severity.INFO,
        evidence={"source": "trusted-feed"},
    )

    result = engine.analyze([finding])

    assert result.verdict is Verdict.SAFE
    assert result.severity is Severity.INFO
    assert result.risk_score == 0


def test_ioc_match_returns_malicious() -> None:
    engine = MultiSignalVerdictEngine()

    finding = make_finding(
        code="ioc_match",
        severity=Severity.HIGH,
        evidence={"value": "malicious.example"},
    )

    result = engine.analyze([finding])

    assert result.verdict is Verdict.MALICIOUS
    assert result.severity is Severity.MEDIUM
    assert result.risk_score == 45
    assert result.confidence == 50


def test_malicious_reputation_returns_malicious() -> None:
    engine = MultiSignalVerdictEngine()

    finding = make_finding(
        code="reputation_malicious",
        severity=Severity.CRITICAL,
    )

    result = engine.analyze([finding])

    assert result.verdict is Verdict.MALICIOUS
    assert result.risk_score == 70
    assert result.severity is Severity.HIGH


def test_medium_signal_returns_suspicious() -> None:
    engine = MultiSignalVerdictEngine()

    finding = make_finding(
        code="behavior_anomaly",
        severity=Severity.MEDIUM,
    )

    result = engine.analyze([finding])

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.risk_score == 25
    assert result.severity is Severity.LOW


def test_multiple_findings_are_correlated() -> None:
    engine = MultiSignalVerdictEngine()

    findings = [
        make_finding(
            code="behavior_anomaly",
            severity=Severity.MEDIUM,
        ),
        make_finding(
            code="suspicious_redirect",
            severity=Severity.HIGH,
        ),
    ]

    result = engine.analyze(
        findings,
        analysis_modules=[
            "behavior",
            "redirects",
        ],
    )

    assert result.verdict is Verdict.MALICIOUS
    assert result.risk_score == 70
    assert result.severity is Severity.HIGH
    assert result.analysis_modules == [
        "behavior",
        "redirects",
    ]


def test_duplicate_finding_codes_do_not_increase_risk_twice() -> None:
    engine = MultiSignalVerdictEngine()

    findings = [
        make_finding(
            code="duplicate_signal",
            severity=Severity.HIGH,
        ),
        make_finding(
            code="duplicate_signal",
            severity=Severity.HIGH,
        ),
    ]

    result = engine.analyze(findings)

    assert result.risk_score == 45
    assert result.severity is Severity.MEDIUM


def test_safe_and_threat_signals_reduce_confidence() -> None:
    engine = MultiSignalVerdictEngine()

    findings = [
        make_finding(
            code="reputation_safe",
            severity=Severity.INFO,
        ),
        make_finding(
            code="behavior_anomaly",
            severity=Severity.MEDIUM,
        ),
    ]

    result = engine.analyze(findings)

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.confidence == 25


def test_evidence_is_converted_to_structured_objects() -> None:
    engine = MultiSignalVerdictEngine()

    finding = make_finding(
        code="ioc_match",
        severity=Severity.HIGH,
        evidence={
            "source": "community-feed",
            "value": "example.test",
        },
    )

    result = engine.analyze([finding])

    assert len(result.evidence) == 2
    assert result.evidence[0].source == "ioc_match"
    assert {
        evidence.key
        for evidence in result.evidence
    } == {
        "source",
        "value",
    }


def test_analysis_modules_are_deduplicated() -> None:
    engine = MultiSignalVerdictEngine()

    result = engine.analyze(
        [],
        analysis_modules=[
            "ioc",
            "reputation",
            "ioc",
        ],
    )

    assert result.analysis_modules == [
        "ioc",
        "reputation",
    ]


def test_result_contains_recommended_action() -> None:
    engine = MultiSignalVerdictEngine()

    result = engine.analyze([])

    assert result.recommended_action is not None
    assert "additional intelligence" in result.recommended_action.lower()