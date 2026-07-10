from ravshield.enums import Severity, Verdict
from ravshield.explain import explain_result
from ravshield.models import AnalysisResult, DetectionFinding


def test_explain_result():
    result = AnalysisResult(
        verdict=Verdict.SUSPICIOUS,
        severity=Severity.MEDIUM,
        risk_score=60,
        confidence=80,
        findings=[
            DetectionFinding(
                code="high_entropy",
                title="High entropy",
                description="The file may be packed or encrypted.",
                severity=Severity.MEDIUM,
                confidence=75,
            )
        ],
        recommended_action="Review the file before opening.",
        analysis_modules=["heuristic_engine"],
    )

    explanation = explain_result(result)

    assert explanation["risk_score"] == 60
    assert explanation["confidence"] == 80
    assert explanation["recommended_action"] == (
        "Review the file before opening."
    )
    assert explanation["reasons"] == [
        "The file may be packed or encrypted."
    ]
    assert "suspicious" in explanation["summary"]