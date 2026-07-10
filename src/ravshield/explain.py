from ravshield.models import AnalysisResult


def explain_result(result: AnalysisResult) -> dict[str, object]:
    return {
        "summary": (
            f"RavShield classified this item as "
            f"{result.verdict.value} with "
            f"{result.severity.value} severity."
        ),
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "reasons": [
            finding.description
            for finding in result.findings
        ],
        "recommended_action": result.recommended_action,
    }