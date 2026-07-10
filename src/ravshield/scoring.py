from ravshield.enums import Severity


def clamp_score(score: int) -> int:
    return max(0, min(score, 100))


def severity_from_score(score: int) -> Severity:
    normalized_score = clamp_score(score)

    if normalized_score >= 90:
        return Severity.CRITICAL

    if normalized_score >= 70:
        return Severity.HIGH

    if normalized_score >= 40:
        return Severity.MEDIUM

    if normalized_score >= 1:
        return Severity.LOW

    return Severity.INFO

def clamp_confidence(confidence: int) -> int:
    return max(0, min(confidence, 100))


def calculate_confidence(
    evidence_count: int,
    strong_signal_count: int = 0,
    contradictory_signal_count: int = 0,
) -> int:
    confidence = 20

    confidence += evidence_count * 10
    confidence += strong_signal_count * 20
    confidence -= contradictory_signal_count * 15

    return clamp_confidence(confidence)