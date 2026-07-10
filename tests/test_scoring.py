from ravshield.enums import Severity
from ravshield.scoring import clamp_score, severity_from_score
from ravshield.scoring import (
    calculate_confidence,
    clamp_confidence,
    clamp_score,
    severity_from_score,
)

def test_clamp_confidence():
    assert clamp_confidence(-5) == 0
    assert clamp_confidence(60) == 60
    assert clamp_confidence(140) == 100


def test_calculate_confidence():
    assert calculate_confidence(evidence_count=0) == 20
    assert calculate_confidence(evidence_count=3) == 50
    assert calculate_confidence(
        evidence_count=3,
        strong_signal_count=2,
    ) == 90
    assert calculate_confidence(
        evidence_count=3,
        strong_signal_count=2,
        contradictory_signal_count=2,
    ) == 60


def test_clamp_score():
    assert clamp_score(-10) == 0
    assert clamp_score(50) == 50
    assert clamp_score(150) == 100


def test_severity_from_score():
    assert severity_from_score(0) is Severity.INFO
    assert severity_from_score(1) is Severity.LOW
    assert severity_from_score(40) is Severity.MEDIUM
    assert severity_from_score(70) is Severity.HIGH
    assert severity_from_score(90) is Severity.CRITICAL