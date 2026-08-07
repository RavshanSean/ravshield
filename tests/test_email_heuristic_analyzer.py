from ravshield.analyzers import EmailHeuristicAnalyzer
from ravshield.enums import Severity


def test_clean_email_returns_no_findings():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "sean@example.com"
    )

    assert findings == []


def test_disposable_email_returns_finding():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "user@mailinator.com"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "EMAIL_DISPOSABLE_PROVIDER" in codes

    finding = next(
        finding
        for finding in findings
        if finding.code == "EMAIL_DISPOSABLE_PROVIDER"
    )

    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 85
    assert finding.evidence["provider"] == "mailinator.com"


def test_suspicious_keywords_return_finding():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "billing-security@example.com"
    )

    finding = next(
        finding
        for finding in findings
        if finding.code == "EMAIL_SUSPICIOUS_LOCAL_KEYWORDS"
    )

    assert finding.severity == Severity.MEDIUM
    assert "billing" in finding.evidence["matched_keywords"]
    assert "security" in finding.evidence["matched_keywords"]


def test_numeric_heavy_email_returns_finding():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "12345678ab@example.com"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "EMAIL_NUMERIC_HEAVY_LOCAL_PART" in codes


def test_punycode_email_domain_returns_high_finding():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "user@xn--example-9d0b.com"
    )

    finding = next(
        finding
        for finding in findings
        if finding.code == "EMAIL_PUNYCODE_DOMAIN"
    )

    assert finding.severity == Severity.HIGH
    assert finding.confidence == 90


def test_multiple_signals_produce_multiple_findings():
    analyzer = EmailHeuristicAnalyzer()

    findings = analyzer.analyze(
        "billing123456789012@mailinator.com"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "EMAIL_DISPOSABLE_PROVIDER" in codes
    assert "EMAIL_SUSPICIOUS_LOCAL_KEYWORDS" in codes
    assert "EMAIL_NUMERIC_HEAVY_LOCAL_PART" in codes

    assert len(findings) >= 3
    