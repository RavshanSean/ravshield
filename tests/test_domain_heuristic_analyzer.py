from ravshield.analyzers import DomainHeuristicAnalyzer
from ravshield.enums import Severity


def test_clean_domain_produces_no_findings():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze("example.com")

    assert findings == []


def test_punycode_domain_produces_high_finding():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze(
        "xn--example-9d0b.com"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "DOMAIN_PUNYCODE" in codes

    punycode_finding = next(
        finding
        for finding in findings
        if finding.code == "DOMAIN_PUNYCODE"
    )

    assert punycode_finding.severity == Severity.HIGH
    assert punycode_finding.confidence == 90


def test_suspicious_keywords_include_evidence():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze(
        "paypal-login-secure.com"
    )

    finding = next(
        finding
        for finding in findings
        if finding.code == "DOMAIN_SUSPICIOUS_KEYWORDS"
    )

    assert "keywords" in finding.evidence
    assert "paypal" in finding.evidence["keywords"]
    assert "login" in finding.evidence["keywords"]
    assert "secure" in finding.evidence["keywords"]


def test_suspicious_tld_includes_tld_evidence():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze("example.zip")

    finding = next(
        finding
        for finding in findings
        if finding.code == "DOMAIN_SUSPICIOUS_TLD"
    )

    assert finding.evidence["tld"] == "zip"


def test_multiple_domain_signals_produce_multiple_findings():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze(
        "xn--paypal-login-secure.zip"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "DOMAIN_PUNYCODE" in codes
    assert "DOMAIN_SUSPICIOUS_KEYWORDS" in codes
    assert "DOMAIN_SUSPICIOUS_TLD" in codes

    assert len(findings) >= 3


def test_high_entropy_domain_produces_finding():
    analyzer = DomainHeuristicAnalyzer()

    findings = analyzer.analyze(
        "q7m2x9v4k8p3z6n5r1t0.com"
    )

    codes = {
        finding.code
        for finding in findings
    }

    assert "DOMAIN_HIGH_ENTROPY" in codes