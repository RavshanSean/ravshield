from ravshield.analyzers import URLHeuristicAnalyzer
from ravshield.models import Severity


def test_clean_url_returns_no_findings():
    analyzer = URLHeuristicAnalyzer()

    findings = analyzer.analyze(
        "https://example.com"
    )

    assert findings == []


def test_keyword_detection():
    analyzer = URLHeuristicAnalyzer()

    findings = analyzer.analyze(
        "https://example.com/login"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "URL_SUSPICIOUS_KEYWORDS"
    assert finding.severity == Severity.MEDIUM


def test_multiple_findings():
    analyzer = URLHeuristicAnalyzer()

    findings = analyzer.analyze(
        "https://user:pass@login.verify.account.example.com/%76erify"
    )

    assert len(findings) >= 4

    codes = {f.code for f in findings}

    assert "URL_EMBEDDED_CREDENTIALS" in codes
    assert "URL_SUSPICIOUS_KEYWORDS" in codes
    assert "URL_EXCESSIVE_SUBDOMAINS" in codes
    assert "URL_ENCODED_CHARACTERS" in codes