import pytest

from ravshield.intel.domain import (
    normalize_domain,
    validate_domain,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM", "example.com"),
        (" example.com ", "example.com"),
        ("example.com.", "example.com"),
        (
            "https://Example.COM/login",
            "example.com",
        ),
        (
            "http://Sub.Example.COM:8080/path",
            "sub.example.com",
        ),
    ],
)
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.example.com",
        "example-security.io",
        "xn--example-9d0b.com",
        "https://example.com/login",
    ],
)
def test_validate_domain_accepts_valid_domains(domain):
    assert validate_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "",
        " ",
        "localhost",
        "127.0.0.1",
        "::1",
        "example",
        ".example.com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.c",
        "exa_mple.com",
    ],
)
def test_validate_domain_rejects_invalid_domains(domain):
    assert validate_domain(domain) is False


def test_validate_domain_rejects_non_string():
    assert validate_domain(None) is False