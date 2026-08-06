import pytest

from ravshield.intel.email import (
    normalize_email,
    validate_email,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "Sean@Example.COM",
            "sean@example.com",
        ),
        (
            "  user@example.com  ",
            "user@example.com",
        ),
        (
            "FIRST.LAST@SUB.EXAMPLE.ORG",
            "first.last@sub.example.org",
        ),
    ],
)
def test_normalize_email(value, expected):
    assert normalize_email(value) == expected


def test_normalize_email_rejects_non_string():
    with pytest.raises(TypeError):
        normalize_email(None)


def test_normalize_email_rejects_empty_value():
    with pytest.raises(ValueError):
        normalize_email("   ")


@pytest.mark.parametrize(
    "email",
    [
        "user@example.com",
        "first.last@example.com",
        "user+tag@example.co.uk",
        "security_team@sub.example.org",
        "123@example.net",
    ],
)
def test_validate_email_accepts_valid_addresses(email):
    assert validate_email(email) is True


@pytest.mark.parametrize(
    "email",
    [
        "",
        " ",
        "user",
        "user@",
        "@example.com",
        "user@example",
        "user@@example.com",
        ".user@example.com",
        "user.@example.com",
        "user..name@example.com",
        "user@-example.com",
        "user@example-.com",
        "user@example..com",
        "user name@example.com",
    ],
)
def test_validate_email_rejects_invalid_addresses(email):
    assert validate_email(email) is False


def test_validate_email_rejects_non_string():
    assert validate_email(None) is False


def test_validate_email_rejects_long_local_part():
    local_part = "a" * 65

    assert validate_email(
        f"{local_part}@example.com"
    ) is False


def test_validate_email_rejects_overall_length():
    local_part = "a" * 64
    domain = ("b" * 60 + ".") * 4 + "com"

    assert validate_email(
        f"{local_part}@{domain}"
    ) is False