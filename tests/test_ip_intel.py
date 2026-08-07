import pytest

from ravshield.intel.ip import (
    normalize_ip,
    validate_ip,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", "8.8.8.8"),
        (" 1.1.1.1 ", "1.1.1.1"),
        (
            "2001:0db8:0000:0000:0000:ff00:0042:8329",
            "2001:db8::ff00:42:8329",
        ),
        (
            "2001:db8::1",
            "2001:db8::1",
        ),
    ],
)
def test_normalize_ip(value, expected):
    assert normalize_ip(value) == expected


def test_normalize_ip_rejects_non_string():
    with pytest.raises(TypeError):
        normalize_ip(None)


def test_normalize_ip_rejects_empty_value():
    with pytest.raises(ValueError):
        normalize_ip("   ")


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "127.0.0.1",
        "192.168.1.1",
        "2001:db8::1",
        "::1",
    ],
)
def test_validate_ip_accepts_valid_addresses(value):
    assert validate_ip(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "999.999.999.999",
        "1.2.3",
        "example.com",
        "http://1.2.3.4",
        "2001:::1",
    ],
)
def test_validate_ip_rejects_invalid_addresses(value):
    assert validate_ip(value) is False


def test_validate_ip_rejects_non_string():
    assert validate_ip(None) is False