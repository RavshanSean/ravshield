from ravshield.intel.ip import analyze_ip_heuristics


def test_public_ip_has_no_special_scope_signals():
    result = analyze_ip_heuristics(
        "8.8.8.8"
    )

    assert result.ip == "8.8.8.8"
    assert result.signals == set()
    assert result.suspicious is False
    assert result.details["version"] == 4
    assert result.details["is_global"] is True


def test_loopback_ip_is_detected():
    result = analyze_ip_heuristics(
        "127.0.0.1"
    )

    assert "loopback" in result.signals
    assert "private_address" in result.signals
    assert result.suspicious is True


def test_private_ip_is_detected():
    result = analyze_ip_heuristics(
        "192.168.1.10"
    )

    assert "private_address" in result.signals
    assert result.details["is_global"] is False


def test_link_local_ip_is_detected():
    result = analyze_ip_heuristics(
        "169.254.10.20"
    )

    assert "link_local" in result.signals
    assert "private_address" in result.signals


def test_multicast_ip_is_detected():
    result = analyze_ip_heuristics(
        "224.0.0.1"
    )

    assert "multicast" in result.signals


def test_reserved_ip_is_detected():
    result = analyze_ip_heuristics(
        "240.0.0.1"
    )

    assert "reserved" in result.signals


def test_ipv6_loopback_is_detected():
    result = analyze_ip_heuristics(
        "::1"
    )

    assert result.details["version"] == 6
    assert "loopback" in result.signals
    assert "private_address" in result.signals


def test_multiple_special_scope_signals_can_exist():
    result = analyze_ip_heuristics(
        "127.0.0.1"
    )

    assert len(result.signals) >= 2