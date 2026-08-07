from ravshield.intel.ip import classify_ip


def test_public_ipv4_classification():
    result = classify_ip("8.8.8.8")

    assert result.ip == "8.8.8.8"
    assert result.version == 4
    assert result.is_global is True
    assert result.is_private is False
    assert result.is_loopback is False


def test_private_ipv4_classification():
    result = classify_ip("192.168.1.10")

    assert result.version == 4
    assert result.is_private is True
    assert result.is_global is False


def test_loopback_ipv4_classification():
    result = classify_ip("127.0.0.1")

    assert result.is_loopback is True
    assert result.is_global is False


def test_link_local_ipv4_classification():
    result = classify_ip("169.254.10.20")

    assert result.is_link_local is True
    assert result.is_global is False


def test_multicast_ipv4_classification():
    result = classify_ip("224.0.0.1")

    assert result.is_multicast is True
    assert result.is_global is True


def test_reserved_ipv4_classification():
    result = classify_ip("240.0.0.1")

    assert result.is_reserved is True
    assert result.is_global is False


def test_ipv6_loopback_classification():
    result = classify_ip("::1")

    assert result.version == 6
    assert result.is_loopback is True
    assert result.is_global is False


def test_ipv6_normalization_is_preserved():
    result = classify_ip(
        "2001:0db8:0000:0000:0000:ff00:0042:8329"
    )

    assert result.ip == "2001:db8::ff00:42:8329"
    assert result.version == 6