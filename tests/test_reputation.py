from ravshield.enums import Verdict
from ravshield.reputation import (
    KNOWN_BAD_HASHES,
    KNOWN_CLEAN_HASHES,
    get_hash_reputation,
)


def test_known_bad_hash_reputation():
    test_hash = "bad123"
    KNOWN_BAD_HASHES.add(test_hash)

    assert get_hash_reputation(test_hash) is Verdict.MALICIOUS

    KNOWN_BAD_HASHES.remove(test_hash)


def test_known_clean_hash_reputation():
    test_hash = "clean123"
    KNOWN_CLEAN_HASHES.add(test_hash)

    assert get_hash_reputation(test_hash) is Verdict.SAFE

    KNOWN_CLEAN_HASHES.remove(test_hash)


def test_unknown_hash_reputation():
    assert get_hash_reputation("unknown123") is Verdict.UNKNOWN