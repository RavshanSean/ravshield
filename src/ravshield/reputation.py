from ravshield.enums import Verdict


KNOWN_BAD_HASHES: set[str] = set()
KNOWN_CLEAN_HASHES: set[str] = set()


def get_hash_reputation(hash_value: str) -> Verdict:
    if hash_value in KNOWN_BAD_HASHES:
        return Verdict.MALICIOUS

    if hash_value in KNOWN_CLEAN_HASHES:
        return Verdict.SAFE

    return Verdict.UNKNOWN