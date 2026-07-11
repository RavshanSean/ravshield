import hashlib
import re
from pathlib import Path


HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}


def calculate_sha256(file_path: str | Path) -> str:
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()


def validate_hash(hash_value: str, algorithm: str) -> bool:
    normalized_algorithm = algorithm.lower()

    expected_length = HASH_LENGTHS.get(normalized_algorithm)

    if expected_length is None:
        return False

    if len(hash_value) != expected_length:
        return False

    return bool(re.fullmatch(r"[0-9a-fA-F]+", hash_value))