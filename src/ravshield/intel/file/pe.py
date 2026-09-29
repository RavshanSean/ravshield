from __future__ import annotations

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PE_DOS_SIGNATURE = b"MZ"


def has_pe_signature(
    file_path: str | Path,
) -> bool:
    """
    Check whether a file begins with the DOS MZ signature
    used by Windows PE executables.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        signature = file.read(2)

    return signature == PE_DOS_SIGNATURE


def has_valid_pe_header(
    file_path: str | Path,
) -> bool:
    """
    Check whether a file contains a valid PE signature
    at the offset specified by the DOS header.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        if file.read(2) != PE_DOS_SIGNATURE:
            return False

        file.seek(0x3C)
        offset_bytes = file.read(4)

        if len(offset_bytes) != 4:
            return False

        pe_offset = int.from_bytes(
            offset_bytes,
            byteorder="little",
        )

        file.seek(pe_offset)
        pe_signature = file.read(4)

    return pe_signature == b"PE\x00\x00"