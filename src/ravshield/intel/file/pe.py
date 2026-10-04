from __future__ import annotations

from dataclasses import dataclass

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PE_DOS_SIGNATURE = b"MZ"

PE_SIGNATURE = b"PE\x00\x00"
COFF_HEADER_SIZE = 20


@dataclass(slots=True)
class PEHeader:
    machine: int
    number_of_sections: int
    timestamp: int
    size_of_optional_header: int
    characteristics: int


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

    return pe_signature == PE_SIGNATURE

def parse_pe_header(
    file_path: str | Path,
) -> PEHeader:
    """
    Parse basic information from a PE COFF file header.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        if file.read(2) != PE_DOS_SIGNATURE:
            raise ValueError("Invalid PE file.")

        file.seek(0x3C)
        offset_bytes = file.read(4)

        if len(offset_bytes) != 4:
            raise ValueError("Invalid PE file.")

        pe_offset = int.from_bytes(
            offset_bytes,
            byteorder="little",
        )

        file.seek(pe_offset)

        if file.read(4) != PE_SIGNATURE:
            raise ValueError("Invalid PE file.")

        coff_header = file.read(COFF_HEADER_SIZE)

        if len(coff_header) != COFF_HEADER_SIZE:
            raise ValueError("Truncated PE COFF header.")

    return PEHeader(
        machine=int.from_bytes(
            coff_header[0:2],
            byteorder="little",
        ),
        number_of_sections=int.from_bytes(
            coff_header[2:4],
            byteorder="little",
        ),
        timestamp=int.from_bytes(
            coff_header[4:8],
            byteorder="little",
        ),
        size_of_optional_header=int.from_bytes(
            coff_header[16:18],
            byteorder="little",
        ),
        characteristics=int.from_bytes(
            coff_header[18:20],
            byteorder="little",
        ),
    )