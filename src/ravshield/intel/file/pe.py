from __future__ import annotations

from dataclasses import dataclass

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PE_DOS_SIGNATURE = b"MZ"

PE_SIGNATURE = b"PE\x00\x00"
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

SUSPICIOUS_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".packed",
    ".petite",
    ".vmp0",
    ".vmp1",
}


@dataclass(slots=True)
class PEHeader:
    machine: int
    number_of_sections: int
    timestamp: int
    size_of_optional_header: int
    characteristics: int
    
@dataclass(slots=True)
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_data_size: int
    raw_data_pointer: int
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
    
def parse_pe_sections(
    file_path: str | Path,
) -> list[PESection]:
    """
    Parse section headers from a PE file.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    file_size = path.stat().st_size
    header = parse_pe_header(path)

    with path.open("rb") as file:
        file.seek(0x3C)
        offset_bytes = file.read(4)

        if len(offset_bytes) != 4:
            raise ValueError("Invalid PE file.")

        pe_offset = int.from_bytes(
            offset_bytes,
            byteorder="little",
        )

        section_table_offset = (
            pe_offset
            + 4
            + COFF_HEADER_SIZE
            + header.size_of_optional_header
        )

        section_table_size = (
            header.number_of_sections
            * SECTION_HEADER_SIZE
        )

        if (
            section_table_offset > file_size
            or section_table_size
            > file_size - section_table_offset
        ):
            raise ValueError("Truncated PE section table.")

        file.seek(section_table_offset)

        sections: list[PESection] = []

        for _ in range(header.number_of_sections):
            section_header = file.read(
                SECTION_HEADER_SIZE,
            )

            if len(section_header) != SECTION_HEADER_SIZE:
                raise ValueError(
                    "Truncated PE section header."
                )

            raw_name = section_header[0:8]
            name = raw_name.split(
                b"\x00",
                1,
            )[0].decode(
                "ascii",
                errors="replace",
            )

            sections.append(
                PESection(
                    name=name,
                    virtual_size=int.from_bytes(
                        section_header[8:12],
                        byteorder="little",
                    ),
                    virtual_address=int.from_bytes(
                        section_header[12:16],
                        byteorder="little",
                    ),
                    raw_data_size=int.from_bytes(
                        section_header[16:20],
                        byteorder="little",
                    ),
                    raw_data_pointer=int.from_bytes(
                        section_header[20:24],
                        byteorder="little",
                    ),
                    characteristics=int.from_bytes(
                        section_header[36:40],
                        byteorder="little",
                    ),
                )
            )

    return sections

def has_writable_executable_section(
    file_path: str | Path,
) -> bool:
    """
    Return True when any PE section is both writable and executable.
    """

    sections = parse_pe_sections(file_path)

    for section in sections:
        is_executable = bool(
            section.characteristics
            & IMAGE_SCN_MEM_EXECUTE
        )
        is_writable = bool(
            section.characteristics
            & IMAGE_SCN_MEM_WRITE
        )

        if is_executable and is_writable:
            return True

    return False

def find_suspicious_section_names(
    file_path: str | Path,
) -> list[str]:
    """
    Return PE section names associated with common packers
    or executable protectors.
    """

    sections = parse_pe_sections(file_path)

    matches: list[str] = []

    for section in sections:
        normalized_name = section.name.lower()

        if normalized_name in SUSPICIOUS_SECTION_NAMES:
            matches.append(section.name)

    return matches