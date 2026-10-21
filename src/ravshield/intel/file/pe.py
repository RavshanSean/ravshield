from __future__ import annotations

from ravshield.intel.file.pe_models import (
    PEHeader,
    PESection,
    PEDataDirectory,
    PEImportDescriptor,
)

from ravshield.intel.file.pe_sections import (
    parse_pe_sections,
    has_writable_executable_section,
    find_suspicious_section_names,
    calculate_entropy,
    calculate_section_entropies,
    find_high_entropy_sections,
)

import math

from ravshield.intel.file.pe_imports import (
    get_import_directory,
    rva_to_file_offset,
    parse_import_descriptors,
    read_pe_string,
    get_imported_dll_names,
    get_import_thunk_rvas,
    get_imported_api_names,
    analyze_pe_imports,
)

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PE_DOS_SIGNATURE = b"MZ"

PE_SIGNATURE = b"PE\x00\x00"
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
HIGH_ENTROPY_THRESHOLD = 7.5
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B
IMPORT_DIRECTORY_INDEX = 1
DATA_DIRECTORY_SIZE = 8

PE32_DATA_DIRECTORY_OFFSET = 96
PE32_PLUS_DATA_DIRECTORY_OFFSET = 112

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
    
def get_optional_header_magic(
    file_path: str | Path,
) -> int:
    """
    Read the magic value from a PE Optional Header.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    file_size = path.stat().st_size
    header = parse_pe_header(path)

    if header.size_of_optional_header < 2:
        raise ValueError("Missing PE Optional Header.")

    with path.open("rb") as file:
        file.seek(0x3C)
        offset_bytes = file.read(4)

        if len(offset_bytes) != 4:
            raise ValueError("Invalid PE file.")

        pe_offset = int.from_bytes(
            offset_bytes,
            byteorder="little",
        )

        optional_header_offset = (
            pe_offset
            + 4
            + COFF_HEADER_SIZE
        )

        if (
            optional_header_offset > file_size
            or 2 > file_size - optional_header_offset
        ):
            raise ValueError(
                "Truncated PE Optional Header."
            )

        file.seek(optional_header_offset)
        magic_bytes = file.read(2)

    if len(magic_bytes) != 2:
        raise ValueError(
            "Truncated PE Optional Header."
        )

    magic = int.from_bytes(
        magic_bytes,
        byteorder="little",
    )

    if magic not in {
        PE32_MAGIC,
        PE32_PLUS_MAGIC,
    }:
        raise ValueError(
            "Unsupported PE Optional Header magic."
        )

    return magic

def analyze_pe(
    file_path: str | Path,
) -> dict:
    """
    Analyze a Windows PE file.

    Return PE format, headers, sections, entropy,
    and imported DLL/API information.
    """

    file_path = Path(file_path).expanduser()

    magic = get_optional_header_magic(file_path)

    if magic == 0x10B:
        pe_format = "PE32"
    elif magic == 0x20B:
        pe_format = "PE32+"
    else:
        raise ValueError("Unsupported PE optional header magic.")

    imports = analyze_pe_imports(file_path)
    header = parse_pe_header(file_path)
    sections = parse_pe_sections(file_path)
    entropies = calculate_section_entropies(file_path)

    section_results = []

    for section in sections:
        section_results.append({
            "name": section.name,
            "virtual_size": section.virtual_size,
            "virtual_address": section.virtual_address,
            "raw_data_size": section.raw_data_size,
            "raw_data_pointer": section.raw_data_pointer,
            "characteristics": section.characteristics,
            "entropy": entropies[section.name],
        })

    return {
        "format": pe_format,
        "header": {
            "machine": header.machine,
            "number_of_sections": header.number_of_sections,
            "timestamp": header.timestamp,
            "size_of_optional_header": header.size_of_optional_header,
            "characteristics": header.characteristics,
        },
        "sections": section_results,
        "imports": imports,
    }
