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


def read_pe_string(
    file_path: str | Path,
    rva: int,
    max_length: int = 256,
) -> str:
    """
    Read a null-terminated ASCII string from a PE RVA.
    """

    if not isinstance(max_length, int) or isinstance(max_length, bool):
        raise ValueError("max_length must be a positive integer.")

    if max_length <= 0 or max_length > 4096:
        raise ValueError("max_length must be between 1 and 4096.")

    file_path = Path(file_path).expanduser()
    file_size = file_path.stat().st_size

    offset = rva_to_file_offset(file_path, rva)

    sections = parse_pe_sections(file_path)

    matching_section = next(
        (
            section
            for section in sections
            if section.virtual_address <= rva
            < section.virtual_address + section.raw_data_size
        ),
        None,
    )

    if matching_section is None:
        raise ValueError("String RVA is not mapped to a section.")

    section_end = (
        matching_section.raw_data_pointer
        + matching_section.raw_data_size
    )

    available_bytes = min(
        max_length,
        section_end - offset,
        file_size - offset,
    )

    with file_path.open("rb") as file:
        file.seek(offset)
        data = file.read(available_bytes)

    null_position = data.find(b"\x00")

    if null_position == -1:
        raise ValueError("PE string is not null-terminated.")

    try:
        return data[:null_position].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("PE string contains non-ASCII bytes.") from exc


def get_imported_dll_names(
    file_path: str | Path,
) -> list[str]:
    """
    Extract imported DLL names from a PE file.
    """

    descriptors = parse_import_descriptors(file_path)
    dll_names = []

    for descriptor in descriptors:
        if descriptor.name_rva == 0:
            raise ValueError("Import descriptor has no DLL name RVA.")

        dll_name = read_pe_string(
            file_path,
            descriptor.name_rva,
        )

        if not dll_name:
            raise ValueError("Import descriptor has an empty DLL name.")

        dll_names.append(dll_name)

    return dll_names


def get_import_thunk_rvas(
    file_path: str | Path,
    descriptor: PEImportDescriptor,
    max_imports: int = 4096,
) -> list[int]:
    """
    Read import thunk values from a PE file.
    """

    if (
        not isinstance(max_imports, int)
        or isinstance(max_imports, bool)
        or not 1 <= max_imports <= 4096
    ):
        raise ValueError("max_imports must be between 1 and 4096.")

    magic = get_optional_header_magic(file_path)

    if magic == 0x10B:
        entry_size = 4
    elif magic == 0x20B:
        entry_size = 8
    else:
        raise ValueError("Unsupported PE optional header magic.")

    thunk_rva = (
        descriptor.original_first_thunk
        or descriptor.first_thunk
    )

    if thunk_rva == 0:
        return []

    file_path = Path(file_path).expanduser()
    file_size = file_path.stat().st_size
    sections = parse_pe_sections(file_path)

    matching_section = next(
        (
            section
            for section in sections
            if section.virtual_address <= thunk_rva
            < section.virtual_address + section.raw_data_size
        ),
        None,
    )

    if matching_section is None:
        raise ValueError("Import thunk RVA is not mapped.")

    offset = rva_to_file_offset(file_path, thunk_rva)

    section_end = min(
        matching_section.raw_data_pointer
        + matching_section.raw_data_size,
        file_size,
    )

    values = []
    found_terminator = False

    with file_path.open("rb") as file:
        for index in range(max_imports):
            entry_offset = offset + index * entry_size

            if entry_offset + entry_size > section_end:
                raise ValueError("Import thunk exceeds section bounds.")

            file.seek(entry_offset)
            data = file.read(entry_size)

            if len(data) != entry_size:
                raise ValueError("Truncated import thunk.")

            value = int.from_bytes(data, "little")

            if value == 0:
                found_terminator = True
                break

            values.append(value)

    if not found_terminator:
        raise ValueError("Import thunk table has no null terminator.")

    return values


def get_imported_api_names(
    file_path: str | Path,
    descriptor: PEImportDescriptor,
) -> list[str]:
    """
    Extract imported API names from a PE import descriptor.

    Ordinal imports are represented as '#<ordinal>'.
    """

    magic = get_optional_header_magic(file_path)

    if magic == 0x10B:
        ordinal_flag = 0x80000000
        address_mask = 0x7FFFFFFF
    elif magic == 0x20B:
        ordinal_flag = 0x8000000000000000
        address_mask = 0x7FFFFFFFFFFFFFFF
    else:
        raise ValueError("Unsupported PE optional header magic.")

    thunk_values = get_import_thunk_rvas(
        file_path,
        descriptor,
    )

    api_names = []

    for value in thunk_values:
        # Import by ordinal.
        if value & ordinal_flag:
            if value & (address_mask & ~0xFFFF):
                raise ValueError("Invalid ordinal import.")

            ordinal = value & 0xFFFF

            if ordinal == 0:
                raise ValueError("Invalid ordinal import.")

            api_names.append(f"#{ordinal}")
            continue

        # Import by name.
        name_rva = value & address_mask

        if name_rva == 0:
            raise ValueError("Invalid API name RVA.")

        # IMAGE_IMPORT_BY_NAME starts with a 2-byte hint.
        # Validate that the hint and name fit in mapped raw data.
        file_offset = rva_to_file_offset(file_path, name_rva)
        next_offset = rva_to_file_offset(file_path, name_rva + 1)

        if next_offset != file_offset + 1:
            raise ValueError("Truncated API name hint.")

        api_name = read_pe_string(
            file_path,
            name_rva + 2,
        )

        if not api_name:
            raise ValueError("Empty imported API name.")

        api_names.append(api_name)

    return api_names


def analyze_pe_imports(
    file_path: str | Path,
) -> dict[str, list[str]]:
    """
    Analyze imported DLLs and their API functions.

    Return a dictionary mapping DLL names to API names.
    """

    descriptors = parse_import_descriptors(file_path)

    imported = {}

    for descriptor in descriptors:
        dll_name = read_pe_string(
            file_path,
            descriptor.name_rva,
        )

        if not dll_name:
            raise ValueError("Empty imported DLL name.")

        api_names = get_imported_api_names(
            file_path,
            descriptor,
        )

        # Preserve imports if a DLL appears multiple times.
        imported.setdefault(dll_name, []).extend(api_names)

    return imported


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
