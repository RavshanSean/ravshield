from __future__ import annotations

from dataclasses import dataclass

import math

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
    
@dataclass(slots=True)
class PEDataDirectory:
    rva: int
    size: int
    
@dataclass(frozen=True)
class PEImportDescriptor:
    original_first_thunk: int
    time_date_stamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int


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

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy for a sequence of bytes.
    """

    if not data:
        return 0.0

    entropy = 0.0
    data_length = len(data)

    for byte_value in set(data):
        frequency = data.count(byte_value)
        probability = frequency / data_length

        entropy -= probability * math.log2(
            probability
        )

    return entropy

def calculate_section_entropies(
    file_path: str | Path,
) -> dict[str, float]:
    """
    Calculate Shannon entropy for the raw data of each PE section.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    file_size = path.stat().st_size
    sections = parse_pe_sections(path)

    entropies: dict[str, float] = {}

    with path.open("rb") as file:
        for section in sections:
            start = section.raw_data_pointer
            size = section.raw_data_size

            if size == 0:
                entropies[section.name] = 0.0
                continue

            if (
                start > file_size
                or size > file_size - start
            ):
                raise ValueError(
                    "PE section data exceeds file bounds."
                )

            file.seek(start)
            section_data = file.read(size)

            if len(section_data) != size:
                raise ValueError(
                    "Truncated PE section data."
                )

            entropies[section.name] = calculate_entropy(
                section_data
            )

    return entropies

def find_high_entropy_sections(
    file_path: str | Path,
    threshold: float = HIGH_ENTROPY_THRESHOLD,
) -> dict[str, float]:
    """
    Return PE sections whose entropy meets or exceeds
    the configured threshold.
    """

    if not 0.0 <= threshold <= 8.0:
        raise ValueError(
            "Entropy threshold must be between 0.0 and 8.0."
        )

    entropies = calculate_section_entropies(
        file_path
    )

    return {
        name: entropy
        for name, entropy in entropies.items()
        if entropy >= threshold
    }
    
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

def get_import_directory(
    file_path: str | Path,
) -> PEDataDirectory:
    """
    Read the import data directory from a PE file.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    file_size = path.stat().st_size

    header = parse_pe_header(path)
    magic = get_optional_header_magic(path)

    directory_start = (
        PE32_DATA_DIRECTORY_OFFSET
        if magic == PE32_MAGIC
        else PE32_PLUS_DATA_DIRECTORY_OFFSET
    )

    directory_end = (
        directory_start
        + (IMPORT_DIRECTORY_INDEX + 1) * DATA_DIRECTORY_SIZE
    )

    if header.size_of_optional_header < directory_end:
        raise ValueError(
            "PE Optional Header is too small for import directory."
        )

    with path.open("rb") as file:
        file.seek(0x3C)
        pe_offset = int.from_bytes(
            file.read(4),
            byteorder="little",
        )

        optional_header_offset = (
            pe_offset + 4 + COFF_HEADER_SIZE
        )

        if (
            optional_header_offset > file_size
            or header.size_of_optional_header
            > file_size - optional_header_offset
        ):
            raise ValueError(
                "Truncated PE Optional Header."
            )

        file.seek(
            optional_header_offset
            + directory_start
            + IMPORT_DIRECTORY_INDEX * DATA_DIRECTORY_SIZE
        )

        raw_directory = file.read(DATA_DIRECTORY_SIZE)

    if len(raw_directory) != DATA_DIRECTORY_SIZE:
        raise ValueError("Truncated PE import directory.")

    return PEDataDirectory(
        rva=int.from_bytes(raw_directory[0:4], "little"),
        size=int.from_bytes(raw_directory[4:8], "little"),
    )
    

def rva_to_file_offset(
    file_path: str | Path,
    rva: int,
) -> int:
    """
    Translate a PE RVA into a raw file offset.
    """

    if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
        raise ValueError("RVA must be a non-negative integer.")

    sections = parse_pe_sections(file_path)
    file_size = Path(file_path).expanduser().stat().st_size

    for section in sections:
        start = section.virtual_address
        raw_size = section.raw_data_size

        if start <= rva < start + raw_size:
            relative_offset = rva - start
            file_offset = section.raw_data_pointer + relative_offset

            if file_offset >= file_size:
                raise ValueError("RVA points outside file bounds.")

            return file_offset

    raise ValueError("RVA is not mapped to raw section data.")


def parse_import_descriptors(
    file_path: str | Path,
) -> list[PEImportDescriptor]:
    """
    Parse PE import directory descriptors.
    """

    import_directory = get_import_directory(file_path)

    if import_directory.rva == 0 or import_directory.size == 0:
        return []

    file_path = Path(file_path).expanduser()
    file_size = file_path.stat().st_size

    descriptor_offset = rva_to_file_offset(
        file_path,
        import_directory.rva,
    )

    descriptor_size = 20

    if import_directory.size < descriptor_size:
        raise ValueError("Import directory is too small.")

    if import_directory.size % descriptor_size != 0:
        raise ValueError("Import directory has an invalid size.")

    max_descriptors = min(
        import_directory.size // descriptor_size,
        4096,
    )

    sections = parse_pe_sections(file_path)

    matching_section = next(
        (
            section
            for section in sections
            if section.virtual_address <= import_directory.rva
            < section.virtual_address + section.raw_data_size
        ),
        None,
    )

    if matching_section is None:
        raise ValueError("Import directory is not mapped to a section.")

    section_end = (
        matching_section.raw_data_pointer
        + matching_section.raw_data_size
    )

    directory_end = descriptor_offset + import_directory.size

    if directory_end > section_end or directory_end > file_size:
        raise ValueError("Import directory exceeds section or file bounds.")

    descriptors = []
    found_terminator = False

    with file_path.open("rb") as file:
        for index in range(max_descriptors):
            offset = descriptor_offset + index * descriptor_size

            if offset + descriptor_size > file_size:
                raise ValueError("Import descriptor exceeds file bounds.")

            file.seek(offset)
            data = file.read(descriptor_size)

            if len(data) != descriptor_size:
                raise ValueError("Truncated PE import descriptor.")

            values = [
                int.from_bytes(data[i:i + 4], "little")
                for i in range(0, descriptor_size, 4)
            ]

            if all(value == 0 for value in values):
                found_terminator = True
                break

            descriptors.append(
                PEImportDescriptor(
                    original_first_thunk=values[0],
                    time_date_stamp=values[1],
                    forwarder_chain=values[2],
                    name_rva=values[3],
                    first_thunk=values[4],
                )
            )
            
    if not found_terminator:
        raise ValueError("Import directory has no null terminator.")

    return descriptors


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


