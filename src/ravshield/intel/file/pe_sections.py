import math
from pathlib import Path

from ravshield.intel.file.validator import validate_file
from ravshield.intel.file.pe_models import PESection

# Imported locally inside parse_pe_sections to avoid circular imports.

COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
HIGH_ENTROPY_THRESHOLD = 7.5

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
    
    from ravshield.intel.file.pe import parse_pe_header
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