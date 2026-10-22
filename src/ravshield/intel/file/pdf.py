from __future__ import annotations

from pathlib import Path

from ravshield.intel.file.validator import validate_file


PDF_SIGNATURE = b"%PDF-"


def has_pdf_signature(file_path: str | Path) -> bool:
    """
    Check whether a file starts with a PDF signature.

    A valid signature alone does not prove that
    the PDF is structurally valid or safe.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        signature = file.read(len(PDF_SIGNATURE))

    return signature == PDF_SIGNATURE

def get_pdf_version(file_path: str | Path) -> str:
    """
    Read the PDF version from its header.

    This does not validate the entire PDF structure.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        header = file.read(8)

    if (
        len(header) != 8
        or not header.startswith(PDF_SIGNATURE)
        or header[5:6] not in (b"1", b"2")
        or header[6:7] != b"."
        or not header[7:8].isdigit()
    ):
        raise ValueError("Invalid PDF version header.")

    return header[5:8].decode("ascii")

def has_pdf_eof_marker(file_path: str | Path) -> bool:
    """
    Check whether a PDF EOF marker exists near the end of the file.

    This does not validate the entire PDF structure.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    with path.open("rb") as file:
        file.seek(0, 2)
        file_size = file.tell()

        read_size = min(file_size, 1024)
        file.seek(-read_size, 2)
        tail = file.read(read_size)

    return b"%%EOF" in tail