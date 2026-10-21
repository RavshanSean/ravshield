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