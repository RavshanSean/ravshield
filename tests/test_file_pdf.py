from pathlib import Path

import pytest

from ravshield.intel.file.pdf import has_pdf_signature


def test_file_with_pdf_signature_is_detected(tmp_path: Path):
    file_path = tmp_path / "sample.pdf"
    file_path.write_bytes(b"%PDF-1.7\n")

    assert has_pdf_signature(file_path) is True


def test_file_without_pdf_signature_is_rejected(tmp_path: Path):
    file_path = tmp_path / "fake.pdf"
    file_path.write_bytes(b"NOT A PDF FILE")

    assert has_pdf_signature(file_path) is False


def test_pdf_signature_does_not_depend_on_extension(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"%PDF-1.7\n")

    assert has_pdf_signature(file_path) is True


def test_missing_pdf_file_raises_value_error(tmp_path: Path):
    file_path = tmp_path / "missing.pdf"

    with pytest.raises(ValueError, match="Invalid file path"):
        has_pdf_signature(file_path)


def test_truncated_pdf_signature_is_rejected(tmp_path: Path):
    file_path = tmp_path / "truncated.pdf"
    file_path.write_bytes(b"%PDF")

    assert has_pdf_signature(file_path) is False