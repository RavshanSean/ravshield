from pathlib import Path
from zipfile import ZipFile

import pytest

from ravshield.intel.file.archive import (
    find_suspicious_archive_files,
    inspect_zip,
)


def test_inspect_zip_lists_files(tmp_path: Path):
    zip_path = tmp_path / "sample.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("hello.txt", "hello")
        archive.writestr("photo.jpg", "fake image")
        archive.writestr("tools/setup.exe", "fake executable")

    result = inspect_zip(zip_path)

    assert result.file_count == 3
    assert result.filenames == [
        "hello.txt",
        "photo.jpg",
        "tools/setup.exe",
    ]


def test_directories_are_not_counted_as_files(tmp_path: Path):
    zip_path = tmp_path / "sample.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("documents/", "")
        archive.writestr("documents/report.txt", "report")

    result = inspect_zip(zip_path)

    assert result.file_count == 1
    assert result.filenames == [
        "documents/report.txt",
    ]


def test_empty_zip_has_zero_files(tmp_path: Path):
    zip_path = tmp_path / "empty.zip"

    with ZipFile(zip_path, "w"):
        pass

    result = inspect_zip(zip_path)

    assert result.file_count == 0
    assert result.filenames == []


def test_invalid_zip_raises_error(tmp_path: Path):
    file_path = tmp_path / "fake.zip"
    file_path.write_text("this is not actually a zip")

    with pytest.raises(
        ValueError,
        match="Invalid ZIP archive.",
    ):
        inspect_zip(file_path)


def test_missing_file_raises_error(tmp_path: Path):
    missing_file = tmp_path / "missing.zip"

    with pytest.raises(
        ValueError,
        match="Invalid file path.",
    ):
        inspect_zip(missing_file)
        
def test_finds_risky_file_inside_archive():
    filenames = [
        "notes.txt",
        "photo.jpg",
        "tools/setup.exe",
    ]

    result = find_suspicious_archive_files(filenames)

    assert result == {
        "tools/setup.exe": {
            "risky_extension",
        }
    }


def test_finds_double_extension_inside_archive():
    filenames = [
        "documents/invoice.pdf.exe",
    ]

    result = find_suspicious_archive_files(filenames)

    assert result == {
        "documents/invoice.pdf.exe": {
            "risky_extension",
            "double_extension",
        }
    }


def test_safe_archive_filenames_have_no_signals():
    filenames = [
        "notes.txt",
        "photo.jpg",
        "documents/report.pdf",
    ]

    result = find_suspicious_archive_files(filenames)

    assert result == {}