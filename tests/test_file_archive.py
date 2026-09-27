from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from ravshield.intel.file.archive import (
    analyze_archive_size_risk,
    find_nested_archives,
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
    
def test_finds_nested_zip_files():
    filenames = [
        "notes.txt",
        "documents.zip",
        "backup/archive.ZIP",
    ]

    result = find_nested_archives(filenames)

    assert result == [
        "documents.zip",
        "backup/archive.ZIP",
    ]


def test_no_nested_zip_files_returns_empty_list():
    filenames = [
        "notes.txt",
        "photo.jpg",
        "report.pdf",
    ]

    result = find_nested_archives(filenames)

    assert result == []


def test_safe_archive_filenames_have_no_signals():
    filenames = [
        "notes.txt",
        "photo.jpg",
        "documents/report.pdf",
    ]

    result = find_suspicious_archive_files(filenames)

    assert result == {}
    
def test_normal_archive_has_no_size_risk(tmp_path: Path):
    zip_path = tmp_path / "normal.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("hello.txt", "hello world")

    result = analyze_archive_size_risk(zip_path)

    assert result.uncompressed_size == 11
    assert result.signals == set()
    assert result.suspicious is False


def test_excessive_uncompressed_size_is_detected(tmp_path: Path):
    zip_path = tmp_path / "large.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("large.txt", "A" * 100)

    result = analyze_archive_size_risk(
        zip_path,
        max_uncompressed_size=50,
    )

    assert "excessive_uncompressed_size" in result.signals
    assert result.suspicious is True


def test_excessive_compression_ratio_is_detected(tmp_path: Path):
    zip_path = tmp_path / "compressed.zip"

    with ZipFile(
        zip_path,
        "w",
        compression=ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "repeated.txt",
            "A" * 10_000,
        )

    result = analyze_archive_size_risk(
        zip_path,
        max_compression_ratio=10.0,
    )

    assert "excessive_compression_ratio" in result.signals
    assert result.suspicious is True


def test_empty_archive_has_zero_compression_ratio(tmp_path: Path):
    zip_path = tmp_path / "empty.zip"

    with ZipFile(zip_path, "w"):
        pass

    result = analyze_archive_size_risk(zip_path)

    assert result.compressed_size == 0
    assert result.uncompressed_size == 0
    assert result.compression_ratio == 0.0
    assert result.signals == set()