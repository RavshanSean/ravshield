"""Tests for bounded, read-only batch triage."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ravshield import batch
from ravshield.cli import main
from ravshield.intel.file.report import SecurityReport


def _fake_report():
    return SecurityReport("unknown", None, "unknown", (), ("Unsupported.",), False)


def test_empty_folder(tmp_path):
    result = batch.scan_directory(tmp_path)
    assert result.scanned == result.failed == 0
    assert result.results == ()


def test_scan_two_files_sorted(tmp_path, monkeypatch):
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    seen = []
    def fake(path):
        seen.append(path.name)
        return _fake_report()
    monkeypatch.setattr(batch, "scan_file", fake)
    result = batch.scan_directory(tmp_path)
    assert seen == ["a.txt", "b.txt"]
    assert result.scanned == 2 and result.failed == 0
    assert all(item["status"] == "ok" for item in result.results)


def test_errors_do_not_stop_batch(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    def fake(path):
        if path.name == "a.txt":
            raise ValueError("Invalid file path.")
        return _fake_report()
    monkeypatch.setattr(batch, "scan_file", fake)
    result = batch.scan_directory(tmp_path)
    assert (result.scanned, result.failed) == (1, 1)
    assert result.results[0]["status"] == "error"
    assert result.results[1]["status"] == "ok"


def test_no_recursion_or_symlink(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "inside.txt").write_text("inside")
    (tmp_path / "real.txt").write_text("real")
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    seen = []
    def fake(path):
        seen.append(path.name)
        return _fake_report()
    monkeypatch.setattr(batch, "scan_file", fake)
    batch.scan_directory(tmp_path)
    assert seen == ["real.txt"]


@pytest.mark.parametrize("limit", [0, -1, 1001, True, "3"])
def test_invalid_limits(tmp_path, limit):
    with pytest.raises(ValueError, match="limit"):
        batch.scan_directory(tmp_path, limit=limit)


def test_limit_rejects_before_scanning(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    monkeypatch.setattr(batch, "scan_file", lambda path: pytest.fail("scan should not run"))
    with pytest.raises(ValueError, match="No files scanned"):
        batch.scan_directory(tmp_path, limit=1)


def test_missing_directory(tmp_path):
    with pytest.raises(ValueError, match="Invalid directory"):
        batch.scan_directory(tmp_path / "missing")


def test_batch_json_cli(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("plain text")
    assert main(["batch", str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["report_type"] == "batch"
    assert output["scanned"] == 1
    assert output["results"][0]["report"]["risk_level"] == "unknown"


def test_batch_text_cli(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("plain text")
    assert main(["batch", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "Summary: 1 scanned, 0 failed" in output
    assert "not a malware verdict" in output


def test_batch_error_exit_code(tmp_path, monkeypatch, capsys):
    (tmp_path / "x.txt").write_text("x")
    monkeypatch.setattr(batch, "scan_file", lambda path: (_ for _ in ()).throw(ValueError("bad")))
    assert main(["batch", str(tmp_path)]) == 1
    assert "1 failed" in capsys.readouterr().out


def test_batch_invalid_directory_cli(tmp_path, capsys):
    assert main(["batch", str(tmp_path / "missing")]) == 2
    assert "batch failed" in capsys.readouterr().err


def test_batch_raw_json(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("plain text")
    assert main(["batch", str(tmp_path), "--json", "--raw"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["results"][0]["report"]["report_type"] == "security"
