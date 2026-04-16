"""Tests for the CLI."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from glassglyph_scanner.cli import app

runner = CliRunner()


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def test_clean_file_exit_0(tmp_path: Path) -> None:
    f = _write(tmp_path, "clean.txt", "Just plain ASCII text here.")
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 0
    assert "clean" in result.output


def test_flagged_file_exit_1(tmp_path: Path) -> None:
    # Homoglyph — flagged, exit 1
    f = _write(tmp_path, "spoof.txt", "visit dоcs.аnthropic.com for docs")
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 1
    assert "FLAGGED" in result.output or "homoglyph" in result.output.lower()


def test_blocked_file_exit_2(tmp_path: Path) -> None:
    f = _write(tmp_path, "attack.txt", "const data = `" + chr(0xFE05) + chr(0xE0155) + "`;")
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 2
    assert "BLOCKED" in result.output


def test_stripped_file_exit_1(tmp_path: Path) -> None:
    f = _write(tmp_path, "zws.txt", "visible\u200bhidden\u200ctext")
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 1
    assert "MODIFIED" in result.output or "stripped" in result.output.lower()


def test_missing_file_exit_64(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nope.txt")])
    assert result.exit_code == 64
    assert "not found" in result.output or "not found" in (result.stderr or "")


def test_json_output(tmp_path: Path) -> None:
    f = _write(tmp_path, "doc.txt", "visit dоcs.аnthropic.com")
    result = runner.invoke(app, ["scan", str(f), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["clean"] is False
    assert data["has_critical_findings"] is False
    assert len(data["findings"]) >= 1


def test_quiet_mode_suppresses_output(tmp_path: Path) -> None:
    f = _write(tmp_path, "clean.txt", "clean text")
    result = runner.invoke(app, ["scan", str(f), "--quiet"])
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_stdin_input() -> None:
    result = runner.invoke(app, ["scan", "-"], input="plain ASCII text")
    assert result.exit_code == 0


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "glassglyph-scanner" in result.output
