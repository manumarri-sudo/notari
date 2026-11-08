"""Imported passports may carry text that the normal scanner never emits."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari.cli import app


@pytest.mark.parametrize("format_name", ["text", "json", "html"])
def test_explain_redacts_imported_passport_text(tmp_path: Path, format_name: str) -> None:
    fixture = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    passport = tmp_path / "passport.json"
    passport.write_text(
        json.dumps(
            {
                "verdict": "BLOCK",
                "mode": "scan",
                "reasons": [f"Credential sample: {fixture}"],
                "evidence": {"gate_tamper_hits": [f"config/{fixture}.txt"]},
            }
        )
    )
    command = ["explain", "--passport", str(passport), "--format", format_name]
    if format_name == "html":
        report = tmp_path / "report.html"
        command.extend(["--out", str(report)])
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 0, result.output
    output = report.read_text() if format_name == "html" else result.output
    assert fixture not in output
    assert "REDACTED" in output


@pytest.mark.parametrize("format_name", ["text", "json", "html", "github", "fix-prompt"])
def test_imported_credential_findings_only_render_valid_metadata(
    tmp_path: Path, format_name: str
) -> None:
    unsupported_value = "fixture-f4pJ7kN8bQ2c"
    recognizable_value = "AKIA" + "X" * 16
    passport = tmp_path / "passport.json"
    passport.write_text(
        json.dumps(
            {
                "verdict": "BLOCK",
                "evidence": {
                    "changed_files": ["src/example.py"],
                    "secret_findings": [
                        {"path": "src/example.py", "line": 7, "pattern": "AWS Access Key ID"},
                        {"path": "src/example.py", "line": unsupported_value, "pattern": []},
                        {"path": unsupported_value, "line": 8, "pattern": unsupported_value},
                    ],
                    "sensitive_surfaces": {recognizable_value: ["src/example.py"]},
                },
            }
        )
    )
    command = ["explain", "--passport", str(passport)]
    command.extend(["--fix-prompt"] if format_name == "fix-prompt" else ["--format", format_name])
    if format_name == "html":
        report = tmp_path / "report.html"
        command.extend(["--out", str(report)])
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 0, result.output
    output = report.read_text() if format_name == "html" else result.output
    assert unsupported_value not in output
    assert recognizable_value not in output
    assert "AWS Access Key ID" in output
    assert "src/example.py" in output
    if format_name == "github":
        assert "file=src/example.py,line=7" in output
