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
