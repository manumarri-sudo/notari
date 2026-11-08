"""Imported passports may carry text that the normal scanner never emits."""

import json
import subprocess
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, format_name: str
) -> None:
    unsupported_value = "fixture-f4pJ7kN8bQ2c"
    recognizable_value = "AKIA" + "X" * 16
    fake_path = f"src/{unsupported_value}.py"
    credential_path = f"src/cache_{recognizable_value}.py"
    monkeypatch.chdir(tmp_path)
    git = ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "commit", "--allow-empty", "-qm", "base"], check=True)
    base = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    Path("src").mkdir()
    Path("src/example.py").write_text("answer = 42\n" * 7)
    Path(credential_path).write_text("answer = 42\n")
    subprocess.run([*git, "add", "src"], check=True)
    subprocess.run([*git, "commit", "-qm", "head"], check=True)
    head = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    passport = tmp_path / "passport.json"
    passport.write_text(
        json.dumps(
            {
                "verdict": "BLOCK",
                "base_commit": base,
                "head_commit": head,
                "evidence": {
                    "changed_files": ["src/example.py", fake_path],
                    "secret_findings": [
                        {"path": "src/example.py", "line": 7, "pattern": "AWS Access Key ID"},
                        {"path": "src/example.py", "line": unsupported_value, "pattern": []},
                        {"path": fake_path, "line": 8, "pattern": unsupported_value},
                        {"path": credential_path, "line": 1, "pattern": "AWS Access Key ID"},
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
