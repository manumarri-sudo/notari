"""First-run output must not expose keys or overstate approval evidence."""

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari import touchid
from notari.approvals import ApprovalStore
from notari.audit import AuditLog, seal_head
from notari.cli import _hmac_key, app


@pytest.mark.parametrize("ignore", ["# .notari/keys/\n", ".notari/keys/\n!.notari/keys/\n"])
def test_init_does_not_stage_private_keys_from_misleading_ignore(
    tmp_path: Path, monkeypatch, ignore: str
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitignore").write_text(ignore)
    result = CliRunner().invoke(app, ["init", "--approved-by", "test fixture"])
    assert result.exit_code == 0, result.output
    subprocess.run(["git", "add", ".notari", ".gitignore"], check=True)
    staged = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only"], text=True
    ).splitlines()
    assert ".notari/keys/approver.pem" not in staged
    assert ".notari/keys/gate.pem" not in staged


@pytest.mark.parametrize("retained", [0, 3])
def test_audit_export_honors_existing_truncation_seal(tmp_path: Path, retained: int) -> None:
    path = tmp_path / "audit.jsonl"
    key = _hmac_key()
    with AuditLog(path=path, hmac_key=key) as audit:
        for _ in range(4):
            audit.emit(event_type="session.open", session_id="export-test")
    seal_head(path, key)
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:retained]))
    out = tmp_path / "pack"
    result = CliRunner().invoke(
        app, ["audit", "export", "--log", str(path), "--out", str(out), "--format", "md"]
    )
    assert result.exit_code == 0, result.output
    report = (out / "audit-evidence.md").read_text()
    assert "**Chain status**: broken" in report


def test_init_private_keys_resist_nested_ignore_negation(tmp_path: Path, monkeypatch) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".notari").mkdir()
    (tmp_path / ".notari/.gitignore").write_text("!keys/\n!keys/**\n")
    result = CliRunner().invoke(app, ["init", "--approved-by", "test fixture"])
    assert result.exit_code == 0, result.output
    subprocess.run(["git", "add", ".notari", ".gitignore"], check=True)
    staged = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only"], text=True
    ).splitlines()
    assert ".notari/keys/approver.pem" not in staged
    assert ".notari/keys/gate.pem" not in staged


def test_require_biometric_cannot_fall_back_to_typed_phrase(monkeypatch) -> None:
    import notari.cli as cli

    monkeypatch.setattr(touchid, "is_available", lambda: False)
    monkeypatch.setattr(cli, "_human_tty_challenge", lambda *_: True)
    store = ApprovalStore.load()
    approval = store.issue("Bash", {"command": "git push --force fixture"})
    result = CliRunner().invoke(app, ["approve", approval.token, "--require-biometric"])
    assert result.exit_code == 2
    assert ApprovalStore.load().consume("Bash", {"command": "git push --force fixture"}) is None


@pytest.mark.parametrize("retained", [0, 3])
def test_doctor_honors_existing_truncation_seal(tmp_path: Path, retained: int) -> None:
    from notari import doctor

    path = tmp_path / "doctor-audit.jsonl"
    key = _hmac_key()
    with AuditLog(path=path, hmac_key=key) as audit:
        for _ in range(4):
            audit.emit(event_type="session.open", session_id="doctor-test")
    seal_head(path, key)
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:retained]))
    assert doctor.check_audit_chain_intact(path).status == doctor.FAIL
