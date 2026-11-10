"""The documented strict CI setup must name every value the workflow reads.

NOTARI_AUDIT.md launch blocker 3 (w01): `notari init` output and QUICKSTART told
the user to set NOTARI_GATE_KEY and NOTARI_APPROVER_PUBKEYS only, while the
generated workflow also reads `vars.NOTARI_GATE_PUBKEYS`. Strict CI then failed
closed on every pull request ("strict mode requires a gate-signed passport").
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari.cli import _CONSUMER_WORKFLOW, app

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_init_output_tells_user_to_set_gate_pubkeys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@t"]):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("x\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    res = CliRunner().invoke(app, ["init"], terminal_width=200)
    assert res.exit_code == 0, res.output
    assert "vars.NOTARI_GATE_PUBKEYS" in _CONSUMER_WORKFLOW
    assert "gh variable set NOTARI_GATE_PUBKEYS" in res.output
    assert "gate.pub" in res.output


def test_quickstart_tells_user_to_set_gate_pubkeys() -> None:
    text = (DOCS / "QUICKSTART.md").read_text()
    assert "gh variable set NOTARI_GATE_PUBKEYS" in text
