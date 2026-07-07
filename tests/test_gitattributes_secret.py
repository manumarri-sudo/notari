"""A .gitattributes -diff entry must not suppress secret detection (review H-2).

`secret.txt -diff` makes git render the file as `Binary files ... differ`, hiding
its added lines from a diff-text scanner. verify() now scans with `git diff
--text`, which overrides the attribute, so the secret is still caught.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill import contract as contract_mod
from quill import verify as verify_mod
from quill.verify import Verdict

_SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE"  # split so this file holds no live key


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "app.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


def test_gitattributes_cannot_hide_a_secret(repo: Path) -> None:
    contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo)
    # Mark the secret file as -diff so git would render it binary...
    (repo / "src" / ".gitattributes").write_text("secret.txt -diff\n")
    (repo / "src" / "secret.txt").write_text(_SECRET + "\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "secret hidden behind -diff")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is Verdict.BLOCK
    assert any(f.path == "src/secret.txt" for f in result.secret_findings), result.reasons
