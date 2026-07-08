"""A .gitattributes -diff entry must not suppress secret detection (review H-2).

`secret.txt -diff` makes git render the file as `Binary files ... differ`, hiding
its added lines from a diff-text scanner. verify() now scans with `git diff
--text`, which overrides the attribute, so the secret is still caught.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nota import contract as contract_mod
from nota import verify as verify_mod
from nota.verify import Verdict

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
    # Assert on the DIFF-TEXT scanner channel specifically. `evaluation` is the
    # output of policy.evaluate_diff over the `git diff --text` text, so it is the
    # exact channel the H-2 --text flag protects: drop --text and git renders the
    # `-diff` file as "Binary files ... differ", the added secret line never appears
    # in the diff, and this channel goes empty. The independent blob-level scan
    # would still populate the final `result.secret_findings`, so asserting only on
    # the verdict / merged findings passes even with --text removed (which is why the
    # earlier test was weak). Pinning the diff channel makes dropping --text a real,
    # caught regression.
    assert any(f.path == "src/secret.txt" for f in result.evaluation.secret_findings), (
        result.evaluation.secret_findings
    )
    # And the merged, unwaived findings that drive the verdict still carry it.
    assert any(f.path == "src/secret.txt" for f in result.secret_findings), result.reasons
