"""`.gitattributes` and `.gitignore` are classified as gitconfig sensitive surfaces.

A `.gitattributes` change can suppress diff visibility (e.g. `-diff` attribute),
so modifying it should trigger NEEDS_REVIEW to alert a human reviewer (security
review H-2 residual: defense-in-depth beyond the `--text` fix).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill.policy import classify_sensitive_surface


def test_gitattributes_is_sensitive() -> None:
    assert classify_sensitive_surface(".gitattributes") == "gitconfig"


def test_gitattributes_nested() -> None:
    assert classify_sensitive_surface("subdir/.gitattributes") == "gitconfig"


def test_gitignore_is_sensitive() -> None:
    assert classify_sensitive_surface(".gitignore") == "gitconfig"


def test_gitignore_nested() -> None:
    assert classify_sensitive_surface("subdir/.gitignore") == "gitconfig"


def test_regular_file_not_gitconfig() -> None:
    assert classify_sensitive_surface("src/app.py") is None


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


def test_gitattributes_triggers_needs_review(repo: Path) -> None:
    """A PR that changes .gitattributes gets NEEDS_REVIEW (not silent PASS)."""
    from quill import contract as contract_mod
    from quill import perimeter as perimeter_mod
    from quill import verify as verify_mod
    from quill.verify import Verdict

    contract, _ = contract_mod.begin("task", allowed_paths=["**"], root=repo)
    perim = perimeter_mod.default_perimeter(allowed_paths=("**",), approved_by="human")
    (repo / ".gitattributes").write_text("*.bin binary\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add gitattributes")
    result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
    assert result.verdict is Verdict.NEEDS_REVIEW
    assert "gitconfig" in result.sensitive_surfaces
    assert ".gitattributes" in result.sensitive_surfaces.get("gitconfig", ())
