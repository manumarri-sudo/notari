"""Symlink opacity: git stores a symlink as a blob whose content is the target
path, so an in-scope symlink can redirect at a forbidden path while the diff
shows only an in-scope file with innocuous "content". Scope and secret scanning
see the target string, not the crossing. A symlink addition/change must therefore
never silently PASS; it surfaces as NEEDS_REVIEW with the target recorded so a
reviewer can see where the link points.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from quill import contract as contract_mod
from quill import verify as verify_mod
from quill.verify import Verdict


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t.t")
    _git(root, "config", "user.name", "t")
    (root / "src").mkdir()
    (root / "src" / "a.txt").write_text("hello\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")


def _contract(base: str, cid: str, allowed: tuple[str, ...] = ("**",)):
    return contract_mod.Contract(
        version=1,
        task="work",
        task_source="text",
        allowed_paths=allowed,
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id=cid,
    )


def test_added_symlink_is_needs_review_with_target(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    # in-scope path, but the link redirects OUT of scope
    (tmp_path / "src" / "link.py").symlink_to("../secret/creds")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "add symlink")

    result = verify_mod.verify(
        contract=_contract(base, "symlink-add", allowed=("src/**",)),
        root=tmp_path,
        strict=False,
    )

    assert result.verdict is Verdict.NEEDS_REVIEW, result.reasons
    assert any("symlink" in r for r in result.reasons), result.reasons
    assert any("../secret/creds" in r for r in result.reasons), result.reasons


def test_ordinary_in_scope_file_still_passes(tmp_path: Path) -> None:
    """Guard against over-firing: a normal regular-file edit is not a symlink."""
    _init_repo(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "src" / "b.txt").write_text("more\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "ordinary add")

    result = verify_mod.verify(
        contract=_contract(base, "ordinary", allowed=("src/**",)),
        root=tmp_path,
        strict=False,
    )
    assert result.verdict is Verdict.PASS, result.reasons
