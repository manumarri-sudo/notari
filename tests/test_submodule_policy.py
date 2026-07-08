"""Submodule (gitlink) opacity: a parent-repo diff shows only a pointer SHA
change, while the nested content is invisible to scope + secret scanning. A
pointer move must therefore never silently PASS as an ordinary in-scope edit, and
the passport must record the old/new commit IDs so a reviewer can audit exactly
which nested commit was pulled in."""

from __future__ import annotations

import subprocess
from pathlib import Path

from nota import contract as contract_mod
from nota import verify as verify_mod
from nota.verify import Verdict

_OLD = "1" * 40
_NEW = "2" * 40


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t.t")
    _git(root, "config", "user.name", "t")
    (root / "a.txt").write_text("hello\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")


def _add_gitlink(root: Path, path: str, sha: str, msg: str) -> str:
    """Add/replace a submodule pointer (mode 160000) without a real submodule."""
    _git(root, "update-index", "--add", "--cacheinfo", f"160000,{sha},{path}")
    _git(root, "commit", "-qm", msg)
    return _git(root, "rev-parse", "HEAD")


def test_submodule_pointer_move_is_needs_review(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    base = _add_gitlink(tmp_path, "vendor/lib", _OLD, "add submodule")
    _add_gitlink(tmp_path, "vendor/lib", _NEW, "bump submodule")

    contract = contract_mod.Contract(
        version=1,
        task="bump vendor",
        task_source="text",
        allowed_paths=("**",),  # in scope on purpose — opacity must still be flagged
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="submod-test",
    )
    result = verify_mod.verify(contract=contract, root=tmp_path, strict=False)

    assert result.verdict is Verdict.NEEDS_REVIEW, result.reasons
    assert result.submodule_changes, "pointer move must be recorded as evidence"
    change = next(c for c in result.submodule_changes if c["path"] == "vendor/lib")
    assert change["old_commit"] == _OLD
    assert change["new_commit"] == _NEW
    assert any("submodule pointer" in r for r in result.reasons)


def test_added_submodule_is_flagged_with_new_commit(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    _add_gitlink(tmp_path, "vendor/new", _NEW, "add submodule")

    contract = contract_mod.Contract(
        version=1,
        task="add vendor",
        task_source="text",
        allowed_paths=("**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="submod-add",
    )
    result = verify_mod.verify(contract=contract, root=tmp_path, strict=False)

    assert result.verdict is Verdict.NEEDS_REVIEW
    change = next(c for c in result.submodule_changes if c["path"] == "vendor/new")
    assert change["old_commit"] == ""  # newly added — no prior commit
    assert change["new_commit"] == _NEW


def test_submodule_evidence_lands_in_passport(tmp_path: Path) -> None:
    from nota import passport as passport_mod

    _init_repo(tmp_path)
    base = _add_gitlink(tmp_path, "vendor/lib", _OLD, "add submodule")
    _add_gitlink(tmp_path, "vendor/lib", _NEW, "bump submodule")
    contract = contract_mod.Contract(
        version=1,
        task="bump",
        task_source="text",
        allowed_paths=("**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="submod-passport",
    )
    result = verify_mod.verify(contract=contract, root=tmp_path, strict=False)
    doc = passport_mod.build_passport(result)
    submods = doc["evidence"]["submodule_changes"]
    assert submods and submods[0]["new_commit"] == _NEW
