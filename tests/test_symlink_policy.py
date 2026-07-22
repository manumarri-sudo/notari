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

from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import verify as verify_mod
from notari.verify import Verdict


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


def test_symlink_onto_forbidden_surface_blocks(tmp_path: Path) -> None:
    """A link aimed at a forbidden surface is the same crossing as renaming a
    file into it, so it BLOCKs rather than merging on a green NEEDS_REVIEW."""
    _init_repo(tmp_path)
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001.sql").write_text("select 1;\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "migrations")
    per = perimeter_mod.default_perimeter(
        allowed_paths=("src/**",), forbidden_paths=("migrations/**",)
    )
    per.write(tmp_path)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "perimeter")
    base = _git(tmp_path, "rev-parse", "HEAD")

    (tmp_path / "src" / "link").symlink_to("../migrations")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "add redirect")

    result = verify_mod.verify(
        contract=_contract(base, "symlink-forbidden", allowed=("src/**",)),
        root=tmp_path,
        perimeter=per,
        strict=False,
    )

    assert result.verdict is Verdict.BLOCK, result.reasons
    assert any("resolve onto a forbidden surface" in r for r in result.reasons), result.reasons
    assert any("migrations" in r for r in result.reasons), result.reasons


def test_symlink_onto_gate_workflow_blocks(tmp_path: Path) -> None:
    """Gate-tamper surfaces are protected with or without a perimeter."""
    _init_repo(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "src" / "wf").symlink_to("../.github/workflows")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "link at the workflow dir")

    result = verify_mod.verify(
        contract=_contract(base, "symlink-gate", allowed=("src/**",)),
        root=tmp_path,
        strict=False,
    )

    assert result.verdict is Verdict.BLOCK, result.reasons


def test_symlink_inside_the_boundary_still_only_reviews(tmp_path: Path) -> None:
    """Guard against over-firing: a link that stays inside the approved scope
    keeps the review treatment instead of failing the build."""
    _init_repo(tmp_path)
    per = perimeter_mod.default_perimeter(
        allowed_paths=("src/**",), forbidden_paths=("migrations/**",)
    )
    per.write(tmp_path)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "perimeter")
    base = _git(tmp_path, "rev-parse", "HEAD")

    (tmp_path / "src" / "alias.txt").symlink_to("a.txt")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "in-boundary link")

    result = verify_mod.verify(
        contract=_contract(base, "symlink-inside", allowed=("src/**",)),
        root=tmp_path,
        perimeter=per,
        strict=False,
    )
    assert result.verdict is Verdict.NEEDS_REVIEW, result.reasons


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
