"""Authoritative inventory: rename endpoints + mode-only changes are policed.

Independent security review found two Critical bypasses and a High parser blind
spot, all from policing paths off a best-effort textual-diff parser:

  - a rename OUT of `.github/workflows/**` (or any gate surface) escaped the
    gate-tamper BLOCK, which only looked at the rename destination;
  - a rename OUT of a forbidden path escaped the forbidden BLOCK for the same
    reason;
  - a quoted, mode-only change (chmod on a unicode filename) vanished from the
    inventory entirely.

`verify` now builds the changed-path set from `git diff --name-status -z`
(authoritative, NUL-delimited, both rename endpoints, mode-only included) and
applies every path rule to both ends. These pin that behavior with real git.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import verify as verify_mod
from quill.verify import Verdict


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "core.filemode", "true")
    return r


def _block_reasons(result: verify_mod.VerifyResult) -> str:
    return " | ".join(result.reasons)


def test_rename_out_of_workflow_is_blocked(repo: Path) -> None:
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "security.yml").write_text("on: pull_request\n")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "mv", ".github/workflows/security.yml", "src/security.yml")
    _git(repo, "commit", "-qm", "move the gate workflow out of the protected path")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is Verdict.BLOCK
    assert ".github/workflows/security.yml" in result.gate_tamper_hits


def test_rename_out_of_action_yml_is_blocked(repo: Path) -> None:
    (repo / "action.yml").write_text("name: x\n")
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "mv", "action.yml", "src/action.yml")
    _git(repo, "commit", "-qm", "move action.yml out")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is Verdict.BLOCK
    assert "action.yml" in result.gate_tamper_hits


def test_rename_out_of_approver_dir_is_blocked(repo: Path) -> None:
    appr = repo / ".quill" / "approvers"
    appr.mkdir(parents=True)
    (appr / "human.pub").write_text("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n")
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "mv", ".quill/approvers/human.pub", "src/human.pub")
    _git(repo, "commit", "-qm", "exfiltrate the approver key out of the protected dir")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is Verdict.BLOCK
    assert ".quill/approvers/human.pub" in result.gate_tamper_hits


def test_rename_out_of_perimeter_is_blocked(repo: Path) -> None:
    # The perimeter file lives in the base commit, so committing it does not
    # itself appear in the candidate diff; only the rename does.
    perim = perimeter_mod.default_perimeter(forbidden_paths=("src/auth/**",), approved_by="h")
    perim.write(repo)
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base with perimeter")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "mv", ".quill/perimeter.json", "src/perimeter.json")
    _git(repo, "commit", "-qm", "move the signed perimeter out")
    result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
    assert result.verdict is Verdict.BLOCK
    assert ".quill/perimeter.json" in result.gate_tamper_hits


def test_rename_out_of_custom_forbidden_path_is_blocked(repo: Path) -> None:
    (repo / "src" / "auth").mkdir(parents=True)
    (repo / "src" / "auth" / "login.py").write_text("def login():\n    return False\n")
    perim = perimeter_mod.default_perimeter(forbidden_paths=("src/auth/**",), approved_by="h")
    perim.write(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base with auth + perimeter")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "mv", "src/auth/login.py", "src/moved.py")
    _git(repo, "commit", "-qm", "move protected auth code out of the forbidden namespace")
    result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
    assert result.verdict is Verdict.BLOCK
    assert "src/auth/login.py" in result.forbidden_hits, _block_reasons(result)


def test_unicode_quoted_mode_only_change_is_inventoried(repo: Path) -> None:
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x\n")
    (repo / "café.sh").write_text("echo hi\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    # contract scopes work to src/**; café.sh is out of scope.
    contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    # Pure mode-only change to the quoted unicode path (no content diff).
    _git(repo, "update-index", "--chmod=+x", "café.sh")
    _git(repo, "commit", "-qm", "make café.sh executable")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is Verdict.BLOCK
    assert "café.sh" in result.out_of_scope, _block_reasons(result)


def test_candidate_sha_is_single_source_of_truth(repo: Path) -> None:
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    # Build a candidate branch, then move HEAD elsewhere so HEAD != candidate.
    _git(repo, "checkout", "-q", "-b", "candidate")
    (repo / "src" / "app.py").write_text("y\n")
    _git(repo, "commit", "-aqm", "candidate change")
    candidate_sha = _git(repo, "rev-parse", "candidate").strip()
    _git(repo, "checkout", "-q", "main")
    result = verify_mod.verify(contract=contract, root=repo, head="candidate")
    # The recorded head must be the EVALUATED candidate, not repo HEAD (main).
    assert result.head_commit == candidate_sha


def test_passport_evidence_uses_authoritative_inventory(repo: Path) -> None:
    """The passport's changed-file list must come from the name-status inventory,
    not the textual parser, so a mode-only change can't make it say 'no changes'
    while enforcement blocks (review M-1)."""
    from quill import passport as passport_mod

    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x\n")
    (repo / "tool.sh").write_text("echo hi\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    contract, _ = contract_mod.begin("task", allowed_paths=[], root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "contract")
    _git(repo, "update-index", "--chmod=+x", "tool.sh")
    _git(repo, "commit", "-qm", "chmod only")
    result = verify_mod.verify(contract=contract, root=repo)
    assert "tool.sh" in result.changed_paths
    passport = passport_mod.build_passport(result)
    assert "tool.sh" in passport["evidence"]["changed_files"]
