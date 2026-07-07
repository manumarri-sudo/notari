"""Contract expiry + scope-bound contract_id (security review 3.7 / 3.12).

A signed contract authenticates its bytes but bound no expiry, so a stale
approval could authorize work forever. `--expires-in` records a lapse date that
`verify --strict` enforces. Separately, contract_id now covers the scope, so two
contracts differing only in scope get distinct ids.
"""

from __future__ import annotations

import dataclasses
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from quill import attest
from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod
from quill import verify as verify_mod
from quill.verify import Verdict

_PAST = "2020-01-01T00:00:00+00:00"


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


def test_is_expired_unit() -> None:
    base = contract_mod.Contract(
        version=1,
        task="t",
        task_source="text",
        allowed_paths=(),
        base_commit=None,
        created_at="now",
        contract_id="x",
    )
    assert base.is_expired() is False  # no expiry -> never
    assert dataclasses.replace(base, expires_at=_PAST).is_expired() is True
    future = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    assert dataclasses.replace(base, expires_at=future).is_expired() is False
    assert dataclasses.replace(base, expires_at="not-a-date").is_expired() is False


def test_contract_id_changes_with_scope(repo: Path) -> None:
    a, _ = contract_mod.begin("same task", allowed_paths=["src/**"], root=repo)
    b, _ = contract_mod.begin("same task", allowed_paths=["src/**", "docs/**"], root=repo)
    assert a.contract_id != b.contract_id


def test_expired_contract_blocks_in_strict(repo: Path) -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    # signed perimeter on the base branch
    perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="human")
    perim.write(repo)
    provenance_mod.sign_artifact(perim.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "perimeter")
    # an EXPIRED but correctly-signed contract
    c, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo, repo="owner/name")
    expired = dataclasses.replace(c, expires_at=_PAST)
    expired.write(repo)
    provenance_mod.sign_artifact(expired.to_dict(), priv_pem, repo / ".quill" / "contract.sig")
    # pin the human key off-box and bind the repo so expiry is the gate that fires
    env = {provenance_mod.APPROVER_ENV: pub_pem, "GITHUB_REPOSITORY": "owner/name"}
    result = verify_mod.verify(contract=expired, root=repo, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.BLOCK
    assert any("expired" in r for r in result.reasons), result.reasons


def test_malformed_expiry_blocks_in_strict(repo: Path) -> None:
    """A malformed expiry must not be silently treated as unlimited (review M-6)."""
    priv_pem, pub_pem = attest.generate_keypair()
    perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="human")
    perim.write(repo)
    provenance_mod.sign_artifact(perim.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "perimeter")
    c, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo, repo="owner/name")
    bad = dataclasses.replace(c, expires_at="not-a-date")
    bad.write(repo)
    provenance_mod.sign_artifact(bad.to_dict(), priv_pem, repo / ".quill" / "contract.sig")
    env = {provenance_mod.APPROVER_ENV: pub_pem, "GITHUB_REPOSITORY": "owner/name"}
    result = verify_mod.verify(contract=bad, root=repo, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.BLOCK
    assert any("malformed" in r for r in result.reasons), result.reasons


def _sign_perimeter_and_commit(repo: Path, priv_pem: str) -> perimeter_mod.Perimeter:
    perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="human")
    perim.write(repo)
    provenance_mod.sign_artifact(perim.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "perimeter")
    return perim


def test_contract_bound_to_other_repo_blocks_in_strict(repo: Path) -> None:
    """A contract bound to owner/A must not authorize a change in owner/B (H-5)."""
    priv_pem, pub_pem = attest.generate_keypair()
    perim = _sign_perimeter_and_commit(repo, priv_pem)
    c, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo, repo="owner/A")
    provenance_mod.sign_artifact(c.to_dict(), priv_pem, repo / ".quill" / "contract.sig")
    env = {provenance_mod.APPROVER_ENV: pub_pem, "QUILL_REPO_ID": "owner/B"}
    result = verify_mod.verify(contract=c, root=repo, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.BLOCK
    assert any("bound to repo" in r for r in result.reasons), result.reasons


def test_contract_bound_to_matching_repo_passes_strict(repo: Path) -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    perim = _sign_perimeter_and_commit(repo, priv_pem)
    c, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo, repo="owner/A")
    provenance_mod.sign_artifact(c.to_dict(), priv_pem, repo / ".quill" / "contract.sig")
    (repo / "src" / "app.py").write_text("x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit")
    env = {provenance_mod.APPROVER_ENV: pub_pem, "QUILL_REPO_ID": "owner/A"}
    result = verify_mod.verify(contract=c, root=repo, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.PASS, result.reasons


def test_unexpired_signed_contract_passes_strict(repo: Path) -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="human")
    perim.write(repo)
    provenance_mod.sign_artifact(perim.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "perimeter")
    c, _ = contract_mod.begin(
        "task", allowed_paths=["src/**"], root=repo, expires_in_days=7, repo="owner/name"
    )
    provenance_mod.sign_artifact(c.to_dict(), priv_pem, repo / ".quill" / "contract.sig")
    (repo / "src" / "app.py").write_text("x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "in-scope edit")
    env = {provenance_mod.APPROVER_ENV: pub_pem, "GITHUB_REPOSITORY": "owner/name"}
    result = verify_mod.verify(contract=c, root=repo, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.PASS, result.reasons
