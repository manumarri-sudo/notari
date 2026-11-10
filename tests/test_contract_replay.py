"""Strict mode must not accept unexpiring, over-long, or replayed contracts.

Audit NOTARI_AUDIT.md launch blocker 2 (attempts k02, k01, t11):
  * k02: an approver-signed contract with no `expires_at` passed strict.
  * k01: a 365-day contract passed strict.
  * t11: a PR swapped in an EARLIER approver-signed contract with scope `**`
    over the newer, narrower contract already on the target branch, and passed.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from notari import attest
from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import provenance as provenance_mod
from notari import verify as verify_mod
from notari.verify import Verdict


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.fixture
def base(tmp_path: Path) -> tuple[Path, str, dict[str, str]]:
    repo = tmp_path
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "src" / "api").mkdir(parents=True)
    (repo / "src" / "api" / "app.py").write_text("x = 1\n")
    priv, pub = attest.generate_keypair()
    p = perimeter_mod.default_perimeter(approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base")
    env = {provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"}
    return repo, priv, env


def _sign(
    repo: Path,
    priv: str,
    *,
    scope: tuple[str, ...],
    created: datetime,
    lifetime: timedelta | None,
) -> contract_mod.Contract:
    """Write and sign a contract with an explicit creation time and lifetime."""
    base_commit = _git(repo, "rev-parse", "HEAD")
    created_at = created.isoformat()
    c = contract_mod.Contract(
        version=contract_mod.CONTRACT_VERSION,
        task="task",
        task_source="text",
        allowed_paths=scope,
        base_commit=base_commit,
        created_at=created_at,
        contract_id=contract_mod._contract_id("task", base_commit, created_at, scope),
        expires_at=(created + lifetime).isoformat() if lifetime is not None else None,
        repo="owner/name",
    )
    c.write(repo)
    provenance_mod.sign_artifact(c.to_dict(), priv, repo / ".notari" / "contract.sig")
    return c


def _commit(repo: Path, path: str, content: str) -> None:
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", f"change {path}")


def _strict(repo: Path, c: contract_mod.Contract, env: dict[str, str]) -> verify_mod.VerifyResult:
    return verify_mod.verify(
        contract=c, root=repo, perimeter=perimeter_mod.load(repo), strict=True, env=env
    )


NOW = datetime.now(UTC)


def test_k02_contract_without_expiry_blocks_in_strict(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c = _sign(repo, priv, scope=("**",), created=NOW, lifetime=None)
    _commit(repo, "other.py", "z = 1\n")
    result = _strict(repo, c, env)
    assert result.verdict is Verdict.BLOCK
    assert any("expir" in r for r in result.reasons), result.reasons


def test_k01_contract_lifetime_over_cap_blocks_in_strict(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c = _sign(repo, priv, scope=("**",), created=NOW, lifetime=timedelta(days=365))
    _commit(repo, "other.py", "z = 1\n")
    result = _strict(repo, c, env)
    assert result.verdict is Verdict.BLOCK
    assert any("lifetime" in r for r in result.reasons), result.reasons


def test_contract_within_cap_passes(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c = _sign(repo, priv, scope=("**",), created=NOW, lifetime=timedelta(days=7))
    _commit(repo, "other.py", "z = 1\n")
    assert _strict(repo, c, env).verdict is Verdict.PASS


def _replay_setup(repo: Path, priv: str) -> tuple[contract_mod.Contract, str]:
    """main carries an older broad C0, then a newer narrow C1. Return (C0, main SHA)."""
    _sign(repo, priv, scope=("**",), created=NOW - timedelta(days=2), lifetime=timedelta(days=7))
    c0_json = (repo / ".notari" / "contract.json").read_text()
    c0_sig = (repo / ".notari" / "contract.sig").read_text()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "C0 broad")
    _sign(
        repo,
        priv,
        scope=("src/api/**",),
        created=NOW - timedelta(days=1),
        lifetime=timedelta(days=7),
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "C1 narrow")
    main = _git(repo, "rev-parse", "HEAD")
    (repo / ".notari" / "contract.json").write_text(c0_json)
    (repo / ".notari" / "contract.sig").write_text(c0_sig)
    return contract_mod.Contract.from_dict(json.loads(c0_json)), main


def test_t11_replayed_older_contract_blocks_in_strict(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c0, main = _replay_setup(repo, priv)
    _commit(repo, "other.py", "z = 1\n")
    result = _strict(repo, c0, {**env, "NOTARI_BASE_SHA": main})
    assert result.verdict is Verdict.BLOCK
    assert any("older than" in r for r in result.reasons), result.reasons


def test_contract_already_on_target_branch_passes(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c = _sign(repo, priv, scope=("src/**",), created=NOW, lifetime=timedelta(days=7))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "contract")
    main = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "src/api/app.py", "x = 2\n")
    assert _strict(repo, c, {**env, "NOTARI_BASE_SHA": main}).verdict is Verdict.PASS


def test_unresolvable_target_base_fails_closed(base) -> None:  # type: ignore[no-untyped-def]
    repo, priv, env = base
    c = _sign(repo, priv, scope=("src/**",), created=NOW, lifetime=timedelta(days=7))
    _commit(repo, "src/api/app.py", "x = 2\n")
    result = _strict(repo, c, {**env, "NOTARI_BASE_SHA": "f" * 40})
    assert result.verdict is Verdict.BLOCK


def test_begin_with_max_lifetime_passes(base) -> None:  # type: ignore[no-untyped-def]
    """`notari begin --expires-in 30` must satisfy the 30-day strict cap even though
    begin stamps expires_at a few microseconds after created_at."""
    repo, priv, env = base
    c, _ = contract_mod.begin(
        "task", allowed_paths=("**",), root=repo, repo="owner/name", expires_in_days=30
    )
    provenance_mod.sign_artifact(c.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit(repo, "other.py", "z = 1\n")
    assert _strict(repo, c, env).verdict is Verdict.PASS
