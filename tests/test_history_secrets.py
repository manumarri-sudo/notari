"""A secret committed and removed later in the same change must still be found.

Audit NOTARI_AUDIT.md attempt s14 (High): a GitHub token added in one commit and
removed in a later commit of the same PR never appears in the net diff, so both
`notari scan` and `notari verify --strict` passed, while the token stayed in the
PR's Git history (`refs/pull/N/head`).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from notari import attest
from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import provenance as provenance_mod
from notari import scan as scan_mod
from notari import verify as verify_mod
from notari.verify import Verdict

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _commit(repo: Path, path: str, content: str, msg: str) -> None:
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", msg)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    _commit(tmp_path, "src/app.py", "x = 1\n", "base")
    return tmp_path


def _add_then_remove_token(repo: Path) -> None:
    _commit(repo, "src/app.py", f'x = 1\nt = "{TOKEN}"\n', "add token")
    _commit(repo, "src/app.py", "x = 1\ny = 2\n", "remove token")


def test_s14_scan_finds_secret_removed_in_later_commit(repo: Path) -> None:
    _git(repo, "checkout", "-q", "-b", "work")
    _add_then_remove_token(repo)
    result = scan_mod.scan(root=repo, base="main", env={})
    assert result.verdict is Verdict.BLOCK, result.reasons
    assert any(f.path == "src/app.py" for f in result.secret_findings)


def test_s14_strict_finds_secret_removed_in_later_commit(repo: Path) -> None:
    priv, pub = attest.generate_keypair()
    p = perimeter_mod.default_perimeter(approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv, perimeter_mod.signature_path(repo))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "perimeter")
    c, _ = contract_mod.begin(
        "work", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(c.to_dict(), priv, repo / ".notari" / "contract.sig")
    _add_then_remove_token(repo)
    env = {provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"}
    result = verify_mod.verify(
        contract=c, root=repo, perimeter=perimeter_mod.load(repo), strict=True, env=env
    )
    assert result.verdict is Verdict.BLOCK, result.reasons
    assert result.secret_findings


def test_clean_multi_commit_change_still_passes(repo: Path) -> None:
    _git(repo, "checkout", "-q", "-b", "work")
    _commit(repo, "src/app.py", "x = 1\ny = 2\n", "one")
    _commit(repo, "src/app.py", "x = 1\ny = 3\n", "two")
    assert scan_mod.scan(root=repo, base="main", env={}).verdict is Verdict.PASS
