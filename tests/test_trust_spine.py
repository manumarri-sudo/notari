"""End-to-end tests for the Change Control trust spine.

The properties under test are the ones that make "I don't watch the agent, I
trust the boundary" actually true:

  * A human signs the perimeter once; many diffs verify against it (approve-once,
    scale-to-many).
  * A diff that touches a forbidden path, a gate-tamper surface, or a secret is
    BLOCKed without any human in the loop.
  * In strict mode an unsigned / tampered / unestablished perimeter is BLOCKed,
    so a missing guarantee never silently passes.
  * An agent cannot bootstrap its own trust: committing its own approver key (to
    self-sign the perimeter) is itself a gate-tamper BLOCK.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quill import attest
from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod
from quill import verify as verify_mod
from quill.verify import Verdict


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "base")
    return tmp_path


def _approver(repo: Path) -> str:
    """Create an approver keypair, commit the pubkey, return the private PEM."""
    priv_pem, pub_pem = attest.generate_keypair()
    d = perimeter_mod.signature_path(repo).parent / "approvers"
    d.mkdir(parents=True, exist_ok=True)
    (d / "human.pub").write_text(pub_pem)
    return priv_pem


def _sign_perimeter(repo: Path, priv_pem: str, *, forbidden: tuple[str, ...] = ()) -> None:
    p = perimeter_mod.default_perimeter(forbidden_paths=forbidden, approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv_pem, perimeter_mod.signature_path(repo))


def _begin(repo: Path, priv: str | None = None) -> contract_mod.Contract:
    """Commit the perimeter/approver setup into `base`, then capture a contract.

    In a real repo the signed perimeter and approver keys live on the base
    branch (committed once, out of band), so a feature PR's diff never contains
    them. Mirroring that here keeps the setup out of the gated diff; only changes
    committed *after* this call land in base..HEAD. When `priv` is given the
    contract is signed (required for `verify --strict`).
    """
    _git(repo, "add", "-A")
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo).returncode != 0:
        _git(repo, "commit", "-m", "perimeter setup")
    c, _ = contract_mod.begin(
        "standing perimeter task", allowed_paths=(), root=repo, repo="owner/name"
    )
    if priv is not None:
        provenance_mod.sign_artifact(c.to_dict(), priv, repo / ".quill" / "contract.sig")
    return c


def _commit_change(repo: Path, path: str, content: str) -> None:
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", f"change {path}")


def _verify(
    repo: Path,
    contract: contract_mod.Contract,
    *,
    strict: bool = True,
    env: dict[str, str] | None = None,
) -> verify_mod.VerifyResult:
    # In strict mode only env-pinned keys are trusted (committed keys are
    # ignored), so simulate the human pinning their approver key as a CI secret.
    if env is None and strict:
        human = repo / ".quill" / "approvers" / "human.pub"
        env = {provenance_mod.APPROVER_ENV: human.read_text()} if human.exists() else {}
    # Contracts from _begin are bound to owner/name; strict now requires a matching
    # current-repo identity, so supply one unless the caller pinned its own.
    if isinstance(env, dict) and "GITHUB_REPOSITORY" not in env and "QUILL_REPO_ID" not in env:
        env = {**env, "GITHUB_REPOSITORY": "owner/name"}
    return verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=strict,
        env=env,
    )


# --------------------------------------------------------------------------- #


def test_signed_perimeter_in_bounds_passes(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.PASS
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.OK


def test_approve_once_scale_to_many(repo: Path) -> None:
    """One signature validates many independent diffs - no re-signing per change."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    for i in range(5):
        contract = _begin(repo, priv)
        _commit_change(repo, f"src/f{i}.py", f"v = {i}\n")
        assert _verify(repo, contract).verdict is Verdict.PASS


def test_forbidden_path_blocks(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv, forbidden=("src/auth/**",))
    contract = _begin(repo, priv)
    _commit_change(repo, "src/auth/login.py", "secret_logic = 1\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert any("forbidden" in r for r in result.reasons)
    assert "src/auth/login.py" in result.forbidden_hits


def test_gate_tamper_workflow_edit_blocks(repo: Path) -> None:
    """Editing the workflow that runs the gate is always a BLOCK."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, ".github/workflows/ci.yml", "name: ci\non: push\n")
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert result.gate_tamper_hits


def test_agent_cannot_bootstrap_trust_by_committing_its_own_key(repo: Path) -> None:
    """The key adversarial property: an agent that adds its own approver key to
    self-sign the perimeter trips the gate-tamper rule on `.quill/approvers/**`,
    so it can never authorize itself."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _, rogue_pub = attest.generate_keypair()
    _commit_change(repo, ".quill/approvers/rogue.pub", rogue_pub)
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert any(".quill/approvers/rogue.pub" in h for h in result.gate_tamper_hits)


def test_strict_unsigned_perimeter_blocks(repo: Path) -> None:
    """An unsigned perimeter cannot establish trust -> BLOCK in strict mode."""
    priv = _approver(repo)
    p = perimeter_mod.default_perimeter()
    p.write(repo)  # no signature
    contract = _begin(repo, priv)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract, strict=True)
    assert result.verdict is Verdict.BLOCK
    assert result.provenance is not None
    assert not result.provenance.status.is_trustworthy


def test_strict_tampered_perimeter_blocks(repo: Path) -> None:
    """Agent widens the perimeter after the human signed it -> signature invalid."""
    priv = _approver(repo)
    _sign_perimeter(repo, priv, forbidden=("src/auth/**",))
    # Tamper: rewrite the perimeter to drop the forbidden path, keep the old sig.
    perimeter_mod.default_perimeter(forbidden_paths=()).write(repo)
    contract = _begin(repo, priv)
    _commit_change(repo, "src/auth/login.py", "x = 1\n")
    result = _verify(repo, contract, strict=True)
    assert result.verdict is Verdict.BLOCK
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.BAD_SIGNATURE


def test_strict_no_perimeter_blocks(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = verify_mod.verify(contract=contract, root=repo, perimeter=None, strict=True)
    assert result.verdict is Verdict.BLOCK


def test_env_pinned_approver_without_committed_dir(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adversarial-safe path: approver pubkey comes from a CI secret (env),
    not the repo, and validates the signature."""
    priv_pem, pub_pem = attest.generate_keypair()
    p = perimeter_mod.default_perimeter()
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv_pem, perimeter_mod.signature_path(repo))
    monkeypatch.setenv(provenance_mod.APPROVER_ENV, pub_pem)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/name")  # match the contract's repo binding
    contract = _begin(repo, priv_pem)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    import os

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env=dict(os.environ),
    )
    assert result.verdict is Verdict.PASS
    assert result.provenance is not None
    assert result.provenance.status is provenance_mod.ProvenanceStatus.OK


def test_secret_on_added_line_blocks(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    _commit_change(repo, "src/config.py", f'KEY = "{key}"\n')
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert result.secret_findings


# --------------------------------------------------------------------------- #
# Signed passports: a verdict a reviewer can verify without trusting the repo  #
# --------------------------------------------------------------------------- #


def test_signed_passport_roundtrips(repo: Path) -> None:
    from quill import passport as passport_mod

    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract)

    gate_priv_pem, gate_pub_pem = attest.generate_keypair()
    passport = passport_mod.sign_passport(passport_mod.build_passport(result), gate_priv_pem)
    gate_pub = attest.load_public_key(gate_pub_pem)
    gate_keys = {attest.key_id(gate_pub): gate_pub}
    assert passport_mod.verify_passport(passport, gate_keys) == attest.key_id(gate_pub)


def test_forged_passport_verdict_is_rejected(repo: Path) -> None:
    """The dangerous twin: flip a BLOCK passport to PASS -> signature invalid."""
    from quill import passport as passport_mod

    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, ".github/workflows/ci.yml", "name: ci\n")  # gate-tamper -> BLOCK
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK

    gate_priv_pem, gate_pub_pem = attest.generate_keypair()
    passport = passport_mod.sign_passport(passport_mod.build_passport(result), gate_priv_pem)
    gate_pub = attest.load_public_key(gate_pub_pem)
    gate_keys = {attest.key_id(gate_pub): gate_pub}

    passport["verdict"] = "PASS"  # attacker flips the verdict
    assert passport_mod.verify_passport(passport, gate_keys) is None


def test_passport_signed_by_untrusted_gate_key_rejected(repo: Path) -> None:
    from quill import passport as passport_mod

    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo, priv)
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract)

    rogue_priv_pem, _ = attest.generate_keypair()
    _, trusted_gate_pub_pem = attest.generate_keypair()  # a different, trusted gate key
    passport = passport_mod.sign_passport(passport_mod.build_passport(result), rogue_priv_pem)
    trusted_pub = attest.load_public_key(trusted_gate_pub_pem)
    assert passport_mod.verify_passport(passport, {attest.key_id(trusted_pub): trusted_pub}) is None


# --------------------------------------------------------------------------- #
# Security review P0-1 / P0-2: the contract is the authorization root          #
# --------------------------------------------------------------------------- #


def test_p0_1_contract_rebase_after_malicious_commit_blocks(repo: Path) -> None:
    """The complete bypass the security review found: an agent commits malicious
    code in M, then rewrites the signed contract to set base=M (so the diff hides
    M) and widen scope. The rewritten contract no longer matches its signature,
    so strict verification BLOCKs."""
    import json as _json

    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    _begin(repo, priv)  # human-signs the contract at begin (writes .quill/contract.sig)

    _commit_change(repo, "src/evil.py", "backdoor = 1\n")  # malicious commit M
    m_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()

    # Forge: rewrite the contract to base=M and a wildcard scope, keep the old sig.
    cpath = repo / ".quill" / "contract.json"
    data = _json.loads(cpath.read_text())
    data["base_commit"] = m_sha
    data["allowed_paths"] = ["**"]
    cpath.write_text(_json.dumps(data))
    forged = contract_mod.Contract.from_dict(data)

    result = verify_mod.verify(
        contract=forged, root=repo, perimeter=perimeter_mod.load(repo), strict=True
    )
    assert result.verdict is Verdict.BLOCK
    assert any("contract provenance" in r for r in result.reasons)


def test_unsigned_contract_blocks_in_strict(repo: Path) -> None:
    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    contract = _begin(repo)  # NOT signed
    _commit_change(repo, "src/feature.py", "y = 2\n")
    result = _verify(repo, contract, strict=True)
    assert result.verdict is Verdict.BLOCK
    assert any("contract provenance" in r for r in result.reasons)


def test_p0_2_unsigned_exceptions_do_not_waive_in_strict(repo: Path) -> None:
    """An unsigned wildcard exceptions file must not waive a finding in strict."""
    import json as _json

    priv = _approver(repo)
    _sign_perimeter(repo, priv)
    # Wildcard 'secret' exception (no path) would waive every secret in cooperative mode.
    (repo / ".quill" / "exceptions.json").write_text(
        _json.dumps({"exceptions": [{"type": "secret", "reason": "approved"}]})
    )
    contract = _begin(repo, priv)
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    _commit_change(repo, "src/config.py", f'KEY = "{key}"\n')
    # Strict ignores the unsigned exception, so the secret stands -> BLOCK.
    assert _verify(repo, contract, strict=True).verdict is Verdict.BLOCK
    # Cooperative mode still honors it (the secret is waived).
    coop = _verify(repo, contract, strict=False)
    assert not coop.secret_findings


def test_p0_1_composite_rogue_key_plus_base_move_blocks(repo: Path) -> None:
    """The stronger bypass the re-review found: the attacker plants its OWN
    approver key + a rogue-signed perimeter + a rogue-signed contract in the base
    commit M (where gate-tamper can't see them, since the diff starts at M), and
    moves the base to hide malicious code. Strict mode trusts ONLY the env-pinned
    human key and ignores the committed approver dir, so the rogue-signed
    artifacts fail provenance and it BLOCKs."""
    import json as _json

    # The human's real approver key, pinned via env (a CI secret a PR can't edit).
    _, human_pub = attest.generate_keypair()
    # The attacker's own key, committed into the repo checkout.
    rogue_priv, rogue_pub = attest.generate_keypair()

    d = repo / ".quill" / "approvers"
    d.mkdir(parents=True, exist_ok=True)
    (d / "rogue.pub").write_text(rogue_pub)
    rogue_per = perimeter_mod.default_perimeter()
    rogue_per.write(repo)
    provenance_mod.sign_artifact(
        rogue_per.to_dict(), rogue_priv, perimeter_mod.signature_path(repo)
    )
    (repo / "src" / "evil.py").write_text("backdoor = 1\n")  # malicious code in M
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "M: rogue key + perimeter + evil")
    m_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()

    # Commit C: rogue-signed contract with base = M (hides evil.py from the diff).
    contract, _ = contract_mod.begin("anything", allowed_paths=("**",), root=repo)
    data = contract.to_dict()
    data["base_commit"] = m_sha
    (repo / ".quill" / "contract.json").write_text(_json.dumps(data))
    forged = contract_mod.Contract.from_dict(data)
    provenance_mod.sign_artifact(forged.to_dict(), rogue_priv, repo / ".quill" / "contract.sig")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "C: rogue contract base=M")

    result = verify_mod.verify(
        contract=forged,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env={provenance_mod.APPROVER_ENV: human_pub},  # only the human key is pinned
    )
    assert result.verdict is Verdict.BLOCK


def test_perimeter_allow_list_is_enforced(repo: Path) -> None:
    """The signed perimeter allow-list is the outer bound (re-review P0/P1): a
    contract cannot widen past it. Perimeter allows only src/**; a contract with
    no restriction still can't authorize a change to docs/."""
    priv = _approver(repo)
    p = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv, perimeter_mod.signature_path(repo))
    contract = _begin(repo, priv)  # contract allowed_paths = () (no per-task restriction)
    _commit_change(repo, "docs/readme.md", "x\n")  # outside the perimeter allow-list
    result = _verify(repo, contract)
    assert result.verdict is Verdict.BLOCK
    assert "docs/readme.md" in result.out_of_scope
