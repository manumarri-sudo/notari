"""First-run regression tests (0.3.2).

The fresh-eyes user test (2026-07-10) found that following the documented
quickstart produced a BLOCK on a fully in-scope change: `begin` freezes its
base before the boundary commit lands, so the perimeter's own files ride
inside base..head and tripped gate-tamper (and the perimeter's baked-in
forbidden globs). These tests pin the fix:

- cooperative mode exempts .notari/perimeter.{json,sig} from gate-tamper and
  forbidden hits WHEN the perimeter signature verifies against pinned approver
  keys (the agent cannot forge it, so it is authorization arriving, not tamper);
- strict mode keeps the out-of-band rule unchanged (replaying even a
  validly-signed perimeter from inside a PR must still BLOCK);
- the documented correct order (setup commit, then begin) yields PASS;
- `notari keygen --out` inside a git repo gitignores both key files so a
  naive `git add -A` cannot commit the private key and trip the secret scan.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari import attest
from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import provenance as provenance_mod
from notari import verify as verify_mod
from notari.cli import app
from notari.verify import Verdict


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


def _keypair_and_perimeter(repo: Path) -> tuple[str, str]:
    """Sign a perimeter to disk (uncommitted) with env-pinned keys, quickstart-style."""
    priv, pub = attest.generate_keypair()
    p = perimeter_mod.default_perimeter(forbidden_paths=("migrations/**",), approved_by="human")
    p.write(repo)
    provenance_mod.sign_artifact(p.to_dict(), priv, perimeter_mod.signature_path(repo))
    return priv, pub


def _env(pub: str) -> dict[str, str]:
    return {provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"}


def _commit_all(repo: Path, msg: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", msg)


def test_wrong_order_boundary_in_diff_cooperative_passes(repo: Path) -> None:
    """Naive quickstart order: begin BEFORE the boundary commit. Cooperative
    verify must not flag the signature-valid perimeter files as tamper."""
    priv, pub = _keypair_and_perimeter(repo)
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "boundary + contract (after begin: the naive order)")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env=_env(pub),
    )
    assert result.verdict is Verdict.PASS, result.reasons
    assert result.gate_tamper_hits == ()
    assert ".notari/perimeter.json" not in result.forbidden_hits
    assert ".notari/perimeter.sig" not in result.forbidden_hits


def test_wrong_order_boundary_in_diff_strict_still_blocks(repo: Path) -> None:
    """Strict keeps the out-of-band rule: an in-diff perimeter BLOCKs even when
    its signature is valid, so a PR cannot replay an old signed perimeter."""
    priv, pub = _keypair_and_perimeter(repo)
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "boundary + contract inside the PR range")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env=_env(pub),
    )
    assert result.verdict is Verdict.BLOCK
    hit_surfaces = set(result.gate_tamper_hits) | set(result.forbidden_hits)
    assert ".notari/perimeter.json" in hit_surfaces
    assert ".notari/perimeter.sig" in hit_surfaces


def test_correct_order_quickstart_passes_cooperative(repo: Path) -> None:
    """The documented order: setup commit, then begin, then contract commit,
    then the in-scope change. This is the happy path the docs promise."""
    priv, pub = _keypair_and_perimeter(repo)
    _commit_all(repo, "notari: signed boundary")
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "notari: open task contract")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env=_env(pub),
    )
    assert result.verdict is Verdict.PASS, result.reasons


def test_wrong_order_untrusted_signature_is_not_exempted(repo: Path) -> None:
    """The exemption's false branch: an in-diff perimeter whose signature does
    NOT verify against the pinned approver keys stays flagged even in
    cooperative mode. A regression to `if not strict:` alone must fail here."""
    _priv, pub = _keypair_and_perimeter(repo)
    # Re-sign the perimeter with a DIFFERENT key than the one pinned in env,
    # so provenance is untrusted while a signature file still exists.
    other_priv, _other_pub = attest.generate_keypair()
    p = perimeter_mod.load(repo)
    provenance_mod.sign_artifact(p.to_dict(), other_priv, perimeter_mod.signature_path(repo))
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    _commit_all(repo, "boundary + contract, untrusted signature")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env=_env(pub),  # pins the ORIGINAL key; the re-sign does not match it
    )
    assert result.verdict is Verdict.BLOCK
    hit_surfaces = set(result.gate_tamper_hits) | set(result.forbidden_hits)
    assert ".notari/perimeter.json" in hit_surfaces


def test_cooperative_exemption_is_surfaced_not_silent(repo: Path) -> None:
    """When the exemption fires, the passport must say so in its reasons."""
    priv, pub = _keypair_and_perimeter(repo)
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "boundary + contract (after begin)")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")

    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env=_env(pub),
    )
    assert result.verdict is Verdict.PASS
    assert any("exempted in cooperative mode" in r for r in result.reasons)


def test_keygen_gitignores_both_key_files(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`keygen --out` in a git repo must gitignore the private AND public key
    (root-anchored) so a naive `git add -A` cannot commit a PEM and trip the
    secret scanner."""
    monkeypatch.chdir(repo)
    runner = CliRunner()
    res = runner.invoke(app, ["keygen", "--out", "approver.pem"])
    assert res.exit_code == 0, res.output
    gi = (repo / ".gitignore").read_text().splitlines()
    assert "/approver.pem" in gi
    assert "/approver.pem.pub" in gi

    # Idempotent: a second keygen must not duplicate the entries.
    res2 = runner.invoke(app, ["keygen", "--out", "approver2.pem"])
    assert res2.exit_code == 0, res2.output
    gi2 = (repo / ".gitignore").read_text().splitlines()
    assert gi2.count("/approver.pem") == 1
    assert "/approver2.pem" in gi2


def test_keygen_gitignore_works_from_subdirectory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running keygen from a repo SUBDIRECTORY must still write a root-anchored
    entry into the repo root's .gitignore (the original fix silently skipped)."""
    sub = repo / "src"
    monkeypatch.chdir(sub)
    runner = CliRunner()
    res = runner.invoke(app, ["keygen", "--out", "approver.pem"])
    assert res.exit_code == 0, res.output
    gi = (repo / ".gitignore").read_text().splitlines()
    assert "/src/approver.pem" in gi
    assert "/src/approver.pem.pub" in gi
    assert not (sub / ".gitignore").exists()


def _cli_ready_repo(repo: Path) -> str:
    """Correct-order CLI setup; returns the pinned approver pubkey PEM."""
    priv, pub = _keypair_and_perimeter(repo)
    _commit_all(repo, "notari: signed boundary")
    contract, _ = contract_mod.begin(
        "add feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "notari: open task contract")
    return pub


def test_verify_open_flag_writes_and_opens_fixit_page(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--open forces the browser handoff even on PASS; the page is written."""
    import webbrowser

    pub = _cli_ready_repo(repo)
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("NOTARI_APPROVER_PUBKEYS", pub)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/name")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
    runner = CliRunner()
    res = runner.invoke(app, ["verify", "--open"])
    assert res.exit_code == 0, res.output
    assert (repo / ".notari" / "explain.html").exists()
    assert len(opened) == 1 and opened[0].startswith("file://")


def test_verify_default_never_opens_in_non_tty_or_ci(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default policy is on-failure AND interactive AND not CI; a BLOCK under
    CliRunner (non-tty) must not open a browser, and CI env forces never."""
    import webbrowser

    pub = _cli_ready_repo(repo)
    (repo / "migrations").mkdir(exist_ok=True)
    (repo / "migrations" / "evil.sql").write_text("drop table users;\n")
    _commit_all(repo, "forbidden change")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("NOTARI_APPROVER_PUBKEYS", pub)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/name")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)
    runner = CliRunner()
    res = runner.invoke(app, ["verify"])
    assert res.exit_code == 1, res.output  # BLOCK still exits 1
    assert opened == []


def _signed_ready(repo: Path, *, repo_bind: str = "owner/name") -> tuple[str, str, object]:
    """Correct-order setup with an env-pinned approver key.

    Returns (approver_priv, approver_pub, contract). The private key is returned
    so tests that need to forge a still-trusted contract can re-sign with it.
    """
    priv, pub = _keypair_and_perimeter(repo)
    _commit_all(repo, "notari: signed boundary")
    contract, _ = contract_mod.begin(
        "feature", allowed_paths=("src/**",), root=repo, repo=repo_bind
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv, repo / ".notari" / "contract.sig")
    _commit_all(repo, "notari: contract")
    return priv, pub, contract


def test_strict_wrong_repo_binding_blocks(repo: Path) -> None:
    """A validly-signed contract bound to repo A must BLOCK when verified as repo
    B (replay across repos). This strict branch had no end-to-end BLOCK test."""
    _priv, pub, contract = _signed_ready(repo, repo_bind="owner/name")
    (repo / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _commit_all(repo, "in-scope change")
    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env={provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "someone-else/other"},
    )
    assert result.verdict is Verdict.BLOCK
    assert any("repo" in r.lower() for r in result.reasons)


def test_strict_forged_base_non_ancestor_blocks(repo: Path) -> None:
    """A contract whose base_commit is a real commit but NOT an ancestor of HEAD
    (a forged/replayed base) must BLOCK in strict. The contract is signed by the
    TRUSTED approver so provenance passes and verify is forced into the ancestry
    check; the assertion on "ancestor" guards against passing on a wrong branch."""
    from notari import contract as _cm

    priv, pub, _ = _signed_ready(repo)
    # A sibling commit on a divergent branch: a real SHA that is NOT an ancestor
    # of the line we verify.
    _git(repo, "checkout", "-q", "-b", "sibling")
    (repo / "src" / "other.py").write_text("z = 9\n")
    _commit_all(repo, "sibling commit")
    sibling = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()
    _git(repo, "checkout", "-q", "main" if _has_main(repo) else "master")
    # Forge a contract pinned to the sibling base, signed by the trusted key so
    # provenance is valid and only the ancestry check can block it.
    forged, _ = contract_mod.begin(
        "feature", allowed_paths=("src/**",), root=repo, repo="owner/name", expires_in_days=7
    )
    forged_d = forged.to_dict()
    forged_d["base_commit"] = sibling
    forged2 = _cm.Contract.from_dict(forged_d)
    provenance_mod.sign_artifact(forged2.to_dict(), priv, repo / ".notari" / "contract.sig")
    (repo / "src" / "app.py").write_text("x = 1\nq = 2\n")
    _commit_all(repo, "change on main line")
    result = verify_mod.verify(
        contract=forged2,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=True,
        env={provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"},
    )
    assert result.verdict is Verdict.BLOCK
    assert any("ancestor" in r.lower() for r in result.reasons), result.reasons


def _has_main(repo: Path) -> bool:
    r = subprocess.run(
        ["git", "branch", "--list", "main"], cwd=repo, capture_output=True, text=True
    )
    return "main" in r.stdout


def test_confusable_path_blocks(repo: Path) -> None:
    """A mixed-script directory name (Cyrillic 'а' inside a Latin path) under a
    broad allow-scope must BLOCK (fail CI), never silent PASS or a soft review
    that merges by default."""
    _priv, pub, contract = _signed_ready(repo)
    # 'аuth' starts with Cyrillic U+0430, the rest Latin: mixed-script.
    sneaky = repo / "src" / "аuth"
    sneaky.mkdir(parents=True)
    (sneaky / "login.py").write_text("pw = 1\n")
    _commit_all(repo, "add mixed-script dir")
    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env={provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"},
    )
    assert result.verdict is Verdict.BLOCK
    assert any("homoglyph" in r or "mixed-script" in r for r in result.reasons)


def test_out_of_table_script_homoglyph_blocks(repo: Path) -> None:
    """Armenian and Cherokee lookalikes are NOT in the confusable table, so this
    exercises the cross-script-mixing path (the class the finite table misses).
    Both must BLOCK under a broad allow-scope."""
    _priv, pub, contract = _signed_ready(repo)
    # 'Аuth' with Armenian capital-O-like is subtle; use Cherokee 'Ꭺ' (U+13AA),
    # a strong 'A' lookalike, spliced into an otherwise-Latin segment.
    sneaky = repo / "src" / "Ꭺuth"
    sneaky.mkdir(parents=True)
    (sneaky / "x.py").write_text("pw = 1\n")
    _commit_all(repo, "add cherokee-mixed dir")
    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env={provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"},
    )
    assert result.verdict is Verdict.BLOCK
    assert any("mixes scripts" in r or "homoglyph" in r for r in result.reasons)


def test_legit_unicode_dir_still_passes(repo: Path) -> None:
    """A wholly non-Latin (single-script) directory name is legitimate and must
    NOT trip the homoglyph review, only cross-script mixing does."""
    _priv, pub, contract = _signed_ready(repo)
    # src is Latin, but the FILE name is wholly Cyrillic: single-script segment.
    d = repo / "src" / "документы"
    d.mkdir(parents=True)
    (d / "readme.py").write_text("x = 1\n")
    _commit_all(repo, "legit cyrillic dir")
    result = verify_mod.verify(
        contract=contract,
        root=repo,
        perimeter=perimeter_mod.load(repo),
        strict=False,
        env={provenance_mod.APPROVER_ENV: pub, "GITHUB_REPOSITORY": "owner/name"},
    )
    assert result.verdict is Verdict.PASS, result.reasons
