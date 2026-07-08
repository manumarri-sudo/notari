"""Resource ceilings: an enormous diff or too many changed files must not exhaust
the runner, and — more importantly — an INCOMPLETE scan must never be reported as
a clean PASS. When coverage is incomplete, strict fails closed (BLOCK) and
cooperative surfaces it (NEEDS_REVIEW), with a disposition recorded as evidence."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from nota import contract as contract_mod
from nota import verify as verify_mod
from nota.verify import ScanLimits, Verdict, VerifyError, _git_capture, git_diff


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def _repo_with_big_change(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t.t")
    _git(root, "config", "user.name", "t")
    (root / "seed.txt").write_text("seed\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = _git(root, "rev-parse", "HEAD")
    # A large in-scope addition (~200 KiB of text).
    (root / "big.txt").write_text("x" * 200_000 + "\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "big change")
    return root, base


def test_scan_limits_from_env_parses_and_defaults() -> None:
    assert ScanLimits.from_env({}) == ScanLimits()
    lim = ScanLimits.from_env({"NOTA_MAX_DIFF_BYTES": "123", "NOTA_GIT_TIMEOUT": "9"})
    assert lim.max_diff_bytes == 123
    assert lim.git_timeout == 9
    # Junk / non-positive values fall back to the safe default.
    bad = ScanLimits.from_env({"NOTA_MAX_DIFF_BYTES": "-5", "NOTA_MAX_FILES": "abc"})
    assert bad.max_diff_bytes == ScanLimits().max_diff_bytes
    assert bad.max_files == ScanLimits().max_files


def test_git_diff_truncates_at_byte_ceiling(tmp_path: Path) -> None:
    root, base = _repo_with_big_change(tmp_path)
    text, truncated = git_diff(base, root, text=True, limits=ScanLimits(max_diff_bytes=1000))
    assert truncated is True
    assert len(text.encode()) <= 1000


def test_git_diff_not_truncated_under_ceiling(tmp_path: Path) -> None:
    root, base = _repo_with_big_change(tmp_path)
    _text, truncated = git_diff(base, root, text=True, limits=ScanLimits(max_diff_bytes=50_000_000))
    assert truncated is False


def test_capture_timeout_bounds_a_process_that_stalls_mid_read(tmp_path: Path) -> None:
    """Regression (R10 review): the deadline must be enforced on each read, not just
    between full chunks. A process that emits a few bytes and then stalls forever
    must still time out — a blocking BufferedReader.read(65536) would hang here."""
    start = time.monotonic()
    with pytest.raises(VerifyError, match="timed out"):
        # Emits 2 bytes (far under one 64 KiB read) then sleeps well past the ceiling.
        _git_capture(
            ["sh", "-c", "printf hi; sleep 30"],
            tmp_path,
            timeout=1,
            max_bytes=1_000_000,
        )
    assert time.monotonic() - start < 10, "timeout was not enforced promptly"


def test_oversized_diff_is_not_a_silent_pass_cooperative(tmp_path: Path) -> None:
    root, base = _repo_with_big_change(tmp_path)
    contract = contract_mod.Contract(
        version=1,
        task="big",
        task_source="text",
        allowed_paths=("**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="oversize",
    )
    result = verify_mod.verify(
        contract=contract, root=root, strict=False, env={"NOTA_MAX_DIFF_BYTES": "1000"}
    )
    assert result.verdict is not Verdict.PASS
    assert result.verdict is Verdict.NEEDS_REVIEW
    assert result.scan_dispositions
    assert any("oversized-diff" in d for d in result.scan_dispositions)


def test_oversized_diff_blocks_in_strict(tmp_path: Path) -> None:
    from nota import attest
    from nota import perimeter as perimeter_mod
    from nota import provenance as provenance_mod

    root, base = _repo_with_big_change(tmp_path)
    priv_pem, pub_pem = attest.generate_keypair()
    perim = perimeter_mod.default_perimeter(allowed_paths=("**",), approved_by="human")
    perim.write(root)
    provenance_mod.sign_artifact(perim.to_dict(), priv_pem, perimeter_mod.signature_path(root))

    contract = contract_mod.Contract(
        version=1,
        task="big",
        task_source="text",
        allowed_paths=("**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="oversize-strict",
        repo="owner/name",
    )
    provenance_mod.sign_artifact(contract.to_dict(), priv_pem, root / ".nota" / "contract.sig")
    env = {
        provenance_mod.APPROVER_ENV: pub_pem,
        "GITHUB_REPOSITORY": "owner/name",
        "NOTA_MAX_DIFF_BYTES": "1000",
    }
    result = verify_mod.verify(contract=contract, root=root, perimeter=perim, strict=True, env=env)
    assert result.verdict is Verdict.BLOCK
    assert any("incomplete scan coverage" in r for r in result.reasons)
