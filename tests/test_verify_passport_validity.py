"""`quill verify-passport` checks validity, not just authenticity (review M-5).

A correctly gate-signed passport can still be the wrong candidate, stale, or have
an expired contract. The command now binds those with --head-sha / --max-age-days
and the contract's own expiry.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from quill import attest
from quill import passport as passport_mod

_QUILL = str(Path(sys.executable).parent / "quill")


def _signed_passport(tmp_path: Path, **overrides: object) -> tuple[Path, Path]:
    gate_priv, gate_pub = attest.generate_keypair()
    body: dict[str, object] = {
        "verdict": "PASS",
        "head_commit": "a" * 40,
        "generated_at": datetime.now(UTC).isoformat(),
        "contract": {"expires_at": None},
    }
    body.update(overrides)
    signed = passport_mod.sign_passport(body, gate_priv)
    pj = tmp_path / "passport.json"
    pj.write_text(json.dumps(signed))
    pub = tmp_path / "gate.pub"
    pub.write_text(gate_pub)
    return pj, pub


def _run(pj: Path, pub: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_QUILL, "verify-passport", str(pj), "--gate-key", str(pub), *args],
        capture_output=True,
        text=True,
        env={**os.environ, "QUILL_GATE_PUBKEYS": ""},
    )


def test_verifies_when_context_matches(tmp_path: Path) -> None:
    pj, pub = _signed_passport(tmp_path)
    assert _run(pj, pub, "--head-sha", "a" * 40).returncode == 0


def test_candidate_mismatch_fails(tmp_path: Path) -> None:
    pj, pub = _signed_passport(tmp_path)
    r = _run(pj, pub, "--head-sha", "b" * 40)
    assert r.returncode == 1
    assert "candidate mismatch" in (r.stdout + r.stderr)


def test_expired_contract_fails(tmp_path: Path) -> None:
    pj, pub = _signed_passport(tmp_path, contract={"expires_at": "2020-01-01T00:00:00+00:00"})
    r = _run(pj, pub)
    assert r.returncode == 1
    assert "expired" in (r.stdout + r.stderr)


def test_stale_passport_fails(tmp_path: Path) -> None:
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    pj, pub = _signed_passport(tmp_path, generated_at=old)
    r = _run(pj, pub, "--max-age-days", "1")
    assert r.returncode == 1
    assert "too old" in (r.stdout + r.stderr)


# ── status-fingerprint cross-check ───────────────────────────────────────────


def test_status_fingerprint_match(tmp_path: Path) -> None:
    mac = "deadbeef" * 8
    pj, pub = _signed_passport(tmp_path, audit={"verification_run_mac": mac})
    fp = tmp_path / "status-fingerprint"
    fp.write_text(f"sha={'a' * 40}\nmac={mac}\ncontext=quill/change-control\nstate=success\n")
    r = _run(pj, pub, "--status-fingerprint", str(fp))
    assert r.returncode == 0


def test_status_fingerprint_mismatch(tmp_path: Path) -> None:
    mac = "deadbeef" * 8
    pj, pub = _signed_passport(tmp_path, audit={"verification_run_mac": mac})
    fp = tmp_path / "status-fingerprint"
    fp.write_text(f"sha={'a' * 40}\nmac={'f' * 64}\ncontext=quill/change-control\nstate=success\n")
    r = _run(pj, pub, "--status-fingerprint", str(fp))
    assert r.returncode == 1
    assert "fingerprint mismatch" in (r.stdout + r.stderr)


def test_status_fingerprint_truncated_mac(tmp_path: Path) -> None:
    mac = "deadbeef" * 8
    pj, pub = _signed_passport(tmp_path, audit={"verification_run_mac": mac})
    fp = tmp_path / "status-fingerprint"
    fp.write_text(f"sha={'a' * 40}\nmac=bbb\n")
    r = _run(pj, pub, "--status-fingerprint", str(fp))
    assert r.returncode == 1
    assert "too short" in (r.stdout + r.stderr)


def test_status_fingerprint_no_passport_mac(tmp_path: Path) -> None:
    pj, pub = _signed_passport(tmp_path)
    fp = tmp_path / "status-fingerprint"
    fp.write_text(f"sha=aaa\nmac={'b' * 64}\n")
    r = _run(pj, pub, "--status-fingerprint", str(fp))
    assert r.returncode == 1
    assert "no audit MAC" in (r.stdout + r.stderr)
