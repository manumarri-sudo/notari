"""`notari verify-passport` checks validity, not just authenticity (review M-5).

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

from notari import attest
from notari import passport as passport_mod

_NOTARI = str(Path(sys.executable).parent / "notari")


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
        [_NOTARI, "verify-passport", str(pj), "--gate-key", str(pub), *args],
        capture_output=True,
        text=True,
        env={**os.environ, "NOTARI_GATE_PUBKEYS": ""},
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
    fp.write_text(f"sha={'a' * 40}\nmac={mac}\ncontext=notari/change-control\nstate=success\n")
    r = _run(pj, pub, "--status-fingerprint", str(fp))
    assert r.returncode == 0


def test_status_fingerprint_mismatch(tmp_path: Path) -> None:
    mac = "deadbeef" * 8
    pj, pub = _signed_passport(tmp_path, audit={"verification_run_mac": mac})
    fp = tmp_path / "status-fingerprint"
    fp.write_text(f"sha={'a' * 40}\nmac={'f' * 64}\ncontext=notari/change-control\nstate=success\n")
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


class TestReviewerIsToldWhatTheVerdictIsWorth:
    """A real signature does NOT mean the verdict was enforced.

    A cooperative run warns at verify time that the contract could have been forged by
    the same agent that wrote the diff, and records `strict: false` with an unverified
    `contract_provenance`. `verify-passport` read neither field, so the one command the
    docs point a reviewer at rendered "a human signed this boundary" and "the agent
    could have forged the contract" identically, as the same green tick."""

    def test_cooperative_passport_is_flagged_as_advisory(self, tmp_path: Path) -> None:
        pj, pub = _signed_passport(
            tmp_path, trust={"strict": False, "contract_provenance": "unsigned"}
        )
        proc = _run(pj, pub)
        # Rich wraps to the terminal width, so collapse whitespace before matching
        # prose; asserting on the raw text makes the test depend on column count.
        combined = " ".join((proc.stdout + proc.stderr).split())
        # Still authentic, so still exit 0: what changes is that the reviewer is told.
        assert proc.returncode == 0, combined
        assert "passport verified" in combined
        assert "not an enforced boundary" in combined
        assert "COOPERATIVE" in combined
        assert "provably approved by a human" in combined

    def test_strict_signed_passport_gets_no_caveat(self, tmp_path: Path) -> None:
        pj, pub = _signed_passport(
            tmp_path, trust={"strict": True, "contract_provenance": "verified"}
        )
        proc = _run(pj, pub)
        combined = " ".join((proc.stdout + proc.stderr).split())
        assert proc.returncode == 0, combined
        assert "passport verified" in combined
        assert "not an enforced boundary" not in combined

    def test_naive_contract_expiry_is_refused_not_crashed(self, tmp_path: Path) -> None:
        """`2027-01-01T00:00:00` is valid ISO-8601 with no offset. Comparing it against
        an aware now() raises TypeError, so a reviewer command must refuse rather than
        crash, and must not read an expiry it cannot evaluate as "not expired"."""
        pj, pub = _signed_passport(tmp_path, contract={"expires_at": "2027-01-01T00:00:00"})
        proc = _run(pj, pub)
        combined = " ".join((proc.stdout + proc.stderr).split())
        assert proc.returncode == 1, combined
        assert "no timezone" in combined
        assert "Traceback" not in combined
