"""`notari audit verify` must detect trailing truncation, not just edits.

A cross-vendor review (Codex, 2026-07-22) found that seal_head/read_head existed
but no CLI path invoked them, so `notari audit verify` walked the chain without a
high-water-mark and reported a truncated log as intact. The chain links alone
cannot see truncation: deleting the last N entries leaves a shorter but still
valid chain. These tests drive the real CLI and pin that the sealed-mark path
now catches it. They fail against the pre-fix CLI (which passed no expected_count
and never sealed).
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from notari.audit import AuditLog
from notari.cli import _hmac_key, app


def _seed_log(path: Path, n: int) -> None:
    """Write n validly chained entries under the CLI's own HMAC key."""
    with AuditLog(path=path, hmac_key=_hmac_key()) as log:
        for i in range(n):
            log.emit(
                event_type="verdict.allowed",
                session_id="s",
                agent_id="a",
                risk="low",
                payload={"i": i},
            )


def test_first_verify_seals_a_high_water_mark(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    _seed_log(p, 5)
    r = CliRunner().invoke(app, ["audit", "verify", "--log", str(p)])
    assert r.exit_code == 0, r.output
    assert "chain intact" in r.output
    assert p.with_name(p.name + ".head").exists(), "verify should seal a .head sidecar"


def test_truncation_after_seal_is_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    _seed_log(p, 6)

    runner = CliRunner()
    first = runner.invoke(app, ["audit", "verify", "--log", str(p)])
    assert first.exit_code == 0, first.output

    # Delete the last two entries: the remaining chain is still internally valid.
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-2]))

    # A plain chain walk would call this intact; the sealed mark must catch it.
    second = runner.invoke(app, ["audit", "verify", "--log", str(p)])
    assert second.exit_code == 2, second.output
    # Rich may hard-wrap the message, so normalise whitespace before matching.
    normalised = " ".join(second.output.split())
    assert "BROKEN" in normalised
    assert "trailing entries were removed" in normalised


def test_legit_growth_after_seal_still_verifies(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    _seed_log(p, 3)

    runner = CliRunner()
    assert runner.invoke(app, ["audit", "verify", "--log", str(p)]).exit_code == 0

    # More real entries appended: total > sealed count is normal, not truncation.
    _seed_log(p, 2)  # appends onto the existing chain
    grown = runner.invoke(app, ["audit", "verify", "--log", str(p)])
    assert grown.exit_code == 0, grown.output
    assert "chain intact" in grown.output


def test_sealed_prefix_rewrite_is_detected(tmp_path: Path) -> None:
    # Red-team finding 6, the MAC half: after a clean verify seals (count, mac),
    # an attacker who keeps the same entry count but rewrites the pinned entry
    # (needs the key, but the check is cheap defense-in-depth) must be caught by
    # the sealed-mac comparison, not silently re-sealed as the new baseline.
    p = tmp_path / "audit.log.jsonl"
    _seed_log(p, 4)
    runner = CliRunner()
    assert runner.invoke(app, ["audit", "verify", "--log", str(p)]).exit_code == 0

    # Rebuild a DIFFERENT but internally valid 4-entry chain under the same key,
    # so count matches but the entry at the sealed position carries a new mac.
    p.unlink()
    _seed_log(p, 4)  # fresh chain, same length, different macs
    out = runner.invoke(app, ["audit", "verify", "--log", str(p)])
    assert out.exit_code == 2, out.output
    normalised = " ".join(out.output.split())
    assert "BROKEN" in normalised
    assert "sealed prefix was rewritten" in normalised
