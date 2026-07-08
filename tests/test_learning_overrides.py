"""Step A tests: overrides.toml is read by the gate.

This closes the biggest single defect from the rc5 honest audit: the
`promote` command wrote overrides.toml but the hook never read it, so
promoting a loosening candidate had no effect on the gate.

Four invariants under test:

  1. A non-expired override for pattern_id `P` downshifts a default-
     HIGH-risk Edit on `P` from ask -> allow, with reason naming the
     remaining TTL.
  2. An expired override (promoted_at + ttl_days in the past) does
     NOT apply. The gate falls back to default ask.
  3. CRITICAL pattern-matches are NOT downshifted by an override,
     even when one exists for that pattern. The safety invariant is
     "loosening never widens beyond default-HIGH; CRITICAL stays
     critical regardless of TTL'd overrides."
  4. Override persistence: writing a new override via the same TOML
     format the `nota suggestions promote` CLI uses is read by the
     hook on the next invocation (no caching/staleness bug between
     write and read).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _isolate(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[session]\nintent = "t"\nscope = []\n[trust]\npaths = []\n')
    monkeypatch.setenv("NOTA_CONFIG", str(cfg))
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("NOTA_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("NOTA_LEARNING_LOG", str(tmp_path / "learning.log"))
    monkeypatch.setenv("NOTA_OVERRIDES", str(tmp_path / "overrides.toml"))
    monkeypatch.setenv("NOTA_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("NOTA_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("NOTA_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("NOTA_APPROVALS_FILE", str(tmp_path / "approvals.json"))
    monkeypatch.setenv("NOTA_NO_AUTO_WATCH", "1")
    monkeypatch.setenv("NOTA_BYPASS_MODE", "0")
    monkeypatch.setenv("NOTA_LEARNING_STRICT", "1")


def _write_override(
    overrides_path: Path,
    pattern_id: str,
    *,
    promoted_at: datetime,
    ttl_days: int,
    evidence: str = "manual test",
) -> None:
    """Format-compatible with what `nota suggestions promote` writes."""
    section = "".join(c if c.isalnum() or c in "_-" else "_" for c in pattern_id)[:60]
    block = (
        f"\n[overrides.{section}]\n"
        f'pattern_id = "{pattern_id}"\n'
        f'promoted_at = "{promoted_at.isoformat()}"\n'
        f"ttl_days = {ttl_days}\n"
        f'evidence = "{evidence}"\n'
    )
    existing = overrides_path.read_text() if overrides_path.exists() else ""
    overrides_path.write_text(existing + block)


def _payload(*, tool_name: str, session_id: str, transcript: str, cwd: str, **tool_input) -> str:
    return json.dumps(
        {
            "session_id": session_id,
            "transcript_path": transcript,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
    )


# ---------------------------------------------------------------------------
# Test A1: A non-expired override downshifts default-HIGH Edit.


def test_non_expired_override_downshifts_default_high_edit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    overrides_path = tmp_path / "overrides.toml"
    # Write override for the Edit default-risk pattern. Promoted 1d ago,
    # 14d TTL: still 13 days remaining.
    _write_override(
        overrides_path,
        pattern_id="Edit:high risk: default risk for Edit",
        promoted_at=datetime.now(UTC) - timedelta(days=1),
        ttl_days=14,
    )

    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s",
                transcript=str(transcript),
                cwd=str(tmp_path),
                file_path="/x.py",
                old_string="a",
                new_string="b",
            ),
            audit=audit,
        )

    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "operator-promoted override" in reason
    assert "days remaining" in reason


# ---------------------------------------------------------------------------
# Test A2: An expired override does NOT apply.


def test_expired_override_does_not_apply(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    overrides_path = tmp_path / "overrides.toml"
    # Promoted 30 days ago with a 7-day TTL - expired 23 days ago.
    _write_override(
        overrides_path,
        pattern_id="Edit:high risk: default risk for Edit",
        promoted_at=datetime.now(UTC) - timedelta(days=30),
        ttl_days=7,
    )

    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s",
                transcript=str(transcript),
                cwd=str(tmp_path),
                file_path="/x.py",
                old_string="a",
                new_string="b",
            ),
            audit=audit,
        )

    # Falls back to default ask. The expired override MUST NOT silently
    # extend itself; permission decay applies to loosenings too.
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "operator-promoted override" not in reason


# ---------------------------------------------------------------------------
# Test A3: CRITICAL events are NOT downshifted, even when an override
# exists for that pattern.


def test_critical_pattern_not_downshifted_by_override(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Safety invariant: an override only downshifts the DEFAULT-HIGH
    ask path. CRITICAL pattern matches (rm -rf, DROP TABLE, vercel
    --prod, etc.) MUST still deny regardless of any override block.
    """
    _isolate(monkeypatch, tmp_path)
    overrides_path = tmp_path / "overrides.toml"

    # Key the override to the EXACT pattern_id the CRITICAL DROP TABLE
    # event produces - the same f"{tool}:{normalized_reason}" the hook
    # computes on the downshift path. This is the load-bearing setup: a
    # non-matching key (e.g. "Bash:rm -rf") could never downshift the
    # event regardless of the guard, so it would let a broken guard pass
    # unnoticed. By making the override a genuine content match, the ONLY
    # thing standing between the override block and an allow verdict is
    # the `permission == "ask" and classified_by == "default"` guard.
    # A CRITICAL event is permission="deny"/classified_by="pattern", so
    # the guard must keep the block from ever firing.
    from nota.adapters.claude_code import decide, run_hook
    from nota.audit import AuditLog
    from nota.learn import _normalize_block_reason

    critical = decide("Bash", {"command": "DROP TABLE users"})
    assert critical.permission == "deny"
    assert critical.classified_by == "pattern"
    head = _normalize_block_reason(critical.reason) or critical.reason
    critical_pattern_id = f"Bash:{head}"[:80]
    _write_override(
        overrides_path,
        pattern_id=critical_pattern_id,
        promoted_at=datetime.now(UTC),
        ttl_days=30,
        evidence="attempted bypass",
    )
    # The override IS active and DOES key on this event's pattern_id, so
    # only the guard prevents a downshift.
    from nota.learning import load_active_overrides

    assert critical_pattern_id in load_active_overrides()

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        # Use a CRITICAL command that's NOT in any operator allowlist.
        # DROP TABLE bypasses /tmp/* allowlists entirely.
        out = run_hook(
            _payload(
                tool_name="Bash",
                session_id="s",
                transcript=str(transcript),
                cwd=str(tmp_path),
                command="DROP TABLE users",
            ),
            audit=audit,
        )

    # A matching, active override exists - yet the CRITICAL verdict must
    # stand. The downshift guard fires only on permission=="ask" AND
    # classified_by=="default"; a CRITICAL deny has neither, so the
    # override block is never reached. Dropping the guard (`if True:`)
    # would flip this exact event to an "operator-promoted override"
    # allow, so this assertion kills that mutant.
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "operator-promoted override" not in reason
    assert "DROP TABLE" in reason


# ---------------------------------------------------------------------------
# Test A4: Override persistence - written via the promote CLI format,
# read by the hook with no stale-cache issue.


def test_override_written_via_promote_format_is_read_by_hook(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The promote CLI writes overrides.toml in a specific format. The
    hook must read that EXACT format (same section names, same field
    names) on the very next invocation. No caching between write and
    read.
    """
    _isolate(monkeypatch, tmp_path)
    overrides_path = tmp_path / "overrides.toml"

    # Replicate the exact write the `suggestions_promote` CLI does.
    pattern_id = "Edit:high risk: default risk for Edit"
    section = "".join(c if c.isalnum() or c in "_-" else "_" for c in pattern_id)[:60]
    promoted_at_iso = datetime.now(UTC).isoformat()
    block = (
        f"\n[overrides.{section}]\n"
        f'pattern_id = "{pattern_id}"\n'
        f'promoted_at = "{promoted_at_iso}"\n'
        f"ttl_days = 14\n"
        f'evidence = "approval 80%"\n'
    )
    overrides_path.write_text(block)
    # Same-instant read must surface the override.
    from nota.learning import load_active_overrides

    active = load_active_overrides()
    assert pattern_id in active
    assert active[pattern_id]["ttl_days"] == 14
    assert active[pattern_id]["remaining_days"] > 13.99

    # Now exercise the full hook path - hook reads the file fresh on
    # each invocation, no daemon-cached state interferes.
    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        # Two back-to-back hook calls.
        out1 = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s1",
                transcript=str(transcript),
                cwd=str(tmp_path),
                file_path="/a.py",
                old_string="x",
                new_string="y",
            ),
            audit=audit,
        )
        out2 = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s1",
                transcript=str(transcript),
                cwd=str(tmp_path),
                file_path="/b.py",
                old_string="x",
                new_string="y",
            ),
            audit=audit,
        )

    # BOTH downshifted.
    for out in (out1, out2):
        assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        assert "operator-promoted override" in reason

    # Adding a SECOND override mid-test is also seen on the next call.
    new_pattern = "Write:high risk: default risk for Write"
    new_section = "".join(c if c.isalnum() or c in "_-" else "_" for c in new_pattern)[:60]
    overrides_path.write_text(
        block
        + f"\n[overrides.{new_section}]\n"
        + f'pattern_id = "{new_pattern}"\n'
        + f'promoted_at = "{promoted_at_iso}"\n'
        + "ttl_days = 14\n"
        + 'evidence = "manual"\n'
    )
    active2 = load_active_overrides()
    assert pattern_id in active2
    assert new_pattern in active2
