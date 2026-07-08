"""Gate pause / resume - the bounded, audited off switch.

Covers the state module (nota.pause) and the hook integration (a paused
gate lets calls through but logs them with gate_paused=true, and the pause
check runs BEFORE self_test so it works as a recovery hatch when the
classifier is broken).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import nota.pause as pause_mod
from nota.pause import (
    DEFAULT_PAUSE_HOURS,
    MAX_PAUSE_HOURS,
    PauseState,
    _now,
)


def _isolate(monkeypatch, tmp_path: Path) -> Path:
    p = tmp_path / "pause.json"
    monkeypatch.setattr(pause_mod, "_state_path", lambda: p)
    return p


def test_default_state_is_not_paused(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    paused, reason = pause_mod.is_paused()
    assert paused is False
    assert reason == ""


def test_pause_then_is_paused(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(duration_hours=1.0, reason="testing")
    paused, reason = pause_mod.is_paused()
    assert paused is True
    assert reason == "testing"


def test_resume_clears_pause(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    pause_mod.resume()
    paused, _ = pause_mod.is_paused()
    assert paused is False


def test_expired_pause_reads_as_not_paused(monkeypatch, tmp_path: Path) -> None:
    """A pause whose window has passed must read as gate-ON. The flag may
    still be True on disk; expiry alone flips behaviour back to safe."""
    _isolate(monkeypatch, tmp_path)
    state = pause_mod.pause(duration_hours=1.0, reason="x")
    # Force expiry by rewriting expires_at into the past.
    state.expires_at = (_now() - timedelta(minutes=1)).isoformat()
    pause_mod.save_state(state)
    paused, _ = pause_mod.is_paused()
    assert paused is False


def test_duration_clamped_to_max(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    state = pause_mod.pause(duration_hours=999.0, reason="x")
    remaining = state.remaining()
    assert remaining is not None
    # Never more than the hard ceiling (+a little slack for execution time).
    assert remaining <= timedelta(hours=MAX_PAUSE_HOURS) + timedelta(seconds=5)


def test_nonpositive_duration_falls_back_to_default(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    state = pause_mod.pause(duration_hours=0, reason="x")
    remaining = state.remaining()
    assert remaining is not None
    assert remaining > timedelta(hours=DEFAULT_PAUSE_HOURS) - timedelta(minutes=1)


def test_corrupt_state_file_safe_defaults_to_on(monkeypatch, tmp_path: Path) -> None:
    """A garbled state file must NEVER read as paused - the failure mode of
    this file is 'gate stays on', never 'gate silently off'."""
    p = _isolate(monkeypatch, tmp_path)
    p.write_text("{ not valid json")
    paused, _ = pause_mod.is_paused()
    assert paused is False


def test_paused_with_unparseable_expiry_is_not_paused(monkeypatch, tmp_path: Path) -> None:
    p = _isolate(monkeypatch, tmp_path)
    p.write_text(json.dumps({"paused": True, "expires_at": "not-a-date", "reason": "x"}))
    paused, _ = pause_mod.is_paused()
    assert paused is False


def test_record_allowed_increments_counter(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    pause_mod.record_allowed_while_paused()
    pause_mod.record_allowed_while_paused()
    assert pause_mod.load_state().allowed_count == 2


def test_pause_resets_allowed_counter(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    pause_mod.record_allowed_while_paused()
    pause_mod.pause(reason="y")  # new window
    assert pause_mod.load_state().allowed_count == 0


def test_state_roundtrip_json() -> None:
    s = PauseState(paused=True, set_at="t0", expires_at="t1", reason="r", allowed_count=3)
    assert PauseState.from_json(s.to_json()) == s


def test_paused_hook_allows_critical_and_logs_marker(monkeypatch, tmp_path: Path) -> None:
    """While paused, a command that would otherwise be CRITICAL-denied is
    allowed - and the let-through is written to the audit log with
    gate_paused=true. The classifier is never consulted on this path."""
    from nota.adapters.claude_code import _handle_paused

    _isolate(monkeypatch, tmp_path)
    log_path = tmp_path / "audit.jsonl"
    payload = json.dumps(
        {
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/x"},  # CRITICAL when gated
            "cwd": "/tmp",
        }
    )
    out = _handle_paused(payload, log_path, "maintenance")
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"

    lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    allowed = [e for e in lines if e.get("payload", {}).get("gate_paused") is True]
    assert len(allowed) == 1
    assert allowed[0]["payload"]["pause_reason"] == "maintenance"
    assert allowed[0]["payload"]["tool_name"] == "Bash"
