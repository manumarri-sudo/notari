"""Gate pause / resume - the bounded, audited off switch.

Covers the state module (notari.pause) and the hook integration (a paused
gate lets calls through but logs them with gate_paused=true, and the pause
check runs BEFORE self_test so it works as a recovery hatch when the
classifier is broken).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import notari.pause as pause_mod
from notari.pause import (
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
    from notari.adapters.claude_code import _handle_paused

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


# ---------------------------------------------------------------------------
# `notari state`: the one-line banner must tell the truth about a pause
# ---------------------------------------------------------------------------


def test_state_reports_on_when_not_paused(monkeypatch, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from notari.cli import app

    _isolate(monkeypatch, tmp_path)
    result = CliRunner().invoke(app, ["state"])
    assert result.exit_code == 0
    assert "Notari is on" in result.output
    assert "PAUSED" not in result.output


def test_state_reports_pause_with_remaining_and_count(monkeypatch, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from notari.cli import app

    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(duration_hours=1, reason="classifier false positive")
    pause_mod.record_allowed_while_paused()
    pause_mod.record_allowed_while_paused()
    result = CliRunner().invoke(app, ["state"])
    assert result.exit_code == 0
    assert "PAUSED" in result.output
    assert "classifier false positive" in result.output
    assert "2 call(s)" in result.output
    assert "Notari is on" not in result.output


def test_state_reports_on_after_pause_expires(monkeypatch, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from notari.cli import app

    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(duration_hours=1, reason="x")
    st = pause_mod.load_state()
    st.expires_at = (pause_mod._now() - timedelta(minutes=1)).isoformat()
    pause_mod.save_state(st)
    result = CliRunner().invoke(app, ["state"])
    assert result.exit_code == 0
    assert "Notari is on" in result.output


# ---------------------------------------------------------------------------
# 0.5.1: the recap must reconcile with the rows (six-month audit read, 2026-11-08)
# ---------------------------------------------------------------------------


def test_record_allowed_tracks_each_log(monkeypatch, tmp_path: Path) -> None:
    # A project with its own .notari/ routes its rows to a per-project log while
    # the recap lands in the global one; 180 of a 186-call recap sat in a project
    # log on 2026-07-27. The split is what lets a reader of one log reconcile.
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    pause_mod.record_allowed_while_paused("/a/audit.log.jsonl")
    pause_mod.record_allowed_while_paused("/a/audit.log.jsonl")
    pause_mod.record_allowed_while_paused("/b/.notari/audit.log.jsonl")
    s = pause_mod.load_state()
    assert s.allowed_count == 3
    assert s.allowed_by_log == {"/a/audit.log.jsonl": 2, "/b/.notari/audit.log.jsonl": 1}


def test_concurrent_increments_are_not_lost(monkeypatch, tmp_path: Path) -> None:
    # Parallel hooks both read N and both wrote N+1 (67 rows against a recap of 55
    # on 2026-06-12). The state file now takes a lock around read-modify-write.
    from concurrent.futures import ThreadPoolExecutor

    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: pause_mod.record_allowed_while_paused("/a"), range(160)))
    assert pause_mod.load_state().allowed_count == 160


def test_resume_if_paused_flips_exactly_once(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="x")
    first = pause_mod.resume_if_paused()
    assert first is not None and first.paused is False
    assert pause_mod.resume_if_paused() is None
    assert pause_mod.record_allowed_while_paused("/a") is None


def test_replacement_keeps_the_new_window_open_and_returns_previous_counts(
    monkeypatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    old = pause_mod.pause(reason="old")
    pause_mod.record_allowed_while_paused("/a")
    current, recap = pause_mod.replace_pause(duration_hours=1, reason="new")
    assert recap is not None and recap.set_at == old.set_at
    assert recap.allowed_by_log == {"/a": 1}
    assert pause_mod.resume_if_paused(expired_only=True) is None
    assert pause_mod.load_state() == current


def test_state_json_without_split_still_loads() -> None:
    raw = {"paused": True, "set_at": "t0", "expires_at": "t1", "reason": "r", "allowed_count": 3}
    assert PauseState.from_json(raw).allowed_by_log == {}


def test_expired_pause_recap_is_emitted_once(monkeypatch, tmp_path: Path) -> None:
    # Two hooks noticing the same expired pause wrote two gate.resumed rows on
    # 2026-06-12; only the process that flips the flag may emit the recap.
    from notari.adapters.claude_code import _emit_resume_if_expired

    _isolate(monkeypatch, tmp_path)
    log_path = tmp_path / "audit.jsonl"
    pause_mod.pause(reason="x", duration_hours=1)
    pause_mod.record_allowed_while_paused(str(log_path))
    state = pause_mod.load_state()
    state.expires_at = (_now() - timedelta(minutes=1)).isoformat()
    pause_mod.save_state(state)

    _emit_resume_if_expired(log_path)
    _emit_resume_if_expired(log_path)

    lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    resumed = [e for e in lines if e.get("type") == "gate.resumed"]
    assert len(resumed) == 1
    assert resumed[0]["payload"]["trigger"] == "auto-expired"
    assert resumed[0]["payload"]["allowed_while_paused"] == 1
    assert resumed[0]["payload"]["allowed_by_log"] == {str(log_path): 1}
    assert pause_mod.load_state().paused is False


def test_failed_expiry_update_writes_no_recap(monkeypatch, tmp_path: Path) -> None:
    from notari.adapters.claude_code import _emit_resume_if_expired

    _isolate(monkeypatch, tmp_path)
    state = pause_mod.pause(reason="x")
    state.expires_at = (_now() - timedelta(minutes=1)).isoformat()
    pause_mod.save_state(state)
    monkeypatch.setattr(pause_mod, "save_state", lambda _: False)
    log = tmp_path / "audit.jsonl"
    _emit_resume_if_expired(log)
    assert not log.exists()
    assert pause_mod.load_state().paused
