"""The remaining 0.5.5 fixes: scanner context across lines, audit events in
transition order, and a lock descriptor that cannot leak on open failure.
Each item cites the Codex review finding (2026-11-08) that produced it.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

import notari.pause as pause_mod
from notari.secrets import redact, scan

# ---------------------------------------------------------------------------
# Finding 6: a mysql password supplied through an argument array or a variable
# sits on a different line from the tool name.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'args=(\n  -u root\n  -pR8vN4xQ7mT2k\n)\nmysql "${args[@]}"',
        "dbcmd=mysql\n$dbcmd -pR8vN4xQ7mT2k",
        "mysql \\\n  -u root \\\n  -pR8vN4xQ7mT2k database",
    ],
)
def test_attached_pflag_context_spans_the_whole_text(text: str) -> None:
    assert any(h.pattern_name == "mysql-pflag" for h in scan(text))
    assert "R8vN4xQ7mT2k" not in redact(text)


def test_attached_pflag_still_ignores_ffmpeg_without_a_password_tool() -> None:
    text = "ffmpeg -i in.mov -pix_fmt yuv420p -profile:v high -preset slow out.mp4"
    assert not [h for h in scan(text) if h.pattern_name == "mysql-pflag"]


# ---------------------------------------------------------------------------
# Finding 8: audit events emitted after the lock was released could land out
# of transition order. The after_save callback runs under the lock.
# ---------------------------------------------------------------------------


def _isolate(monkeypatch, tmp_path: Path) -> Path:
    p = tmp_path / "pause.json"
    monkeypatch.setattr(pause_mod, "_state_path", lambda: p)
    return p


def test_after_save_runs_under_the_lock_so_events_keep_transition_order(
    monkeypatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    events: list[str] = []

    def slow_pause_record(new: pause_mod.PauseState, superseded) -> None:
        time.sleep(0.05)  # a slow audit append, still inside the lock
        events.append("paused")

    def resume_record(closed: pause_mod.PauseState) -> None:
        events.append("resumed")

    pauser = threading.Thread(
        target=lambda: pause_mod.replace_pause(
            duration_hours=1, reason="x", after_save=slow_pause_record
        )
    )
    pauser.start()
    time.sleep(0.01)
    # Blocks on the lock until the pause record has been appended.
    closed = pause_mod.resume_if_paused(after_save=resume_record)
    pauser.join()

    assert closed is not None and closed.reason == "x"
    assert events == ["paused", "resumed"]
    assert pause_mod.load_state().paused is False


def test_after_save_is_not_called_when_nothing_changed(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    called: list[pause_mod.PauseState] = []
    assert pause_mod.resume_if_paused(after_save=called.append) is None
    assert called == []


def test_superseded_window_is_handed_to_the_callback(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    pause_mod.pause(reason="old")
    seen: list[tuple[str, str | None]] = []
    pause_mod.replace_pause(
        duration_hours=1,
        reason="new",
        after_save=lambda new, old: seen.append((new.reason, old.reason if old else None)),
    )
    assert seen == [("new", "old")]


# ---------------------------------------------------------------------------
# Finding 11: the lock descriptor is opened inside the try, so a failure
# between open and lock cannot leak it, and a failed open closes nothing.
# ---------------------------------------------------------------------------


def test_failed_lock_open_closes_nothing_and_propagates(monkeypatch, tmp_path: Path) -> None:
    _isolate(monkeypatch, tmp_path)
    closed: list[int] = []
    monkeypatch.setattr(pause_mod.os, "close", closed.append)

    def failing_open(*args, **kwargs):
        raise OSError("no fd for you")

    monkeypatch.setattr(pause_mod.os, "open", failing_open)
    with pytest.raises(OSError), pause_mod._state_lock():
        pass
    assert closed == []


def test_state_json_round_trip_keeps_per_log_counts() -> None:
    state = pause_mod.PauseState(
        paused=True, set_at="t0", expires_at="t1", reason="r", allowed_count=3
    )
    state.allowed_by_log["/a"] = 3
    raw = json.loads(json.dumps(state.to_json()))
    assert pause_mod.PauseState.from_json(raw) == state
