"""The remaining 0.5.5 fixes: scanner context across lines without the
ffmpeg false positive, resume that never waits on audit I/O, transition
events that reconcile with the per-log counts, and a lock descriptor that
cannot leak on open failure. Each item cites the Codex review finding
(2026-11-08) or Manu's numbered item that produced it.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

import notari.pause as pause_mod
from notari.cli import app
from notari.pause import _now
from notari.secrets import redact, scan

# ---------------------------------------------------------------------------
# Item 4 / review finding 6 and 7: a mysql password supplied through an
# argument array or a variable sits on another line, while a mention of mysql
# in a comment must not turn an ffmpeg flag into a credential.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'args=(\n  -u root\n  -pR8vN4xQ7mT2k\n)\nmysql "${args[@]}"',
        "dbcmd=mysql\n$dbcmd -pR8vN4xQ7mT2k",
        "mysql \\\n  -u root \\\n  -pR8vN4xQ7mT2k database",
        "sudo mysqldump -u root -pR8vN4xQ7mT2k app > dump.sql",
    ],
)
def test_attached_pflag_context_is_the_tool_in_command_position(text: str) -> None:
    assert any(h.pattern_name == "mysql-pflag" for h in scan(text))
    assert "R8vN4xQ7mT2k" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "ffmpeg -i in.mov -pix_fmt yuv420p -profile:v high -preset slow out.mp4",
        "# mysql migration below\nffmpeg -i in.mov -pix_fmt yuv420p -profile:v high -preset slow out.mp4",
        "# TODO: move the data to mysql one day\nffmpeg -i a.mov -pix_fmt yuv420p b.mp4",
    ],
)
def test_mixed_file_with_a_mysql_mention_does_not_flag_ffmpeg(text: str) -> None:
    assert not [h for h in scan(text) if h.pattern_name == "mysql-pflag"]


@pytest.mark.parametrize("separator", ["\n", " && ", "; "])
def test_attached_password_stays_with_its_command(separator: str) -> None:
    credential = "R8vN4xQ7mT2k"
    text = (
        f"mysql -p{credential} app{separator}ffmpeg -i in.mov -profile:v high -preset slow out.mp4"
    )
    hits = [h for h in scan(text) if h.pattern_name == "mysql-pflag"]
    assert [text[h.matched_at : h.matched_at + h.length] for h in hits] == [credential]


def test_pflag_context_is_computed_once_per_scan() -> None:
    # 10,000 candidate flags with no tool anywhere: the first candidate took
    # 13 s on the first candidate because the whole text was searched per hit.
    text = "tool -pAbC123456\n" * 10000
    t0 = time.monotonic()
    hits = scan(text)
    assert time.monotonic() - t0 < 1.0
    assert not [h for h in hits if h.pattern_name == "mysql-pflag"]


# ---------------------------------------------------------------------------
# Item 3 / review finding 4: resume must restore gating even while another
# process holds the audit file's lock, and the transition events must still
# reconcile with the per-log counts.
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "notari-home"
    home.mkdir()
    monkeypatch.setenv("NOTARI_HOME", str(home))
    monkeypatch.delenv("NOTARI_PAUSE_FILE", raising=False)
    monkeypatch.delenv("NOTARI_LOG", raising=False)
    # `notari off` authenticates the human first; with Touch ID reported absent
    # and the tty challenge failing, `--no-biometric` is the documented headless
    # opt-in, so the suite never pops a Touch ID dialog on the operator's Mac.
    from notari import cli as cli_mod
    from notari import touchid

    monkeypatch.setattr(touchid, "is_available", lambda: False)
    monkeypatch.setattr(cli_mod, "_human_tty_challenge", lambda *_a, **_k: False)
    return home


def _events(home: Path) -> list[dict]:
    log = home / "audit.log.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def _off(reason: str) -> None:
    result = CliRunner().invoke(app, ["off", "--for", "1h", "--reason", reason, "--no-biometric"])
    assert result.exit_code == 0, result.output


def test_manual_resume_restores_gating_while_the_audit_lock_is_held(isolated_home: Path) -> None:
    _off("contention")
    assert pause_mod.is_paused()[0] is True
    log = isolated_home / "audit.log.jsonl"
    assert log.stat().st_size > 0

    holder = os.open(log, os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX)
    results: list = []
    try:
        worker = threading.Thread(target=lambda: results.append(CliRunner().invoke(app, ["on"])))
        worker.start()
        deadline = time.monotonic() + 3.0
        while pause_mod.load_state().paused and time.monotonic() < deadline:
            time.sleep(0.02)
        # The gate is back on while the audit append is still blocked.
        assert pause_mod.is_paused()[0] is False
        assert worker.is_alive()
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert results and results[0].exit_code == 0, results[0].output if results else "no result"
    resumed = [e for e in _events(isolated_home) if e["type"] == "gate.resumed"]
    assert len(resumed) == 1 and resumed[0]["payload"]["trigger"] == "manual"


def test_transitions_stay_ordered_and_reconcile_with_per_log_counts(isolated_home: Path) -> None:
    from notari.adapters.claude_code import _emit_resume_if_expired

    audit = isolated_home / "audit.log.jsonl"
    log1 = isolated_home / "project-a" / "audit.log.jsonl"
    log2 = isolated_home / "project-b" / "audit.log.jsonl"

    _off("A")
    pause_mod.record_allowed_while_paused(log1)
    pause_mod.record_allowed_while_paused(log1)
    pause_mod.record_allowed_while_paused(log2)
    _off("B")  # supersedes A
    pause_mod.record_allowed_while_paused(log1)
    state = pause_mod.load_state()
    state.expires_at = (_now() - timedelta(minutes=1)).isoformat()
    pause_mod.save_state(state)
    _emit_resume_if_expired(audit)  # the hook closes the expired window B
    _off("C")
    assert CliRunner().invoke(app, ["on"]).exit_code == 0

    events = [e for e in _events(isolated_home) if e["type"] in ("gate.paused", "gate.resumed")]
    kinds = [(e["type"], e["payload"].get("trigger", e["payload"].get("reason"))) for e in events]
    assert kinds == [
        ("gate.paused", "A"),
        ("gate.resumed", "superseded"),
        ("gate.paused", "B"),
        ("gate.resumed", "auto-expired"),
        ("gate.paused", "C"),
        ("gate.resumed", "manual"),
    ]
    for opened, closed in zip(events[0::2], events[1::2], strict=True):
        assert closed["payload"]["pause_set_at"] == opened["payload"]["pause_set_at"]
        recap = closed["payload"]
        assert recap["allowed_while_paused"] == sum(recap["allowed_by_log"].values())
    recaps = [e["payload"] for e in events if e["type"] == "gate.resumed"]
    assert recaps[0]["allowed_while_paused"] == 3
    assert recaps[0]["allowed_by_log"] == {str(log1): 2, str(log2): 1}
    assert recaps[1]["allowed_while_paused"] == 1
    assert recaps[2]["allowed_while_paused"] == 0
    assert pause_mod.is_paused()[0] is False


# ---------------------------------------------------------------------------
# Review finding 11: the lock descriptor is opened inside the cleanup try, so
# a failed open closes nothing and propagates.
# ---------------------------------------------------------------------------


def test_failed_lock_open_closes_nothing_and_propagates(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(pause_mod, "_state_path", lambda: tmp_path / "pause.json")
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
