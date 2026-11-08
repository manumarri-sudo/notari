"""Gate pause: a true, bounded, audited off switch for the whole gate.

The problem this solves: when the gate is in the way (a broken classifier,
a noisy session, a maintenance window), the operator needs ONE command to
turn it off - and historically the only escape hatches were editing
settings.json by hand or running the host agent with
`--dangerously-skip-permissions`, both of which destroy the audit trail.
That is the exact developer-failure-mode the kill-test doc warns about:
friction pushes people to bypass the gate in ways that leave no evidence.

`notari off` (alias `notari pause`) flips the gate fully off. The honesty
contract that makes this safe rather than a silent hole:

  1. BOUNDED - every pause auto-expires (default 1h, hard max 24h). A
     forgotten pause self-heals; the gate can never be left off forever.
  2. LOGGED - the pause and the resume are each their own audit event
     (gate.paused / gate.resumed) carrying reason, duration, and who.
  3. MARKED - every tool call allowed while paused is still written to the
     audit log with `gate_paused: true`, so "what ran while the gate was
     off" is answerable after the fact, call by call.

Difference from overnight mode (`notari night`): overnight auto-approves
HIGH but STILL gates CRITICAL (rm -rf, DROP TABLE, force-push, sudo). Pause
turns the gate fully off - including CRITICAL - because a half-off switch
that still blocks the destructive class is what drives operators to the
trail-destroying bypasses above. Pause trades the gate for accountability,
not for silence: the window is short, bounded, and every action in it is
on the record.

State file: $NOTARI_HOME/pause.json (mode 0o600).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import fcntl  # POSIX only

    _HAS_FLOCK = True
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
    _HAS_FLOCK = False

DEFAULT_PAUSE_HOURS: float = 1.0
MAX_PAUSE_HOURS: float = 24.0


def _state_path() -> Path:
    from notari.paths import default_path

    return default_path("pause.json", env_override="NOTARI_PAUSE_FILE")


@contextlib.contextmanager
def _state_lock() -> Iterator[None]:
    """Serialize updates without hanging a hook if the lock is unavailable."""
    if not _HAS_FLOCK:
        yield
        return
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = -1
    try:
        # Opened inside the try so a signal between open and the lock loop cannot
        # leak the descriptor (Codex review of 0.5.1, finding 11).
        fd = os.open(f"{p}.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        deadline = time.monotonic() + 2
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("could not acquire the Notari pause lock") from exc
                time.sleep(0.01)
        yield
    finally:
        if fd >= 0:
            os.close(fd)


def _now() -> datetime:
    """Current time as a timezone-aware datetime (local zone).

    Stored/compared in local time for the same reason overnight does: the
    operator reasons about "I paused it at 3pm for an hour" in wall-clock
    terms, and the audit reader is a human in the operator's timezone.
    """
    return datetime.now(UTC).astimezone()


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


@dataclass(slots=True)
class PauseState:
    """On-disk record of the pause toggle.

    `paused`        True iff the operator ran `notari off` and the pause has
                    not yet auto-expired.
    `set_at`        ISO 8601 timestamp the pause was flipped on.
    `expires_at`    ISO 8601 timestamp the pause auto-expires.
    `reason`        Operator-supplied reason (free text), for the audit trail.
    `allowed_count` Cumulative count of tool calls allowed while this pause
                    window was active. Reset on each `pause()`.
    `allowed_by_log` Counts by destination audit log, including project logs.
    """

    paused: bool = False
    set_at: str = ""
    expires_at: str = ""
    reason: str = ""
    allowed_count: int = 0
    allowed_by_log: dict[str, int] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "paused": self.paused,
            "set_at": self.set_at,
            "expires_at": self.expires_at,
            "reason": self.reason,
            "allowed_count": self.allowed_count,
            "allowed_by_log": dict(self.allowed_by_log),
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> PauseState:
        return cls(
            paused=bool(raw.get("paused", False)),
            set_at=str(raw.get("set_at", "") or ""),
            expires_at=str(raw.get("expires_at", "") or ""),
            reason=str(raw.get("reason", "") or ""),
            allowed_count=int(raw.get("allowed_count", 0) or 0),
            allowed_by_log=_int_map(raw.get("allowed_by_log")),
        )

    def remaining(self, *, now: datetime | None = None) -> timedelta | None:
        """Time left before auto-expiry, or None if not pause-active."""
        expires = _parse_iso(self.expires_at)
        if expires is None:
            return None
        n = now or _now()
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC).astimezone()
        delta = expires - n
        return delta if delta.total_seconds() > 0 else None


def _int_map(raw: Any) -> dict[str, int]:
    """Tolerant parse of the per-log split; anything malformed reads as empty."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        with contextlib.suppress(TypeError, ValueError, OverflowError):
            out[str(k)] = int(v)
    return out


def load_state() -> PauseState:
    """Read state from disk. Returns a fresh default on any read error.

    Safe-default by design: a corrupt or unreadable state file MUST NOT
    flip the gate OFF by accident. We always fall back to the not-paused
    default - the failure mode of this file is "gate stays on", never
    "gate silently off".
    """
    p = _state_path()
    if not p.exists():
        return PauseState()
    try:
        raw = json.loads(p.read_text() or "{}")
        if not isinstance(raw, dict):
            return PauseState()
        return PauseState.from_json(raw)
    except (OSError, ValueError, TypeError, OverflowError):
        return PauseState()


def save_state(state: PauseState) -> bool:
    """Persist state. Best effort; errors swallowed (runs on the gate path)."""
    p = _state_path()
    temp = None
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=p.parent, delete=False) as stream:
            temp = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state.to_json(), stream, indent=2, sort_keys=True)
        os.replace(temp, p)
        return True
    except OSError:
        if temp is not None:
            with contextlib.suppress(OSError):
                temp.unlink()
        return False


def is_paused(
    state: PauseState | None = None,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Return (paused, reason).

    True iff the operator flipped the gate off AND the pause has not yet
    auto-expired. A paused state with no/un-parseable expiry is treated as
    NOT paused (malformed data → safe-default the gate back on).
    """
    s = state if state is not None else load_state()
    if not s.paused:
        return False, ""
    if s.remaining(now=now) is None:
        return False, ""
    return True, (s.reason or "no reason given")


def pause(
    *,
    duration_hours: float = DEFAULT_PAUSE_HOURS,
    reason: str = "",
) -> PauseState:
    """Flip the gate off. Auto-expires after `duration_hours` (clamped to
    (0, MAX_PAUSE_HOURS]). Resets the allowed-while-paused counter so it
    measures only this window."""
    return replace_pause(duration_hours=duration_hours, reason=reason)[0]


def replace_pause(*, duration_hours: float, reason: str) -> tuple[PauseState, PauseState | None]:
    """Start a new window and return any old window that needs a recap.

    Audit events for the transition are emitted by the caller AFTER the lock
    is released: the audit log takes its own blocking flock, and holding the
    state lock across that wait let a stalled audit writer keep `notari on`
    from clearing a pause (Codex review of 0.5.5, finding 4). Readers order
    transitions by the `pause_set_at` each event carries, not by file order.
    """
    hours = duration_hours
    if hours <= 0:
        hours = DEFAULT_PAUSE_HOURS
    hours = min(hours, MAX_PAUSE_HOURS)
    with _state_lock():
        previous = load_state()
        now = _now()
        state = PauseState(
            paused=True,
            set_at=now.isoformat(),
            expires_at=(now + timedelta(hours=hours)).isoformat(),
            reason=reason.strip(),
            allowed_count=0,
        )
        if not save_state(state):
            raise OSError("could not save the new Notari pause")
    return state, previous if previous.paused else None


def resume() -> PauseState:
    """Flip the gate back on. Preserves allowed_count for the resume recap."""
    with _state_lock():
        state = load_state()
        state.paused = False
        if not save_state(state):
            raise OSError("could not clear the Notari pause")
    return state


def resume_if_paused(*, expired_only: bool = False) -> PauseState | None:
    """Flip the gate back on only if the flag is still set; None if it was not.

    Exactly one caller wins when several hook processes notice an expired
    pause at the same time, so the gate.resumed bracket is emitted once. The
    caller emits that event after the lock is released (see replace_pause).
    """
    with _state_lock():
        state = load_state()
        if not state.paused or (expired_only and is_paused(state)[0]):
            return None
        state.paused = False
        if not save_state(state):
            raise OSError("could not clear the Notari pause")
    return state


def record_allowed_while_paused(
    log_path: str | os.PathLike[str] | None = None,
) -> PauseState | None:
    """Best-effort counter increment for a call let through while paused.

    `log_path` is the destination for the call's audit row. Return the
    active window only when the call was admitted to it.
    """
    try:
        with _state_lock():
            state = load_state()
            if not is_paused(state)[0]:
                return None
            state.allowed_count += 1
            if log_path is not None:
                key = str(log_path)
                state.allowed_by_log[key] = state.allowed_by_log.get(key, 0) + 1
            return state if save_state(state) else None
    except Exception:
        return None
