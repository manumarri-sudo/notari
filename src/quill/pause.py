"""Gate pause: a true, bounded, audited off switch for the whole gate.

The problem this solves: when the gate is in the way (a broken classifier,
a noisy session, a maintenance window), the operator needs ONE command to
turn it off - and historically the only escape hatches were editing
settings.json by hand or running the host agent with
`--dangerously-skip-permissions`, both of which destroy the audit trail.
That is the exact developer-failure-mode the kill-test doc warns about:
friction pushes people to bypass the gate in ways that leave no evidence.

`quill off` (alias `quill pause`) flips the gate fully off. The honesty
contract that makes this safe rather than a silent hole:

  1. BOUNDED - every pause auto-expires (default 1h, hard max 24h). A
     forgotten pause self-heals; the gate can never be left off forever.
  2. LOGGED - the pause and the resume are each their own audit event
     (gate.paused / gate.resumed) carrying reason, duration, and who.
  3. MARKED - every tool call allowed while paused is still written to the
     audit log with `gate_paused: true`, so "what ran while the gate was
     off" is answerable after the fact, call by call.

Difference from overnight mode (`quill night`): overnight auto-approves
HIGH but STILL gates CRITICAL (rm -rf, DROP TABLE, force-push, sudo). Pause
turns the gate fully off - including CRITICAL - because a half-off switch
that still blocks the destructive class is what drives operators to the
trail-destroying bypasses above. Pause trades the gate for accountability,
not for silence: the window is short, bounded, and every action in it is
on the record.

State file: $QUILL_HOME/pause.json (mode 0o600).
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_PAUSE_HOURS: float = 1.0
MAX_PAUSE_HOURS: float = 24.0


def _state_path() -> Path:
    from quill.paths import default_path

    return default_path("pause.json", env_override="QUILL_PAUSE_FILE")


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

    `paused`        True iff the operator ran `quill off` and the pause has
                    not yet auto-expired.
    `set_at`        ISO 8601 timestamp the pause was flipped on.
    `expires_at`    ISO 8601 timestamp the pause auto-expires.
    `reason`        Operator-supplied reason (free text), for the audit trail.
    `allowed_count` Cumulative count of tool calls allowed while this pause
                    window was active. Reset on each `pause()`.
    """

    paused: bool = False
    set_at: str = ""
    expires_at: str = ""
    reason: str = ""
    allowed_count: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "paused": self.paused,
            "set_at": self.set_at,
            "expires_at": self.expires_at,
            "reason": self.reason,
            "allowed_count": self.allowed_count,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> PauseState:
        return cls(
            paused=bool(raw.get("paused", False)),
            set_at=str(raw.get("set_at", "") or ""),
            expires_at=str(raw.get("expires_at", "") or ""),
            reason=str(raw.get("reason", "") or ""),
            allowed_count=int(raw.get("allowed_count", 0) or 0),
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
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return PauseState()


def save_state(state: PauseState) -> None:
    """Persist state. Best effort; errors swallowed (runs on the gate path)."""
    p = _state_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state.to_json(), indent=2, sort_keys=True))
        with contextlib.suppress(OSError):
            p.chmod(0o600)
    except OSError:
        pass


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
    hours = duration_hours
    if hours <= 0:
        hours = DEFAULT_PAUSE_HOURS
    hours = min(hours, MAX_PAUSE_HOURS)
    now = _now()
    state = PauseState(
        paused=True,
        set_at=now.isoformat(),
        expires_at=(now + timedelta(hours=hours)).isoformat(),
        reason=reason.strip(),
        allowed_count=0,
    )
    save_state(state)
    return state


def resume() -> PauseState:
    """Flip the gate back on. Preserves allowed_count for the resume recap."""
    state = load_state()
    state.paused = False
    save_state(state)
    return state


def record_allowed_while_paused() -> None:
    """Best-effort counter increment for a call let through while paused.

    Called from the gate path; swallows every exception so a persist
    failure can never affect (or break) the let-through decision.
    """
    try:
        state = load_state()
        state.allowed_count += 1
        save_state(state)
    except Exception:
        pass
