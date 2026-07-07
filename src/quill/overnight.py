"""Overnight mode: auto-approve HIGH risk so unattended agents do not stall.

Safety contract (load-bearing, do not weaken):
  CRITICAL risk is NEVER auto-approved by overnight mode. The whole point of
  CRITICAL (rm -rf, DROP TABLE, vercel --prod, git push --force, sudo, etc.)
  is that you wake up to find the deploy did NOT happen rather than waking
  up to find the wrong thing was overwritten. Overnight mode trades attended
  HIGH-risk friction for sleep, not safety.

Active sources, evaluated in order:
  1. Manual toggle from `quill night` (highest priority, time-bounded)
  2. Configured `[overnight] enabled = true` window in config.toml

The manual toggle has a hard auto-expiry (default 12h) so a forgotten flip
cannot leave the gate degraded indefinitely.

State file: $QUILL_HOME/overnight.json (mode 0o600).
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

DEFAULT_AUTO_EXPIRE_HOURS: float = 12.0


def _state_path() -> Path:
    from quill.paths import default_path

    return default_path("overnight.json", env_override="QUILL_OVERNIGHT_FILE")


def _now() -> datetime:
    """Current local time as a timezone-aware datetime.

    We keep the gate's notion of "now" in the operator's local zone because
    the configured overnight window (default 22:00-08:00) is a wall-clock
    statement, not a UTC-relative one. Operators sleep on local time.
    """
    return datetime.now(UTC).astimezone()


@dataclass(slots=True)
class OvernightState:
    """On-disk record of the manual toggle plus session counters.

    `enabled`        True iff the user ran `quill night [on]` and the toggle
                     has not yet auto-expired.
    `set_at`         ISO 8601 timestamp the toggle was flipped on (empty when off).
    `expires_at`     ISO 8601 timestamp the toggle auto-expires (empty when off).
    `high_approved`  Cumulative count of HIGH actions auto-approved while
                     overnight was active this session.
    `critical_blocked` Cumulative count of CRITICAL actions still blocked
                     while overnight was active this session.

    Counters reset on `turn_on()`. They are preserved on `turn_off()` so the
    morning recap line can summarise what happened overnight.
    """

    enabled: bool = False
    set_at: str = ""
    expires_at: str = ""
    high_approved: int = 0
    critical_blocked: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "set_at": self.set_at,
            "expires_at": self.expires_at,
            "high_approved": self.high_approved,
            "critical_blocked": self.critical_blocked,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> OvernightState:
        return cls(
            enabled=bool(raw.get("enabled", False)),
            set_at=str(raw.get("set_at", "") or ""),
            expires_at=str(raw.get("expires_at", "") or ""),
            high_approved=int(raw.get("high_approved", 0) or 0),
            critical_blocked=int(raw.get("critical_blocked", 0) or 0),
        )


def load_state() -> OvernightState:
    """Read state from disk. Returns a fresh default on any read error.

    Safe-default by design: a corrupt or unreadable state file MUST NOT
    flip the gate into overnight mode by accident. We always fall back to
    the disabled default.
    """
    p = _state_path()
    if not p.exists():
        return OvernightState()
    try:
        raw = json.loads(p.read_text() or "{}")
        if not isinstance(raw, dict):
            return OvernightState()
        return OvernightState.from_json(raw)
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return OvernightState()


def save_state(state: OvernightState) -> None:
    """Persist state. Best effort. Errors are swallowed because this runs
    on the gate hot path and a failed persist must never break a tool call.
    The next read will fall through to defaults, which is safer than
    raising mid-gate."""
    p = _state_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state.to_json(), indent=2, sort_keys=True))
        with contextlib.suppress(OSError):
            p.chmod(0o600)
    except OSError:
        pass


def _parse_iso(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def is_manual_toggle_active(
    state: OvernightState | None = None,
    *,
    now: datetime | None = None,
) -> bool:
    """True iff `quill night` was flipped on AND has not yet auto-expired.

    A toggle with no expiry timestamp is treated as inactive (the data
    file is malformed; safe-default off).
    """
    s = state if state is not None else load_state()
    if not s.enabled:
        return False
    expires = _parse_iso(s.expires_at)
    if expires is None:
        return False
    n = now or _now()
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC).astimezone()
    return n < expires


def _is_within_window(
    now: datetime,
    start: time,
    end: time,
) -> bool:
    """True iff `now` (local) is within [start, end).

    Handles the common case of an overnight window crossing midnight:
    if `start > end` (e.g. 22:00 to 08:00), the window is the union of
    [start, 24:00) and [00:00, end).
    """
    nt = now.time()
    if start <= end:
        return start <= nt < end
    return nt >= start or nt < end


def _parse_hhmm(s: str) -> time | None:
    """Parse 'HH:MM' (24h) into a time. Returns None on malformed input.

    Safe-default: a malformed window string MUST NOT make the window
    silently match the whole day. Returning None short-circuits the
    window branch in is_active().
    """
    try:
        h_str, m_str = s.split(":", 1)
        h, m = int(h_str), int(m_str)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return time(h, m)
    except (ValueError, AttributeError):
        pass
    return None


def is_active(
    *,
    state: OvernightState | None = None,
    config_enabled: bool = False,
    window_start: time | str | None = None,
    window_end: time | str | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Return (active, reason).

    `reason` is a short human-readable string (e.g. 'manual toggle' or
    'config window 22:00-08:00'). Empty when inactive.

    Sources of activation, in priority order:
      1. Manual toggle (`quill night`) - bounded by its expiry
      2. Configured time window in [overnight] - only if enabled = true
    """
    s = state if state is not None else load_state()
    n = now or _now()

    if is_manual_toggle_active(s, now=n):
        return True, "manual toggle"

    if config_enabled and window_start is not None and window_end is not None:
        ws = _parse_hhmm(window_start) if isinstance(window_start, str) else window_start
        we = _parse_hhmm(window_end) if isinstance(window_end, str) else window_end
        if ws is not None and we is not None and _is_within_window(n, ws, we):
            return True, f"config window {ws.strftime('%H:%M')}-{we.strftime('%H:%M')}"

    return False, ""


def is_active_from_config(*, now: datetime | None = None) -> tuple[bool, str]:
    """Convenience wrapper: read [overnight] from QuillConfig + state file,
    return is_active() result. Safe-default off on any load failure.

    Used by the gate path (claude_code.decide) so callers do not need to
    know about config loading internals.
    """
    s = load_state()
    cfg_enabled = False
    ws: str | None = None
    we: str | None = None
    try:
        from quill.config import load_config

        cfg = load_config()
        ovn = getattr(cfg, "overnight", None)
        if ovn is not None:
            cfg_enabled = bool(getattr(ovn, "enabled", False))
            ws = getattr(ovn, "window_start", None)
            we = getattr(ovn, "window_end", None)
    except Exception:
        pass
    return is_active(
        state=s,
        config_enabled=cfg_enabled,
        window_start=ws,
        window_end=we,
        now=now,
    )


def turn_on(*, duration_hours: float = DEFAULT_AUTO_EXPIRE_HOURS) -> OvernightState:
    """Flip the manual toggle on. Auto-expires after `duration_hours`.

    Counters reset on each `turn_on` so the morning recap line counts
    only what happened during the most recent overnight window.
    """
    now = _now()
    state = OvernightState(
        enabled=True,
        set_at=now.isoformat(),
        expires_at=(now + timedelta(hours=duration_hours)).isoformat(),
        high_approved=0,
        critical_blocked=0,
    )
    save_state(state)
    return state


def turn_off() -> OvernightState:
    """Flip the manual toggle off. Preserves counters for the recap line.

    The state row stays on disk because the high_approved/critical_blocked
    counters are useful for the next-morning report even after the toggle
    is off.
    """
    state = load_state()
    state.enabled = False
    save_state(state)
    return state


def record_event(risk_value: str) -> None:
    """Best-effort counter increment. Silent on failure.

    Called from the gate hot path AFTER the gate decision is made, so a
    failure here cannot affect the tool-call decision. We swallow every
    exception class to guarantee the gate keeps working.

    `risk_value` is the lowercased risk string ('high' or 'critical').
    Other values are ignored.
    """
    if risk_value not in ("high", "critical"):
        return
    try:
        state = load_state()
        if risk_value == "high":
            state.high_approved += 1
        else:
            state.critical_blocked += 1
        save_state(state)
    except Exception:
        pass
