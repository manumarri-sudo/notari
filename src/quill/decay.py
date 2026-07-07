"""Permission Decay tracking.

Implements Manu's Permission Decay framework (vault note
`agentos-vault/claude-code/views/decay-queue`) for Quill's own granted
permissions: per-tool policy overrides in config.toml and the implicit
"trust this" set the user accumulates by saying yes to high-risk
actions.

Schema (matches the vault decay metadata exactly):

    permissions.json
    {
      "<kind>:<pattern>": {
          "granted_at":       <iso8601>,
          "last_reaffirmed":  <iso8601>,
          "decay_after_days": <int>,
          "decay_action":     "reaffirm" | "warn" | "retire",
          "decay_owner":      "<who>",
          "use_count":        <int>,
          "last_use":         <iso8601>,
          "notes":            "<freeform>"
      },
      ...
    }

Where kind is one of: 'policy', 'scope', 'session_ack'.

Behaviour:
  - First time a policy override / scope is used, register it with
    granted_at = last_reaffirmed = now().
  - Each subsequent use bumps last_reaffirmed. Active permissions
    never decay; that's the framework's claim.
  - When a permission's age (now - last_reaffirmed) exceeds its
    decay_after_days window, it's decayed: Quill ignores the override
    AND emits a `policy.decayed` audit event so the user sees the
    fall-back happen.
  - The user can `quill decay reaffirm <pattern>` to bump the timestamp
    without using the permission, or `quill decay forget <pattern>`
    to drop it entirely.

This is the framework end-to-end - actively-used permissions stay
healthy, dormant ones lose force, and the audit log records every
decay-driven downgrade.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

# Default decay windows, tunable via config. HIGH/CRITICAL overrides
# decay faster because they're more dangerous to leave loose.
DEFAULT_WINDOWS: Final[dict[str, int]] = {
    "policy.critical_to_low": 14,  # downgrading critical to low: 2 weeks
    "policy.critical_to_medium": 30,
    "policy.critical_to_high": 60,
    "policy.high_to_low": 30,
    "policy.high_to_medium": 60,
    "policy.medium_to_low": 90,
    "policy.default": 60,  # any other override
    "scope.default": 90,  # scope grants
    "session_ack.default": 1,  # one-day trust after a y/N
}


def _path() -> Path:
    from quill.paths import default_path

    return default_path("permissions.json", env_override="QUILL_DECAY_FILE")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class Permission:
    kind: str
    pattern: str
    granted_at: str
    last_reaffirmed: str
    decay_after_days: int
    decay_action: str = "reaffirm"
    decay_owner: str = "user"
    use_count: int = 1
    last_use: str = ""
    notes: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.pattern}"

    @property
    def age_days(self) -> int:
        """Integer-day age, kept for backwards compatibility with the CLI
        display (`quill decay show`). Use `age_seconds` for boundary checks
        so a 23h ack vs 25h ack don't flip on the same `delta.days` value."""
        try:
            ts = datetime.fromisoformat(self.last_reaffirmed)
        except ValueError:
            return 0
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - ts
        return delta.days

    @property
    def age_seconds(self) -> float:
        """Fractional-day age in seconds. The decay-boundary check uses this
        so a permission acked 23h ago is not 'older' than one acked 25h ago
        merely because delta.days happens to flip across the day boundary."""
        try:
            ts = datetime.fromisoformat(self.last_reaffirmed)
        except ValueError:
            return 0.0
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return (datetime.now(UTC) - ts).total_seconds()

    @property
    def is_decayed(self) -> bool:
        # Compare in seconds (not integer days) so the boundary is precise.
        # decay_after_days is interpreted as exact 86400-second multiples.
        return self.age_seconds > self.decay_after_days * 86400.0

    @property
    def days_left(self) -> int:
        # Ceil the remaining fractional days so a permission with 0.4 days
        # left still displays as "1 day left" (not "0", which reads as "decayed").
        from math import ceil

        remaining = self.decay_after_days - (self.age_seconds / 86400.0)
        return max(0, ceil(remaining))

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "pattern": self.pattern,
            "granted_at": self.granted_at,
            "last_reaffirmed": self.last_reaffirmed,
            "decay_after_days": self.decay_after_days,
            "decay_action": self.decay_action,
            "decay_owner": self.decay_owner,
            "use_count": self.use_count,
            "last_use": self.last_use,
            "notes": self.notes,
        }

    @classmethod
    def from_json(cls, kind: str, pattern: str, raw: dict[str, Any]) -> Permission:
        return cls(
            kind=kind,
            pattern=pattern,
            granted_at=str(raw.get("granted_at", _now_iso())),
            last_reaffirmed=str(raw.get("last_reaffirmed", _now_iso())),
            decay_after_days=int(raw.get("decay_after_days", 60)),
            decay_action=str(raw.get("decay_action", "reaffirm")),
            decay_owner=str(raw.get("decay_owner", "user")),
            use_count=int(raw.get("use_count", 1)),
            last_use=str(raw.get("last_use", "")),
            notes=str(raw.get("notes", "")),
        )


@dataclass(slots=True)
class DecayStore:
    """On-disk permissions registry. Mode 0o600. Atomic writes."""

    permissions: dict[str, Permission] = field(default_factory=dict)
    path: Path = field(default_factory=_path)

    @classmethod
    def load(cls, path: Path | None = None) -> DecayStore:
        p = path or _path()
        store = cls(path=p)
        if not p.exists():
            return store
        try:
            data = json.loads(p.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            return store
        if not isinstance(data, dict):
            return store
        for key, raw in data.items():
            if not isinstance(raw, dict):
                continue
            kind, _, pattern = key.partition(":")
            if not kind or not pattern:
                continue
            store.permissions[key] = Permission.from_json(kind, pattern, raw)
        return store

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = {p.key: p.to_json() for p in self.permissions.values()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True))
        tmp.replace(self.path)
        with contextlib.suppress(OSError):
            self.path.chmod(0o600)

    # ---- public API --------------------------------------------------

    def record_use(
        self,
        kind: str,
        pattern: str,
        *,
        decay_after_days: int | None = None,
        notes: str = "",
    ) -> tuple[Permission, bool]:
        """Mark a permission as used. Creates if missing.

        Returns (permission, was_decayed_at_use_time). Caller decides
        whether to honour the override or fall back to defaults - by
        the framework, decayed permissions don't fire.
        """
        key = f"{kind}:{pattern}"
        now = _now_iso()
        existing = self.permissions.get(key)
        if existing is None:
            window = decay_after_days if decay_after_days is not None else _default_window(kind)
            existing = Permission(
                kind=kind,
                pattern=pattern,
                granted_at=now,
                last_reaffirmed=now,
                decay_after_days=window,
                decay_action="reaffirm",
                decay_owner="user",
                use_count=1,
                last_use=now,
                notes=notes,
            )
            self.permissions[key] = existing
            self.save()
            return existing, False

        was_decayed = existing.is_decayed
        existing.last_reaffirmed = now
        existing.last_use = now
        existing.use_count += 1
        if notes:
            existing.notes = notes
        self.save()
        return existing, was_decayed

    def reaffirm(self, kind: str, pattern: str) -> Permission | None:
        key = f"{kind}:{pattern}"
        p = self.permissions.get(key)
        if p is None:
            return None
        p.last_reaffirmed = _now_iso()
        self.save()
        return p

    def forget(self, kind: str, pattern: str) -> bool:
        key = f"{kind}:{pattern}"
        if key in self.permissions:
            del self.permissions[key]
            self.save()
            return True
        return False

    def is_decayed(self, kind: str, pattern: str) -> bool:
        p = self.permissions.get(f"{kind}:{pattern}")
        return p is not None and p.is_decayed

    # ---- query -------------------------------------------------------

    def all(self) -> list[Permission]:
        return list(self.permissions.values())

    def decayed(self) -> list[Permission]:
        return [p for p in self.permissions.values() if p.is_decayed]

    def approaching(self, within_days: int = 14) -> list[Permission]:
        """Permissions whose decay window is within N days of expiry."""
        out: list[Permission] = []
        for p in self.permissions.values():
            left = p.days_left
            if 0 < left <= within_days and not p.is_decayed:
                out.append(p)
        return out


def _default_window(kind: str) -> int:
    """Best-match window from DEFAULT_WINDOWS based on the kind key."""
    if kind in DEFAULT_WINDOWS:
        return DEFAULT_WINDOWS[kind]
    base = kind.split(".", 1)[0]
    fallback = f"{base}.default"
    return DEFAULT_WINDOWS.get(fallback, 60)


def policy_kind(from_risk: str, to_risk: str) -> str:
    """Compose a kind string for a policy downgrade override.

    Used when the user sets `[policy] "fs.delete" = "low"` - the kind
    becomes 'policy.critical_to_low' so the appropriate decay window
    applies.
    """
    return f"policy.{from_risk}_to_{to_risk}"
