"""Opt-in anonymous usage telemetry.

Disabled by default. Asks once on first run; never re-asks. Ships only
aggregate signals - counts, risk distribution, namespace top-N - never
tool args, never paths, never intent text, never the audit log.

State is at ~/.quill/telemetry.json (or $QUILL_TELEMETRY_PATH):

    { "version": 1, "install_id": "<uuid4>", "opted_in": true|false,
      "asked_at": "<iso8601>", "endpoint": "<url>" }

Endpoint defaults to https://telemetry.quill.dev/v1/events. Self-host by
setting QUILL_TELEMETRY_ENDPOINT or [telemetry.endpoint] in config.toml.

Privacy contract:
    SHIPPED: install_id, quill_version, py_version, os, session counts
        (n_attempts, n_blocked, n_scope_violations, n_human_paused),
        risk distribution histogram, top-N tool *namespaces* (e.g.
        "fs", "git", "github" - never full tool names), session
        duration, upstream count, whether a budget cap was set.
    NEVER SHIPPED: scope strings, tool arguments, file paths, intent
        text, audit log contents, the HMAC key, anything user-identifiable.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

DEFAULT_ENDPOINT: Final[str] = "https://telemetry.quill.dev/v1/events"
SCHEMA_VERSION: Final[int] = 1


def _state_path() -> Path:
    from quill.paths import default_path

    return default_path("telemetry.json", env_override="QUILL_TELEMETRY_PATH")


@dataclass(slots=True)
class TelemetryState:
    """On-disk record of the user's opt-in choice + their install_id."""

    install_id: str = ""
    opted_in: bool = False
    asked: bool = False
    asked_at: str | None = None
    endpoint: str = DEFAULT_ENDPOINT

    @classmethod
    def load(cls, path: Path | None = None) -> TelemetryState:
        p = path or _state_path()
        if not p.exists():
            return cls(install_id=str(uuid.uuid4()))
        try:
            data = json.loads(p.read_text() or "{}")
        except (OSError, json.JSONDecodeError):
            return cls(install_id=str(uuid.uuid4()))
        return cls(
            install_id=str(data.get("install_id") or uuid.uuid4()),
            opted_in=bool(data.get("opted_in", False)),
            asked=bool(data.get("asked", False)),
            asked_at=data.get("asked_at"),
            endpoint=str(data.get("endpoint") or DEFAULT_ENDPOINT),
        )

    def save(self, path: Path | None = None) -> None:
        p = path or _state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "version": SCHEMA_VERSION,
            "install_id": self.install_id,
            "opted_in": self.opted_in,
            "asked": self.asked,
            "asked_at": self.asked_at,
            "endpoint": self.endpoint,
        }
        p.write_text(json.dumps(body, indent=2) + "\n")
        with contextlib.suppress(OSError):
            p.chmod(0o600)


def opt_in(state: TelemetryState | None = None) -> TelemetryState:
    s = state or TelemetryState.load()
    s.opted_in = True
    s.asked = True
    s.asked_at = datetime.now(UTC).isoformat()
    s.save()
    return s


def opt_out(state: TelemetryState | None = None) -> TelemetryState:
    s = state or TelemetryState.load()
    s.opted_in = False
    s.asked = True
    s.asked_at = datetime.now(UTC).isoformat()
    s.save()
    return s


# ---------------------------------------------------------------------------
# Aggregate computation - derived from a list of audit-log events.
# ---------------------------------------------------------------------------


def _ns(tool_name: str) -> str:
    """Namespace prefix of a tool name. 'fs.read_file' -> 'fs'.

    For un-namespaced names (e.g. Claude Code's 'Bash'), returns the name
    itself. We never ship the right-of-dot portion, only the namespace, so
    we don't reveal which specific tool was used.
    """
    return tool_name.split(".", 1)[0] if "." in tool_name else tool_name


def aggregate_events(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Reduce an iterable of audit events to the aggregate fields we ship.

    The OUTPUT of this function is the only thing that ever leaves the
    machine; if you're ever in doubt about what telemetry sends, look here.
    """
    n_attempts = n_allowed = n_blocked = n_scope_viols = n_paused = 0
    risk_dist: Counter[str] = Counter()
    ns_counter: Counter[str] = Counter()
    duration_s = 0.0
    n_upstreams = 0
    has_budget = False
    budget_exceeded = False
    first_ts: str | None = None
    last_ts: str | None = None

    for evt in events:
        t = evt.get("type", "")
        ts = evt.get("ts")
        if isinstance(ts, str):
            first_ts = first_ts or ts
            last_ts = ts

        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        tool_name = payload.get("tool_name") if isinstance(payload, Mapping) else None
        risk = evt.get("risk", "low") if isinstance(evt.get("risk"), str) else "low"

        if t == "session.start":
            scope = payload.get("scope") or []
            if isinstance(scope, list):
                # bare scope COUNT is fine; never ship the strings themselves
                pass
            ups = payload.get("upstreams") or []
            if isinstance(ups, list):
                n_upstreams = len(ups)
            if payload.get("budget_usd") is not None:
                has_budget = True

        elif t == "tool.attempted":
            n_attempts += 1
            risk_dist[risk] += 1
            if isinstance(tool_name, str):
                ns_counter[_ns(tool_name)] += 1

        elif t == "verdict.allowed":
            n_allowed += 1
        elif t == "verdict.blocked":
            n_blocked += 1
            if (payload.get("reason") or "") == "human_declined":
                n_paused += 1
        elif t == "verdict.scope_violation":
            n_scope_viols += 1

        elif t == "budget.exceeded":
            budget_exceeded = True

    if first_ts and last_ts:
        with contextlib.suppress(ValueError):
            duration_s = (
                datetime.fromisoformat(last_ts) - datetime.fromisoformat(first_ts)
            ).total_seconds()

    # Top-N namespaces, never the full tool name. Cap at 5 to stay aggregate.
    top_ns = [n for n, _ in ns_counter.most_common(5)]

    return {
        "n_attempts": n_attempts,
        "n_allowed": n_allowed,
        "n_blocked": n_blocked,
        "n_scope_violations": n_scope_viols,
        "n_human_paused": n_paused,
        "risk_dist": dict(risk_dist),
        "top_namespaces": top_ns,
        "n_upstreams": n_upstreams,
        "duration_s": round(duration_s, 1),
        "has_budget_cap": has_budget,
        "budget_exceeded": budget_exceeded,
    }


def build_event(
    state: TelemetryState,
    aggregate: Mapping[str, Any] | None = None,
    *,
    event_kind: str = "session.summary",
) -> dict[str, Any]:
    """Compose the JSON envelope that ships, given a state + aggregate."""
    from quill._version import __version__

    py = platform.python_version()
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": datetime.now(UTC).isoformat(),
        "install_id": state.install_id,
        "quill_version": __version__,
        "py_version": py,
        "os": platform.system().lower(),
        "event": event_kind,
        "data": dict(aggregate or {}),
    }


def preview_event_for_user(
    state: TelemetryState,
    aggregate: Mapping[str, Any] | None = None,
) -> str:
    """Render the JSON Quill *would* send, so the user can audit before opting in."""
    return json.dumps(build_event(state, aggregate or {}), indent=2)


# ---------------------------------------------------------------------------
# Wire emission. Fire-and-forget HTTPS POST. Never blocks the proxy.
# ---------------------------------------------------------------------------


def emit_session_summary(
    aggregate: Mapping[str, Any],
    *,
    state: TelemetryState | None = None,
    timeout_s: float = 2.0,
) -> bool:
    """Send a session.summary event if (and only if) the user has opted in.

    Returns True if the request was attempted and got a 2xx response, False
    in every other case (opted out, no network, timeout, error). Never
    raises - telemetry must not affect the proxy's correctness.
    """
    s = state or TelemetryState.load()
    if not s.opted_in:
        return False

    endpoint = os.environ.get("QUILL_TELEMETRY_ENDPOINT") or s.endpoint
    body = build_event(s, aggregate)
    raw = json.dumps(body).encode("utf-8")

    try:
        # Use stdlib only - never add an httpx hard-dep just for this.
        import urllib.request

        req = urllib.request.Request(
            endpoint,
            data=raw,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": f"quill/{body['quill_version']}",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status: int = resp.status
            return 200 <= status < 300
    except Exception:
        return False
