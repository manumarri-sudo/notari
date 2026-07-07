"""Session-scoped approval memory (anti-yes-fatigue, #52).

Within ONE Claude Code session, an exact (tool_name, args-digest) pair the
operator already approved should not re-ask. The audit log still grows
fully - this only suppresses the operator-facing prompt, not the record.

Bright lines (never qualify for session memory):
  - Risk.CRITICAL (rm -rf, force-push, DROP TABLE, sudo, etc.)
  - secret_detected events
  - trifecta_closed events
  - Any pattern whose ID starts with `critical:` / `secret:` / `trifecta:`

Storage: `~/.quill/session_approvals/<session_id>.json`. Atomic
tmp-rename writes, mode 0o600. Per-file 24h hard TTL so an interrupted
session can't leave a forever-live approval; the session_id rotates
anyway when Claude Code restarts.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# Hard cap: any entry older than this is ignored on recall, even within
# the same session_id. Defends against very-long-running sessions
# accumulating stale approvals.
SESSION_APPROVAL_TTL_SEC: float = 24 * 3600.0


def _dir() -> Path:
    base = os.environ.get("QUILL_SESSION_APPROVALS_DIR")
    if base:
        return Path(base)
    return Path.home() / ".quill" / "session_approvals"


def _session_file(session_id: str) -> Path:
    # session_id sanitization: only allow [A-Za-z0-9_-]; everything else
    # collapses to '_'. Defends against a malformed session_id from
    # Claude Code trying to write outside the directory.
    safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in (session_id or "default"))
    safe = safe[:64] or "default"
    return _dir() / f"{safe}.json"


def args_digest(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    """Canonical 16-hex-char digest of (tool_name, tool_input).

    JSON canonicalization: sort_keys + separators=(',',':'). Matches
    sibling digesters elsewhere in the codebase. Truncating SHA-256 to
    16 hex chars gives 64 bits of entropy, which is plenty for in-session
    collision avoidance (a session has ~thousands of calls, not 2^32).
    """
    blob = json.dumps(
        {"t": tool_name, "i": tool_input},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _load(session_id: str) -> dict[str, float]:
    p = _session_file(session_id)
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, float] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, (int, float)):
            out[k] = float(v)
    return out


def _save(session_id: str, data: dict[str, float]) -> None:
    p = _session_file(session_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")))
    with contextlib.suppress(OSError):
        tmp.chmod(0o600)
    os.replace(tmp, p)


def remember(
    session_id: str,
    tool_name: str,
    tool_input: Mapping[str, Any],
    *,
    now: float | None = None,
) -> None:
    """Persist that (session, tool, args) was approved. No-op on any
    error - this is decoration over the existing approval flow, not
    a safety mechanism."""
    try:
        digest = args_digest(tool_name, tool_input)
        data = _load(session_id)
        # Prune anything past TTL while we have the file open.
        now = now if now is not None else time.time()
        data = {k: v for k, v in data.items() if (now - v) < SESSION_APPROVAL_TTL_SEC}
        data[digest] = now
        _save(session_id, data)
    except Exception:
        # Memory is decoration; never break the hook.
        pass


def recall(
    session_id: str,
    tool_name: str,
    tool_input: Mapping[str, Any],
    *,
    now: float | None = None,
) -> bool:
    """True if (session, tool, args) was approved within this session
    and not yet past the 24h TTL. False on any error or miss."""
    try:
        digest = args_digest(tool_name, tool_input)
        data = _load(session_id)
        ts = data.get(digest)
        if ts is None:
            return False
        now = now if now is not None else time.time()
        if (now - ts) >= SESSION_APPROVAL_TTL_SEC:
            return False
        return True
    except Exception:
        return False


def forget_session(session_id: str) -> None:
    """Wipe one session's approval cache. Called by `quill session reset`
    if we ever surface that command - otherwise the file lives until the
    24h TTL expires entries on the next remember()/list call."""
    with contextlib.suppress(OSError):
        _session_file(session_id).unlink()
