"""Tool description pinning - anti-tool-poisoning + anti-rug-pull.

Mitigation for the Invariant Labs tool-poisoning attack class
(https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks):
a malicious upstream hides exfiltration instructions in `description` or
`annotations` - visible to the LLM, hidden from typical user UIs. Even a
benign upstream can rug-pull a previously-trusted tool by silently changing
its description.

Defense: at first sight of each tool, hash the canonicalized
`(name, description, inputSchema, annotations)` tuple and persist as a "pin".
On subsequent connect, refuse to advertise a tool whose hash changed without
explicit re-approval (`nota pins approve <fingerprint>`).

The annotations field is **explicitly untrusted by the MCP spec** - never
let it bypass pinning by being excluded.

Persisted at $NOTA_HOME/tool_pins.jsonl, mode 0o600. Append-only by design;
revocation = appending a `revoked` event, not deleting the prior pin.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def fingerprint(tool: Mapping[str, Any]) -> str:
    """SHA-256 of the canonicalized tool identity.

    Inputs into the hash:
        - name
        - description (the LLM-visible payload)
        - inputSchema (the JSON Schema; structurally significant)
        - annotations (untrusted but identity-bearing)

    Canonicalization: JSON dump with sort_keys, no whitespace.
    """
    body = {
        "name": str(tool.get("name") or ""),
        "description": str(tool.get("description") or ""),
        "inputSchema": tool.get("inputSchema") or {},
        "annotations": tool.get("annotations") or {},
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(slots=True)
class ToolPin:
    """One persisted entry. Records first-sight + approval state."""

    upstream: str
    name: str
    digest: str
    first_seen: str
    approved_by: str = "auto"  # "auto" on first sight; "user:<sid>" after explicit approval
    revoked_at: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "upstream": self.upstream,
            "name": self.name,
            "digest": self.digest,
            "first_seen": self.first_seen,
            "approved_by": self.approved_by,
            "revoked_at": self.revoked_at,
        }


def _path() -> Path:
    from nota.paths import default_path

    return default_path("tool_pins.jsonl", env_override="NOTA_PINS_FILE")


@dataclass(slots=True)
class PinStore:
    """Append-only JSONL pin registry.

    Reading replays the entire file and folds events into a (upstream, name) →
    latest-pin map. Writing appends one line. Cross-process safe through
    O_APPEND atomicity (pins are not security-critical to ordering - at worst
    a duplicate entry is read on next load).
    """

    pins: dict[tuple[str, str], ToolPin] = field(default_factory=dict)
    path: Path = field(default_factory=_path)

    @classmethod
    def load(cls, path: Path | None = None) -> PinStore:
        p = path or _path()
        store = cls(path=p)
        if not p.exists():
            return store
        with p.open() as f:
            for line in f:
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw, dict):
                    continue
                pin = ToolPin(
                    upstream=str(raw.get("upstream") or ""),
                    name=str(raw.get("name") or ""),
                    digest=str(raw.get("digest") or ""),
                    first_seen=str(raw.get("first_seen") or ""),
                    approved_by=str(raw.get("approved_by") or "auto"),
                    revoked_at=str(raw.get("revoked_at") or ""),
                )
                if pin.upstream and pin.name:
                    store.pins[(pin.upstream, pin.name)] = pin
        return store

    def _append(self, pin: ToolPin) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(pin.to_json(), separators=(",", ":")) + "\n"
        # O_APPEND is atomic for writes under PIPE_BUF (4 KB on Linux,
        # 512 B on some BSDs). Tool schemas with long descriptions easily
        # exceed that; without flock, concurrent hook subprocesses can
        # interleave partial writes and corrupt the JSONL. Wrap in flock
        # so writes of any size are serialised on this host. Mirrors
        # `audit.py`'s emit-under-flock pattern.
        with self.path.open("a") as f:
            try:
                import fcntl

                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(line)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError):
                # No flock on this platform (rare; Windows) or transient
                # OS error - fall back to bare write. Still safer than
                # nothing because most tool descriptions stay under PIPE_BUF.
                f.write(line)
        with contextlib.suppress(OSError):
            self.path.chmod(0o600)
        self.pins[(pin.upstream, pin.name)] = pin

    def verify(self, upstream: str, tool: Mapping[str, Any]) -> tuple[bool, str]:
        """Return (ok, reason).

        ok=True paths:
            - First sight of this tool - auto-pin on first seen, AFTER the
              tool-description scanner clears it of hidden-instruction
              payloads (invisible Unicode tag block, injection imperatives,
              encoded blobs). See `nota.tool_scan`.
            - Digest matches the existing pin and it isn't revoked.
        ok=False paths:
            - Description scan finds CRITICAL hidden-instruction payload
              (Snyk ToxicSkills / ClawHavoc threat class, Apr 2026) -
              caller refuses regardless of pin state.
            - Digest changed (possible rug-pull / poisoning) - caller refuses.
            - Pin was explicitly revoked.
        """
        name = str(tool.get("name") or "")
        if not name:
            return False, "tool has no name"

        # Hidden-instruction scan runs BEFORE pin lookup so a freshly
        # poisoned tool fails on first sight, not only on rug-pull.
        from nota.tool_scan import scan as _scan

        scan_result = _scan(tool)
        if not scan_result.safe:
            details = "; ".join(f.detail for f in scan_result.findings)
            return False, (
                f"tool description failed hidden-instruction scan: {details}. "
                f"this is the tool-poisoning attack class (Invariant Labs, "
                f"Snyk ToxicSkills). approve manually only after reading the "
                f"raw description: nota pins inspect {upstream}.{name}"
            )

        digest = fingerprint(tool)
        existing = self.pins.get((upstream, name))
        now = datetime.now(UTC).isoformat()
        if existing is None:
            self._append(
                ToolPin(
                    upstream=upstream,
                    name=name,
                    digest=digest,
                    first_seen=now,
                    approved_by="auto",
                )
            )
            return True, "first sight; auto-pinned"
        if existing.revoked_at:
            return False, f"pin revoked at {existing.revoked_at}"
        if existing.digest != digest:
            return False, (
                f"digest changed (was {existing.digest[:8]}…, now {digest[:8]}…); "
                f"possible rug-pull or tool-poisoning. "
                f"approve with: nota pins approve {upstream}.{name} {digest}"
            )
        return True, "matches existing pin"

    def approve(self, upstream: str, name: str, digest: str, *, by: str = "user") -> None:
        """Replace a pin with a new digest after user approval."""
        self._append(
            ToolPin(
                upstream=upstream,
                name=name,
                digest=digest,
                first_seen=datetime.now(UTC).isoformat(),
                approved_by=by,
            )
        )

    def revoke(self, upstream: str, name: str) -> None:
        """Mark a pin revoked. Future verify() will refuse."""
        existing = self.pins.get((upstream, name))
        digest = existing.digest if existing else ""
        self._append(
            ToolPin(
                upstream=upstream,
                name=name,
                digest=digest,
                first_seen=existing.first_seen if existing else datetime.now(UTC).isoformat(),
                approved_by=existing.approved_by if existing else "auto",
                revoked_at=datetime.now(UTC).isoformat(),
            )
        )


def filter_pinned(
    upstream: str,
    tools: Iterable[Mapping[str, Any]],
    *,
    store: PinStore | None = None,
) -> tuple[list[Mapping[str, Any]], list[tuple[str, str]]]:
    """Walk an upstream's tool list, return (kept, refused).

    `kept`    - tools whose pin matches (or were first-seen).
    `refused` - list of (tool_name, reason) for tools whose pin failed.

    Caller decides whether to advertise refused tools as quarantined or hide
    them entirely. Default: hide; the LLM never sees a rug-pulled tool.
    """
    s = store or PinStore.load()
    kept: list[Mapping[str, Any]] = []
    refused: list[tuple[str, str]] = []
    for tool in tools:
        ok, reason = s.verify(upstream, tool)
        if ok:
            kept.append(tool)
        else:
            refused.append((str(tool.get("name") or ""), reason))
    return kept, refused
