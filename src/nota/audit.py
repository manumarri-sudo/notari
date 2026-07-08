"""Append-only signed audit log.

Format: JSONL, one event per line. Every event includes:
  - ts            ISO-8601 timestamp UTC
  - session_id    parent or current session
  - agent_id      which sub-agent in the delegation tree (root if absent)
  - prev_mac      HMAC of the previous entry (the chain anchor)
  - payload       event-specific fields
  - mac           HMAC-SHA256 of (prev_mac || canonical(payload)) under the
                  per-installation HMAC key

Tamper-evidence: any modification or insertion breaks the chain at the next
verify. Use `nota audit verify <logfile>` to validate.

Performance: writes use O_APPEND for atomicity, fcntl.flock(LOCK_EX) for
cross-process serialization of the read-tail+append sequence (each emit
re-reads the tail mac under the lock so the chain stays intact when many
hook subprocesses fire concurrently). fsync is BATCHED by default (every
N entries or M ms, whichever first), with FORCE-fsync on any entry whose
risk >= HIGH so a power loss never drops a critical-risk row.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

try:
    import fcntl  # POSIX only

    _HAS_FLOCK = True
except ImportError:  # pragma: no cover - Windows path
    fcntl = None  # type: ignore[assignment]
    _HAS_FLOCK = False

from nota.errors import AuditError

# fsync discipline
FSYNC_BATCH_SIZE: Final[int] = 16
FSYNC_BATCH_MS: Final[int] = 250


def _canon(obj: Mapping[str, Any]) -> bytes:
    """Canonical JSON encoding for stable HMAC computation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class AuditLog:
    """Append-only signed audit log.

    Cross-process safe on POSIX: emit() takes fcntl.LOCK_EX on the file,
    re-reads the tail mac under the lock, then writes. Concurrent hook
    subprocesses chain correctly. On Windows (no fcntl) the in-process
    threading lock still serializes a single process; multi-process use
    on Windows requires routing all clients through one instance.
    """

    path: Path
    hmac_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _fd: int | None = field(default=None, init=False)
    _prev_mac: bytes = field(default=b"", init=False)
    _pending: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_APPEND ensures atomic appends even with concurrent writers
        self._fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            mode=0o600,  # never world-readable
        )
        # Anchor: read the last MAC if file already had entries. The read
        # must happen under the same LOCK_EX that emit() uses: another
        # process can be mid-append, and an unlocked reader can observe a
        # torn trailing line (JSONDecodeError -> AuditError at construction).
        # emit() re-reads the tail under its own lock anyway, so this anchor
        # only needs to be consistent, not fresh.
        if self.path.stat().st_size > 0:
            if _HAS_FLOCK:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                self._prev_mac = self._tail_mac()
            finally:
                if _HAS_FLOCK:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _tail_mac(self) -> bytes:
        """Read the last line's mac (for chain continuation across restarts).

        Walks backwards from EOF in 4 KB chunks until at least one complete
        trailing line is in the buffer. The earlier version read only the
        last 4 KB and called `splitlines()` on it: any audit event whose
        serialised line exceeded 4 KB returned a leading fragment of that
        line, json.loads raised JSONDecodeError, and `__post_init__`
        crashed for every subsequent emit on the log. Long Bash commands
        plus the chain bookkeeping (prev_mac, mac, ts, ids) routinely
        crossed 4 KB. The walk-backwards algorithm bounds the read at one
        complete trailing line regardless of size.
        """
        try:
            with self.path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return b""

                chunk_size = 4096
                buf = b""
                pos = size
                line: bytes | None = None
                while pos > 0 and line is None:
                    read_size = min(chunk_size, pos)
                    pos -= read_size
                    f.seek(pos)
                    buf = f.read(read_size) + buf
                    # Drop the file's trailing newline so rfind below gives
                    # us the newline *before* the last record, not after it.
                    stripped = buf.rstrip(b"\r\n")
                    last_nl = stripped.rfind(b"\n")
                    if last_nl >= 0:
                        line = stripped[last_nl + 1 :]
                    elif pos == 0:
                        # Read the entire file; only one record present.
                        line = stripped

            if not line:
                return b""
            last = json.loads(line)
            mac = last.get("mac")
            return bytes.fromhex(mac) if isinstance(mac, str) else b""
        except (OSError, json.JSONDecodeError, ValueError) as e:
            msg = f"cannot read existing audit chain at {self.path}: {e}"
            raise AuditError(msg) from e

    def emit(
        self,
        *,
        event_type: str,
        session_id: str,
        agent_id: str = "root",
        risk: str = "low",
        payload: Mapping[str, Any] | None = None,
        force_fsync: bool | None = None,
    ) -> str:
        """Append a single audit event. Returns the line's mac (hex).

        force_fsync: if None, fsyncs when risk in {high, critical} OR batch
        threshold reached. Pass True/False to override.

        Cross-process safety: the read-tail+write sequence is serialized
        with fcntl.flock(LOCK_EX), so concurrent hook subprocesses never
        race on the chain anchor. Inside the flock we re-read the tail
        mac, since another process may have appended since this instance
        last computed it.
        """
        if self._fd is None:
            msg = "audit log is closed"
            raise AuditError(msg)

        with self._lock:
            if _HAS_FLOCK:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                # Re-read the tail mac under the lock so concurrent
                # writers all chain off the actual on-disk last entry.
                if self.path.stat().st_size > 0:
                    self._prev_mac = self._tail_mac()

                body: dict[str, Any] = {
                    "ts": _now(),
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "type": event_type,
                    "risk": risk,
                    "prev_mac": self._prev_mac.hex(),
                    "payload": dict(payload or {}),
                }
                mac = hmac.new(self.hmac_key, _canon(body), hashlib.sha256).digest()
                body["mac"] = mac.hex()
                line = (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")

                os.write(self._fd, line)
                self._prev_mac = mac
                self._pending += 1

                need_fsync = (
                    force_fsync
                    if force_fsync is not None
                    else (risk in ("high", "critical") or self._pending >= FSYNC_BATCH_SIZE)
                )
                if need_fsync:
                    os.fsync(self._fd)
                    self._pending = 0
            finally:
                if _HAS_FLOCK:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)

        # Dual-write to OpenTelemetry AFTER the chain write so OTel can
        # never corrupt the audit log. No-op if nota[otel] isn't installed.
        # Failures are silently dropped from the hot path (the chain is the
        # source of truth) but counted + surfaced once on first failure to
        # stderr so a misconfigured OTel endpoint doesn't silently swallow
        # every event for the rest of the session. The counter is exposed
        # via `nota doctor` (read `otel.dual_write_failed_count`).
        try:
            from nota import otel

            otel.emit_span(
                event_type=event_type,
                session_id=session_id,
                agent_id=agent_id,
                risk=risk,
                payload=payload,
            )
        except Exception as e:
            from nota import otel as _otel_mod

            _otel_mod._dual_write_failed_count += 1
            if not _otel_mod._dual_write_failed_announced:
                _otel_mod._dual_write_failed_announced = True
                import sys as _sys

                _sys.stderr.write(
                    f"[nota] OTel dual-write failed ({type(e).__name__}: {e}). "
                    f"Audit chain is intact; OTel span dropped. Subsequent "
                    f"failures suppressed; count via `nota doctor`.\n"
                )

        return mac.hex()

    def close(self) -> None:
        if self._fd is not None:
            try:
                if self._pending:
                    os.fsync(self._fd)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def verify_chain(
    path: Path,
    hmac_key: bytes,
    *,
    expected_count: int | None = None,
) -> tuple[int, list[int]]:
    """Verify the HMAC chain over an existing log file.

    Returns (total_events, list of 1-based line numbers that failed verify).
    Empty failure list means the chain is intact.

    `expected_count` closes the trailing-TRUNCATION gap. The chain alone can't
    detect that the last N lines were deleted: each remaining entry still links
    to its predecessor, so a truncated-but-valid shorter log verifies clean.
    Pass the high-water-mark from a prior `seal_head` (see `read_head`) and a
    shortfall (`total < expected_count`) is reported as a failure at line 0
    (the "missing trailing entries" marker), so `if failures:` callers treat
    the chain as broken.
    """
    failures: list[int] = []
    prev_mac_hex = ""
    total = 0
    with path.open("rb") as f:
        for i, raw in enumerate(f, start=1):
            total += 1
            try:
                evt = json.loads(raw)
                claimed_mac = evt.pop("mac", "")
                if evt.get("prev_mac") != prev_mac_hex:
                    failures.append(i)
                    prev_mac_hex = claimed_mac
                    continue
                expected = hmac.new(hmac_key, _canon(evt), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, claimed_mac):
                    failures.append(i)
                prev_mac_hex = claimed_mac
            except (json.JSONDecodeError, KeyError, ValueError):
                failures.append(i)
    if expected_count is not None and total < expected_count:
        failures.insert(0, 0)  # line 0 == trailing truncation vs sealed count
    return total, failures


def _head_path(path: Path) -> Path:
    """Sidecar path holding the sealed high-water-mark for `path`."""
    return path.with_name(path.name + ".head")


def seal_head(path: Path, hmac_key: bytes) -> dict[str, Any]:
    """Record a high-water-mark (verified entry count + last mac) to a
    `<log>.head` sidecar (mode 0o600), so later truncation is detectable.

    Refuses to seal a chain that does not currently verify clean. This is an
    EXPLICIT, off-write operation (e.g. invoked by `nota audit verify`); it is
    deliberately NOT on the per-event hot path, so the gate's audited write path
    is unchanged. Per-write truncation detection (a head pointer updated under
    the emit flock) is the stronger form and is intentionally deferred rather
    than risk the tamper-evidence write path.
    """
    total, failures = verify_chain(path, hmac_key)
    if failures:
        msg = f"refusing to seal: chain has {len(failures)} broken link(s)"
        raise AuditError(msg)
    last_mac = ""
    if path.stat().st_size > 0:
        lines = path.read_bytes().splitlines()
        if lines:
            with contextlib.suppress(json.JSONDecodeError, ValueError):
                last_mac = json.loads(lines[-1]).get("mac", "")
    head = {"count": total, "mac": last_mac, "ts": _now()}
    hp = _head_path(path)
    hp.write_text(json.dumps(head))
    with contextlib.suppress(OSError):
        hp.chmod(0o600)
    return head


def read_head(path: Path) -> dict[str, Any] | None:
    """Read the sealed high-water-mark sidecar, or None if absent/unreadable."""
    hp = _head_path(path)
    if not hp.exists():
        return None
    with contextlib.suppress(OSError, json.JSONDecodeError, ValueError):
        data = json.loads(hp.read_text())
        if isinstance(data, dict):
            return data
    return None
