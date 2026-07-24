"""One-shot approval tokens - the "go ahead" path.

When Notari blocks a tool call, the user gets a notification with a token.
Running `notari approve <token>` writes a short-lived approval record. The
next time the same agent retries the same tool with the same args within
the TTL, the gate consumes the approval and lets it through (one-shot).

Why one-shot:
  - A multi-use approval is just a config-file edit; we already have that
    via `[policy]` overrides.
  - A multi-use approval implicitly bypasses Permission Decay.
  - One-shot matches the human's mental model: "yes, just this one time."

Approval is keyed by `(tool_name, args_digest)` - args_digest is SHA-256
of the canonicalized args dict. So the user pre-authorizes the EXACT call
that was blocked, not "the next rm -rf". An attacker who hijacks the agent
mid-session can't reuse the token for a different command.

Storage: $NOTARI_HOME/approvals.json, mode 0o600. TTL default 10 minutes;
expired approvals are cleaned on every load.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import fcntl  # POSIX only

    _HAS_FLOCK = True
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]
    _HAS_FLOCK = False

DEFAULT_TTL_SECONDS = 600  # 10 minutes


class ApprovalLockUnavailable(RuntimeError):
    """Raised when an approval mutation cannot take the POSIX file lock.

    The store fails closed rather than perform an unlocked read-modify-write
    that could resurrect a consumed one-shot token (F9). Hook callers suppress
    this so the effect is "the call stays blocked", never "silently allowed"."""


def args_digest(args: Mapping[str, Any]) -> str:
    """Stable SHA-256 of the canonicalized args dict.

    Same algorithm as the audit-log canonicalization so digests match
    between the gate and the approval record.
    """
    encoded = json.dumps(dict(args), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _path() -> Path:
    from notari.paths import default_path

    return default_path("approvals.json", env_override="NOTARI_APPROVALS_FILE")


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().isoformat()


@dataclass(slots=True)
class Approval:
    """One pending approval. Single-use; consumed on first match.

    Lifecycle: issued (pending) → approved → consumed. Issuance does NOT
    grant the call - a token only becomes consumable once the operator
    explicitly approves it (`notari approve <token>`, Touch-ID-gated where
    available). This separation is load-bearing: the gate auto-issues a
    token on every block so the notification can offer `notari approve`,
    and if issuance alone were consumable, a denied call would silently
    auto-allow its own immediate retry, defeating the gate against any
    retrying agent.
    """

    token: str
    tool_name: str
    args_digest: str
    expires_at: str
    issued_at: str
    reason: str = ""  # human-readable note about what was approved
    consumed_at: str = ""  # set when the approval is used; persisted for audit
    approved_at: str = ""  # set when the operator confirms; gate of consumability

    @property
    def is_expired(self) -> bool:
        try:
            return _now() >= datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True

    @property
    def is_active(self) -> bool:
        """Issued, not yet consumed, not expired - i.e. still listable.

        Includes pending (un-approved) tokens; used by `active()` so the
        operator can see what's awaiting their approval.
        """
        return not self.consumed_at and not self.is_expired

    @property
    def is_consumable(self) -> bool:
        """Approved by the operator, not yet consumed, not expired.

        This - NOT is_active - is what consume() gates on. A token the gate
        merely issued (pending) is never consumable until approved.
        """
        return bool(self.approved_at) and not self.consumed_at and not self.is_expired

    def to_json(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "tool_name": self.tool_name,
            "args_digest": self.args_digest,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "reason": self.reason,
            "consumed_at": self.consumed_at,
            "approved_at": self.approved_at,
        }


@dataclass(slots=True)
class ApprovalStore:
    """JSON-on-disk approval registry. Never blocks; safe to call from hooks."""

    approvals: dict[str, Approval] = field(default_factory=dict)
    path: Path = field(default_factory=_path)

    @classmethod
    def load(cls, path: Path | None = None) -> ApprovalStore:
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
        for token, raw in data.items():
            if not isinstance(raw, dict):
                continue
            ap = Approval(
                token=str(token),
                tool_name=str(raw.get("tool_name") or ""),
                args_digest=str(raw.get("args_digest") or ""),
                expires_at=str(raw.get("expires_at") or ""),
                issued_at=str(raw.get("issued_at") or ""),
                reason=str(raw.get("reason") or ""),
                consumed_at=str(raw.get("consumed_at") or ""),
                approved_at=str(raw.get("approved_at") or ""),
            )
            # Garbage-collect expired+consumed entries on load.
            if ap.is_expired and ap.consumed_at:
                continue
            store.approvals[token] = ap
        return store

    def _write(self) -> None:
        """Low-level writer. PRIVATE and unlocked: only `_locked` calls it, while
        holding the exclusive lock, right after re-reading the authoritative
        on-disk state. There is deliberately no public `save()`: a bare
        blind-overwrite save on a stale in-memory snapshot could resurrect a
        just-consumed token even under a lock (the write persists stale state,
        not the concurrent consume), so the only supported mutation path is the
        locked read-modify-write in `_locked` (security re-review 2026-07-23,
        defect 7)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = {tok: ap.to_json() for tok, ap in self.approvals.items()}
        self.path.write_text(json.dumps(body, indent=2, sort_keys=True))
        with contextlib.suppress(OSError):
            self.path.chmod(0o600)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[ApprovalStore]:
        """Exclusive lock around a full read-modify-write of the approvals file.

        Every mutator (issue / approve / revoke / consume) runs inside this so
        the sequence is atomic against other processes. The authoritative
        on-disk state is re-read INSIDE the lock and yielded as a fresh store;
        the caller mutates that, then it is written and adopted as `self`'s
        state, all before the lock releases. Previously only consume() locked, so
        a stale issue/approve/revoke writer could save an in-memory dict that
        still held a since-consumed token and restore it (security re-review
        2026-07-23, F9). `self.approvals` is rebound to the fresh dict, so a
        caller only ever sees the just-persisted authoritative state.

        Fails CLOSED where POSIX file locking is unavailable: without a lock the
        race is unavoidable, so a mutation raises rather than risk a double
        consume. Callers on the hook path already suppress exceptions, so this
        degrades to "stay blocked", never to "silently allow"."""
        if not _HAS_FLOCK:
            raise ApprovalLockUnavailable(
                "notari approvals require POSIX file locking (fcntl), which this "
                "platform lacks; refusing an unlocked write that could restore a "
                "consumed approval token"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A dedicated lock file so locking never depends on the data file
        # existing and never truncates it.
        lock_path = self.path.with_name(self.path.name + ".lock")
        with open(lock_path, "a+") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                fresh = ApprovalStore.load(self.path)
                yield fresh
                fresh._write()
                # Adopt the fresh dict wholesale. The object a mutator returns is
                # taken FROM this fresh store, so the caller's handle and
                # self.approvals reference the same instance (no stale-copy or
                # split-identity, re-review defect 9).
                self.approvals = fresh.approvals
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def issue(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        reason: str = "",
    ) -> Approval:
        """Generate a fresh approval token. Returns the persisted record."""
        # base64url can start with "-", which makes the token unpassable as a
        # CLI argument (the parser reads it as an option flag). Re-draw.
        token = secrets.token_urlsafe(8)
        while token.startswith("-"):
            token = secrets.token_urlsafe(8)
        ap = Approval(
            token=token,
            tool_name=tool_name,
            args_digest=args_digest(args),
            expires_at=(_now() + timedelta(seconds=ttl_seconds)).isoformat(),
            issued_at=_now_iso(),
            reason=reason,
        )
        with self._locked() as fresh:
            # Redraw against the authoritative state on the vanishingly rare
            # chance the token already exists on disk.
            while ap.token in fresh.approvals or ap.token.startswith("-"):
                ap.token = secrets.token_urlsafe(8)
            fresh.approvals[ap.token] = ap
        return ap

    def latest_pending(self) -> Approval | None:
        """The most recently issued token awaiting operator approval (issued,
        unconsumed, unexpired, not yet approved).

        Backs `notari approve --latest`, so the operator can confirm the most
        recent block with Touch ID without copying the exact token string.
        """
        pending = [ap for ap in self.approvals.values() if ap.is_active and not ap.approved_at]
        if not pending:
            return None
        return max(pending, key=lambda a: a.issued_at)

    def approve(self, token: str) -> Approval | None:
        """Mark a pending token approved (the user ran `notari approve <token>`).

        Flips `approved_at`, which is what makes the token consumable. Until
        this runs, the token the gate auto-issued on a block is inert - it
        exists only so the notification can name it. Returns the approval on
        success, or None if the token is unknown / expired / already consumed.
        """
        with self._locked() as fresh:
            ap = fresh.approvals.get(token)
            if ap is None or not ap.is_active:
                return None
            ap.approved_at = _now_iso()
            return ap

    def consume(
        self,
        tool_name: str,
        args: Mapping[str, Any],
    ) -> Approval | None:
        """Look up + consume an active approval matching this exact call.

        One-shot and race-safe: the whole read-check-mark-write sequence runs
        under an exclusive file lock, and the on-disk state is re-read inside the
        lock, so two concurrent hook processes retrying the same blocked call
        cannot both consume the single token (security red-team 2026-07-22,
        finding 9). Without the lock, both processes loaded an unconsumed token
        and each authorized the supposedly one-time action.

        Returns the approval if found (marks consumed and saves), else None.
        """
        digest = args_digest(args)
        # The whole read-check-mark-write runs under the exclusive lock, and the
        # on-disk state is re-read inside it, so two concurrent hooks retrying
        # the same blocked call cannot both consume the single token.
        with self._locked() as fresh:
            for ap in fresh.approvals.values():
                # is_consumable (not is_active): a token must have been
                # explicitly approved by the operator. A merely-issued
                # (pending) token never releases a call, that would let a
                # denied call auto-allow its own retry.
                if not ap.is_consumable:
                    continue
                if ap.tool_name != tool_name:
                    continue
                if ap.args_digest != digest:
                    continue
                ap.consumed_at = _now_iso()
                return ap
            return None

    def revoke(self, token: str) -> bool:
        """Drop a token without consuming it. Returns True if present.

        Locked read-modify-write (F9): an unlocked delete-then-save could be
        overwritten by, or overwrite, a concurrent consume/approve."""
        with self._locked() as fresh:
            if token in fresh.approvals:
                del fresh.approvals[token]
                return True
            return False

    def active(self) -> list[Approval]:
        """List approvals that are issued, unconsumed, and unexpired."""
        return [ap for ap in self.approvals.values() if ap.is_active]
