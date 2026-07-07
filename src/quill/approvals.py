"""One-shot approval tokens - the "go ahead" path.

When Quill blocks a tool call, the user gets a notification with a token.
Running `quill approve <token>` writes a short-lived approval record. The
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

Storage: $QUILL_HOME/approvals.json, mode 0o600. TTL default 10 minutes;
expired approvals are cleaned on every load.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_TTL_SECONDS = 600  # 10 minutes


def args_digest(args: Mapping[str, Any]) -> str:
    """Stable SHA-256 of the canonicalized args dict.

    Same algorithm as the audit-log canonicalization so digests match
    between the gate and the approval record.
    """
    encoded = json.dumps(dict(args), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _path() -> Path:
    from quill.paths import default_path

    return default_path("approvals.json", env_override="QUILL_APPROVALS_FILE")


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().isoformat()


@dataclass(slots=True)
class Approval:
    """One pending approval. Single-use; consumed on first match.

    Lifecycle: issued (pending) → approved → consumed. Issuance does NOT
    grant the call - a token only becomes consumable once the operator
    explicitly approves it (`quill approve <token>`, Touch-ID-gated where
    available). This separation is load-bearing: the gate auto-issues a
    token on every block so the notification can offer `quill approve`,
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

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = {tok: ap.to_json() for tok, ap in self.approvals.items()}
        self.path.write_text(json.dumps(body, indent=2, sort_keys=True))
        with contextlib.suppress(OSError):
            self.path.chmod(0o600)

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
        self.approvals[token] = ap
        self.save()
        return ap

    def latest_pending(self) -> Approval | None:
        """The most recently issued token awaiting operator approval (issued,
        unconsumed, unexpired, not yet approved).

        Backs `quill approve --latest`, so the operator can confirm the most
        recent block with Touch ID without copying the exact token string.
        """
        pending = [ap for ap in self.approvals.values() if ap.is_active and not ap.approved_at]
        if not pending:
            return None
        return max(pending, key=lambda a: a.issued_at)

    def approve(self, token: str) -> Approval | None:
        """Mark a pending token approved (the user ran `quill approve <token>`).

        Flips `approved_at`, which is what makes the token consumable. Until
        this runs, the token the gate auto-issued on a block is inert - it
        exists only so the notification can name it. Returns the approval on
        success, or None if the token is unknown / expired / already consumed.
        """
        ap = self.approvals.get(token)
        if ap is None or not ap.is_active:
            return None
        ap.approved_at = _now_iso()
        self.save()
        return ap

    def consume(
        self,
        tool_name: str,
        args: Mapping[str, Any],
    ) -> Approval | None:
        """Look up + consume an active approval matching this exact call.

        Returns the approval if found (one-shot: marks consumed and saves).
        Returns None if no active approval matches.
        """
        digest = args_digest(args)
        for ap in self.approvals.values():
            # is_consumable (not is_active): a token must have been
            # explicitly approved by the operator. A merely-issued (pending)
            # token never releases a call - that would let a denied call
            # auto-allow its own retry.
            if not ap.is_consumable:
                continue
            if ap.tool_name != tool_name:
                continue
            if ap.args_digest != digest:
                continue
            ap.consumed_at = _now_iso()
            self.save()
            return ap
        return None

    def revoke(self, token: str) -> bool:
        """Drop a token without consuming it. Returns True if present."""
        if token in self.approvals:
            del self.approvals[token]
            self.save()
            return True
        return False

    def active(self) -> list[Approval]:
        """List approvals that are issued, unconsumed, and unexpired."""
        return [ap for ap in self.approvals.values() if ap.is_active]
