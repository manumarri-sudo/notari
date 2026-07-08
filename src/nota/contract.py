"""Change contract: the human-approved task, captured at `nota begin`.

A contract is the anchor of Nota Change Control. Before an agent writes code,
a human records WHAT was approved (the task), WHERE it may touch (allowed
paths), and the base commit the work starts from. `nota verify` later compares
`git diff <base_commit> HEAD` against this record, so the contract is the fixed
point the whole verdict is measured against.

The file lives at ``<repo-root>/.nota/contract.json`` and is intentionally
plain JSON - it is committed nowhere by Nota itself, reviewable by a human, and
small enough to paste into a PR. Creation is audit-chained (``contract.created``)
so a Change Passport can cite a tamper-evident record of when the task was
approved and against which base commit.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nota import events as ev
from nota.errors import NotaError

if TYPE_CHECKING:
    from nota.audit import AuditLog

CONTRACT_VERSION = 1


class ContractError(NotaError):
    """Raised when a contract cannot be created, read, or parsed."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def repo_root(start: Path | None = None) -> Path:
    """The git work-tree root containing `start` (cwd by default).

    Falls back to `start` itself when not inside a git repo, so `nota begin`
    still works in a fresh directory a user is about to `git init`.
    """
    start = (start or Path.cwd()).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return start


def head_sha(root: Path) -> str | None:
    """Current HEAD commit SHA, or None when there are no commits yet."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def contract_path(root: Path) -> Path:
    return root / ".nota" / "contract.json"


def _looks_like_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))


@dataclass(frozen=True)
class Contract:
    """The human-approved task and the boundaries of the change.

    `allowed_paths` is the scope allow-list (globs / directory prefixes / exact
    paths) that `nota verify` measures the diff against. An empty list means no
    path restriction was declared.
    """

    version: int
    task: str
    task_source: str  # "url" | "text"
    allowed_paths: tuple[str, ...]
    base_commit: str | None
    created_at: str
    contract_id: str
    approved_by: str | None = None
    expires_at: str | None = None  # ISO-8601; the approval lapses after this
    repo: str | None = None  # e.g. "owner/name"; binds the approval to one repo

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["allowed_paths"] = list(self.allowed_paths)
        # Omit optional fields when unset so a contract WITHOUT them serializes
        # exactly as before they existed - keeping older signatures valid.
        for opt in ("expires_at", "repo"):
            if getattr(self, opt) is None:
                d.pop(opt, None)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Contract:
        try:
            return cls(
                version=int(data.get("version", CONTRACT_VERSION)),
                task=str(data["task"]),
                task_source=str(data.get("task_source", "text")),
                allowed_paths=tuple(data.get("allowed_paths", ())),
                base_commit=data.get("base_commit"),
                created_at=str(data.get("created_at", "")),
                contract_id=str(data.get("contract_id", "")),
                approved_by=data.get("approved_by"),
                expires_at=data.get("expires_at"),
                repo=data.get("repo"),
            )
        except (KeyError, TypeError, ValueError) as e:
            msg = f"malformed contract: {e}"
            raise ContractError(msg) from e

    def expiry_is_malformed(self) -> bool:
        """True iff an expiry was set but cannot be parsed. A security control must
        not silently reinterpret a malformed expiry as unlimited authorization
        (security review M-6), so strict mode treats this as a BLOCK."""
        if not self.expires_at:
            return False
        try:
            datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True
        return False

    def is_expired(self, now: datetime | None = None) -> bool:
        """True iff an expiry was set and has passed. A contract with no expiry
        never expires; an unparseable expiry is NOT 'expired' here (see
        ``expiry_is_malformed`` - strict mode blocks on that separately)."""
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        return (now or datetime.now(UTC)) >= exp

    def write(self, root: Path) -> Path:
        p = contract_path(root)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        return p


def _contract_id(
    task: str, base_commit: str | None, created_at: str, allowed_paths: Sequence[str] = ()
) -> str:
    """Short stable id: a hash over the task, base commit, creation time, AND the
    approved scope, so two contracts that differ only in scope get distinct ids
    (security review: contract_id omitted scope). Still not a security primitive -
    a human-citable handle ("contract a1b2c3d"); tamper-evidence comes from the
    HMAC audit chain and the contract signature, not from this id.
    """
    scope = "\x00".join(allowed_paths)
    h = hashlib.sha256(f"{task}\x00{base_commit}\x00{created_at}\x00{scope}".encode()).hexdigest()
    return h[:12]


def load(root: Path | None = None) -> Contract:
    """Read the contract for the repo containing `root` (cwd by default)."""
    root = repo_root(root)
    p = contract_path(root)
    if not p.exists():
        msg = (
            f"no contract at {p}. Run `nota begin <task>` first to capture the "
            f"human-approved task before verifying."
        )
        raise ContractError(msg)
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        msg = f"cannot read contract at {p}: {e}"
        raise ContractError(msg) from e
    return Contract.from_dict(data)


def begin(
    task: str,
    *,
    allowed_paths: Sequence[str] = (),
    root: Path | None = None,
    approved_by: str | None = None,
    expires_in_days: int | None = None,
    repo: str | None = None,
    audit: AuditLog | None = None,
    session_id: str = "nota-change-control",
) -> tuple[Contract, Path]:
    """Create and persist a contract from the approved task. Returns (contract, path).

    `task` is the issue URL or free text the human approved. `allowed_paths` is
    the scope allow-list. The base commit is the repo's current HEAD.
    `expires_in_days`, when set, records an expiry after which `nota verify
    --strict` BLOCKs - so a stale approval cannot authorize work indefinitely.
    When an `audit` log is supplied, a ``contract.created`` event is chained so
    the approval is tamper-evidently recorded.
    """
    task = task.strip()
    if not task:
        msg = "refusing to create a contract with an empty task"
        raise ContractError(msg)

    root = repo_root(root)
    base = head_sha(root)
    created = _now()
    expires_at: str | None = None
    if expires_in_days is not None:
        if expires_in_days <= 0:
            msg = "expires_in_days must be a positive number of days"
            raise ContractError(msg)
        expires_at = (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat()
    contract = Contract(
        version=CONTRACT_VERSION,
        task=task,
        task_source="url" if _looks_like_url(task) else "text",
        allowed_paths=tuple(allowed_paths),
        base_commit=base,
        created_at=created,
        contract_id=_contract_id(task, base, created, allowed_paths),
        approved_by=approved_by,
        expires_at=expires_at,
        repo=repo or None,
    )
    path = contract.write(root)

    if audit is not None:
        audit.emit(
            event_type=ev.CONTRACT_CREATED,
            session_id=session_id,
            risk="low",
            payload={
                "contract_id": contract.contract_id,
                "base_commit": base or "",
                "allowed_paths": list(contract.allowed_paths),
                "task_source": contract.task_source,
                # The task text can carry sensitive context; store a digest in
                # the audit chain rather than the raw text. The full task lives
                # in the reviewable contract.json beside the repo.
                "task_sha256": hashlib.sha256(task.encode()).hexdigest(),
            },
        )

    return contract, path
