"""Drop-in scan: secrets, gate tamper, and sensitive surfaces, with no contract
and no keys.

This is the on-ramp a team can adopt in one pull request. It reuses the whole
verify engine by handing it a synthetic contract whose scope is every path and
whose base is the merge-base of the pull request, so the scope checks are
vacuous and the evidence rules (secret findings on added lines, edits to the
gate's own surfaces, sensitive surfaces, submodule and symlink inventory) are
exactly the ones `notari verify` runs. The passport says `mode: scan` and the
contract's `task_source` is `scan`, so nothing downstream can mistake a scan
for a signed boundary.

Fail-closed properties carried over: a BLOCK exits 1, anything that is not a
verdict exits 2, and the scan never reads `.notari/contract.json`, so a pull
request that deletes a contract changes nothing here.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from notari import verify as verify_mod
from notari.audit import AuditLog
from notari.contract import CONTRACT_VERSION, Contract, repo_root

SCAN_TASK_SOURCE = "scan"
SCAN_TASK = "scan: secrets, gate tamper, sensitive surfaces (no contract)"
SCAN_CONTRACT_ID = "scan"

# Where the base comes from when the caller gives none, in order. CI sets
# NOTARI_BASE_SHA from the pull request; a developer on a branch usually has an
# upstream; the rest are the common default-branch names.
_BASE_FALLBACKS: tuple[str, ...] = ("@{upstream}", "origin/HEAD", "origin/main", "main", "master")


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=verify_mod.DEFAULT_GIT_TIMEOUT,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return out.stdout.strip() or None


def _reject_option_shaped(ref: str, what: str) -> None:
    if ref.startswith("-"):
        msg = f"{what} {ref!r} looks like an option, not a git ref"
        raise verify_mod.VerifyError(msg)


def resolve_base(root: Path, base: str | None, env: dict[str, str]) -> str:
    """Return the full SHA of the base ref: explicit `base`, else NOTARI_BASE_SHA,
    else the first fallback ref that exists in this repo."""
    # An explicit base, from the flag or from CI's NOTARI_BASE_SHA, must resolve:
    # falling through to a default branch would scan a different diff than the
    # one asked for, and a shallow checkout would turn that into a quiet PASS.
    explicit = base or env.get("NOTARI_BASE_SHA", "")
    candidates = [explicit] if explicit else list(_BASE_FALLBACKS)
    for ref in candidates:
        if not ref:
            continue
        _reject_option_shaped(ref, "base")
        sha = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        if sha and verify_mod._is_hex_sha(sha):
            return sha
    msg = (
        "no base ref found (tried " + ", ".join(c for c in candidates if c) + "); pass --base <ref>"
    )
    raise verify_mod.VerifyError(msg)


def merge_base(root: Path, base_sha: str, head: str) -> str:
    """The merge-base of base and head, which is what a pull request diff is
    measured from. Unrelated histories are an error, never an empty diff."""
    _reject_option_shaped(head, "head")
    mb = _git(root, "merge-base", base_sha, head)
    if not mb or not verify_mod._is_hex_sha(mb):
        msg = f"no merge-base between {base_sha[:12]} and {head!r}"
        raise verify_mod.VerifyError(msg)
    return mb


def scan_contract(base_commit: str) -> Contract:
    """The synthetic, unsigned, every-path contract a scan runs against."""
    return Contract(
        version=CONTRACT_VERSION,
        task=SCAN_TASK,
        task_source=SCAN_TASK_SOURCE,
        allowed_paths=("**",),
        base_commit=base_commit,
        created_at=datetime.now(UTC).isoformat(),
        contract_id=SCAN_CONTRACT_ID,
    )


def is_scan(contract: Contract) -> bool:
    return contract.task_source == SCAN_TASK_SOURCE


def scan(
    *,
    root: Path | None = None,
    base: str | None = None,
    head: str = "HEAD",
    audit: AuditLog | None = None,
    env: dict[str, str] | None = None,
) -> verify_mod.VerifyResult:
    """Scan the diff from merge-base(base, head) to head. Returns the same
    VerifyResult `notari verify` produces, minus any boundary."""
    root = repo_root(root)
    env = dict(os.environ) if env is None else env
    base_sha = resolve_base(root, base, env)
    mb = merge_base(root, base_sha, head)
    head_sha = _git(root, "rev-parse", "--verify", "--quiet", f"{head}^{{commit}}")
    if head_sha == mb:
        # Nothing between base and head: a push or workflow_dispatch run with no
        # base, `--base HEAD`, or swapped refs. A green check on a scan of
        # nothing is exactly the fail-open this mode must not have.
        msg = (
            f"nothing to scan: base {base_sha[:12]} is not behind head {head!r} "
            "(merge-base equals head); pass --base <the ref the change targets>"
        )
        raise verify_mod.VerifyError(msg)
    return verify_mod.verify(
        contract=scan_contract(mb),
        root=root,
        head=head,
        audit=audit,
        session_id="notari-scan",
        perimeter=None,
        strict=False,
        env=env,
    )
