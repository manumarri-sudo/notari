"""Git `prepare-commit-msg` hook: append the active agent session's
summary as a comment block in the commit message.

The hook is opt-in (installed via `nota git-hook install` inside a
repo) and writes the summary as `#`-prefixed comment lines so git
ignores them by default. The user can uncomment any line they want
to surface in the actual commit message, or delete the block
entirely if they don't want it.

The block surfaces:
  - session id (first 12 chars)
  - tool call count + blocked count + TDR
  - top touched directory
  - any critical-class blocks with their reason
  - the time window

If no recent agent session exists, the hook is a no-op. The hook
also no-ops on merge / squash / amend commits where prepending a
new block would be wrong.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from nota.receipt import Receipt, derive_from_events, load_audit_events

# How recent does "active session" need to be? If the latest session_close
# is older than this, the hook adds nothing (we don't want a 3-day-old
# session's summary on today's commit).
DEFAULT_FRESHNESS_SECONDS: Final[int] = 4 * 60 * 60  # 4 hours

# Source types from git's prepare-commit-msg (second positional arg).
# Skip the cases where prepending is wrong.
_SKIP_SOURCE_TYPES: Final[frozenset[str]] = frozenset(
    {"merge", "squash", "commit"},  # `commit` = `git commit --amend`
)

_BLOCK_MARKER: Final[str] = "# === Nota session summary ==="


def find_active_session(
    receipts: dict[str, Receipt],
    *,
    now: datetime | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> Receipt | None:
    """Return the most recent session whose latest activity is within window.

    Sessions are ranked by max(opened_at, closed_at). Ties go to the
    session with more tool calls.
    """
    if not receipts:
        return None
    now = now or datetime.now(UTC)
    cutoff = now.timestamp() - freshness_seconds
    best: Receipt | None = None
    best_ts = 0.0
    for r in receipts.values():
        ts_str = r.closed_at or r.opened_at
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if ts < cutoff:
            continue
        if ts > best_ts or (ts == best_ts and best and r.tool_call_count > best.tool_call_count):
            best = r
            best_ts = ts
    return best


def render_commit_block(r: Receipt) -> str:
    """Render a Receipt as a #-prefixed comment block.

    Designed to slot into a commit message buffer without changing the
    user's authored text. Each line is a comment so git ignores it
    unless the user uncomments specific lines.
    """
    lines: list[str] = [
        _BLOCK_MARKER,
        f"# session  : {r.session_id[:12]}",
    ]
    if r.opened_at and r.closed_at:
        lines.append(f"# window   : {r.opened_at[:19]} → {r.closed_at[:19]}")
    elif r.opened_at:
        lines.append(f"# started  : {r.opened_at[:19]}")
    lines.append(
        f"# calls    : {r.tool_call_count} "
        f"(blocked={len(r.blocks_summary)}, "
        f"asks={len(r.asks_summary)}, "
        f"touchid={r.biometric_approvals})",
    )
    if r.top_changed_dir:
        lines.append(f"# touched  : {r.top_changed_dir}")
    if r.tdr_contribution < 1.0:
        lines.append(f"# TDR      : {r.tdr_contribution:.2f}")
    if r.intent:
        lines.append(f"# intent   : {r.intent[:140]}")
    if r.blocks_summary:
        lines.append("# blocked  :")
        for b in r.blocks_summary[:5]:
            lines.append(f"#   - {b[:200]}")
        if len(r.blocks_summary) > 5:
            lines.append(f"#   ... and {len(r.blocks_summary) - 5} more")
    if r.to_verify:
        lines.append("# to verify:")
        for v in r.to_verify[:3]:
            lines.append(f"#   ? {v[:200]}")
    lines.append(
        "# (added by nota prepare-commit-msg; uncomment a line to keep it, or delete this block)",
    )
    lines.append("")
    return "\n".join(lines)


def prepare_commit_msg(
    commit_msg_path: Path,
    *,
    source_type: str = "",
    log_path: Path | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> int:
    """Entry point for the `prepare-commit-msg` git hook.

    Returns the exit code git expects (0 = continue). Git ignores
    stdout/stderr for this hook, so we don't print user-facing
    messages.
    """
    if source_type in _SKIP_SOURCE_TYPES:
        return 0
    try:
        events = load_audit_events(log_path)
    except OSError:
        return 0
    if not events:
        return 0
    receipts = derive_from_events(events)
    active = find_active_session(receipts, freshness_seconds=freshness_seconds)
    if active is None or active.tool_call_count == 0:
        return 0

    try:
        original = commit_msg_path.read_text()
    except OSError:
        return 0
    if _BLOCK_MARKER in original:
        # Already injected (re-run on amend or similar); leave it alone.
        return 0

    block = render_commit_block(active)
    # Inject after the user's authored content but before the standard
    # "# Please enter the commit message ..." comment block git adds.
    # Find the first git-comment header and insert before it; if none
    # exists, append.
    insertion_marker = "# Please enter the commit message"
    if insertion_marker in original:
        idx = original.index(insertion_marker)
        new_content = original[:idx] + block + "\n" + original[idx:]
    else:
        new_content = original.rstrip() + "\n\n" + block

    try:
        commit_msg_path.write_text(new_content)
    except OSError:
        return 0
    return 0


def main() -> int:
    """CLI shim invoked by the installed hook script.

    Git calls `prepare-commit-msg` with positional args:
      1: path to the commit message file
      2: source of the message (one of: message, template, merge, squash, commit)
      3: SHA-1 of the commit being amended (only when source == commit)
    """
    if len(sys.argv) < 2:
        return 0
    msg_path = Path(sys.argv[1])
    source_type = sys.argv[2] if len(sys.argv) > 2 else ""
    return prepare_commit_msg(msg_path, source_type=source_type)


# ---------------------------------------------------------------------------
# install / uninstall


def _resolve_nota_binary() -> str:
    """Find the absolute path to the `nota` binary that should be invoked
    by the installed hook.

    Prefers `sys.executable`'s sibling `nota` (matches the interpreter
    running the install, which is what the user wants in a venv). Falls
    back to `shutil.which("nota")`. Final fallback is the literal
    string `nota`, which leaves the hook depending on PATH.
    """
    import shutil
    import sys

    venv_nota = Path(sys.executable).parent / "nota"
    if venv_nota.exists() and os.access(venv_nota, os.X_OK):
        return str(venv_nota)
    on_path = shutil.which("nota")
    if on_path:
        return on_path
    return "nota"


def _hook_script() -> str:
    """Render the prepare-commit-msg shim that exec's nota git-hook.

    Resolves the absolute path to the nota binary at install time so
    the hook works even when the user's shell at commit time doesn't
    have the venv activated. The string "nota git-hook" remains
    discoverable for the install/uninstall idempotency check.
    """
    binary = _resolve_nota_binary()
    return (
        "#!/bin/sh\n"
        "# nota prepare-commit-msg hook\n"
        "# Installed by `nota commit-hook-install`; remove with "
        "`nota commit-hook-uninstall`.\n"
        f'exec {binary} git-hook "$@"\n'
    )


# Kept for back-compat with any code that imported _HOOK_SCRIPT before
# this change; new code should call _hook_script() to get the resolved
# binary path baked in.
_HOOK_SCRIPT: Final[str] = '#!/bin/sh\n# nota prepare-commit-msg hook\nexec nota git-hook "$@"\n'


def hook_path(repo_root: Path) -> Path:
    """Return the path where the prepare-commit-msg hook should live."""
    # Git supports a `core.hooksPath` config that overrides the default,
    # but we read the default location only. Operators using a custom
    # hooksPath can copy the file manually.
    return repo_root / ".git" / "hooks" / "prepare-commit-msg"


def install_hook(repo_root: Path) -> tuple[Path, bool]:
    """Write the hook into .git/hooks/prepare-commit-msg.

    Returns (path, already). `already=True` if the hook was already
    Nota's (idempotent). Refuses to overwrite a non-Nota existing
    hook so we don't silently break someone's custom hook chain.
    """
    p = hook_path(repo_root)
    if p.exists():
        existing = p.read_text(errors="replace")
        if "nota git-hook" in existing:
            return p, True
        raise FileExistsError(
            f"a non-nota prepare-commit-msg hook already exists at {p}; "
            "back it up and remove it before installing the nota hook",
        )
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_hook_script())
    p.chmod(0o755)
    return p, False


def uninstall_hook(repo_root: Path) -> tuple[Path, bool]:
    """Remove the hook. Returns (path, removed)."""
    p = hook_path(repo_root)
    if not p.exists():
        return p, False
    existing = p.read_text(errors="replace")
    if "nota git-hook" not in existing:
        raise RuntimeError(
            f"hook at {p} is not a nota hook; refusing to remove",
        )
    p.unlink()
    return p, True
