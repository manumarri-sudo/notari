"""Session-journal writer.

Reads a Claude Code (or compatible) transcript JSONL and writes a
markdown session log into the user's AgentOS vault under
`ClaudeCode/Sessions/`.

Designed to run as a Claude Code SessionEnd hook so journaling is
zero-effort: every session ends with a journal entry, no human prompt.

Privacy: only writes to ClaudeCode/Sessions/ within the configured vault
root. Never writes to other vault subtrees (Lattice, AgentBrain, etc.).
Tool arguments are summarized at the namespace level only - never logs
full file paths from edits, never logs shell command bodies, never logs
intent text verbatim. The journal is a record of *what was attempted
and how it was gated*, not what was edited.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_VAULT_SESSIONS = Path(
    os.environ.get(
        "QUILL_VAULT_SESSIONS",
        "~/agentbrain/AgentOS-Vault/ClaudeCode/Sessions",
    ),
).expanduser()

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(s: str, max_words: int = 5) -> str:
    """Turn a free-text headline into a 3-5 word kebab slug."""
    words = _SLUG_RE.sub(" ", s.lower()).split()
    return "-".join(words[:max_words]) if words else "session"


@dataclass(slots=True)
class JournalSummary:
    """The data we extracted from the transcript, ready to render."""

    started_at: str
    ended_at: str
    n_user_turns: int = 0
    n_assistant_turns: int = 0
    tool_use_counts: Counter[str] = field(default_factory=Counter)
    files_touched: set[str] = field(default_factory=set)
    bash_commands_seen: int = 0
    headline: str = ""
    cwd: str | None = None


def _safe_str(x: Any) -> str:
    return x if isinstance(x, str) else str(x)


# Path segments that identify credential / secret directories. Any path
# whose first non-empty segment matches one of these is redacted in the
# journal (we still record that SOMETHING in that area was touched but
# never name the filename). Match is exact for fixed names, prefix for
# .env (covers .env, .env.local, .env.production, etc.).
_SENSITIVE_SEGMENT_EXACT: frozenset[str] = frozenset(
    {
        ".aws",
        ".ssh",
        ".gnupg",
        ".gpg",
        ".password-store",
        ".kube",
        ".docker",
        ".netrc",
        ".config",  # too broad? often holds creds (gh, sentry, etc.) - be safe
        ".credentials",
        "credentials",
        ".secrets",
        "secrets",
    }
)


def _is_sensitive_segment(seg: str) -> bool:
    if seg in _SENSITIVE_SEGMENT_EXACT:
        return True
    # .env, .env.local, .env.production, etc.
    if seg.startswith(".env"):
        return True
    # private key / cert file segments (rare as top-level dirs but worth it)
    return False


def summarize_transcript(events: Iterable[Mapping[str, Any]]) -> JournalSummary:
    """Reduce a transcript JSONL to the privacy-safe summary we render.

    Handles two transcript shapes:
      1. Flat: {role, content, ts/timestamp} - original assumption.
      2. Claude Code: {type: "user"|"assistant", timestamp,
         message: {role, content}, cwd, ...} - actual on-disk shape.
    """
    s = JournalSummary(started_at="", ended_at="")
    first_ts = last_ts = None
    for evt in events:
        ts = evt.get("ts") or evt.get("timestamp")
        if isinstance(ts, str):
            first_ts = first_ts or ts
            last_ts = ts

        inner = evt.get("message") if isinstance(evt.get("message"), Mapping) else None
        # Claude Code uses evt["type"] for role; the flat shape uses evt["role"].
        role = evt.get("role")
        if role not in ("user", "assistant"):
            etype = evt.get("type")
            if etype in ("user", "assistant"):
                role = etype
        # Content lives at top level in the flat shape, nested for Claude Code.
        content = evt.get("content")
        if content is None and inner is not None:
            content = inner.get("content")

        if role == "user":
            s.n_user_turns += 1
            if isinstance(content, str) and not s.headline and content.strip():
                # First user turn becomes the headline (truncated).
                s.headline = content.strip()[:80]
            elif isinstance(content, list) and not s.headline:
                # Claude Code wraps user text in content blocks too.
                for b in content:
                    if isinstance(b, Mapping) and b.get("type") == "text":
                        text = b.get("text")
                        if isinstance(text, str) and text.strip():
                            s.headline = text.strip()[:80]
                            break
        elif role == "assistant":
            s.n_assistant_turns += 1

        # Tool-use entries always live inside the message content blocks.
        blocks = content if isinstance(content, list) else []
        for b in blocks:
            if not isinstance(b, Mapping):
                continue
            if b.get("type") == "tool_use":
                tname = _safe_str(b.get("name", ""))
                if tname:
                    s.tool_use_counts[tname] += 1
                # Privacy: store namespace of the touched path, not full path.
                inp = b.get("input")
                if isinstance(inp, Mapping):
                    p = inp.get("file_path") or inp.get("path") or inp.get("notebook_path")
                    if isinstance(p, str):
                        # Privacy: keep first two meaningful path segments only.
                        # Strip $HOME so absolute paths under home don't all
                        # collapse to the same "/Users/<name>" prefix.
                        home = str(Path.home())
                        if p.startswith(home):
                            p = p[len(home) :].lstrip("/")
                        parts = [seg for seg in Path(p).parts if seg not in ("/", "")]
                        # Privacy denylist: certain top-level segments name
                        # credentials directories. Logging "agentbrain/vault"
                        # is fine; logging ".aws/credentials" leaks the
                        # filename of a secret. Collapse those to a redacted
                        # bucket so the journal still records that SOMETHING
                        # in that area was touched without naming the file.
                        if parts and _is_sensitive_segment(parts[0]):
                            s.files_touched.add("(redacted credential path)")
                        elif len(parts) >= 2:
                            s.files_touched.add(f"{parts[0]}/{parts[1]}")
                        elif parts:
                            s.files_touched.add(parts[0])
                        else:
                            s.files_touched.add("(root)")
                    if tname == "Bash":
                        s.bash_commands_seen += 1

        if evt.get("cwd") and not s.cwd:
            s.cwd = _safe_str(evt["cwd"])

    s.started_at = first_ts or datetime.now(UTC).isoformat()
    s.ended_at = last_ts or datetime.now(UTC).isoformat()
    return s


def render_markdown(summary: JournalSummary) -> str:
    """Render the JournalSummary as the markdown the skill writes."""
    date = (summary.ended_at or "")[:10]
    headline = summary.headline or "untitled session"
    slug = slugify(headline)
    name = f"Session journal {date} · {headline}"

    top_tools = ", ".join(f"{n}×{c}" for n, c in summary.tool_use_counts.most_common(8)) or "none"
    files = ", ".join(sorted(summary.files_touched)[:10]) or "none"

    # Yes - two YAML frontmatter blocks. The first carries the
    # basic-memory permalink; the second carries human-friendly metadata
    # the user keeps elsewhere in the vault. Mirrors existing convention.
    body = f"""---
permalink: agentos-vault/claude-code/sessions/{date}-{slug}
---

---
name: {name}
description: Auto-generated session journal. {summary.n_user_turns} user turns, {summary.n_assistant_turns} assistant turns. Top tools used: {top_tools}.
type: session
date: {date}
auto_generated: true
---

# Session journal - {date} · {headline}

> Written automatically by `quill journal save` at session end.
> Privacy contract: namespaces and counts only - no shell commands,
> no full file paths, no intent text verbatim.

## Counts

- user turns: {summary.n_user_turns}
- assistant turns: {summary.n_assistant_turns}
- shell commands attempted: {summary.bash_commands_seen}
- top-level file areas touched: {files}
- session start: {summary.started_at}
- session end:   {summary.ended_at}

## Tools used (top 8 by count)

{chr(10).join(f"- `{n}` × {c}" for n, c in summary.tool_use_counts.most_common(8)) or "- (no tool calls recorded in transcript)"}

## What to do next

(Auto-journaling does not infer next steps. If you want a substantive
session journal, ask me to write one explicitly - I'll use the
`quill-session-journal` skill which produces a richer log.)

"""
    return body


def write_journal(
    summary: JournalSummary,
    *,
    sessions_dir: Path | None = None,
) -> Path:
    """Write the rendered markdown to ClaudeCode/Sessions/ and return the path.

    The filename is `<date>-<slug>.md`. If a file with that exact name
    already exists, appends `-2`, `-3`, etc. - never overwrites.
    """
    out_dir = sessions_dir or DEFAULT_VAULT_SESSIONS
    out_dir.mkdir(parents=True, exist_ok=True)

    date = (summary.ended_at or "")[:10]
    slug = slugify(summary.headline or "untitled")
    base = f"{date}-{slug}"
    target = out_dir / f"{base}.md"
    n = 2
    while target.exists():
        target = out_dir / f"{base}-{n}.md"
        n += 1
    target.write_text(render_markdown(summary))
    return target


def save_from_transcript(
    transcript_path: Path,
    *,
    sessions_dir: Path | None = None,
) -> Path:
    """Read a Claude Code transcript JSONL and write a journal.

    The transcript path is what Claude Code's hooks pass on stdin
    (field `transcript_path`). Best-effort: if the file is missing or
    malformed, we still write a stub journal so the session is recorded.
    """
    events: list[dict[str, Any]] = []
    if transcript_path.exists():
        with transcript_path.open() as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
    summary = summarize_transcript(events)
    if not summary.headline and events:
        summary.headline = "claude code session"
    return write_journal(summary, sessions_dir=sessions_dir)


def _emit_session_close(session_id: str, cwd: str, reason: str) -> None:
    """Emit a `session.close` audit event for the ending session.

    Walks the audit log once to:
      1. Confirm idempotence (no duplicate close for this session_id).
      2. Derive `duration_seconds` from the matching `session.open` timestamp.
      3. Derive `tool_call_count` from `tool.attempted` events.

    Determinism: the emission is gated by an exact-match check on
    `session_id` against existing `session.close` events in the chain;
    a second SessionEnd invocation for the same session is a no-op.
    Errors are swallowed so the journal write (the next step) still
    runs even if the audit emission fails - the audit chain is the
    authoritative store and self-heals if a session is left open.
    """
    if not session_id:
        return
    try:
        from quill import events as ev
        from quill.adapters.claude_code import (
            _default_load_hmac_key,
            _resolve_project_paths,
        )
        from quill.audit import AuditLog

        log_path, _ = _resolve_project_paths(cwd)
        if not log_path.exists():
            return  # no log, nothing to close against

        already_closed = False
        opened_at: str | None = None
        tool_call_count = 0
        with log_path.open() as f:
            for line in f:
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("session_id") != session_id:
                    continue
                etype = evt.get("type")
                if etype == ev.SESSION_CLOSE:
                    already_closed = True
                    break
                if etype == ev.SESSION_OPEN and opened_at is None:
                    ts = evt.get("ts")
                    if isinstance(ts, str):
                        opened_at = ts
                if etype == ev.TOOL_ATTEMPTED:
                    tool_call_count += 1

        if already_closed:
            return

        duration_seconds = 0
        if opened_at:
            try:
                opened_dt = datetime.fromisoformat(opened_at.replace("Z", "+00:00"))
                duration_seconds = int((datetime.now(UTC) - opened_dt).total_seconds())
            except (ValueError, AttributeError):
                duration_seconds = 0

        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            audit.emit(
                event_type=ev.SESSION_CLOSE,
                session_id=session_id,
                agent_id="claude-code",
                risk="low",
                payload={
                    "reason": reason or "transcript_end",
                    "duration_seconds": duration_seconds,
                    "tool_call_count": tool_call_count,
                    "cwd": cwd,
                },
                force_fsync=True,
            )
    except Exception:
        # Audit emission is best-effort; the chain is intact either way.
        return


def _check_session_drift(session_id: str, cwd: str) -> None:
    """At SessionEnd, run Page-Hinkley over this session's audit
    outcomes. Emits a `drift_detected` suggestion when the approval
    rate has shifted meaningfully. Best-effort; failures are swallowed.
    """
    if not session_id:
        return
    try:
        from quill.adapters.claude_code import _resolve_project_paths

        log_path, _ = _resolve_project_paths(cwd)
        if not log_path.exists():
            return
        events: list[dict[str, Any]] = []
        with log_path.open() as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and obj.get("session_id") == session_id:
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
        from quill.learning import check_drift_for_session

        check_drift_for_session(events, session_id)
    except Exception:
        # Drift check is observational only; never block journal write.
        return


def session_end_hook(stdin_text: str) -> dict[str, Any]:
    """Pure-function entry for the SessionEnd hook.

    Reads `{transcript_path, session_id, cwd, reason}` from stdin,
    emits `session.close` to the audit log (idempotent), and writes the
    journal markdown. Returns a hookSpecificOutput-shaped response
    (Claude Code ignores SessionEnd output but we return one so it's
    symmetric with the PreToolUse adapter).
    """
    try:
        payload = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    session_id = str(payload.get("session_id") or "")
    cwd = str(payload.get("cwd") or "")
    reason = str(payload.get("reason") or "transcript_end")
    _emit_session_close(session_id, cwd, reason)
    _check_session_drift(session_id, cwd)

    tpath_raw = payload.get("transcript_path")
    if not isinstance(tpath_raw, str) or not tpath_raw:
        return {"ok": False, "reason": "no transcript_path"}
    try:
        path = save_from_transcript(Path(tpath_raw).expanduser())
        return {"ok": True, "path": str(path)}
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}
