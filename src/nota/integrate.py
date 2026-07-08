"""nota integrate — append Nota-instruction snippets to your coding agent's rules file.

The idea: most users are already in Claude Code or Cursor when they want to
ask "what did the agent do this morning?" Their coding agent IS an LLM with
file-read tools. Nota doesn't need to ship its own LLM caller; it needs to
teach the user's existing agent how to query Nota's CLI and audit log.

This module appends a small instructions snippet to the user's coding-agent
rules file (CLAUDE.md / .cursorrules / CONVENTIONS.md / etc). The snippet
lists the deterministic `nota` commands the agent can call when the user
asks about agent activity. Zero LLM dependency in Nota.

Idempotent: a `<!-- nota-integration v1 -->` marker bookends the block.
Re-runs detect the marker and report "already integrated." Snippet
version bumps trigger a clean replace, not a duplicate append.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MARKER_BEGIN: Final[str] = "<!-- nota-integration v1 -->"
MARKER_END: Final[str] = "<!-- end nota-integration v1 -->"


# ---------------------------------------------------------------------------
# the snippet text per agent
#
# Voice and instruction shape are tuned per agent because each rules-file
# convention sets its own style expectations. Each snippet ends with a
# stable signature line that includes the version marker for idempotency.


_SNIPPET_CLAUDE_CODE: Final[str] = """\
## Nota integration

The user has Nota installed for AI agent governance (https://github.com/manumarri-sudo/nota).
When the user asks about agent activity, audit logs, blocks, secrets, or compliance,
prefer running these deterministic CLI commands rather than guessing from memory:

- `nota saves` — counts of approvals saved, secrets caught, destructive operations blocked
- `nota saves --month` — same, expanded to 30-day window
- `nota receipts list --last 10` — recent session summaries (plain-English narrative + structured detail)
- `nota receipts show <session_id>` — full session detail
- `nota audit show --last 30` — pretty-print recent audit events
- `nota audit show --type verdict.blocked --last 30` — recent blocks only
- `nota audit export --pack` — SOC 2 / EU AI Act / AIUC-1 / NIST / ISO 42001 / MITRE ATLAS PDF
- `nota trifecta show` — lethal-trifecta exposure state per session
- `nota scan-secrets <path>` — scan files for hardcoded credentials
- `nota scan-prompts <path>` — scan files for prompt-injection-shape patterns

The audit log lives at `~/.nota/audit.log.jsonl` (HMAC-chained JSONL, one event per line).
When citing audit events, include the session_id and timestamp so the user can verify
against the chain via `nota audit verify`.

Nota's positioning principle: do not invent claims about agent activity; run the CLI,
read the actual log, cite specific events.
"""


_SNIPPET_CURSOR: Final[str] = """\
# Nota integration (https://github.com/manumarri-sudo/nota)

The user has Nota installed for AI agent governance. When the user asks about agent
activity, blocks, secrets, or compliance evidence, prefer running these CLI commands:

- `nota saves` — what Nota caught for the user
- `nota receipts list --last 10` — recent session summaries
- `nota receipts show <session_id>` — full session detail
- `nota audit show --last 30` — recent audit events
- `nota audit export --pack` — compliance evidence pack PDF
- `nota trifecta show` — lethal-trifecta state per session

The audit log lives at `~/.nota/audit.log.jsonl`. Always cite session_id + timestamp.
"""


_SNIPPET_AIDER: Final[str] = """\
## Nota integration

Nota is installed: https://github.com/manumarri-sudo/nota.

When asked about agent activity, audit logs, or compliance, run these commands and cite the output:

* `nota saves` — verified counts of what Nota caught
* `nota receipts list --last 10` — recent sessions
* `nota receipts show <session_id>` — session detail
* `nota audit show --last 30` — recent events
* `nota audit export --pack` — compliance PDF

Audit log path: `~/.nota/audit.log.jsonl`. Always cite session_id + timestamp.
"""


# ---------------------------------------------------------------------------
# integration definitions


@dataclass(frozen=True, slots=True)
class Integration:
    """One coding agent that Nota can plug instructions into."""

    name: str  # internal id (matches CLI arg)
    label: str  # human-readable
    detect_paths: tuple[Path, ...]  # files/dirs whose existence indicates the agent
    target_path_global: Path | None  # ~/.claude/CLAUDE.md style; per-user
    target_path_project: Path  # ./CLAUDE.md style; per-repo
    snippet: str  # the text to inject


def _claude_code() -> Integration:
    return Integration(
        name="claude-code",
        label="Claude Code",
        detect_paths=(Path.home() / ".claude",),
        target_path_global=Path.home() / ".claude" / "CLAUDE.md",
        target_path_project=Path.cwd() / "CLAUDE.md",
        snippet=_SNIPPET_CLAUDE_CODE,
    )


def _cursor() -> Integration:
    return Integration(
        name="cursor",
        label="Cursor",
        detect_paths=(Path("/Applications/Cursor.app"), Path.home() / ".cursor"),
        target_path_global=None,
        target_path_project=Path.cwd() / ".cursorrules",
        snippet=_SNIPPET_CURSOR,
    )


def _aider() -> Integration:
    return Integration(
        name="aider",
        label="Aider",
        detect_paths=(),  # no canonical install marker; aider is just a PATH binary
        target_path_global=None,
        target_path_project=Path.cwd() / "CONVENTIONS.md",
        snippet=_SNIPPET_AIDER,
    )


def all_integrations() -> tuple[Integration, ...]:
    """Every supported coding agent. Order is preserved for display."""
    return (_claude_code(), _cursor(), _aider())


def get_integration(name: str) -> Integration | None:
    """Look up an integration by its CLI-arg name. Returns None on miss."""
    for integ in all_integrations():
        if integ.name == name:
            return integ
    return None


def detect_installed() -> list[Integration]:
    """Return integrations whose detect_paths indicate the agent is installed.

    Aider has no canonical install marker (it's just a PATH binary), so it's
    detected via `shutil.which("aider")`. Other agents check filesystem
    presence; this is cheap and survives unmounted Application bundles.
    """
    found: list[Integration] = []
    for integ in all_integrations():
        if integ.name == "aider":
            if shutil.which("aider"):
                found.append(integ)
            continue
        if any(p.exists() for p in integ.detect_paths):
            found.append(integ)
    return found


# ---------------------------------------------------------------------------
# install / uninstall logic


def _existing_block(text: str) -> tuple[int, int] | None:
    """Return (start, end) offsets of an existing nota-integration block,
    or None if not present. End offset is exclusive (one past the closing
    marker line)."""
    start_re = re.compile(re.escape(MARKER_BEGIN), re.MULTILINE)
    end_re = re.compile(re.escape(MARKER_END), re.MULTILINE)
    sm = start_re.search(text)
    if not sm:
        return None
    em = end_re.search(text, sm.end())
    if not em:
        # marker_begin without marker_end is corrupt — treat as no block so
        # the next install rewrites cleanly
        return None
    # extend end-of-block past trailing newline
    end_off = em.end()
    if end_off < len(text) and text[end_off] == "\n":
        end_off += 1
    return (sm.start(), end_off)


def _build_block(snippet: str) -> str:
    """Wrap a snippet with begin/end markers for idempotent replace."""
    return f"\n{MARKER_BEGIN}\n{snippet.rstrip()}\n{MARKER_END}\n"


def install(
    integ: Integration,
    *,
    global_scope: bool = False,
) -> tuple[Path, str]:
    """Append (or refresh) the Nota snippet in the target rules file.

    Returns (path_written, status) where status is one of:
      - "installed"    a fresh block was appended
      - "refreshed"    an existing block was replaced (snippet drifted)
      - "current"      an existing block already matches the current snippet

    Idempotent: re-runs with no snippet change are no-ops.

    `global_scope=True` writes to the per-user rules file (e.g.
    `~/.claude/CLAUDE.md`); default is per-project (e.g. `./CLAUDE.md` in
    the current working directory). Only Claude Code has a global path
    today; other integrations raise on `global_scope=True`.
    """
    if global_scope:
        if integ.target_path_global is None:
            raise ValueError(
                f"{integ.label} has no per-user rules file; use the project scope",
            )
        target = integ.target_path_global
    else:
        target = integ.target_path_project

    target.parent.mkdir(parents=True, exist_ok=True)

    existing_text = target.read_text() if target.exists() else ""
    block = _build_block(integ.snippet)

    existing_offsets = _existing_block(existing_text)
    if existing_offsets is None:
        new_text = existing_text.rstrip() + ("\n" if existing_text.strip() else "") + block
        target.write_text(new_text)
        return target, "installed"

    start, end = existing_offsets
    existing_block_text = existing_text[start:end]
    if existing_block_text.strip() == block.strip():
        return target, "current"

    new_text = existing_text[:start] + block.lstrip("\n") + existing_text[end:]
    target.write_text(new_text)
    return target, "refreshed"


def uninstall(
    integ: Integration,
    *,
    global_scope: bool = False,
) -> tuple[Path, bool]:
    """Remove the Nota snippet from the rules file. Returns (path, removed).

    Removed=False means there was nothing to remove (block not present).
    The rest of the file is preserved.
    """
    if global_scope:
        if integ.target_path_global is None:
            raise ValueError(
                f"{integ.label} has no per-user rules file; use the project scope",
            )
        target = integ.target_path_global
    else:
        target = integ.target_path_project

    if not target.exists():
        return target, False

    text = target.read_text()
    offsets = _existing_block(text)
    if offsets is None:
        return target, False

    start, end = offsets
    new_text = text[:start].rstrip() + ("\n" + text[end:] if text[end:].strip() else "\n")
    target.write_text(new_text)
    return target, True
