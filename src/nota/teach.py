"""Write promoted Nota lessons into agent instruction files, and render the
compact fix-prompt / agent-brief surfaces.

Managed-block contract: everything between the nota-lessons markers belongs
to Nota; everything outside is the user's and is never touched. Updates are
idempotent — re-running with the same lessons is a byte-for-byte no-op.

Token discipline: agents get compressed briefs and fix prompts, never the
full passport (that stays for humans and auditors).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nota import lessons as lessons_mod
from nota.explain import build_remediations

BLOCK_START = "<!-- nota-lessons:start -->"
BLOCK_END = "<!-- nota-lessons:end -->"

_BASE_LINES = [
    "Before finishing, run `git diff --name-only` and verify every changed "
    "file belongs to the approved task.",
    "If a needed change is outside scope, stop and ask for a new signed "
    "approval instead of sneaking it into this PR.",
]

AGENT_TARGETS: dict[str, str] = {
    "claude": "CLAUDE.md",
    "codex": "AGENTS.md",
    "cursor": ".cursor/rules/nota-scope.mdc",
}


def render_block(promoted: list[dict[str, str]]) -> str:
    lines = [
        BLOCK_START,
        "## Nota agent lessons",
        "",
        "These rules come from prior Nota findings in this repo. Follow them before editing files.",
        "",
    ]
    for entry in promoted:
        lines.append(f"- {entry['text']}")
    for base in _BASE_LINES:
        lines.append(f"- {base}")
    lines += ["", BLOCK_END]
    return "\n".join(lines)


def update_file(path: Path, promoted: list[dict[str, str]]) -> bool:
    """Insert or replace the managed block. Returns True if the file changed.

    User content outside the markers is preserved byte-for-byte.
    """
    block = render_block(promoted)
    if path.exists():
        text = path.read_text()
        if BLOCK_START in text and BLOCK_END in text:
            head, _, rest = text.partition(BLOCK_START)
            _, _, tail = rest.partition(BLOCK_END)
            new = head + block + tail
        else:
            sep = (
                ""
                if (not text or text.endswith("\n\n"))
                else ("\n" if text.endswith("\n") else "\n\n")
            )
            new = text + sep + block + "\n"
    else:
        new = block + "\n"
    if path.exists() and path.read_text() == new:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new)
    return True


def teach(root: Path, agents: list[str]) -> list[tuple[str, bool]]:
    """Write promoted lessons into each selected agent surface.

    Also updates `.cursorrules` for cursor when the file already exists
    (never creates the legacy file).
    """
    promoted = lessons_mod.load_promoted(root)
    results: list[tuple[str, bool]] = []
    for agent in agents:
        target = AGENT_TARGETS.get(agent)
        if target is None:
            results.append((agent, False))
            continue
        results.append((target, update_file(root / target, promoted)))
        if agent == "cursor" and (root / ".cursorrules").exists():
            results.append((".cursorrules", update_file(root / ".cursorrules", promoted)))
    return results


# --- compact agent-facing renderings ---------------------------------------


def fix_prompt(passport: dict[str, Any], *, max_findings: int = 5) -> str:
    """A compact, paste-ready prompt for the coding agent. Never the full
    passport, never a secret value, never trust internals."""
    verdict = passport.get("verdict", "")
    task = passport.get("contract", {}).get("task", "")
    scope = passport.get("contract", {}).get("allowed_paths", [])
    if verdict == "PASS":
        return "Nota passed this change; nothing to fix."

    recs = build_remediations(passport)
    lines = [
        f"Nota {'blocked' if verdict == 'BLOCK' else 'flagged'} this PR. "
        f"Fix ONLY the findings below — do not weaken, bypass, or edit Nota's "
        f"configuration, keys, or workflows to get past the gate.",
        "",
        f"Approved task: {task}",
        "Approved scope: " + ", ".join(scope),
        "",
        "Findings:",
    ]
    for r in recs[:max_findings]:
        where = f" [{r['where']}]" if r["where"] else ""
        lines.append(f"- {r['plain']}{where}")
        lines.append(f"  Action: {r['cc_prompt'] or r['self_fix']}")
    if len(recs) > max_findings:
        lines.append(
            f"- …and {len(recs) - max_findings} more (run `nota explain` for the full list)."
        )
    lines += [
        "",
        "When done: run `git diff --name-only` and confirm every remaining "
        "changed file belongs to the approved task; anything else gets "
        "reverted or split into a separately approved PR.",
    ]
    return "\n".join(lines)


def agent_brief(
    *,
    task: str,
    allowed_paths: list[str],
    forbidden_paths: list[str],
    review_surfaces: list[str],
    promoted: list[dict[str, str]],
) -> str:
    """The compact brief an agent reads before starting work."""
    lines = [
        f"Task: {task}",
        "Allowed: " + (", ".join(allowed_paths) or "(anywhere not forbidden)"),
    ]
    if forbidden_paths:
        lines.append("Never touch: " + ", ".join(forbidden_paths))
    if review_surfaces:
        lines.append("Human review is triggered by edits to: " + ", ".join(review_surfaces))
    if promoted:
        lines.append("Repo lessons from prior findings:")
        lines += [f"- {entry['text']}" for entry in promoted]
    lines.append(
        "Before your final answer: run `git diff --name-only` and confirm "
        "every changed file belongs to the approved task."
    )
    return "\n".join(lines)
