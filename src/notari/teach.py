"""Compact agent-facing renderings of a contract and a passport.

Two surfaces, both paste-ready for a coding agent:
  fix_prompt(passport)  what to fix after a NEEDS_REVIEW / BLOCK verdict
  agent_brief(...)      what the approved scope is, before work starts

Token discipline: agents get compressed briefs and fix prompts, never the
full passport, which stays for humans and auditors.
"""

from __future__ import annotations

from typing import Any

from notari.explain import build_remediations

# --- compact agent-facing renderings ---------------------------------------


def fix_prompt(passport: dict[str, Any], *, max_findings: int = 5) -> str:
    """A compact, paste-ready prompt for the coding agent. Never the full
    passport, never a secret value, never trust internals."""
    verdict = passport.get("verdict", "")
    task = passport.get("contract", {}).get("task", "")
    scope = passport.get("contract", {}).get("allowed_paths", [])
    if verdict == "PASS":
        return "Notari passed this change; nothing to fix."

    recs = build_remediations(passport)
    lines = [
        f"Notari {'blocked' if verdict == 'BLOCK' else 'flagged'} this PR. "
        f"Fix ONLY the findings below, do not weaken, bypass, or edit Notari's "
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
            f"- …and {len(recs) - max_findings} more (run `notari explain` for the full list)."
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
    lines.append(
        "Before your final answer: run `git diff --name-only` and confirm "
        "every changed file belongs to the approved task."
    )
    return "\n".join(lines)
