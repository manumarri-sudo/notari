"""Nota Lessons: turn blocked AI PRs into lessons future agents learn from.

Every BLOCK / NEEDS_REVIEW verdict is converted into small structured
mistake events (never code, diffs, prompts, or secret values), stored
locally in ``.nota/mistakes.jsonl``. Repeated patterns aggregate into
deterministic suggested lessons a human can promote into agent
instruction files (see teach.py). Nothing here influences the verdict:
this module runs post-decision, mirrors learning.py's non-negotiables
(tightening guidance may be suggested; nothing auto-applies without a
human command), and never sends anything off-machine.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nota._version import __version__

MISTAKE_SCHEMA = "nota.mistake/v1"

_LOCKFILE_NAMES = {
    "uv.lock",
    "package-lock.json",
    "poetry.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
    "composer.lock",
}


def classify_path(path: str) -> str:
    """Deterministic path-kind bucket used for aggregation and redaction."""
    name = path.rsplit("/", 1)[-1]
    lowered = path.lower()
    if path.startswith(".nota/") or path.startswith(".github/workflows/nota"):
        return "nota_trust_surface"
    if path.startswith(".github/workflows/"):
        return "ci_workflow"
    if name in _LOCKFILE_NAMES:
        return "lockfile"
    if "migration" in lowered or lowered.endswith(".sql"):
        return "migration"
    if "auth" in lowered:
        return "auth"
    if lowered.startswith("tests/") or name.startswith("test_") or "/tests/" in lowered:
        return "test"
    return "other"


def redact_path(path: str) -> str:
    """Directory kept, basename dropped — safe for any future aggregation."""
    if "/" not in path:
        return "<file>"
    return path.rsplit("/", 1)[0] + "/<file>"


def _task_hint(passport: dict[str, Any]) -> str:
    for scope in passport.get("contract", {}).get("allowed_paths", []):
        for seg in str(scope).split("/"):
            if seg and seg not in ("src", "**", "*", "tests", "lib"):
                return seg.strip("*")
    return ""


def events_from_passport(passport: dict[str, Any]) -> list[dict[str, Any]]:
    """Zero or more structured mistake events. No code, no diffs, no secrets."""
    verdict = passport.get("verdict", "")
    if verdict == "PASS":
        return []
    ev = passport.get("evidence", {})
    base = {
        "schema": MISTAKE_SCHEMA,
        "created_at": datetime.now(UTC).isoformat(),
        "nota_version": __version__,
        "contract_id": passport.get("contract", {}).get("id", ""),
        "verdict": verdict,
        "task_hint": _task_hint(passport),
        "approved_scope_shape": list(passport.get("contract", {}).get("allowed_paths", [])),
    }

    head = passport.get("head_commit", "") or ""

    def mk(rule_id: str, finding_type: str, path: str, fix_action: str) -> dict[str, Any]:
        kind = classify_path(path) if path else ""
        redacted = redact_path(path) if path else ""
        # Stable identity of this mistake so re-running verify on the same
        # failing commit doesn't inflate lesson counts (path kept out so two
        # different files of the same kind still both count).
        fp = "|".join([base["contract_id"], head, rule_id, finding_type, redacted, kind])
        return {
            **base,
            "rule_id": rule_id,
            "finding_type": finding_type,
            "path": path,
            "violating_path_kind": kind,
            "violating_path_redacted": redacted,
            "fix_action": fix_action,
            "fingerprint": fp,
        }

    out: list[dict[str, Any]] = []
    tamper = set(ev.get("gate_tamper_hits", []))
    forbidden = set(ev.get("forbidden_hits", [])) - tamper

    for p in sorted(tamper):
        out.append(mk("GATE_TAMPER", "gate_tamper_hit", p, "revert_trust_surface_change"))
    for p in sorted(forbidden):
        out.append(mk("FORBIDDEN_PATH", "forbidden_path", p, "revert_forbidden_change"))
    for p in ev.get("out_of_scope", []):
        if p in tamper or p in forbidden:
            continue
        out.append(
            mk("SCOPE_OUT", "out_of_scope_path", p, "remove_or_split_or_request_new_approval")
        )
    for s in ev.get("secret_findings", []):
        e = mk(
            "SECRET_HIT", "secret_finding", s.get("path", ""), "remove_secret_use_env_placeholder"
        )
        e["pattern"] = s.get("pattern", "")  # pattern NAME only; never the value
        out.append(e)
    for name, paths in ev.get("sensitive_surfaces", {}).items():
        for p in paths:
            e = mk("SENSITIVE_SURFACE", f"sensitive_{name}", p, "explain_necessity_or_split_pr")
            e["surface"] = name
            out.append(e)
    for c in ev.get("symlink_changes", []):
        out.append(mk("OPAQUE_CHANGE", "symlink", c.get("path", ""), "human_review_required"))
    for c in ev.get("submodule_changes", []):
        out.append(mk("OPAQUE_CHANGE", "submodule", c.get("path", ""), "human_review_required"))
    for d in ev.get("scan_dispositions", []):
        e = mk("SCAN_INCOMPLETE", "scan_disposition", "", "reduce_diff_size_or_adjust_limits")
        e["disposition"] = d
        out.append(e)
    return out


# --- local store -----------------------------------------------------------


def mistakes_path(root: Path) -> Path:
    return root / ".nota" / "mistakes.jsonl"


def lessons_store_path(root: Path) -> Path:
    return root / ".nota" / "lessons.json"


def record_mistakes(passport: dict[str, Any], root: Path) -> int:
    """Append this verdict's mistake events locally, skipping ones already
    recorded (same fingerprint). Returns the count actually written.

    Re-running `nota verify` on the same failing commit is idempotent; a new
    commit with the same pattern still records (its head_commit differs).
    """
    events = events_from_passport(passport)
    if not events:
        return 0
    seen = {e["fingerprint"] for e in load_events(root) if "fingerprint" in e}
    fresh = [e for e in events if e.get("fingerprint") not in seen]
    if not fresh:
        return 0
    path = mistakes_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Swarm-safe append: many agents may run `nota verify` against the same
    # repo concurrently. Serialize each record's bytes into ONE os.write to an
    # O_APPEND fd, so writes from different processes never interleave a line.
    # (The dedup read above is best-effort under a tight race — worst case a
    # duplicate slips through and inflates one count by one; suggest() and the
    # fingerprint make that harmless, and it never corrupts the file.)
    blob = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in fresh)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, blob.encode("utf-8"))
    finally:
        os.close(fd)
    return len(fresh)


def load_events(root: Path) -> list[dict[str, Any]]:
    path = mistakes_path(root)
    if not path.exists():
        return []
    events = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a torn/hand-edited line never breaks the loop
    return events


# --- deterministic lesson suggestions --------------------------------------

_LESSONS: dict[tuple[str, str], tuple[str, str]] = {
    ("SCOPE_OUT", "ci_workflow"): (
        "no-ci-edits-without-ci-scope",
        "Do not edit .github/workflows/** unless the approved task explicitly "
        "includes CI or workflow changes.",
    ),
    ("SCOPE_OUT", "migration"): (
        "no-migration-edits-without-db-scope",
        "Do not edit migrations or schema files unless the approved task "
        "explicitly includes database changes.",
    ),
    ("SCOPE_OUT", "lockfile"): (
        "no-lockfile-updates-without-dependency-scope",
        "Do not update lockfiles unless dependencies changed intentionally and "
        "the approved task includes that dependency change.",
    ),
    ("SCOPE_OUT", "*"): (
        "stay-inside-approved-scope",
        "Only change files that belong to the approved task; if a needed change "
        "is outside scope, stop and ask for a new signed approval instead of "
        "sneaking it into this PR.",
    ),
    ("FORBIDDEN_PATH", "*"): (
        "never-edit-forbidden-paths",
        "Never edit paths the project marked forbidden, whatever the task says.",
    ),
    ("GATE_TAMPER", "*"): (
        "never-edit-nota-trust-surfaces",
        "Never edit Nota trust files, approver keys, perimeter files, or "
        "workflows that run Nota unless a human explicitly approves that "
        "trust-surface change.",
    ),
    ("SECRET_HIT", "*"): (
        "no-realistic-credentials",
        "Never add real-looking credentials. Use environment variable "
        "placeholders or test fixtures that cannot be mistaken for live secrets.",
    ),
    ("SENSITIVE_SURFACE", "lockfile"): (
        "no-lockfile-updates-without-dependency-scope",
        "Do not update lockfiles unless dependencies changed intentionally and "
        "the approved task includes that dependency change.",
    ),
    ("SENSITIVE_SURFACE", "*"): (
        "explain-sensitive-surface-edits",
        "When a task genuinely needs to touch CI, tests, lockfiles, or git "
        "config, say so explicitly in the PR so a reviewer can approve fast — "
        "otherwise leave those surfaces alone.",
    ),
    ("OPAQUE_CHANGE", "*"): (
        "no-opaque-redirects",
        "Do not add symlinks or move submodule pointers unless the task "
        "requires it; opaque changes always need a human look.",
    ),
    ("SCAN_INCOMPLETE", "*"): (
        "keep-changes-scannable",
        "Keep each PR small enough to be fully checked; split large changes "
        "into reviewable pieces.",
    ),
}

# Friendly one-line headline per lesson, and its level. Severity is the
# lesson's role, NOT the verdict (the verdict stays deterministic):
#   inform  - just mentioned in the agent brief
#   warn    - worth flagging before it happens
#   block   - Nota already blocks this deterministically today
#   policy_candidate - a human should consider adding it to the signed perimeter
_LESSON_META: dict[str, tuple[str, str]] = {
    "no-ci-edits-without-ci-scope": (
        "CI workflow touched during a non-CI task",
        "policy_candidate",
    ),
    "no-migration-edits-without-db-scope": (
        "Migration or schema touched during a non-database task",
        "policy_candidate",
    ),
    "no-lockfile-updates-without-dependency-scope": (
        "Lockfile changed during a non-dependency task",
        "policy_candidate",
    ),
    "stay-inside-approved-scope": ("Files changed outside the approved task", "warn"),
    "never-edit-forbidden-paths": ("A forbidden path was edited", "block"),
    "never-edit-nota-trust-surfaces": ("Nota trust surface or gate workflow touched", "block"),
    "no-realistic-credentials": ("Secret-like value added to the code", "block"),
    "explain-sensitive-surface-edits": ("Sensitive surface touched without explanation", "warn"),
    "no-opaque-redirects": ("Opaque change (symlink or submodule) added", "warn"),
    "keep-changes-scannable": ("Change too large to fully scan", "inform"),
}


def suggest(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate events into repeated patterns with suggested lessons."""
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in events:
        rule = e.get("rule_id", "")
        kind = (
            e.get("violating_path_kind", "")
            or (e.get("surface", "") == "lockfiles" and "lockfile")
            or ""
        )
        key = (rule, kind) if (rule, kind) in _LESSONS else (rule, "*")
        if key not in _LESSONS:
            continue
        buckets.setdefault(key, []).append(e)

    patterns = []
    for key, evs in buckets.items():
        lesson_id, text = _LESSONS[key]
        headline, severity = _LESSON_META.get(lesson_id, (text, "warn"))
        patterns.append(
            {
                "lesson_id": lesson_id,
                "headline": headline,
                "severity": severity,
                "source_rule": key[0],
                "rule_id": key[0],
                "path_kind": key[1],
                "count": len(evs),
                "last_seen": max(e.get("created_at", "") for e in evs),
                "lesson": text,
                "promotion_required": True,
                "promote_command": f"nota lessons promote {lesson_id}",
            }
        )
    # Most-repeated first; within a count, more severe first.
    _sev_rank = {"block": 0, "policy_candidate": 1, "warn": 2, "inform": 3}
    patterns.sort(key=lambda p: (-p["count"], _sev_rank.get(p["severity"], 9), p["lesson_id"]))
    return patterns


def load_promoted(root: Path) -> list[dict[str, str]]:
    path = lessons_store_path(root)
    if not path.exists():
        return []
    try:
        promoted = json.loads(path.read_text()).get("promoted", [])
    except (OSError, json.JSONDecodeError):
        return []
    return [e for e in promoted if isinstance(e, dict) and "id" in e and "text" in e]


def promote(lesson_id: str, root: Path) -> tuple[bool, str]:
    """Human-gated: add a suggested lesson to the promoted store (idempotent).

    Returns (newly_promoted, lesson_text). Raises KeyError for unknown ids.
    """
    by_id = {lid: text for lid, text in _LESSONS.values()}
    if lesson_id not in by_id:
        raise KeyError(lesson_id)
    text = by_id[lesson_id]
    _, severity = _LESSON_META.get(lesson_id, (text, "warn"))
    promoted = load_promoted(root)
    if any(entry["id"] == lesson_id for entry in promoted):
        return False, text
    promoted.append({"id": lesson_id, "text": text, "severity": severity})
    path = lessons_store_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"promoted": promoted}, indent=2) + "\n")
    return True, text
