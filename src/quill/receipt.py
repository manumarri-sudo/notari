"""Agent Receipts - derived audit-log artifact.

A Receipt is what the agent actually did during a session, in the human-readable
form auditors and the user both want:
    did[]         - distinct actions performed
    changed[]     - files the agent mutated
    uncertain[]   - high/critical-risk calls the human allowed (or the agent
                    self-flagged with agent.flag.uncertain)
    to_verify[]   - explicit "please confirm" items the agent surfaced
    trust_delta   - net change in (executed - blocked - asked)
    intervention_count
    tdr_contribution

Receipts are *derived* from the existing audit log; nothing new is written
unless the user explicitly runs `quill receipts emit` to write a session.receipt
event back to the chain.

Schema source: internal A2A event-schema design notes §6.1.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quill import events as ev
from quill.config import default_audit_path

# Tool names whose first/second arg is a path the agent is mutating.
_MUTATING_TOOLS_PATH_KEYS: dict[str, tuple[str, ...]] = {
    "Edit": ("file_path",),
    "Write": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
}


def _arg_path(tool_name: str, args: Mapping[str, Any]) -> str | None:
    keys = _MUTATING_TOOLS_PATH_KEYS.get(tool_name)
    if not keys:
        return None
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


@dataclass(slots=True)
class Receipt:
    """Per-session receipt aggregated from audit-log events.

    `did` and `changed` are insertion-ordered, deduped lists. The
    `_did_set` / `_changed_set` shadow fields provide O(1) membership
    so derivation over a 5000-event log stays linear instead of O(N^2).
    They are internal: `to_dict` and the public API still expose the
    list forms.

    The narrative fields (blocks_summary, asks_summary,
    biometric_approvals, top_changed_dir) feed `narrate()` and let
    `quill receipts show` open with a plain-English paragraph instead
    of four labeled arrays.
    """

    session_id: str
    opened_at: str = ""
    closed_at: str = ""
    intent: str = ""
    did: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)
    to_verify: list[str] = field(default_factory=list)
    intervention_count: int = 0
    tool_call_count: int = 0
    tdr_contribution: float = 0.0
    trust_delta: float = 0.0
    # Narrative inputs. Populated by derive_from_events; consumed by narrate().
    blocks_summary: list[str] = field(default_factory=list)  # "tool: reason"
    asks_summary: list[str] = field(default_factory=list)  # "tool: reason"
    biometric_approvals: int = 0
    top_changed_dir: str = ""
    # Internal: O(1) dedup membership for `did` / `changed`. Not exported.
    _did_set: set[str] = field(default_factory=set, repr=False, compare=False)
    _changed_set: set[str] = field(default_factory=set, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "intent": self.intent,
            "did": self.did,
            "changed": self.changed,
            "uncertain": self.uncertain,
            "to_verify": self.to_verify,
            "intervention_count": self.intervention_count,
            "tool_call_count": self.tool_call_count,
            "tdr_contribution": round(self.tdr_contribution, 3),
            "trust_delta": round(self.trust_delta, 3),
            "blocks_summary": self.blocks_summary,
            "asks_summary": self.asks_summary,
            "biometric_approvals": self.biometric_approvals,
            "top_changed_dir": self.top_changed_dir,
        }


def derive_from_events(events: list[dict[str, Any]]) -> dict[str, Receipt]:
    """Fold a list of audit events into per-session Receipts.

    Returns {session_id: Receipt}. Sessions without an explicit session.open
    are still returned (opened_at remains empty); this lets us derive
    receipts from older logs that pre-date the session-lifecycle events.
    """
    receipts: dict[str, Receipt] = {}

    def _r(sid: str) -> Receipt:
        if sid not in receipts:
            receipts[sid] = Receipt(session_id=sid)
        return receipts[sid]

    for evt in events:
        sid = str(evt.get("session_id") or "")
        if not sid:
            continue
        etype = evt.get("type", "")
        ts = evt.get("ts", "")
        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        risk = str(evt.get("risk") or "")
        tool_name = str(payload.get("tool_name") or "")
        r = _r(sid)

        if etype == ev.SESSION_OPEN:
            r.opened_at = str(ts)
            intent = payload.get("intent")
            if isinstance(intent, str):
                r.intent = intent

        elif etype == ev.SESSION_CLOSE:
            r.closed_at = str(ts)

        elif etype == ev.TOOL_ATTEMPTED:
            r.tool_call_count += 1
            if tool_name and tool_name not in r._did_set:
                r._did_set.add(tool_name)
                r.did.append(tool_name)
            args = payload.get("args_preview") or payload.get("args") or {}
            if isinstance(args, Mapping):
                p = _arg_path(tool_name, args)
                if p and p not in r._changed_set:
                    r._changed_set.add(p)
                    r.changed.append(p)

        elif etype == ev.VERDICT_ALLOWED and risk in ("high", "critical"):
            reason = str(payload.get("reason") or tool_name or "")
            r.uncertain.append(f"{risk}: {reason}")

        elif etype == ev.VERDICT_BLOCKED:
            r.intervention_count += 1
            r.trust_delta -= 1.0
            reason = str(payload.get("reason") or "blocked")
            if len(r.blocks_summary) < 20:
                r.blocks_summary.append(f"{tool_name or '?'}: {reason}")

        elif etype == ev.VERDICT_ASK:
            r.intervention_count += 1
            r.trust_delta -= 0.5
            reason = str(payload.get("reason") or "ask")
            if len(r.asks_summary) < 20:
                r.asks_summary.append(f"{tool_name or '?'}: {reason}")

        elif etype == ev.APPROVE_BIOMETRIC_OK:
            r.biometric_approvals += 1

        elif etype == ev.AGENT_FLAG_UNCERTAIN:
            note = str(payload.get("uncertainty") or "")
            if note:
                r.to_verify.append(note)

    # TDR = executed / (executed + blocked + asked). Also derive top_changed_dir.
    for r in receipts.values():
        denom = r.tool_call_count + r.intervention_count
        r.tdr_contribution = (r.tool_call_count / denom) if denom else 1.0
        if r.tool_call_count > 0:
            r.trust_delta = r.trust_delta / r.tool_call_count
        if r.changed:
            r.top_changed_dir = _top_directory(r.changed)

    return receipts


def _top_directory(paths: list[str]) -> str:
    """Pick the most common parent directory across a list of paths.

    Used by narrate() to say 'mostly in src/auth/' instead of listing
    every file. Ties broken by the directory that appears first.
    """
    from collections import Counter

    parents: list[str] = []
    for p in paths:
        # Take everything before the last slash; fall back to the path itself
        # if there's no slash (filename only).
        if "/" in p:
            parents.append(p.rsplit("/", 1)[0])
        else:
            parents.append("")
    counts = Counter(parents)
    if not counts:
        return ""
    top, _ = counts.most_common(1)[0]
    return top


def _format_window(opened_at: str, closed_at: str) -> str:
    """Render a human-readable time window from two ISO timestamps."""
    o = (opened_at or "")[:19].replace("T", " ")
    c = (closed_at or "")[:19].replace("T", " ")
    if o and c:
        # Same day? Show only times for the second timestamp.
        if o[:10] == c[:10]:
            return f"between {o} and {c[11:]}"
        return f"between {o} and {c}"
    if o:
        return f"starting at {o}"
    return "in this session"


def _pluralize(n: int, singular: str, plural: str | None = None) -> str:
    """Tiny grammar helper. plural defaults to singular + 's'."""
    if plural is None:
        plural = singular + "s"
    return singular if n == 1 else plural


def narrate(r: Receipt) -> str:
    """Render a Receipt as a plain-English paragraph.

    Deterministic template, no LLM. The template's whole job is to
    turn the structured Receipt into a sentence a non-technical
    reader can scan in three seconds. Used by `quill receipts show`
    above the structured-detail blocks.
    """
    if r.tool_call_count == 0 and not r.changed and r.intervention_count == 0:
        return "No tool calls recorded in this session yet."

    clauses: list[str] = []
    window = _format_window(r.opened_at, r.closed_at)
    clauses.append(
        f"{window} the agent ran {r.tool_call_count} tool {_pluralize(r.tool_call_count, 'call')}"
    )

    if r.changed:
        n = len(r.changed)
        loc = f" mostly in {r.top_changed_dir}" if r.top_changed_dir else ""
        clauses.append(f"touched {n} {_pluralize(n, 'file')}{loc}")

    n_blocks = len(r.blocks_summary)
    n_asks = len(r.asks_summary)
    if n_blocks:
        clauses.append(
            f"refused {n_blocks} destructive {_pluralize(n_blocks, 'operation')}",
        )
    if n_asks:
        clauses.append(f"paused {n_asks} {_pluralize(n_asks, 'time')} for a human y/N")
    if r.biometric_approvals:
        clauses.append(
            f"confirmed {r.biometric_approvals} critical "
            f"{_pluralize(r.biometric_approvals, 'action')} via Touch ID",
        )

    # Stitch with commas + final "and"
    body = ", ".join(clauses[:-1]) + ", and " + clauses[-1] if len(clauses) > 1 else clauses[0]
    sentence = body + "."

    # Footer: trust delivery + flags
    extras: list[str] = []
    extras.append(f"Trust delivery rate {r.tdr_contribution:.0%}")
    if r.to_verify:
        n = len(r.to_verify)
        extras.append(
            f"{n} {_pluralize(n, 'item')} flagged for your review",
        )
    sentence += " " + ". ".join(extras) + "."

    # Block detail (capped) so the reader sees what got refused.
    if r.blocks_summary:
        shown = r.blocks_summary[:3]
        sentence += f" Blocked: {'; '.join(shown)}"
        if len(r.blocks_summary) > 3:
            sentence += f" (and {len(r.blocks_summary) - 3} more)"
        sentence += "."

    return sentence


def load_audit_events(path: Path | None = None) -> list[dict[str, Any]]:
    """Read the audit log JSONL and return a list of events.

    Best-effort: malformed lines are skipped, not raised.
    """
    p = path or default_audit_path()
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except json.JSONDecodeError:
                continue
    return out
