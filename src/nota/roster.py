"""Agent roster: which agents ran, what they were permitted, and what they touched.

A read over the audit chain for the shadow-AI / audit-readiness question an
auditor (and an anxious operator) actually asks: *prove which agents ran, with
what permissions, and what they touched.* One row per (agent, session): how many
actions it took, the verdict mix (allowed / asked / blocked = what it was
permitted to do and what got stopped), what tools and directories it touched, and
how many hardware-attested approvals it consumed. Pure fold over recorded events,
no new enforcement and nothing written.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from nota import events as ev


@dataclass(slots=True)
class RosterEntry:
    agent_id: str
    session_id: str
    opened_at: str = ""
    closed_at: str = ""
    actions: int = 0  # tool calls + change-control verifications
    allowed: int = 0
    asked: int = 0
    blocked: int = 0
    approvals: int = 0  # hardware-attested (Touch ID) approvals consumed
    tools: list[str] = field(default_factory=list)
    touched_dirs: list[str] = field(default_factory=list)
    _tools: set[str] = field(default_factory=set, repr=False, compare=False)
    _dirs: set[str] = field(default_factory=set, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "actions": self.actions,
            "allowed": self.allowed,
            "asked": self.asked,
            "blocked": self.blocked,
            "approvals": self.approvals,
            "tools": self.tools,
            "touched_dirs": self.touched_dirs,
        }


def _top_dir(path: str) -> str:
    path = path.strip().lstrip("./")
    if "/" not in path:
        return path or "."
    return path.split("/", 1)[0]


_CC_VERDICT = {"PASS": "allowed", "NEEDS_REVIEW": "asked", "BLOCK": "blocked"}


def derive_roster(events: list[dict[str, Any]]) -> list[RosterEntry]:
    """Fold audit events into one RosterEntry per (agent_id, session_id)."""
    by_key: dict[tuple[str, str], RosterEntry] = {}

    def _e(agent: str, sid: str) -> RosterEntry:
        key = (agent, sid)
        if key not in by_key:
            by_key[key] = RosterEntry(agent_id=agent, session_id=sid)
        return by_key[key]

    for evt in events:
        sid = str(evt.get("session_id") or "")
        if not sid:
            continue
        agent = str(evt.get("agent_id") or "root")
        etype = str(evt.get("type") or "")
        ts = str(evt.get("ts") or "")
        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        e = _e(agent, sid)

        if etype == ev.SESSION_OPEN:
            e.opened_at = ts
        elif etype == ev.SESSION_CLOSE:
            e.closed_at = ts
        elif etype == ev.TOOL_ATTEMPTED:
            e.actions += 1
            tool = str(payload.get("tool_name") or "")
            if tool and tool not in e._tools:
                e._tools.add(tool)
                e.tools.append(tool)
        elif etype == ev.VERDICT_ALLOWED:
            e.allowed += 1
        elif etype == ev.VERDICT_ASK:
            e.asked += 1
        elif etype in (ev.VERDICT_BLOCKED, ev.VERDICT_SCOPE_VIOLATION):
            e.blocked += 1
        elif etype == ev.APPROVE_BIOMETRIC_OK:
            e.approvals += 1
        elif etype == ev.VERIFICATION_RUN:
            # Change-Control: one verification of a diff against the contract.
            e.actions += 1
            if "change-control" not in e._tools:
                e._tools.add("change-control")
                e.tools.append("change-control")
            bucket = _CC_VERDICT.get(str(payload.get("verdict") or ""))
            if bucket == "allowed":
                e.allowed += 1
            elif bucket == "asked":
                e.asked += 1
            elif bucket == "blocked":
                e.blocked += 1

        # Touched dirs: from tool args (writes) and out-of-scope/forbidden hits.
        for src in (payload.get("args_preview"), payload.get("args")):
            if isinstance(src, Mapping):
                for k in ("path", "file_path", "notebook_path"):
                    v = src.get(k)
                    if isinstance(v, str) and v:
                        d = _top_dir(v)
                        if d not in e._dirs:
                            e._dirs.add(d)
                            e.touched_dirs.append(d)
        for listkey in ("out_of_scope", "forbidden_hits", "gate_tamper_hits"):
            for v in payload.get(listkey) or []:
                if isinstance(v, str) and v:
                    d = _top_dir(v)
                    if d not in e._dirs:
                        e._dirs.add(d)
                        e.touched_dirs.append(d)

    return sorted(
        by_key.values(),
        key=lambda e: e.closed_at or e.opened_at or "",
        reverse=True,
    )
