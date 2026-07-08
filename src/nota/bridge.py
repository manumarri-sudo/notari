"""A2A Bridge - inter-agent handoff audit shape.

Records the cryptographic edge between agents on a handoff:
  agent.handoff.out   - sender side, includes payload_hash + contract
  agent.handoff.in    - receiver side, references a specific out by event_mac

The framework (LangGraph, CrewAI, AutoGen) routes the message; Nota records
the handoff edge so orphans and cascades become tractable downstream.

Schema source: internal A2A event-schema design notes §6.1 + §6.4.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from nota import events as ev


def payload_hash(payload: Mapping[str, Any] | str | bytes) -> str:
    """Canonical SHA-256 of a handoff payload.

    Stable across writers: dicts are JSON-encoded with sorted keys.
    """
    if isinstance(payload, bytes):
        data = payload
    elif isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass(slots=True)
class Handoff:
    """One side of a handoff edge as derived from the audit log."""

    payload_hash: str
    out_event: dict[str, Any] | None = None
    in_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_orphan(self) -> bool:
        return self.out_event is not None and not self.in_events

    @property
    def is_cascade(self) -> bool:
        # Same payload hash consumed by >= 3 distinct receivers => cascade.
        receivers = {
            (e.get("session_id"), (e.get("payload") or {}).get("from_session_id"))
            for e in self.in_events
        }
        return len(receivers) >= 3


def fold_handoffs(events: list[dict[str, Any]]) -> dict[str, Handoff]:
    """Fold audit events into {payload_hash: Handoff}.

    Pairs each agent.handoff.out with the agent.handoff.in events that
    reference the same payload_hash. Orphaned outs surface via is_orphan;
    cascades (>=3 distinct receivers) surface via is_cascade.
    """
    handoffs: dict[str, Handoff] = {}
    for evt in events:
        etype = evt.get("type", "")
        if etype not in (ev.AGENT_HANDOFF_OUT, ev.AGENT_HANDOFF_IN):
            continue
        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        ph = str(payload.get("payload_hash") or "")
        if not ph:
            continue
        h = handoffs.setdefault(ph, Handoff(payload_hash=ph))
        if etype == ev.AGENT_HANDOFF_OUT:
            h.out_event = dict(evt)
        else:
            h.in_events.append(dict(evt))
    return handoffs
