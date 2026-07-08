"""Determinism contract tests.

Nota is a security gate. Operators must be able to reason about it
predictably: same inputs -> same outputs, every time. These tests pin
the contract for every derive/fold/classify entry point that
production code calls more than once.

Non-deterministic things that are intentionally so (and out of scope
here): approval tokens (cryptographic randomness by design), wall-clock
timestamps inside emitted events (timestamp IS part of input).

What we pin:
  - `classify(tool_name)` returns the same Risk for the same input.
  - `classify_command(cmd)` returns the same CommandClassification.
  - `derive_from_events(events)` produces identical Receipt dicts on
    repeated runs.
  - `fold_handoffs(events)` produces identical handoff pairings.
  - `fold_audit_events(events)` (taint) produces identical state.
  - `payload_hash` is stable across dict key order.
  - `fingerprint` (pinning) is stable across dict key order.
"""

from __future__ import annotations

import json

from nota import events as ev
from nota.bridge import fold_handoffs, payload_hash
from nota.pinning import fingerprint
from nota.policy import Risk, classify, classify_command
from nota.receipt import derive_from_events
from nota.taint import fold_audit_events


def _sample_audit_events() -> list[dict[str, object]]:
    """A small but varied audit-log sample touching every fold path."""
    h = payload_hash({"to": "sub", "from": "root"})
    return [
        {
            "type": ev.SESSION_OPEN,
            "session_id": "root",
            "ts": "2026-05-11T10:00:00Z",
            "payload": {"intent": "ship"},
        },
        {
            "type": ev.TOOL_ATTEMPTED,
            "session_id": "root",
            "risk": "low",
            "payload": {"tool_name": "Bash", "args_preview": {"command": "ls"}},
        },
        {
            "type": ev.TOOL_ATTEMPTED,
            "session_id": "root",
            "risk": "high",
            "payload": {"tool_name": "Edit", "args_preview": {"file_path": "/x/y.py"}},
        },
        {
            "type": ev.VERDICT_ALLOWED,
            "session_id": "root",
            "risk": "high",
            "payload": {"tool_name": "Edit", "reason": "operator confirmed"},
        },
        {
            "type": ev.AGENT_HANDOFF_OUT,
            "session_id": "root",
            "payload": {"to_agent_id": "sub", "payload_hash": h},
        },
        {
            "type": ev.AGENT_HANDOFF_IN,
            "session_id": "sub",
            "payload": {"from_session_id": "root", "payload_hash": h},
        },
        {
            "type": ev.SESSION_TAINT_UPDATE,
            "session_id": "root",
            "risk": "low",
            "payload": {
                "trifecta": {
                    "has_seen_untrusted": True,
                    "has_accessed_private": False,
                    "can_exfiltrate": False,
                }
            },
        },
        {
            "type": ev.SESSION_CLOSE,
            "session_id": "root",
            "ts": "2026-05-11T10:30:00Z",
            "payload": {"reason": "user_quit", "duration_seconds": 1800, "tool_call_count": 2},
        },
    ]


def test_classify_is_deterministic() -> None:
    """Same tool_name must classify the same way every time."""
    for op in (
        "Bash",
        "Edit",
        "stripe.create_charge",
        "stripe.list_charges",
        "banking.send_money",
        "filesystem.read_file",
        "Write",
    ):
        r1, r2, r3 = classify(op), classify(op), classify(op)
        assert r1 is r2 is r3, f"{op}: {r1} != {r2} != {r3}"
        assert isinstance(r1, Risk)


def test_classify_command_is_deterministic() -> None:
    """Same shell command -> same classification every time."""
    cmds = [
        "ls",
        "rm -rf /tmp/x",
        "git push --force origin main",
        "git commit -m 'fix: removed TRUNCATE TABLE'",
        "vercel deploy --prod --yes",
    ]
    for c in cmds:
        a = classify_command(c)
        b = classify_command(c)
        assert a.risk == b.risk
        assert a.reason == b.reason
        assert a.suggestion == b.suggestion


def test_derive_from_events_is_deterministic() -> None:
    """Repeated runs over the same audit log must produce byte-identical
    receipt dicts. This is the heart of `nota receipts` reproducibility."""
    events = _sample_audit_events()
    r1 = derive_from_events(list(events))
    r2 = derive_from_events(list(events))
    # Compare the JSON-serialised forms so dict-order issues surface.
    a = json.dumps({sid: r.to_dict() for sid, r in r1.items()}, sort_keys=True)
    b = json.dumps({sid: r.to_dict() for sid, r in r2.items()}, sort_keys=True)
    assert a == b


def test_fold_handoffs_is_deterministic() -> None:
    """A2A bridge fold must be stable across runs."""
    events = _sample_audit_events()
    h1 = fold_handoffs(list(events))
    h2 = fold_handoffs(list(events))
    assert set(h1.keys()) == set(h2.keys())
    for ph in h1:
        assert h1[ph].is_orphan == h2[ph].is_orphan
        assert h1[ph].is_cascade == h2[ph].is_cascade


def test_taint_fold_is_deterministic() -> None:
    """Trifecta state fold must be stable across runs."""
    events = _sample_audit_events()
    t1 = fold_audit_events(list(events))
    t2 = fold_audit_events(list(events))
    # Both should produce identical per-session state.
    assert set(t1.keys()) == set(t2.keys())
    for sid in t1:
        assert t1[sid].to_dict() == t2[sid].to_dict()


def test_payload_hash_stable_across_key_order() -> None:
    """Payload hash MUST be insensitive to dict key insertion order or
    the bridge will fail to pair otherwise-identical handoffs. The bridge
    pairing key depends on this."""
    a = {"to": "sub", "from": "root", "contract": "task"}
    b = {"contract": "task", "to": "sub", "from": "root"}
    c = {"from": "root", "contract": "task", "to": "sub"}
    assert payload_hash(a) == payload_hash(b) == payload_hash(c)


def test_fingerprint_stable_across_key_order() -> None:
    """Tool description fingerprint MUST be stable across dict key
    order. A drifting hash would force re-approval on every connect."""
    a = {
        "name": "search",
        "description": "find things",
        "inputSchema": {"properties": {"q": {"type": "string"}}},
    }
    b = {
        "description": "find things",
        "name": "search",
        "inputSchema": {"properties": {"q": {"type": "string"}}},
    }
    assert fingerprint(a) == fingerprint(b)


def test_classifier_no_hidden_state_between_calls() -> None:
    """Repeated classifications must not be affected by prior calls.
    The classifier's user-allowlist cache is process-lifetime, but the
    per-input result must not depend on the order of prior queries."""
    for first in ("Bash", "stripe.create_charge", "fs.delete", "Edit"):
        classify(first)  # warm
    risks_a = [classify(op) for op in ("Edit", "stripe.create_charge", "fs.delete", "Bash")]
    risks_b = [classify(op) for op in ("Edit", "stripe.create_charge", "fs.delete", "Bash")]
    assert risks_a == risks_b
