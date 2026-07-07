"""Receipt + taint + bridge - the three pieces of Manu's Trust Infrastructure
that just landed. These are unit tests against the pure-function derive APIs;
the adapter integration test for handoff.out lives in test_claude_hook.py.
"""

from __future__ import annotations

from quill import events as ev
from quill.bridge import fold_handoffs, payload_hash
from quill.receipt import derive_from_events
from quill.taint import (
    TaintState,
    classify_call_taint,
    fold_audit_events,
    update_for_call,
    would_close_trifecta,
)

# ---------------------------------------------------------------------------
# receipts


def _evt(t: str, sid: str = "s1", **payload: object) -> dict[str, object]:
    return {
        "type": t,
        "session_id": sid,
        "ts": "2026-05-07T12:00:00Z",
        "risk": payload.pop("__risk", "low"),
        "payload": payload,
    }


def test_receipt_aggregates_did_and_changed() -> None:
    events = [
        _evt(ev.SESSION_OPEN, intent="ship the wizard"),
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Edit",
            args_preview={"file_path": "src/dashboard/page.tsx"},
        ),
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Write",
            args_preview={"file_path": "src/dashboard/style.css"},
        ),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Bash", args_preview={"command": "npm test"}),
        _evt(ev.SESSION_CLOSE),
    ]
    receipts = derive_from_events(events)
    assert "s1" in receipts
    r = receipts["s1"]
    assert r.intent == "ship the wizard"
    assert "Edit" in r.did
    assert "Write" in r.did
    assert "Bash" in r.did
    assert "src/dashboard/page.tsx" in r.changed
    assert "src/dashboard/style.css" in r.changed
    # Bash should NOT add a `changed` entry since it has no _MUTATING_TOOLS_PATH_KEYS
    assert all("npm test" not in c for c in r.changed)


def test_receipt_uncertain_from_high_risk_allowed() -> None:
    events = [
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Bash",
            __risk="high",
            args_preview={"command": "rm -rf build"},
        ),
        _evt(ev.VERDICT_ALLOWED, tool_name="Bash", __risk="high", reason="user typed yes"),
    ]
    receipts = derive_from_events(events)
    r = receipts["s1"]
    assert r.uncertain
    assert "high" in r.uncertain[0]


def test_receipt_to_verify_from_explicit_flag() -> None:
    events = [
        _evt(ev.AGENT_FLAG_UNCERTAIN, uncertainty="color contrast may be insufficient"),
    ]
    receipts = derive_from_events(events)
    r = receipts["s1"]
    assert "color contrast may be insufficient" in r.to_verify


def test_receipt_tdr_and_trust_delta() -> None:
    events = [
        _evt(ev.TOOL_ATTEMPTED, tool_name="Read"),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Read"),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Read"),
        _evt(ev.VERDICT_BLOCKED, reason="rm -rf"),
    ]
    r = derive_from_events(events)["s1"]
    # 3 calls + 1 blocked => TDR = 3/4 = 0.75
    assert abs(r.tdr_contribution - 0.75) < 0.01
    assert r.intervention_count == 1
    assert r.trust_delta < 0  # one block = -1, divided by tool_call_count


# ---------------------------------------------------------------------------
# taint


def test_taint_classify_webfetch_marks_untrusted() -> None:
    untrusted, private, exfil = classify_call_taint("WebFetch", {"url": "https://x.com"})
    assert untrusted is True
    assert exfil is True  # WebFetch is also exfil-capable
    assert private is False


def test_taint_classify_local_read_does_not_mark_untrusted() -> None:
    """Regression: Claude Code's `Read` tool on a local file is NOT
    adversary-controlled content. Marking it untrusted made the trifecta
    gate fire on benign workflows (read README -> read .env -> git push)."""
    # Plain local file
    untrusted, private, _ = classify_call_taint("Read", {"file_path": "/repo/README.md"})
    assert untrusted is False
    assert private is False
    # filesystem.read_file MCP tool name - also not untrusted
    untrusted, _, _ = classify_call_taint("filesystem.read_file", {"path": "/repo/notes.md"})
    assert untrusted is False
    # .env still marks private (it's sensitive, just not untrusted-content)
    untrusted, private, _ = classify_call_taint("Read", {"file_path": "/repo/.env"})
    assert untrusted is False
    assert private is True


def test_taint_classify_bash_curl_marks_untrusted() -> None:
    untrusted, private, exfil = classify_call_taint("Bash", {"command": "curl https://x"})
    assert untrusted is True
    assert exfil is False


def test_taint_classify_env_path_marks_private() -> None:
    untrusted, private, exfil = classify_call_taint("Read", {"file_path": "/x/.env"})
    assert private is True
    assert untrusted is False


def test_taint_classify_git_push_marks_exfil() -> None:
    untrusted, private, exfil = classify_call_taint("Bash", {"command": "git push origin main"})
    assert exfil is True
    assert untrusted is False


def test_taint_state_monotonic_and_flips_once() -> None:
    state = TaintState()
    _, flipped1 = update_for_call(state, "WebFetch", {"url": "https://x"})
    assert "has_seen_untrusted" in flipped1
    # second WebFetch should NOT re-flip (monotonic)
    _, flipped2 = update_for_call(state, "WebFetch", {"url": "https://x"})
    assert "has_seen_untrusted" not in flipped2


def test_taint_trifecta_closes_with_all_three() -> None:
    state = TaintState()
    update_for_call(state, "WebFetch", {"url": "https://x"})  # untrusted+exfil
    assert not state.trifecta_closed
    update_for_call(state, "Read", {"file_path": "/x/.env"})  # private
    assert state.trifecta_closed


def test_taint_fold_replays_audit_events() -> None:
    events = [
        {
            "type": ev.TOOL_ATTEMPTED,
            "session_id": "s1",
            "mac": "m1",
            "payload": {"tool_name": "WebFetch", "args_preview": {"url": "https://x"}},
        },
        {
            "type": ev.TOOL_ATTEMPTED,
            "session_id": "s1",
            "mac": "m2",
            "payload": {"tool_name": "Read", "args_preview": {"file_path": "/.env"}},
        },
        {
            "type": ev.TOOL_ATTEMPTED,
            "session_id": "s2",
            "mac": "m3",
            "payload": {"tool_name": "Read", "args_preview": {"file_path": "README.md"}},
        },
    ]
    states = fold_audit_events(events)
    assert states["s1"].trifecta_closed
    assert not states["s2"].trifecta_closed


# ---------------------------------------------------------------------------
# bridge


def test_payload_hash_stable_across_dict_orderings() -> None:
    a = {"to": "x", "from": "y", "contract": "test"}
    b = {"contract": "test", "from": "y", "to": "x"}
    assert payload_hash(a) == payload_hash(b)


def test_bridge_pairs_out_and_in_by_payload_hash() -> None:
    h = payload_hash({"to": "sub", "from": "root"})
    events = [
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
    ]
    handoffs = fold_handoffs(events)
    assert len(handoffs) == 1
    pair = handoffs[h]
    assert pair.out_event is not None
    assert len(pair.in_events) == 1
    assert not pair.is_orphan


def test_bridge_orphan_when_no_in() -> None:
    h = payload_hash({"to": "lost", "from": "root"})
    events = [
        {
            "type": ev.AGENT_HANDOFF_OUT,
            "session_id": "root",
            "payload": {"to_agent_id": "lost", "payload_hash": h},
        },
    ]
    pair = fold_handoffs(events)[h]
    assert pair.is_orphan


def test_bridge_cascade_with_three_distinct_receivers() -> None:
    h = payload_hash({"contract": "broadcast"})
    events = [
        {"type": ev.AGENT_HANDOFF_OUT, "session_id": "root", "payload": {"payload_hash": h}},
    ]
    for sid in ("a", "b", "c"):
        events.append(
            {
                "type": ev.AGENT_HANDOFF_IN,
                "session_id": sid,
                "payload": {"from_session_id": "root", "payload_hash": h},
            }
        )
    pair = fold_handoffs(events)[h]
    assert pair.is_cascade


# ---------------------------------------------------------------------------
# trifecta enforcement (would_close_trifecta peek)


def test_would_close_trifecta_only_when_third_flag_flips() -> None:
    state = TaintState()
    # Empty state: webfetch alone flips untrusted+exfil but not private.
    assert not would_close_trifecta(state, "WebFetch", {"url": "https://x"})

    # Set untrusted+exfil. Now any private-data call closes the trifecta.
    state.has_seen_untrusted = True
    state.can_exfiltrate = True
    assert would_close_trifecta(state, "Read", {"file_path": "/x/.env"})
    # A read of a normal file does NOT close it.
    assert not would_close_trifecta(state, "Read", {"file_path": "/x/README.md"})


def test_would_close_returns_false_once_already_closed() -> None:
    """Once the trifecta is closed, subsequent calls don't trigger another
    escalation - the secrets are already at risk; gating later doesn't help."""
    state = TaintState(
        has_seen_untrusted=True,
        has_accessed_private=True,
        can_exfiltrate=True,
    )
    assert state.trifecta_closed
    assert not would_close_trifecta(state, "WebFetch", {"url": "https://x"})


def test_would_close_does_not_mutate_state() -> None:
    """Pure peek - no mutation, no provenance push."""
    state = TaintState()
    would_close_trifecta(state, "WebFetch", {"url": "https://x"})
    assert state.has_seen_untrusted is False
    assert state.has_accessed_private is False
    assert state.can_exfiltrate is False
    assert state.provenance == []
