"""Tests for the agent roster (which agents ran / permitted / touched)."""

from __future__ import annotations

from nota import events as ev
from nota.roster import derive_roster


def _evt(etype: str, sid: str, agent: str = "root", **payload: object) -> dict[str, object]:
    return {
        "type": etype,
        "session_id": sid,
        "agent_id": agent,
        "ts": payload.pop("ts", "t"),
        "payload": payload,
    }


def test_groups_by_agent_and_session() -> None:
    events = [
        _evt(ev.TOOL_ATTEMPTED, "s1", "planner", tool_name="Bash"),
        _evt(
            ev.TOOL_ATTEMPTED,
            "s1",
            "planner",
            tool_name="Edit",
            args_preview={"path": "src/app.py"},
        ),
        _evt(
            ev.TOOL_ATTEMPTED, "s2", "coder", tool_name="Write", args_preview={"path": "tests/t.py"}
        ),
    ]
    rows = derive_roster(events)
    by_agent = {r.agent_id: r for r in rows}
    assert set(by_agent) == {"planner", "coder"}
    assert by_agent["planner"].actions == 2
    assert set(by_agent["planner"].tools) == {"Bash", "Edit"}
    assert "src" in by_agent["planner"].touched_dirs
    assert "tests" in by_agent["coder"].touched_dirs


def test_verdict_mix_counts() -> None:
    events = [
        _evt(ev.VERDICT_ALLOWED, "s1"),
        _evt(ev.VERDICT_ASK, "s1"),
        _evt(ev.VERDICT_BLOCKED, "s1", reason="rm -rf"),
        _evt(ev.VERDICT_SCOPE_VIOLATION, "s1"),
        _evt(ev.APPROVE_BIOMETRIC_OK, "s1"),
    ]
    r = derive_roster(events)[0]
    assert (r.allowed, r.asked, r.blocked, r.approvals) == (1, 1, 2, 1)


def test_change_control_verification_maps_into_roster() -> None:
    events = [
        _evt(ev.VERIFICATION_RUN, "cc", verdict="PASS"),
        _evt(ev.VERIFICATION_RUN, "cc", verdict="BLOCK", forbidden_hits=["migrations/001.sql"]),
    ]
    r = derive_roster(events)[0]
    assert r.actions == 2
    assert "change-control" in r.tools
    assert r.allowed == 1 and r.blocked == 1
    assert "migrations" in r.touched_dirs


def test_empty_log_yields_no_rows() -> None:
    assert derive_roster([]) == []
