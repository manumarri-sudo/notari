"""Tests for the plain-English receipt narrator.

The narrator is a deterministic template, so we can pin specific phrases
and check the grammar (singular/plural, "and" connective, capped blocks).
"""

from __future__ import annotations

from quill import events as ev
from quill.receipt import (
    Receipt,
    _format_window,
    _pluralize,
    _top_directory,
    derive_from_events,
    narrate,
)


def _evt(
    t: str,
    sid: str = "ses_aaaa",
    ts: str = "2026-06-08T09:14:22Z",
    risk: str = "low",
    **payload: object,
) -> dict[str, object]:
    return {
        "type": t,
        "session_id": sid,
        "ts": ts,
        "risk": risk,
        "payload": dict(payload),
    }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_pluralize_singular_and_plural():
    assert _pluralize(1, "call") == "call"
    assert _pluralize(2, "call") == "calls"
    assert _pluralize(0, "call") == "calls"
    assert _pluralize(1, "child", "children") == "child"
    assert _pluralize(3, "child", "children") == "children"


def test_top_directory_picks_most_common_parent():
    paths = [
        "src/auth/login.py",
        "src/auth/signup.py",
        "src/auth/reset.py",
        "tests/test_auth.py",
    ]
    assert _top_directory(paths) == "src/auth"


def test_top_directory_handles_filename_only():
    assert _top_directory(["README.md"]) == ""


def test_top_directory_empty_input():
    assert _top_directory([]) == ""


def test_format_window_same_day():
    out = _format_window("2026-06-08T09:14:22Z", "2026-06-08T11:42:11Z")
    assert "2026-06-08 09:14:22" in out
    assert "11:42:11" in out


def test_format_window_different_days():
    out = _format_window("2026-06-08T23:50:00Z", "2026-06-09T01:30:00Z")
    assert "2026-06-08 23:50:00" in out
    assert "2026-06-09 01:30:00" in out


def test_format_window_open_session():
    out = _format_window("2026-06-08T09:14:22Z", "")
    assert "starting at" in out


# ---------------------------------------------------------------------------
# narrate
# ---------------------------------------------------------------------------


def test_narrate_empty_receipt_explicit_message():
    r = Receipt(session_id="ses_zero")
    s = narrate(r)
    assert "No tool calls" in s


def test_narrate_simple_session():
    r = Receipt(
        session_id="ses_a4f1",
        opened_at="2026-06-08T09:14:22Z",
        closed_at="2026-06-08T11:42:11Z",
        did=["Bash", "Edit"],
        changed=["src/auth/login.py", "src/auth/signup.py"],
        tool_call_count=12,
        top_changed_dir="src/auth",
        tdr_contribution=0.92,
    )
    s = narrate(r)
    assert "12 tool calls" in s
    assert "2 files" in s
    assert "src/auth" in s
    assert "Trust delivery rate 92%" in s


def test_narrate_with_blocks_and_asks_and_touchid():
    r = Receipt(
        session_id="ses_blk",
        opened_at="2026-06-08T09:14:22Z",
        closed_at="2026-06-08T11:42:11Z",
        tool_call_count=20,
        intervention_count=3,
        blocks_summary=[
            "Bash: rm -rf is critical-risk",
            "Bash: git push --force rewrites shared history",
        ],
        asks_summary=["Edit: high-risk file write"],
        biometric_approvals=1,
        tdr_contribution=0.85,
    )
    s = narrate(r)
    assert "refused 2 destructive operations" in s
    assert "paused 1 time for a human y/N" in s
    assert "confirmed 1 critical action via Touch ID" in s
    assert "Blocked:" in s
    assert "rm -rf" in s
    assert "git push --force" in s


def test_narrate_caps_block_breakdown_at_three():
    r = Receipt(
        session_id="ses_many",
        opened_at="2026-06-08T09:14:22Z",
        closed_at="2026-06-08T11:42:11Z",
        tool_call_count=50,
        intervention_count=8,
        blocks_summary=[f"Bash: blocked {i}" for i in range(8)],
    )
    s = narrate(r)
    assert "and 5 more" in s


def test_narrate_uses_singular_for_count_one():
    r = Receipt(
        session_id="ses_one",
        opened_at="2026-06-08T09:14:22Z",
        closed_at="2026-06-08T11:42:11Z",
        tool_call_count=1,
        changed=["README.md"],
        biometric_approvals=1,
        intervention_count=1,
        blocks_summary=["Bash: example"],
    )
    s = narrate(r)
    assert "1 tool call" in s
    assert "1 file" in s
    assert "1 destructive operation" in s
    assert "1 critical action" in s


def test_narrate_includes_flagged_to_verify_count():
    r = Receipt(
        session_id="ses_v",
        opened_at="2026-06-08T09:14:22Z",
        closed_at="2026-06-08T11:42:11Z",
        tool_call_count=5,
        to_verify=["the migration didn't roll back cleanly", "double-check the index"],
        tdr_contribution=1.0,
    )
    s = narrate(r)
    assert "2 items flagged for your review" in s


# ---------------------------------------------------------------------------
# end-to-end through derive_from_events
# ---------------------------------------------------------------------------


def test_derive_populates_narrative_fields():
    events = [
        _evt(ev.SESSION_OPEN, intent="exploratory dev"),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Edit", args_preview={"file_path": "src/auth/login.py"}),
        _evt(ev.VERDICT_ALLOWED, tool_name="Edit"),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Edit", args_preview={"file_path": "src/auth/signup.py"}),
        _evt(ev.VERDICT_ALLOWED, tool_name="Edit"),
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Bash",
            risk="critical",
            args_preview={"command": "rm -rf /"},
        ),
        _evt(
            ev.VERDICT_BLOCKED, tool_name="Bash", risk="critical", reason="rm -rf is critical-risk"
        ),
        _evt(ev.APPROVE_BIOMETRIC_OK, tool_name="Bash"),
        _evt(ev.SESSION_CLOSE),
    ]
    receipts = derive_from_events(events)
    assert "ses_aaaa" in receipts
    r = receipts["ses_aaaa"]
    assert r.tool_call_count == 3
    assert r.top_changed_dir == "src/auth"
    assert r.biometric_approvals == 1
    assert len(r.blocks_summary) == 1
    assert "rm -rf" in r.blocks_summary[0]


def test_to_dict_includes_narrative_fields():
    r = Receipt(
        session_id="ses_x",
        blocks_summary=["a: b"],
        biometric_approvals=2,
        top_changed_dir="src/",
    )
    d = r.to_dict()
    assert d["blocks_summary"] == ["a: b"]
    assert d["biometric_approvals"] == 2
    assert d["top_changed_dir"] == "src/"
