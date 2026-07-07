"""Tests for `quill insights` — per-pattern analysis + recommendations."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from quill import events as ev
from quill.insights import (
    PatternStat,
    _extract_trust_path,
    compute_insights,
    format_insights,
)


def _evt(t: str, ts: str, *, sid: str = "ses_t1", risk: str = "low", **payload: object) -> dict:
    return {"ts": ts, "session_id": sid, "type": t, "risk": risk, "payload": dict(payload)}


def _write(events: list[dict], path: Path) -> None:
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


# ---------------------------------------------------------------------------
# PatternStat.recommendation


def test_recommendation_keep_critical():
    s = PatternStat(pattern="rm -rf", blocked_count=5, asked_count=0)
    assert s.recommendation == "keep critical"


def test_recommendation_trust_path_candidate():
    s = PatternStat(pattern="Edit (default)", blocked_count=0, asked_count=8)
    assert s.recommendation == "trust-path candidate"


def test_recommendation_review_mixed():
    s = PatternStat(pattern="npm publish", blocked_count=3, asked_count=4)
    assert s.recommendation == "review (mixed signal)"


def test_recommendation_low_signal():
    s = PatternStat(pattern="curl | sh", blocked_count=1, asked_count=0)
    assert s.recommendation == "watching (low signal)"


def test_recommendation_no_fires():
    s = PatternStat(pattern="banking.send_money", blocked_count=0, asked_count=0)
    assert s.recommendation == "no fires in window"


# ---------------------------------------------------------------------------
# trust-path extraction


def test_extract_trust_path_basic():
    assert _extract_trust_path("trusted scope: Edit in /Users/me/repo") == "/Users/me/repo"


def test_extract_trust_path_with_trailing_period():
    assert _extract_trust_path("trusted scope: Write in /tmp/foo.") == "/tmp/foo"


def test_extract_trust_path_returns_none_for_other_reasons():
    assert _extract_trust_path("user policy override") is None
    assert _extract_trust_path("default risk for Read") is None
    assert _extract_trust_path("") is None


# ---------------------------------------------------------------------------
# compute_insights


def test_empty_log_handled(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    p.write_text("")
    insights = compute_insights(p)
    assert insights.events_scanned == 0
    assert insights.pattern_stats == {}


def test_blocked_events_aggregated_by_canonical_pattern(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="force-push detected"),
        _evt(
            ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="git push --force origin"
        ),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    assert insights.pattern_stats["rm -rf"].blocked_count == 2
    assert insights.pattern_stats["git push --force"].blocked_count == 2


def test_ask_events_aggregated_by_tool_name(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Write"),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    assert insights.pattern_stats["Edit (default)"].asked_count == 2
    assert insights.pattern_stats["Write (default)"].asked_count == 1


def test_trust_paths_aggregated_from_verdict_allowed_reasons(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/repo-a"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/repo-a"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Write in /tmp/repo-b"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="user policy override"),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    paths = {tp.path: tp.auto_allows for tp in insights.trust_paths}
    assert paths["/tmp/repo-a"] == 2
    assert paths["/tmp/repo-b"] == 1
    # user-policy-override doesn't count as trust-path
    assert "user policy override" not in paths


def test_trifecta_sessions_flagged_for_review(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(
            ev.VERDICT_BLOCKED,
            now.isoformat(),
            sid="ses_trifecta",
            risk="critical",
            reason="trifecta close · session has seen untrusted + accessed private + exfil",
        ),
        _evt(
            ev.VERDICT_BLOCKED, now.isoformat(), sid="ses_normal", risk="critical", reason="rm -rf"
        ),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    flagged_ids = {rs.session_id for rs in insights.reviewable_sessions}
    assert "ses_trifecta" in flagged_ids
    # ses_normal is NOT flagged for trifecta (no trifecta keyword) — only flagged
    # if it had a critical block at 2-4am, which our test data didn't
    trifecta_session = next(
        rs for rs in insights.reviewable_sessions if rs.session_id == "ses_trifecta"
    )
    assert "trifecta" in trifecta_session.reason


def test_chain_repair_sessions_flagged(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.CHAIN_REPAIRED, now.isoformat(), sid="ses_repair"),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    flagged = {rs.session_id: rs.reason for rs in insights.reviewable_sessions}
    assert "ses_repair" in flagged
    assert "chain repaired" in flagged["ses_repair"]


def test_late_night_critical_block_flagged(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    late_night = datetime(2026, 6, 5, 2, 30, tzinfo=UTC)
    events = [
        _evt(
            ev.VERDICT_BLOCKED,
            late_night.isoformat(),
            sid="ses_late",
            risk="critical",
            reason="rm -rf",
        ),
    ]
    _write(events, p)
    insights = compute_insights(p)  # unbounded window
    flagged = {rs.session_id: rs.reason for rs in insights.reviewable_sessions}
    assert "ses_late" in flagged
    assert "02:30" in flagged["ses_late"]


def test_top_patterns_sorted_by_total_fires(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events: list[dict] = []
    # rm -rf: 5 blocks
    for _ in range(5):
        events.append(_evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"))
    # Edit: 8 asks
    for _ in range(8):
        events.append(_evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"))
    # vercel --prod: 2 blocks
    for _ in range(2):
        events.append(
            _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="vercel --prod")
        )
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    top = insights.top_patterns
    # Edit (default) has 8 fires, more than rm -rf's 5 -> Edit comes first
    assert top[0].pattern == "Edit (default)"
    assert top[1].pattern == "rm -rf"


def test_downgrade_candidates_filtered(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events: list[dict] = []
    # Edit: 6 asks (downgrade candidate)
    for _ in range(6):
        events.append(_evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"))
    # rm -rf: 5 blocks (NOT downgrade)
    for _ in range(5):
        events.append(_evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"))
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    candidates = {s.pattern for s in insights.downgrade_candidates}
    assert "Edit (default)" in candidates
    assert "rm -rf" not in candidates


# ---------------------------------------------------------------------------
# format_insights


def test_format_insights_empty_window(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    p.write_text("")
    insights = compute_insights(p)
    out = format_insights(insights, plain=True)
    assert "no gated events in window" in out


def test_format_insights_includes_all_sections(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ASK, now.isoformat(), tool_name="Edit"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/x"),
        _evt(
            ev.VERDICT_BLOCKED,
            now.isoformat(),
            sid="ses_trifecta",
            risk="critical",
            reason="trifecta close · session has seen untrusted",
        ),
    ]
    _write(events, p)
    insights = compute_insights(
        p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1)
    )
    out = format_insights(insights, plain=True)
    assert "top patterns by fire frequency" in out
    assert "trust-path effectiveness" in out
    assert "sessions worth reviewing" in out
    assert "downgrade candidates" in out
    assert "what's next" in out
