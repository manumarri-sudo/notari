"""Tests for the in-flow auto-promote candidate detector (#51).

The detector fires when a pattern has accumulated >= 5 approvals within a
7-day window with 0 denies. The bright line: critical/secret/trifecta
patterns are never candidates. Suggestion type is `policy.promotion_suggested`
with `in_flow: True`.
"""

from __future__ import annotations

import time

from quill.learning import (
    AUTOPROMOTE_MIN_APPROVALS,
    AUTOPROMOTE_WINDOW_SEC,
    PatternStats,
    detect_auto_promote_candidate,
)


def _stats_with_approvals(
    pattern_id: str, n_approvals: int, n_denies: int = 0, span_sec: float = 86400.0
) -> PatternStats:
    """Synthesize a PatternStats with the given approval/deny counts and
    a fire-span (last_fire_ts - first_fire_ts) matching span_sec."""
    p = PatternStats(pattern_id=pattern_id)
    now = time.time()
    p.first_fire_ts = now - span_sec
    p.last_fire_ts = now
    p.approvals = n_approvals
    p.denies = n_denies
    p.fires = n_approvals + n_denies
    return p


def test_fires_at_threshold():
    p = _stats_with_approvals("Edit:fmt", AUTOPROMOTE_MIN_APPROVALS)
    sug = detect_auto_promote_candidate(p)
    assert sug is not None
    assert sug["type"] == "policy.promotion_suggested"
    assert sug["pattern_id"] == "Edit:fmt"
    assert sug["in_flow"] is True


def test_does_not_fire_below_threshold():
    p = _stats_with_approvals("Edit:fmt", AUTOPROMOTE_MIN_APPROVALS - 1)
    assert detect_auto_promote_candidate(p) is None


def test_does_not_fire_with_any_deny():
    p = _stats_with_approvals("Edit:fmt", AUTOPROMOTE_MIN_APPROVALS, n_denies=1)
    assert detect_auto_promote_candidate(p) is None


def test_does_not_fire_outside_window():
    p = _stats_with_approvals(
        "Edit:fmt",
        AUTOPROMOTE_MIN_APPROVALS,
        span_sec=AUTOPROMOTE_WINDOW_SEC + 86400.0,
    )
    assert detect_auto_promote_candidate(p) is None


def test_critical_patterns_never_promote():
    """Critical-class pattern IDs are excluded; the bright line never softens
    even if the operator has 'approved' (e.g., approved-via-token) repeatedly.
    """
    for prefix in ("critical:", "secret:", "trifecta:"):
        p = _stats_with_approvals(f"{prefix}rm-rf", AUTOPROMOTE_MIN_APPROVALS)
        assert detect_auto_promote_candidate(p) is None, prefix


def test_evidence_is_present_and_short():
    p = _stats_with_approvals("Edit:fmt", 5)
    sug = detect_auto_promote_candidate(p)
    assert sug is not None
    assert "5 approvals" in sug["evidence"]


def test_suggestion_has_expiry():
    p = _stats_with_approvals("Edit:fmt", 5)
    sug = detect_auto_promote_candidate(p)
    assert sug is not None
    assert "expires_ts" in sug
    assert sug["expires_ts"] > time.time()
