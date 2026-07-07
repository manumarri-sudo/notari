"""Tests for the self-improvement engine (`quill learn`) + KPIs.

Pins:
  - normalize_block_reason collapses every known historical format
    variant of a verdict.blocked reason string to the same key, so the
    top-blocked-patterns table doesn't double-count.
  - derive_kpis produces the three KPIs that matter (noise_ratio,
    taint_closures, cascade_events) plus the operator-bypass count.
  - noise_ratio handles zero-block logs gracefully (returns the raw
    ask count, doesn't crash).
  - The trust-scope-candidate analyzer fires on high-ask-low-block
    directories.
  - The silent-failure analyzer fires when the last N journals are
    all zero-turn stubs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quill import events as ev
from quill.learn import (
    KPIReport,
    SuggestionCategory,
    _normalize_block_reason,
    analyze_silent_failures,
    analyze_trust_scope_candidates,
    derive_kpis,
)


def _ev(type_: str, **payload_kv) -> dict:
    return {"type": type_, "session_id": "s", "ts": "2026-05-12T00:00:00Z", "payload": payload_kv}


# ---------------------------------------------------------------------------
# normalize_block_reason - the key thing that makes top-patterns useful


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("rm -rf", "rm -rf"),
        ("rm -rf.", "rm -rf"),
        ("Quill blocked: rm -rf.", "rm -rf"),
        (
            "Quill blocked: rm -rf. To allow, lower the risk in your quill config "
            "or run the command outside Claude Code.",
            "rm -rf",
        ),
        ("rm -rf · try instead: Move to /tmp/quarantine.", "rm -rf"),
        ("rm -rf - try instead: Move to /tmp/quarantine.", "rm -rf"),
        ("rm -rf.  ↪ try: Move to a quarantine dir", "rm -rf"),
        ("vercel --prod", "vercel --prod"),
        ("Quill blocked: vercel --prod. To allow, lower the risk...", "vercel --prod"),
        ("DROP TABLE/DATABASE/SCHEMA", "DROP TABLE/DATABASE/SCHEMA"),
        ("", ""),
    ],
)
def test_normalize_block_reason_collapses_history(raw: str, expected: str) -> None:
    """Every historical format of the SAME underlying rule must
    normalize to the SAME key. Without this, top-patterns shows
    four flavours of `rm -rf` and dilutes the headline."""
    assert _normalize_block_reason(raw) == expected


# ---------------------------------------------------------------------------
# KPI shape + math


def test_kpi_noise_ratio_basic() -> None:
    events = [_ev(ev.VERDICT_ASK, reason="default risk for Edit")] * 100 + [
        _ev(ev.VERDICT_BLOCKED, reason="rm -rf")
    ] * 10
    k = derive_kpis(events)
    assert k.n_asks == 100
    assert k.n_blocks == 10
    assert k.noise_ratio == 10.0
    assert k.health == "loud"  # 5 < 10 < 20


def test_kpi_noise_ratio_zero_blocks_no_divide_error() -> None:
    """A brand-new install with zero blocks must not divide by zero.
    Floor the denominator at 1 (the asks count IS the ratio)."""
    events = [_ev(ev.VERDICT_ASK, reason="default risk for Edit")] * 30
    k = derive_kpis(events)
    assert k.n_blocks == 0
    assert k.noise_ratio == 30.0  # floor of 1 in denom
    assert k.health == "broken"


def test_kpi_noise_ratio_zero_events() -> None:
    """Empty log: ratio is 0 (no asks, no blocks), health "healthy"."""
    k = derive_kpis([])
    assert k.noise_ratio == 0
    assert k.health == "healthy"


def test_kpi_health_thresholds() -> None:
    """Healthy < 5 < loud < 20 < broken. Exact boundary check."""

    def k(asks: int, blocks: int) -> KPIReport:
        return derive_kpis(
            [_ev(ev.VERDICT_ASK)] * asks + [_ev(ev.VERDICT_BLOCKED, reason="rm -rf")] * blocks,
        )

    assert k(4, 1).health == "healthy"  # ratio 4
    assert k(5, 1).health == "loud"  # ratio 5
    assert k(19, 1).health == "loud"  # ratio 19
    assert k(20, 1).health == "broken"  # ratio 20


def test_kpi_taint_closures_counts_only_full_trifecta() -> None:
    """session.taint.update events count toward closures ONLY when all
    three flags are true. Single-flag flips are not closures."""
    events = [
        _ev(
            ev.SESSION_TAINT_UPDATE,
            trifecta={
                "has_seen_untrusted": True,
                "has_accessed_private": False,
                "can_exfiltrate": False,
            },
        ),
        _ev(
            ev.SESSION_TAINT_UPDATE,
            trifecta={
                "has_seen_untrusted": True,
                "has_accessed_private": True,
                "can_exfiltrate": True,
            },
        ),  # this one
        _ev(
            ev.SESSION_TAINT_UPDATE,
            trifecta={
                "has_seen_untrusted": True,
                "has_accessed_private": True,
                "can_exfiltrate": False,
            },
        ),
    ]
    k = derive_kpis(events)
    assert k.n_taint_closures == 1


def test_kpi_cascade_events_counted() -> None:
    events = [_ev(ev.AGENT_CASCADE_AFFECTED, parent_session_id="root")] * 3
    k = derive_kpis(events)
    assert k.n_cascade_events == 3


def test_kpi_operator_bypasses_counted() -> None:
    """verdict.allowed with reason starting 'approved one-shot' is an
    operator-bypass via quill approve. Counted but reported as a raw
    number (not a ratio) because data is sparse."""
    events = [
        _ev(ev.VERDICT_ALLOWED, reason="approved one-shot via quill approve abc"),
        _ev(ev.VERDICT_ALLOWED, reason="approved one-shot via quill approve xyz"),
        _ev(ev.VERDICT_ALLOWED, reason="read-only command"),  # not an override
    ]
    k = derive_kpis(events)
    assert k.n_overrides == 2


def test_kpi_top_blocked_patterns_dedupes_via_normalizer() -> None:
    """Historical format drift must NOT produce duplicate rows."""
    events = [
        _ev(ev.VERDICT_BLOCKED, reason="rm -rf"),
        _ev(ev.VERDICT_BLOCKED, reason="rm -rf."),
        _ev(ev.VERDICT_BLOCKED, reason="Quill blocked: rm -rf."),
        _ev(ev.VERDICT_BLOCKED, reason="rm -rf.  ↪ try: Move to a quarantine dir"),
        _ev(ev.VERDICT_BLOCKED, reason="vercel --prod"),
    ]
    k = derive_kpis(events)
    # 4 rm -rf variants must collapse to one row with hits=4
    patterns = dict(k.top_blocked_patterns)
    assert patterns["rm -rf"] == 4
    assert patterns["vercel --prod"] == 1


# ---------------------------------------------------------------------------
# Suggestion engine


def test_trust_scope_suggestion_fires_on_noisy_dir() -> None:
    events = []
    for _ in range(30):
        events.append(
            {
                "type": ev.VERDICT_ASK,
                "payload": {
                    "tool_name": "Edit",
                    "reason": "default risk for Edit",
                    "cwd": "/Users/u/my-app",
                },
            }
        )
    suggestions = analyze_trust_scope_candidates(events)
    assert any(
        s.category == SuggestionCategory.TRUST_SCOPE and "/Users/u/my-app" in s.title
        for s in suggestions
    )


def test_trust_scope_suggestion_does_not_fire_on_dir_with_many_real_blocks() -> None:
    """A directory with high asks AND high real blocks is doing real
    work; the gate should NOT suggest trusting it away."""
    events = []
    for _ in range(30):
        events.append(
            {
                "type": ev.VERDICT_ASK,
                "payload": {
                    "tool_name": "Edit",
                    "reason": "default risk for Edit",
                    "cwd": "/Users/u/risky",
                },
            }
        )
    for _ in range(20):
        events.append(
            {
                "type": ev.VERDICT_BLOCKED,
                "payload": {"tool_name": "Bash", "reason": "rm -rf", "cwd": "/Users/u/risky"},
            }
        )
    suggestions = analyze_trust_scope_candidates(events)
    assert not any("/Users/u/risky" in s.title for s in suggestions)


def test_silent_failure_suggestion_fires_when_majority_journals_stub_shaped(
    tmp_path: Path,
) -> None:
    """The bug-class that hid for 3 weeks. If recent journals look like
    the stub-shape (0 user turns + 0 assistant turns) the analyzer
    must surface it loudly."""
    for i in range(8):
        (tmp_path / f"2026-05-{i:02d}-x.md").write_text(
            "---\nname: x\n---\nuser turns: 0\nassistant turns: 0\n",
        )
    suggestions = analyze_silent_failures(sessions_dir=tmp_path)
    assert suggestions, "should have detected stub-shaped journals"
    assert suggestions[0].category == SuggestionCategory.SILENT_FAILURE
    assert suggestions[0].severity == "high"


def test_silent_failure_does_not_fire_on_healthy_journals(
    tmp_path: Path,
) -> None:
    for i in range(8):
        (tmp_path / f"2026-05-{i:02d}-x.md").write_text(
            "---\nname: x\n---\nuser turns: 42\nassistant turns: 87\n",
        )
    suggestions = analyze_silent_failures(sessions_dir=tmp_path)
    assert not suggestions
