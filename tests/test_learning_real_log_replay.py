"""Step C test: replay-against-real-log integration.

Feed every learning-signal event from the user's actual
~/.nota/audit.log.jsonl through post_decision_update, then assert
the resulting pattern_stats match a hand-derived expectation.

This is the test the rc5 honest audit was missing - end-to-end
exercise of the learning loop against the same data shape the
production gate produces. If this test passes, the learner's
state-derivation is sound against the real distribution.

The test is gated on the real log being present; skipped otherwise.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

REAL_LOG = Path.home() / ".nota" / "audit.log.jsonl"


def _classify_event_to_learning_signal(evt: dict) -> tuple[str | None, str | None]:
    """Mirror the adapter's hook-time logic for what becomes a learning
    event. Returns (pattern_id, decision) or (None, None) to skip.

    A learning event is:
      - verdict.blocked       -> decision "deny"
      - verdict.ask           -> decision "deny" (treated as a deny
                                 outcome until a token consume flips
                                 it later)
      - verdict.allowed where reason starts "approved one-shot"
                              -> decision "approve" (token consume)

    Plain-LOW allows carry no operator signal and are excluded.

    The pattern_id is derived the same way the adapter derives it.
    """
    from nota.learn import _normalize_block_reason

    etype = evt.get("type")
    payload = evt.get("payload") or {}
    if not isinstance(payload, dict):
        return None, None
    tool_name = str(payload.get("tool_name") or "")
    reason = str(payload.get("reason") or "")
    if not tool_name:
        return None, None
    if etype == "verdict.blocked":
        head = _normalize_block_reason(reason) or reason
        return f"{tool_name}:{head}"[:80], "deny"
    if etype == "verdict.ask":
        head = _normalize_block_reason(reason) or reason
        return f"{tool_name}:{head}"[:80], "deny"
    if etype == "verdict.allowed":
        if not reason.startswith("approved one-shot"):
            return None, None
        head = _normalize_block_reason(reason) or reason
        return f"{tool_name}:{head}"[:80], "approve"
    return None, None


@pytest.mark.skipif(
    not REAL_LOG.exists(),
    reason="no real audit log to replay (run on the operator's machine)",
)
def test_replay_against_real_audit_log_matches_hand_derived_counts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The acid test: replay every learning signal from the real log,
    verify the resulting pattern_stats matches what a hand-derived
    aggregation produces. If they diverge, the in-line learner has
    a bug the unit tests didn't catch.
    """
    # Isolate so the test never touches the operator's REAL stats file.
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("NOTA_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("NOTA_LEARNING_LOG", str(tmp_path / "learning.log"))

    # 1. Load the real audit log.
    events: list[dict] = []
    with REAL_LOG.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue
    # This is a dogfooding integration test: it only means something against
    # a real, high-volume operator log. A small log (e.g. the 2-entry log a
    # fresh `nota` run leaves in ~/.nota on any machine) satisfies the
    # skipif-exists guard above but is not the dogfooded distribution this
    # test targets, so skip rather than fail. On CI, where no ~/.nota log
    # exists at all, the skipif already handles it.
    if len(events) < 1000:
        pytest.skip(
            f"real log only has {len(events)} events; this replay test needs "
            "a dogfooded log with thousands of entries (operator machine only)"
        )

    # 2. Build the hand-derived expectation: per pattern_id, count
    # approvals + denies the way the post_decision_update SHOULD record.
    expected_approves: dict[str, int] = defaultdict(int)
    expected_denies: dict[str, int] = defaultdict(int)
    n_signal_events = 0
    for evt in events:
        pattern_id, decision = _classify_event_to_learning_signal(evt)
        if pattern_id is None:
            continue
        n_signal_events += 1
        if decision == "approve":
            expected_approves[pattern_id] += 1
        elif decision == "deny":
            expected_denies[pattern_id] += 1

    assert n_signal_events >= 500, (
        f"only {n_signal_events} learning-signal events in the log; "
        "the test is too sparse to be meaningful"
    )

    # 3. Replay every event through post_decision_update.
    from nota.learning import load_stats, post_decision_update

    for evt in events:
        pattern_id, decision = _classify_event_to_learning_signal(evt)
        if pattern_id is None:
            continue
        post_decision_update(pattern_id, decision)

    # 4. Verify the produced stats match the hand-derived expectation.
    produced = load_stats()
    all_patterns = set(expected_approves) | set(expected_denies)
    assert all_patterns, "no patterns derived from the real log"

    # Every expected pattern is present.
    missing = all_patterns - set(produced)
    assert not missing, f"learner did NOT record {len(missing)} patterns: {sorted(missing)[:5]}"

    # Counts match.
    mismatches: list[str] = []
    for pid in all_patterns:
        exp_approves = expected_approves[pid]
        exp_denies = expected_denies[pid]
        exp_fires = exp_approves + exp_denies
        got = produced[pid]
        if (got.approvals, got.denies, got.fires) != (
            exp_approves,
            exp_denies,
            exp_fires,
        ):
            mismatches.append(
                f"  {pid[:60]:60s} "
                f"expected fires={exp_fires} a={exp_approves} d={exp_denies}, "
                f"got fires={got.fires} a={got.approvals} d={got.denies}"
            )
    assert not mismatches, (
        f"{len(mismatches)} pattern(s) diverged from hand-derived expectation:\n"
        + "\n".join(mismatches[:20])
    )

    # 5. Sanity: total fires count == total signal events.
    total_fires = sum(p.fires for p in produced.values())
    assert total_fires == n_signal_events, (
        f"total fires recorded ({total_fires}) != signal events processed ({n_signal_events})"
    )

    # 6. The replay produced a healthy distribution (more than one
    # pattern, more than one tool). Defends against a regression that
    # silently collapses all events into a single pattern.
    distinct_tools = {pid.split(":", 1)[0] for pid in produced}
    assert len(distinct_tools) >= 3, (
        f"only {len(distinct_tools)} distinct tools in replay; "
        f"real log should have at least Bash + Edit + Write"
    )
