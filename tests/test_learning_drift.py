"""Step 3 tests: Page-Hinkley drift detection at SessionEnd.

Four cases, each pinning one invariant the production drift detector
must hold:

  1. A clear upward shift (operator starts approving everything after
     a long deny streak) is detected, with the correct direction.
  2. A clear downward shift (operator was approving a lot, then stops)
     is also detected.
  3. Random noise around a stable mean does NOT trigger detection
     (false-positive guard - operator behaviour fluctuating in normal
     range must not fire).
  4. Empty / sparse sessions (< 20 observations) do NOT crash AND do
     NOT report drift (Page-Hinkley is unreliable in sparse regime
     by design).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from quill.learning import (
    PH_LAMBDA,
    PatternStats,  # noqa: F401  - import lock-in
    aggregate_observations_for_session,
    check_drift_for_session,
    page_hinkley,
)

# ---------------------------------------------------------------------------
# Test 1: Upward shift is detected.


def test_page_hinkley_detects_upward_shift(tmp_path: Path, monkeypatch) -> None:
    """50 denies followed by 50 approves is the canonical upward
    shift. Detector must fire with direction='upward'."""
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "s.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "sug.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "l.log"))
    observations = [0.0] * 50 + [1.0] * 50
    result = page_hinkley(observations)
    assert result.detected, (
        f"clear upward shift must fire; got stat={result.statistic:.2f}, lambda={PH_LAMBDA}"
    )
    assert result.direction == "upward"
    assert result.rate_now > result.rate_prior_window
    assert result.n_observations == 100


# ---------------------------------------------------------------------------
# Test 2: Downward shift is detected.


def test_page_hinkley_detects_downward_shift(tmp_path: Path, monkeypatch) -> None:
    """50 approves followed by 50 denies is the symmetric downward
    case. Detector must fire with direction='downward'."""
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "s.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "sug.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "l.log"))
    observations = [1.0] * 50 + [0.0] * 50
    result = page_hinkley(observations)
    assert result.detected
    assert result.direction == "downward"
    assert result.rate_now < result.rate_prior_window


# ---------------------------------------------------------------------------
# Test 3: Noise does not trigger detection.


def test_page_hinkley_does_not_fire_on_stable_noise(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """200 observations drawn from a stable Bernoulli(0.3) should NOT
    trigger drift. Run twice with different seeds; both must stay
    below threshold. If this test ever fires, the lambda/delta
    defaults are too aggressive for the operator's normal volume."""
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "s.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "sug.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "l.log"))
    for seed in (12345, 67890, 42):
        rng = random.Random(seed)
        observations = [1.0 if rng.random() < 0.30 else 0.0 for _ in range(200)]
        result = page_hinkley(observations)
        assert not result.detected, (
            f"seed {seed}: stable Bernoulli(0.30) noise should NOT fire "
            f"(stat={result.statistic:.2f}, lambda={PH_LAMBDA}); "
            f"either the test is flaky or the threshold is too tight"
        )


# ---------------------------------------------------------------------------
# Test 4: Sparse sessions do not crash and do not report drift.


def test_drift_check_handles_sparse_and_empty_sessions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A session with < 20 outcomes returns no-detect. An empty event
    list returns no-detect. A session whose session_id is unknown
    returns no-detect. None of these crash."""
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "s.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "sug.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "l.log"))

    # Empty Page-Hinkley
    r0 = page_hinkley([])
    assert not r0.detected
    assert r0.n_observations == 0

    # 15 observations - below threshold of 20 - never fires
    r_sparse = page_hinkley([0.0] * 10 + [1.0] * 5)
    assert not r_sparse.detected
    assert r_sparse.n_observations == 15

    # End-to-end: 5-event session, unknown session_id, both no-detect.
    fake_events = [
        {"type": "verdict.blocked", "session_id": "s1", "payload": {}},
        {"type": "verdict.ask", "session_id": "s1", "payload": {}},
        {
            "type": "verdict.allowed",
            "session_id": "s1",
            "payload": {"reason": "read-only command"},
        },  # plain LOW, excluded
        {"type": "verdict.blocked", "session_id": "s2", "payload": {}},
    ]
    obs_s1 = aggregate_observations_for_session(fake_events, "s1")
    # 2 deny-flavored events, 0 approvals (the LOW allow is excluded).
    assert obs_s1 == [0.0, 0.0]
    sug = check_drift_for_session(fake_events, "s1")
    assert sug is None

    # Unknown session
    sug2 = check_drift_for_session(fake_events, "does-not-exist")
    assert sug2 is None

    # Strong-signal session - upward shift across 60 outcomes - DOES
    # fire and writes a suggestion to the configured suggestions path.
    big_events: list[dict] = []
    for _i in range(30):
        big_events.append({"type": "verdict.blocked", "session_id": "big", "payload": {}})
    for _i in range(30):
        big_events.append(
            {
                "type": "verdict.allowed",
                "session_id": "big",
                "payload": {"reason": "approved one-shot via foo"},
            }
        )
    sug3 = check_drift_for_session(big_events, "big")
    assert sug3 is not None
    assert sug3["type"] == "drift_detected"
    assert sug3["direction"] == "upward"
    # Suggestion file was written and contains the entry.
    sug_path = tmp_path / "sug.jsonl"
    assert sug_path.exists()
    raw = sug_path.read_text().strip().splitlines()
    found = [json.loads(line) for line in raw]
    assert any(s.get("type") == "drift_detected" for s in found)
