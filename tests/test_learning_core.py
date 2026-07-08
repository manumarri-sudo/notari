"""Step 1 tests: the math + persistence foundation of learning.py.

Four detailed tests, each pinning one invariant the rest of the
learning loop will depend on. If any of these fails, every later
step is built on sand:

  1. Beta-binomial math matches hand calculation across the relevant
     boundary cases (zero data, single observation, many).
  2. Wilson 95% interval matches the canonical formula (cross-checked
     against an explicit reference computation) and behaves correctly
     at the boundaries (0/0 = max uncertainty; n=1 doesn't divide-by-
     anything-zero).
  3. EWMA recency tracking decays at the expected rate; the half-life
     matches the chosen alpha=0.1.
  4. Atomic save survives a mid-write interruption simulated by
     poisoning the tmp file, plus round-trips through asdict/dict
     cleanly across many records.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from nota.learning import (
    EWMA_ALPHA,
    PRIOR_ALPHA,
    PRIOR_BETA,
    PatternStats,
    load_stats,
    save_stats,
)

# ---------------------------------------------------------------------------
# Test 1: Beta-binomial math correctness.


def test_beta_binomial_matches_hand_calculation(tmp_path: Path, monkeypatch) -> None:
    """The posterior of Beta(alpha_0, beta_0) + k approvals out of n
    fires is Beta(alpha_0 + k, beta_0 + n - k). Posterior mean is
    (alpha_0 + k) / (alpha_0 + beta_0 + n). Hand-verify across the
    boundary cases that drive the auto-tighten / loosen decisions.
    """
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))

    # In this codebase the "approve" event is an operator-BYPASS of a
    # block (operator used `nota approve` to release a one-shot block).
    # The "deny" event is the block standing (the default outcome).
    # We want the prior to encode "default to LOW approval / bypass
    # rate" so a single early bypass doesn't flip a pattern toward
    # loosening. Prior Beta(1, 9): mean = 1/10 = 0.10 = 10% default
    # bypass rate. Verify against PRIOR_ALPHA / (PRIOR_ALPHA+PRIOR_BETA).
    p = PatternStats(pattern_id="canary")
    expected_prior_mean = PRIOR_ALPHA / (PRIOR_ALPHA + PRIOR_BETA)
    assert expected_prior_mean == pytest.approx(0.10, abs=1e-9)
    assert p.posterior_mean == pytest.approx(expected_prior_mean, abs=1e-9)

    # 5 approvals, 0 denies. Posterior mean = (1+5)/(1+9+5) = 6/15 = 0.4.
    for _ in range(5):
        p.record("approve", now=time.time())
    assert p.fires == 5
    assert p.approvals == 5
    assert p.denies == 0
    assert p.posterior_mean == pytest.approx(
        (PRIOR_ALPHA + 5) / (PRIOR_ALPHA + PRIOR_BETA + 5),
        abs=1e-9,
    )
    assert p.posterior_mean == pytest.approx(6.0 / 15.0, abs=1e-9)

    # +5 denies. Posterior mean = (1+5)/(1+9+10) = 6/20 = 0.3.
    for _ in range(5):
        p.record("deny", now=time.time())
    assert p.posterior_mean == pytest.approx(6.0 / 20.0, abs=1e-9)

    # Strong evidence that the operator DOES override: 50 approvals,
    # 5 denies. Posterior mean = (1+50)/(1+9+55) = 51/65 ~= 0.785.
    # Wilson 95% lower bound should be well above the 0.65 loosening
    # threshold, so this is unambiguously a loosening candidate.
    p2 = PatternStats(pattern_id="loose-candidate")
    for _ in range(50):
        p2.record("approve", now=time.time())
    for _ in range(5):
        p2.record("deny", now=time.time())
    assert p2.posterior_mean == pytest.approx(51.0 / 65.0, abs=1e-9)
    lo, _ = p2.wilson_interval(0.95)
    assert lo > 0.65, f"strong override evidence should clear 0.65 threshold (got {lo:.3f})"


# ---------------------------------------------------------------------------
# Test 2: Wilson 95% interval correctness + boundary behaviour.


def test_wilson_interval_is_correct_at_known_points(tmp_path: Path, monkeypatch) -> None:
    """Wilson score interval for a binomial proportion at confidence
    0.95. Reference values computed from the canonical formula:

        center = (p + z^2 / 2n) / (1 + z^2 / n)
        half   = z * sqrt(p(1-p)/n + z^2 / 4n^2) / (1 + z^2 / n)

    with z = 1.959964 (95%). Cross-check at a few representative n,k.
    """
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))

    # n=0: maximum uncertainty (0.0, 1.0).
    p = PatternStats(pattern_id="empty")
    lo, hi = p.wilson_interval(0.95)
    assert (lo, hi) == (0.0, 1.0)

    # n=20, k=15 approvals. Hand-computed:
    # z=1.959964, p=0.75, z^2=3.84146, denom=1+3.84146/20=1.192073
    # center = (0.75 + 0.0960365)/1.192073 = 0.709712
    # half   = z * sqrt(0.75*0.25/20 + 3.84146/1600) / 1.192073
    #        = 1.959964 * sqrt(0.009375+0.0024009)/1.192073
    #        = 1.959964 * 0.108512 / 1.192073 = 0.178419
    # Wilson interval: (0.531293, 0.888131)
    p = PatternStats(pattern_id="x", fires=20, approvals=15, denies=5)
    lo, hi = p.wilson_interval(0.95)
    assert lo == pytest.approx(0.531293, abs=1e-4)
    assert hi == pytest.approx(0.888131, abs=1e-4)
    assert 0.0 <= lo <= hi <= 1.0

    # Edge: n=1, k=1. p=1.0. center=(1+z^2/2)/(1+z^2)=(1+1.92)/(1+3.84)=0.604
    # half = z*sqrt(0 + z^2/4)/(1+z^2) = z*(z/2)/(1+z^2) = z^2/2/(1+z^2)
    #      = 3.84146/2 / 4.84146 = 0.3967
    # Interval: (0.207, 1.0).
    p = PatternStats(pattern_id="y", fires=1, approvals=1, denies=0)
    lo, hi = p.wilson_interval(0.95)
    assert lo == pytest.approx(0.207, abs=1e-2)
    assert hi == pytest.approx(1.0, abs=1e-3)

    # Edge: n=1, k=0. Mirror of above; lower should be near 0.
    p = PatternStats(pattern_id="z", fires=1, approvals=0, denies=1)
    lo, hi = p.wilson_interval(0.95)
    assert lo == pytest.approx(0.0, abs=1e-3)
    assert hi == pytest.approx(0.793, abs=1e-2)

    # Edge: 90% interval is tighter than 95%.
    p = PatternStats(pattern_id="w", fires=20, approvals=15, denies=5)
    lo90, hi90 = p.wilson_interval(0.90)
    lo95, hi95 = p.wilson_interval(0.95)
    assert lo90 > lo95
    assert hi90 < hi95


# ---------------------------------------------------------------------------
# Test 3: EWMA recency behaviour at the chosen alpha=0.1.


def test_ewma_decays_at_expected_rate(tmp_path: Path, monkeypatch) -> None:
    """EWMA(alpha=0.1) should reach ~50% of a step change after roughly
    log(0.5)/log(1 - alpha) = log(0.5)/log(0.9) ~= 6.6 observations.
    Pin the value at n=10 against a hand calculation for the exact
    sequence: 10 approvals (all 1.0), starting from EWMA=0.

    Recurrence: e[n] = alpha*x[n] + (1-alpha)*e[n-1]. With x always 1,
    e[n] = 1 - (1-alpha)^n. At n=10, alpha=0.1: 1 - 0.9^10 = 0.6513.
    """
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))
    p = PatternStats(pattern_id="ewma")
    for _ in range(10):
        p.record("approve", now=time.time())
    expected = 1.0 - (1.0 - EWMA_ALPHA) ** 10
    assert p.ewma_approval_rate == pytest.approx(expected, abs=1e-9)

    # Switch direction: 10 denies after 10 approvals. EWMA should track
    # toward 0. After 10 more steps with x=0: e[20] = (1-alpha)^10 *
    # e[10] = 0.9^10 * 0.6513 = 0.349 * 0.6513 = 0.227. Approximately.
    for _ in range(10):
        p.record("deny", now=time.time())
    expected_after = (1.0 - EWMA_ALPHA) ** 10 * expected
    assert p.ewma_approval_rate == pytest.approx(expected_after, abs=1e-6)

    # Inter-arrival history is bounded at 50 even after 100 records.
    p2 = PatternStats(pattern_id="ring")
    for i in range(100):
        p2.record("approve", now=float(i))
    assert len(p2.inter_arrival_sec) == 50, (
        "inter_arrival_sec must be bounded so the persisted JSON does "
        "not grow unbounded across a long-running session"
    )


# ---------------------------------------------------------------------------
# Test 4: Atomic save survives mid-write interruption + round-trips.


def test_atomic_save_survives_mid_write_interruption(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """tmp-rename means a partial write to the .tmp file cannot
    corrupt the canonical pattern_stats.json. Simulate an
    interruption by writing garbage to the .tmp file BEFORE save_stats
    runs; the save should overwrite it cleanly, and load_stats on the
    poisoned-tmp + good-canonical state should succeed.
    """
    stats_path = tmp_path / "stats.json"
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(stats_path))

    # Write one round.
    p = PatternStats(
        pattern_id="alpha",
        fires=10,
        approvals=7,
        denies=3,
        last_fire_ts=1234.0,
        first_fire_ts=1100.0,
        ewma_approval_rate=0.42,
    )
    save_stats({"alpha": p})
    assert stats_path.exists()

    # Poison the .tmp file with garbage. Future save must overwrite it.
    tmp = stats_path.with_suffix(stats_path.suffix + ".tmp")
    tmp.write_text("THIS IS NOT JSON {{{{{{")
    # Load_stats still returns the canonical state because the .tmp
    # file is not read.
    loaded = load_stats()
    assert "alpha" in loaded
    assert loaded["alpha"].fires == 10
    assert loaded["alpha"].approvals == 7

    # Save again; should clean up + overwrite the garbage tmp.
    p2 = PatternStats(pattern_id="alpha", fires=11, approvals=8, denies=3)
    save_stats({"alpha": p2})
    loaded2 = load_stats()
    assert loaded2["alpha"].fires == 11
    assert loaded2["alpha"].approvals == 8

    # Many records round-trip cleanly.
    big = {
        f"pat-{i}": PatternStats(
            pattern_id=f"pat-{i}",
            fires=i,
            approvals=i // 2,
            denies=i // 2,
            ewma_approval_rate=i / 100.0,
        )
        for i in range(50)
    }
    save_stats(big)
    loaded3 = load_stats()
    assert len(loaded3) == 50
    for i in range(50):
        k = f"pat-{i}"
        assert loaded3[k].fires == i
        assert loaded3[k].approvals == i // 2
        assert loaded3[k].denies == i // 2

    # File mode is 0o600 (no group/other read).
    if hasattr(os, "stat"):
        mode = stats_path.stat().st_mode & 0o777
        assert mode & 0o077 == 0, f"too permissive: {oct(mode)}"

    # A corrupted canonical file returns {} without crashing - so the
    # hook never fails open on a parse error.
    stats_path.write_text("CORRUPT NOT JSON")
    loaded4 = load_stats()
    assert loaded4 == {}
