"""Step B tests: pattern_stats.json under concurrent writers.

The honest-audit gap: without flock, two concurrent hook subprocesses
both call load_stats() (same baseline), both record() (in-memory
divergent updates), both save_stats() - the second write atomically
replaces the first, losing the first's increment.

The fix: exclusive flock around the entire read-modify-write cycle.

Four invariants under test:

  1. Single-writer behaviour is unchanged. Adding flock doesn't break
     the sequential case.
  2. 8 OS processes hammering post_decision_update for the same
     pattern_id, 50 records each, end up with fires == 400 (not
     fires < 400 due to lost updates). This is the canonical
     read-modify-write race test.
  3. Mixed concurrency: 4 processes recording approves, 4 recording
     denies, each 100x. Final counts match the sent totals exactly.
  4. Locked reader during writer: a reader can complete a load_stats()
     without blocking forever even when writers are active (shared
     lock semantics work).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def _isolate(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "learning.log"))


# ---------------------------------------------------------------------------
# Test B1: Single-writer behaviour is unchanged.


def test_single_writer_still_works(tmp_path: Path, monkeypatch) -> None:
    _isolate(monkeypatch, tmp_path)
    from quill.learning import load_stats, post_decision_update

    for _ in range(20):
        post_decision_update("Bash:rm -rf", "deny")
    for _ in range(5):
        post_decision_update("Bash:rm -rf", "approve")

    stats = load_stats()
    assert "Bash:rm -rf" in stats
    p = stats["Bash:rm -rf"]
    assert p.fires == 25
    assert p.denies == 20
    assert p.approvals == 5


# ---------------------------------------------------------------------------
# Test B2: 8 concurrent processes, 50 records each = 400 total.
# This is the canonical read-modify-write race test. Without the
# flock fix, the test sees fires < 400 due to lost updates.


def _worker_record(stats_path: str, n: int, pattern_id: str, decision: str) -> None:
    """Subprocess entry: hammer post_decision_update n times."""
    import os as _os

    _os.environ["QUILL_PATTERN_STATS"] = stats_path
    _os.environ["QUILL_SUGGESTIONS"] = stats_path + ".sug"
    _os.environ["QUILL_LEARNING_LOG"] = stats_path + ".log"
    import importlib

    # Subprocess workers don't inherit pytest's import path; point at this
    # repo's src/ relative to the test file, never an absolute machine path.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    if "quill.learning" in sys.modules:
        importlib.reload(sys.modules["quill.learning"])
    from quill.learning import post_decision_update

    for _ in range(n):
        post_decision_update(pattern_id, decision)


def test_8_concurrent_writers_lose_no_updates(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Fork 8 child processes, each pounds 50 records into the SAME
    pattern. Without flock, lost updates make total < 400. With flock,
    fires == 400 exactly."""
    _isolate(monkeypatch, tmp_path)
    stats_path = str(tmp_path / "stats.json")
    pattern_id = "Bash:race-test"
    n_per = 50
    n_workers = 8

    pids: list[int] = []
    for _i in range(n_workers):
        pid = os.fork()
        if pid == 0:
            # Child.
            try:
                _worker_record(stats_path, n_per, pattern_id, "deny")
            finally:
                os._exit(0)
        pids.append(pid)

    # Wait for all children to finish.
    for pid in pids:
        os.waitpid(pid, 0)

    from quill.learning import load_stats

    stats = load_stats()
    assert pattern_id in stats, f"pattern missing; stats keys: {list(stats)}"
    p = stats[pattern_id]
    expected = n_workers * n_per
    assert p.fires == expected, (
        f"LOST UPDATES: expected {expected} fires from {n_workers}x{n_per} "
        f"concurrent writers, got {p.fires}. flock is missing or broken."
    )
    assert p.denies == expected


# ---------------------------------------------------------------------------
# Test B3: Mixed concurrency - approves + denies, each 100 records.


def test_mixed_concurrent_approves_and_denies_balance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    stats_path = str(tmp_path / "stats.json")
    pattern_id = "Bash:mixed-test"
    n_per = 100
    n_approve_workers = 4
    n_deny_workers = 4

    pids: list[int] = []
    for _ in range(n_approve_workers):
        pid = os.fork()
        if pid == 0:
            try:
                _worker_record(stats_path, n_per, pattern_id, "approve")
            finally:
                os._exit(0)
        pids.append(pid)
    for _ in range(n_deny_workers):
        pid = os.fork()
        if pid == 0:
            try:
                _worker_record(stats_path, n_per, pattern_id, "deny")
            finally:
                os._exit(0)
        pids.append(pid)

    for pid in pids:
        os.waitpid(pid, 0)

    from quill.learning import load_stats

    stats = load_stats()
    p = stats[pattern_id]
    expected_approves = n_approve_workers * n_per
    expected_denies = n_deny_workers * n_per
    expected_fires = expected_approves + expected_denies
    assert p.fires == expected_fires, f"expected {expected_fires} fires, got {p.fires}"
    assert p.approvals == expected_approves, (
        f"expected {expected_approves} approvals, got {p.approvals}"
    )
    assert p.denies == expected_denies, f"expected {expected_denies} denies, got {p.denies}"


# ---------------------------------------------------------------------------
# Test B4: Reader does not block on shared lock.


def test_reader_does_not_block_indefinitely(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A reader (load_stats with shared flock) completing while writers
    are active proves the lock semantics work. We just verify no
    deadlock: read after one writer finishes, before next starts."""
    _isolate(monkeypatch, tmp_path)
    from quill.learning import load_stats, post_decision_update

    # Seed: a few writes.
    for _ in range(5):
        post_decision_update("Bash:read-test", "deny")

    # Read should not block (no writer is currently in the lock).
    t0 = time.perf_counter()
    stats = load_stats()
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000
    assert elapsed_ms < 100, (
        f"load_stats() took {elapsed_ms:.1f}ms with no contention; flock contention or deadlock"
    )
    assert "Bash:read-test" in stats
    assert stats["Bash:read-test"].fires == 5

    # Interleave more writes + reads.
    for i in range(10):
        post_decision_update("Bash:read-test", "deny")
        s = load_stats()
        # Each read sees the cumulative state - no stale reads.
        assert s["Bash:read-test"].fires == 6 + i, (
            f"iteration {i}: expected fires={6 + i}, got {s['Bash:read-test'].fires}"
        )
