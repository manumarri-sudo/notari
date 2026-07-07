"""Step D tests: stale token-suffixed pattern cleanup.

Pre-rc5 bug: when an approve-token was consumed the pattern_id was
derived from the FLIPPED reason ("approved one-shot via quill approve
<token-prefix>") instead of the ORIGINAL deny reason. That produced
one dead pattern_stats row per token consumed. The bug is fixed in
rc5 but the historical rows don't migrate themselves.

Four invariants under test:

  1. find_stale_patterns identifies the per-token rows by their
     distinctive "approved one-shot via quill approve" infix and
     ignores everything else.
  2. cleanup_stale_patterns removes the stale rows AND leaves the
     real patterns intact (no collateral damage).
  3. Idempotent: a second cleanup invocation after a first removes
     nothing further.
  4. The `quill suggestions cleanup --dry-run` CLI surface reports
     what WOULD be removed without writing; the real `cleanup`
     subcommand writes and surfaces what changed.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner


def _isolate(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "learning.log"))


def _seed_stats(tmp_path: Path, patterns: dict[str, dict]) -> None:
    """Write a pattern_stats.json directly without going through
    post_decision_update so we can simulate the historical bug state."""
    p = tmp_path / "stats.json"
    p.write_text(json.dumps(patterns, indent=2))


# ---------------------------------------------------------------------------
# Test D1: identify stale rows without false-positives.


def test_find_stale_patterns_identifies_token_rows_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    # Mix of stale (token-suffixed) and real patterns.
    _seed_stats(
        tmp_path,
        {
            "Bash:rm -rf": {
                "pattern_id": "Bash:rm -rf",
                "fires": 50,
                "approvals": 5,
                "denies": 45,
                "consecutive_denies": 5,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:approved one-shot via quill approve aBcDeFg1": {
                "pattern_id": "Bash:approved one-shot via quill approve aBcDeFg1",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:approved one-shot via quill approve xyZ12345": {
                "pattern_id": "Bash:approved one-shot via quill approve xyZ12345",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Edit:high risk: default risk for Edit": {
                "pattern_id": "Edit:high risk: default risk for Edit",
                "fires": 100,
                "approvals": 0,
                "denies": 100,
                "consecutive_denies": 100,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.0,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            # An edge case: a pattern with "approved one-shot" as a substring
            # of its CONTENT (e.g. someone literally writing a commit message
            # about it). This is NOT a stale token row - the marker has to
            # be specifically "approved one-shot via quill approve <token>"
            # to qualify.
            "Bash:git commit -m 'we use approved one-shot tokens here'": {
                "pattern_id": "Bash:git commit",
                "fires": 1,
                "approvals": 0,
                "denies": 1,
                "consecutive_denies": 1,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.0,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
        },
    )

    from quill.learning import find_stale_patterns

    stale = find_stale_patterns()
    assert sorted(stale) == sorted(
        [
            "Bash:approved one-shot via quill approve aBcDeFg1",
            "Bash:approved one-shot via quill approve xyZ12345",
        ]
    ), f"unexpected stale set: {stale}"


# ---------------------------------------------------------------------------
# Test D2: cleanup removes stale, leaves real patterns intact.


def test_cleanup_removes_stale_and_preserves_real(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    _seed_stats(
        tmp_path,
        {
            "Bash:rm -rf": {
                "pattern_id": "Bash:rm -rf",
                "fires": 50,
                "approvals": 5,
                "denies": 45,
                "consecutive_denies": 5,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:approved one-shot via quill approve aBcDeFg1": {
                "pattern_id": "Bash:approved one-shot via quill approve aBcDeFg1",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Edit:high risk: default risk for Edit": {
                "pattern_id": "Edit:high risk: default risk for Edit",
                "fires": 100,
                "approvals": 0,
                "denies": 100,
                "consecutive_denies": 100,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.0,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
        },
    )

    from quill.learning import cleanup_stale_patterns, load_stats

    n, removed = cleanup_stale_patterns()
    assert n == 1
    assert removed == ["Bash:approved one-shot via quill approve aBcDeFg1"]

    after = load_stats()
    # Real patterns intact with their original counts.
    assert "Bash:rm -rf" in after
    assert after["Bash:rm -rf"].fires == 50
    assert after["Bash:rm -rf"].denies == 45
    assert "Edit:high risk: default risk for Edit" in after
    assert after["Edit:high risk: default risk for Edit"].fires == 100
    # Stale pattern is gone.
    assert "Bash:approved one-shot via quill approve aBcDeFg1" not in after


# ---------------------------------------------------------------------------
# Test D3: Idempotent - second cleanup is a no-op.


def test_cleanup_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    _isolate(monkeypatch, tmp_path)
    _seed_stats(
        tmp_path,
        {
            "Bash:approved one-shot via quill approve A": {
                "pattern_id": "Bash:approved one-shot via quill approve A",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:approved one-shot via quill approve B": {
                "pattern_id": "Bash:approved one-shot via quill approve B",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:rm -rf": {
                "pattern_id": "Bash:rm -rf",
                "fires": 50,
                "approvals": 5,
                "denies": 45,
                "consecutive_denies": 5,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
        },
    )

    from quill.learning import cleanup_stale_patterns, load_stats

    n1, _ = cleanup_stale_patterns()
    assert n1 == 2
    state_after_first = load_stats()

    # Second call: no-op.
    n2, removed = cleanup_stale_patterns()
    assert n2 == 0
    assert removed == []

    # File state identical between the two reads.
    state_after_second = load_stats()
    assert set(state_after_first) == set(state_after_second)
    for k in state_after_first:
        a = state_after_first[k]
        b = state_after_second[k]
        assert a.fires == b.fires
        assert a.approvals == b.approvals
        assert a.denies == b.denies


# ---------------------------------------------------------------------------
# Test D4: CLI surface - dry-run + real run, semantics match.


def test_cli_cleanup_dry_run_then_real_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    _seed_stats(
        tmp_path,
        {
            "Bash:approved one-shot via quill approve Q": {
                "pattern_id": "Bash:approved one-shot via quill approve Q",
                "fires": 1,
                "approvals": 1,
                "denies": 0,
                "consecutive_denies": 0,
                "consecutive_approvals": 1,
                "ewma_approval_rate": 0.1,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
            "Bash:rm -rf": {
                "pattern_id": "Bash:rm -rf",
                "fires": 5,
                "approvals": 0,
                "denies": 5,
                "consecutive_denies": 5,
                "consecutive_approvals": 0,
                "ewma_approval_rate": 0.0,
                "inter_arrival_sec": [],
                "last_fire_ts": 0,
                "first_fire_ts": 0,
            },
        },
    )

    runner = CliRunner()
    from quill.cli import app

    # Dry-run shows the candidate but does NOT write.
    r1 = runner.invoke(app, ["suggestions", "cleanup", "--dry-run"])
    assert r1.exit_code == 0
    assert "would remove" in r1.output
    assert "approved one-shot via quill approve Q" in r1.output

    # File state unchanged after dry-run.
    from quill.learning import load_stats

    s_after_dry = load_stats()
    assert "Bash:approved one-shot via quill approve Q" in s_after_dry
    assert "Bash:rm -rf" in s_after_dry

    # Real run removes the stale row.
    r2 = runner.invoke(app, ["suggestions", "cleanup"])
    assert r2.exit_code == 0
    assert "removed" in r2.output.lower()
    s_after_real = load_stats()
    assert "Bash:approved one-shot via quill approve Q" not in s_after_real
    assert "Bash:rm -rf" in s_after_real
    assert s_after_real["Bash:rm -rf"].fires == 5

    # Re-run: nothing to do.
    r3 = runner.invoke(app, ["suggestions", "cleanup"])
    assert r3.exit_code == 0
    assert "nothing" in r3.output.lower() or "no stale" in r3.output.lower()
