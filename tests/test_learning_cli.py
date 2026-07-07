"""Step 5 tests: `quill suggestions` CLI + `quill log` live tail.

Four invariants:

  1. `quill suggestions list` shows the pending learner-surfaced items
     newest-first, deduplicated by (type, pattern_id), with the
     `apply:` line only on loosening_candidate (auto-tightenings are
     already applied; surfacing the apply hint would be misleading).
  2. `quill suggestions promote <key>` writes a versioned override
     block to ~/.quill/overrides.toml WITH a TTL and a `promoted_at`
     timestamp; the operator's promotion is itself audited as a
     `loosening_promoted` suggestion.
  3. `quill suggestions dismiss <key>` appends a `dismissed` entry to
     suggestions.jsonl (append-only; the original is never edited),
     and follow-up `list` invocations no longer surface the dismissed
     key.
  4. `quill log` (non-follow mode) shows recent learning.log lines
     AND tails recent suggestions; with `--no-suggestions` it omits
     the suggestion stream; gracefully prints when no log exists.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _isolate(monkeypatch, tmp_path: Path) -> None:
    """Point every learning + override path at tmp_path."""
    cfg = tmp_path / "config.toml"
    cfg.write_text('[session]\nintent = "t"\nscope = []\n[trust]\npaths = []\n')
    monkeypatch.setenv("QUILL_CONFIG", str(cfg))
    monkeypatch.setenv("QUILL_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("QUILL_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("QUILL_LEARNING_LOG", str(tmp_path / "learning.log"))
    monkeypatch.setenv("QUILL_OVERRIDES", str(tmp_path / "overrides.toml"))
    monkeypatch.setenv("QUILL_APPROVALS_FILE", str(tmp_path / "approvals.json"))
    monkeypatch.setenv("QUILL_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("HOME", str(tmp_path))


def _seed_suggestions(tmp_path: Path, items: list[dict]) -> None:
    p = tmp_path / "suggestions.jsonl"
    with p.open("a") as f:
        for s in items:
            f.write(json.dumps(s) + "\n")


# ---------------------------------------------------------------------------
# Test 1: list shows newest-first, deduplicated.


def test_suggestions_list_shows_newest_first_and_dedups(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    # Same loosening_candidate fired three times across the week. The
    # `list` view must show it once (dedup by type+pattern_id) and
    # newest first.
    base_ts = time.time()
    _seed_suggestions(
        tmp_path,
        [
            {
                "type": "loosening_candidate",
                "pattern_id": "Bash:curl-sh",
                "evidence": "approval 70% n=20",
                "proposal": "Review for override; never auto-applied",
                "ts": base_ts - 86400 * 2,
            },
            {
                "type": "tightening_auto_applied",
                "pattern_id": "Bash:rm -rf",
                "evidence": "5 consecutive denies",
                "applied_change": "X",
                "ts": base_ts - 86400,
            },
            {
                "type": "loosening_candidate",
                "pattern_id": "Bash:curl-sh",
                "evidence": "approval 75% n=25",
                "proposal": "Review for override; never auto-applied",
                "ts": base_ts - 3600,
            },
            {
                "type": "loosening_candidate",
                "pattern_id": "Bash:curl-sh",
                "evidence": "approval 80% n=30",
                "proposal": "Review for override; never auto-applied",
                "ts": base_ts,
            },
        ],
    )

    from quill.cli import app

    result = runner.invoke(app, ["suggestions", "list"])
    assert result.exit_code == 0, result.stderr
    out = result.output
    # Only the NEWEST evidence appears (older 70%/75% suppressed).
    assert "approval 80% n=30" in out
    assert "approval 70% n=20" not in out
    assert "approval 75% n=25" not in out
    # The unrelated tightening still shows.
    assert "tightening_auto_applied" in out
    assert "Bash:rm -rf" in out
    # apply hint shows on loosening_candidate (which is the only
    # surface that operator must promote).
    assert "quill suggestions promote" in out


# ---------------------------------------------------------------------------
# Test 2: promote writes a TTL'd override block + audits the promotion.


def test_suggestions_promote_writes_override_block_with_ttl(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    base_ts = time.time()
    _seed_suggestions(
        tmp_path,
        [
            {
                "type": "loosening_candidate",
                "pattern_id": "Bash:curl-sh",
                "evidence": "approval 75% (Wilson 95% lower 0.65, n=22)",
                "proposal": "Review; promote with quill suggestions promote",
                "ts": base_ts,
            },
        ],
    )

    from quill.cli import app

    # Promote with explicit TTL.
    result = runner.invoke(
        app,
        ["suggestions", "promote", "loosening_candidate:Bash:curl-sh", "--ttl-days", "14"],
    )
    assert result.exit_code == 0, (result.output, result.stderr)

    overrides_path = tmp_path / "overrides.toml"
    assert overrides_path.exists(), "promote must write overrides.toml"
    body = overrides_path.read_text()
    assert 'pattern_id = "Bash:curl-sh"' in body
    assert "ttl_days = 14" in body
    assert "promoted_at" in body
    assert "evidence" in body

    # File mode is 0o600 (security: overrides are sensitive).
    mode = overrides_path.stat().st_mode & 0o777
    assert mode & 0o077 == 0, f"overrides.toml too permissive: {oct(mode)}"

    # The promotion itself was audited as a loosening_promoted entry.
    sug = (tmp_path / "suggestions.jsonl").read_text().splitlines()
    parsed = [json.loads(line) for line in sug]
    promoted = [s for s in parsed if s.get("type") == "loosening_promoted"]
    assert promoted, "promotion must be audited in suggestions.jsonl"
    assert promoted[-1]["pattern_id"] == "Bash:curl-sh"
    assert promoted[-1]["ttl_days"] == 14


# ---------------------------------------------------------------------------
# Test 3: dismiss appends an audit entry and hides the suggestion.


def test_suggestions_dismiss_is_append_only_and_hides_the_suggestion(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    base_ts = time.time()
    _seed_suggestions(
        tmp_path,
        [
            {
                "type": "loosening_candidate",
                "pattern_id": "Bash:noisy",
                "evidence": "approval 90% n=50",
                "proposal": "Review",
                "ts": base_ts,
            },
        ],
    )
    sug_path = tmp_path / "suggestions.jsonl"
    original = sug_path.read_text()

    from quill.cli import app

    key = "loosening_candidate:Bash:noisy"
    result = runner.invoke(app, ["suggestions", "dismiss", key])
    assert result.exit_code == 0

    # Original entries untouched (append-only invariant).
    new_body = sug_path.read_text()
    assert new_body.startswith(original), (
        "dismiss must NOT rewrite suggestions.jsonl in place; it must append a `dismissed` row"
    )
    # New tail entry is a dismissal audit.
    extra_lines = new_body[len(original) :].splitlines()
    extra = [json.loads(line) for line in extra_lines if line.strip()]
    assert any(e.get("type") == "dismissed" and e.get("dismissed_key") == key for e in extra), (
        f"extra entries: {extra}"
    )


# ---------------------------------------------------------------------------
# Test 4: log shows recent learning + suggestions; --no-suggestions
# omits suggestion stream; empty state prints a friendly message.


def test_log_streams_recent_activity_and_handles_empty_state(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    from quill.cli import app

    # Empty state: friendly message, exit 0.
    result = runner.invoke(app, ["log"])
    assert result.exit_code == 0
    assert "no learner activity yet" in result.output.lower()

    # Seed: 3 log lines + 2 suggestions.
    log_path = tmp_path / "learning.log"
    log_path.write_text(
        "2026-05-12T00:00:00Z update pattern=Bash:rm -rf decision=deny fires=1\n"
        "2026-05-12T00:00:01Z update pattern=Bash:rm -rf decision=deny fires=2\n"
        "2026-05-12T00:00:02Z update pattern=Bash:rm -rf decision=deny fires=3\n"
    )
    sug_path = tmp_path / "suggestions.jsonl"
    sug_path.write_text(
        '{"type":"tightening_auto_applied","pattern_id":"Bash:rm -rf",'
        '"evidence":"3 consecutive denies","ts":0}\n'
        '{"type":"loosening_candidate","pattern_id":"Bash:foo",'
        '"evidence":"approval 80%","ts":1}\n'
    )

    result = runner.invoke(app, ["log", "-n", "10"])
    assert result.exit_code == 0
    out = result.output
    # Log lines shown.
    assert "Bash:rm -rf decision=deny fires=1" in out
    assert "Bash:rm -rf decision=deny fires=3" in out
    # Suggestions also rendered.
    assert "tightening_auto_applied" in out
    assert "loosening_candidate" in out
    assert "Bash:foo" in out

    # --no-suggestions hides the suggestion stream.
    result = runner.invoke(app, ["log", "-n", "10", "--no-suggestions"])
    assert result.exit_code == 0
    assert "Bash:rm -rf decision=deny fires=3" in result.output
    # The suggestion lines have "(suggestion)" prefix which should be gone.
    assert "(suggestion)" not in result.output
