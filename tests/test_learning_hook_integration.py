"""Step 2 tests: hook integration + auto-tighten + loosen-candidate.

The contract under test:

  - post_decision_update is called from run_hook AFTER the gate has
    emitted its verdict, NEVER from the hot path.
  - The hook still produces valid Claude Code JSON regardless of
    learning success or failure (graceful-degradation invariant).
  - Repeated denies of the same pattern auto-tighten and append a
    suggestion of type "tightening_auto_applied".
  - High approval rates surface a "loosening_candidate" suggestion
    but the override never actually applies (no overrides.toml write).

Four detailed tests pin these one at a time. Each uses an isolated
NOTA_HOME via monkeypatch so the operator's real pattern_stats are
never touched.
"""

from __future__ import annotations

import json
from pathlib import Path


def _payload(
    *,
    tool_name: str,
    session_id: str = "ses-learning",
    transcript: str = "/tmp/t.jsonl",
    cwd: str = "/tmp",
    **tool_input,
) -> str:
    return json.dumps(
        {
            "session_id": session_id,
            "transcript_path": transcript,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
    )


def _isolate(monkeypatch, tmp_path: Path) -> None:
    """Point every learning-related path at tmp_path so the test never
    touches the operator's real ~/.nota state."""
    # Write a minimal config so the operator's real bash allowlist /
    # trust scopes / policy overrides don't leak in.
    cfg = tmp_path / "config.toml"
    cfg.write_text('[session]\nintent = "test"\nscope = []\n[trust]\npaths = []\n')
    monkeypatch.setenv("NOTA_CONFIG", str(cfg))
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(tmp_path / "stats.json"))
    monkeypatch.setenv("NOTA_SUGGESTIONS", str(tmp_path / "suggestions.jsonl"))
    monkeypatch.setenv("NOTA_LEARNING_LOG", str(tmp_path / "learning.log"))
    monkeypatch.setenv("NOTA_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("NOTA_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("NOTA_KEY", str(tmp_path / "key"))
    # Approvals store: isolate from operator's real store so tests
    # don't read or write tokens to the live approvals.json.
    monkeypatch.setenv("NOTA_APPROVALS_FILE", str(tmp_path / "approvals.json"))
    monkeypatch.setenv("NOTA_NO_AUTO_WATCH", "1")
    # Force-off bypass-mode detection so test isolation matches the
    # gating semantics under test (the operator's real settings.json
    # might have skipDangerousModePermissionPrompt=true; that's not
    # what the integration tests are exercising).
    monkeypatch.setenv("NOTA_BYPASS_MODE", "0")
    # Surface any learning-pipeline error instead of swallowing it,
    # so test failures are debuggable instead of silently undercounting.
    monkeypatch.setenv("NOTA_LEARNING_STRICT", "1")


# ---------------------------------------------------------------------------
# Test 1: The hook still produces valid Claude Code JSON, with the
# required hookEventName field, regardless of learning success/failure.


def test_hook_response_shape_unchanged_by_learning_integration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    # Three different hook flows: allow, ask, deny. All must produce
    # valid JSON with hookEventName == "PreToolUse".
    # Use commands that don't match the operator's real bash allowlist
    # (config is isolated via NOTA_CONFIG in _isolate, but stay safe).
    cases = [
        # tool_name, tool_input, expected_permission
        ("Bash", {"command": "ls"}, "allow"),
        ("Edit", {"file_path": "/x.py", "old_string": "a", "new_string": "b"}, "ask"),
        ("Bash", {"command": "DROP TABLE users"}, "deny"),
    ]

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        for tool, inp, expected in cases:
            out = run_hook(
                _payload(tool_name=tool, transcript=str(transcript), cwd=str(tmp_path), **inp),
                audit=audit,
            )
            assert "hookSpecificOutput" in out
            hso = out["hookSpecificOutput"]
            assert hso.get("hookEventName") == "PreToolUse"
            assert hso.get("permissionDecision") == expected, (
                f"{tool}: expected {expected}, got {hso.get('permissionDecision')}"
            )


# ---------------------------------------------------------------------------
# Test 2: A learning failure cannot break the hook.


def test_learning_exception_does_not_break_the_hook(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    # Force the learning module to fail by pointing its stats path at
    # something that can't be written (a directory that already exists
    # where the file should be).
    bad_dir = tmp_path / "blockage"
    bad_dir.mkdir()
    monkeypatch.setenv("NOTA_PATTERN_STATS", str(bad_dir))  # path is a dir
    # Disable strict mode for THIS test specifically; we want the
    # production failure path (swallow + log, never raise) under test.
    monkeypatch.delenv("NOTA_LEARNING_STRICT", raising=False)

    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Bash",
                transcript=str(transcript),
                cwd=str(tmp_path),
                command="DROP TABLE users",
            ),
            audit=audit,
        )

    # Despite the learning sub-system being broken, the gate verdict
    # rendered correctly and the response JSON is well-formed.
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---------------------------------------------------------------------------
# Test 3: Repeated denies of the same pattern auto-tighten.


def test_repeated_denies_emit_tightening_suggestion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    from nota.adapters.claude_code import run_hook
    from nota.audit import AuditLog
    from nota.learning import TIGHTEN_DENY_STREAK, load_stats

    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    # Fire TIGHTEN_DENY_STREAK identical block-class events. Each
    # records a "deny" against the same pattern_id, so consecutive_denies
    # reaches the threshold and the tightening suggestion fires.
    # Use `DROP TABLE` instead of `rm -rf /tmp/...` because the operator's
    # real config might allowlist /tmp paths (the isolated test config
    # turns this off but defence-in-depth).
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        for _ in range(TIGHTEN_DENY_STREAK):
            run_hook(
                _payload(
                    tool_name="Bash",
                    transcript=str(transcript),
                    cwd=str(tmp_path),
                    command="DROP TABLE users",
                ),
                audit=audit,
            )

    # The learner accumulated state for the pattern. Each iteration
    # records under the SAME pattern_id (we snapshot the original
    # classifier reason before any token-consume flips it). The
    # isolated store carries no approval tokens, so every iteration is
    # a clean deny: fires, denies, and the consecutive-deny streak all
    # land at exactly TIGHTEN_DENY_STREAK.
    stats = load_stats()
    bash_keys = [k for k in stats if k.startswith("Bash:")]
    assert bash_keys, f"expected a Bash:... pattern in stats, got {list(stats)}"
    p = stats[bash_keys[0]]
    assert p.fires == TIGHTEN_DENY_STREAK, (
        f"expected {TIGHTEN_DENY_STREAK} fires recorded under the same "
        f"pattern_id, got {p.fires} (token-consumes should NOT split "
        f"into a separate pattern row)"
    )
    assert p.denies == TIGHTEN_DENY_STREAK
    assert p.consecutive_denies == TIGHTEN_DENY_STREAK

    # Boundary assertion (the point of this test): EXACTLY
    # TIGHTEN_DENY_STREAK consecutive denies must fire the auto-tighten
    # suggestion. detect_tightening triggers on
    # `consecutive_denies >= TIGHTEN_DENY_STREAK`, so the suggestion is
    # emitted on the final iteration when the streak first hits the
    # threshold. An off-by-one at that boundary (`>` instead of `>=`)
    # would need one MORE deny, leaving suggestions.jsonl without a
    # tightening row and failing this assertion.
    sug_file = tmp_path / "suggestions.jsonl"
    assert sug_file.exists(), (
        "a suggestion must have been written once the deny streak "
        f"reached exactly {TIGHTEN_DENY_STREAK}"
    )
    suggestions = [json.loads(line) for line in sug_file.read_text().splitlines()]
    tightening = [s for s in suggestions if s.get("type") == "tightening_auto_applied"]
    assert tightening, (
        f"expected a tightening_auto_applied suggestion after exactly "
        f"{TIGHTEN_DENY_STREAK} consecutive denies, got types "
        f"{[s.get('type') for s in suggestions]}"
    )
    # The suggestion cites the deny streak that triggered it, at the
    # exact boundary count (not one fewer, not one more).
    assert f"{TIGHTEN_DENY_STREAK} consecutive denies" in tightening[0]["evidence"]


# ---------------------------------------------------------------------------
# Test 4: A high-approval pattern surfaces a loosen-candidate but never
# auto-applies to overrides.toml.


def test_loosen_candidate_surfaces_but_never_auto_applies(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _isolate(monkeypatch, tmp_path)
    overrides_path = tmp_path / "overrides.toml"
    monkeypatch.setenv("NOTA_OVERRIDES", str(overrides_path))

    # Drive the learner directly: 30 approvals (operator bypasses) for
    # one pattern, then verify a loosening_candidate is suggested but
    # overrides.toml is NOT created.
    from nota.learning import LOOSEN_MIN_FIRES, post_decision_update

    pattern_id = "Bash:some-noisy-pattern"
    for _ in range(LOOSEN_MIN_FIRES + 10):
        post_decision_update(pattern_id, "approve")

    sug_file = tmp_path / "suggestions.jsonl"
    assert sug_file.exists(), "suggestions.jsonl should exist after enough fires"
    suggestions = [json.loads(line) for line in sug_file.read_text().splitlines()]
    loosen = [s for s in suggestions if s.get("type") == "loosening_candidate"]
    assert loosen, (
        f"expected loosening_candidate after {LOOSEN_MIN_FIRES + 10} approvals, "
        f"got types {[s.get('type') for s in suggestions]}"
    )
    # Suggestion carries an expiry, the pattern_id, and a proposal that
    # tells the operator HOW to apply (never auto-applies).
    s = loosen[0]
    assert s["pattern_id"] == pattern_id
    assert "expires_ts" in s
    assert "promote" in s["proposal"].lower() or "review" in s["proposal"].lower()
    assert "never auto-applied" in s["proposal"].lower() or "auto-applied" in s["proposal"].lower()

    # CRITICAL invariant: no overrides.toml was created. The learner
    # MUST never silently widen the attack surface.
    assert not overrides_path.exists(), (
        "loosen-candidate must NOT auto-write overrides.toml; operator promotion is required"
    )

    # And the learning.log records the suggestion event.
    log_file = tmp_path / "learning.log"
    assert log_file.exists()
    log_text = log_file.read_text()
    assert "suggestion[loosening_candidate]" in log_text
