"""Tests for the Claude Code PreToolUse hook adapter.

Covers: stdin → stdout contract, decision matrix per built-in tool, audit
log writes for every gate decision, install_into_settings idempotency.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quill.adapters.claude_code import (
    classify_event,
    decide,
    install_into_settings,
    install_snippet,
    run_hook,
)
from quill.audit import AuditLog
from quill.policy import Risk

# ---- decision matrix -----------------------------------------------------


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected_permission", "expected_risk"),
    [
        # Bash uses content-aware classification
        ("Bash", {"command": "ls -la"}, "allow", Risk.LOW),
        ("Bash", {"command": "git status"}, "allow", Risk.LOW),
        ("Bash", {"command": "git push"}, "ask", Risk.HIGH),
        ("Bash", {"command": "git push --force"}, "deny", Risk.CRITICAL),
        ("Bash", {"command": "rm -rf node_modules"}, "deny", Risk.CRITICAL),
        ("Bash", {"command": "npm publish"}, "deny", Risk.CRITICAL),
        ("Bash", {"command": "vercel --prod"}, "deny", Risk.CRITICAL),
        ("Bash", {"command": "DROP TABLE users"}, "deny", Risk.CRITICAL),
        # File mutation tools default to HIGH (= "ask")
        ("Edit", {"file_path": "/x", "old_string": "a", "new_string": "b"}, "ask", Risk.HIGH),
        ("Write", {"file_path": "/x", "content": "..."}, "ask", Risk.HIGH),
        ("NotebookEdit", {"notebook_path": "/x"}, "ask", Risk.HIGH),
        # Read-only built-ins
        ("Read", {"file_path": "/x"}, "allow", Risk.LOW),
        ("Glob", {"pattern": "**/*.py"}, "allow", Risk.LOW),
        ("Grep", {"pattern": "TODO"}, "allow", Risk.LOW),
        ("WebSearch", {"query": "claude code"}, "allow", Risk.LOW),
        ("TodoWrite", {"todos": []}, "allow", Risk.LOW),
        # Network reads default to MEDIUM (still allowed silently)
        ("WebFetch", {"url": "https://example.com"}, "allow", Risk.MEDIUM),
        # Sub-agent spawning is logged but not blocked
        ("Task", {"description": "sub", "prompt": "..."}, "allow", Risk.MEDIUM),
    ],
)
def test_decision_matrix(
    tool_name: str,
    tool_input: dict[str, object],
    expected_permission: str,
    expected_risk: Risk,
) -> None:
    d = decide(tool_name, tool_input)
    assert d.permission == expected_permission, (
        f"{tool_name}({tool_input}): got {d.permission}/{d.risk.value} "
        f"({d.reason}); expected {expected_permission}/{expected_risk.value}"
    )
    assert d.risk is expected_risk


# ---- end-to-end hook contract --------------------------------------------


def _stdin_for(tool_name: str, **input_fields: object) -> str:
    return json.dumps(
        {
            "session_id": "abc",
            "transcript_path": "/tmp/x.jsonl",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": dict(input_fields),
        }
    )


def test_run_hook_returns_well_formed_response_for_critical(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(_stdin_for("Bash", command="rm -rf /"), audit=audit)

    assert "hookSpecificOutput" in out
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert (
        "rm -rf" in hso["permissionDecisionReason"].lower()
        or "blocked" in hso["permissionDecisionReason"].lower()
    )


def test_run_hook_allows_low_risk(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(_stdin_for("Bash", command="ls -la"), audit=audit)
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_response_includes_hook_event_name(tmp_path: Path) -> None:
    """Regression: Claude Code rejects PreToolUse responses missing
    `hookEventName` with `hook json output validation failed`. The field
    is REQUIRED on every response shape, including the fail-open paths."""
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(_stdin_for("Bash", command="ls"), audit=audit)
    assert out["hookSpecificOutput"].get("hookEventName") == "PreToolUse"


def test_run_hook_malformed_input_still_includes_hook_event_name(tmp_path: Path) -> None:
    """The malformed-input fail-closed path must still include hookEventName.

    Without hookEventName, every malformed-stdin payload trips Claude Code's
    validator with a less actionable error. SECURITY: this used to fail-open;
    it now fails-CLOSED (deny) so an agent that can crash the parser can't
    extract a free pass.
    """
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook("this is not json", audit=audit)
    assert out["hookSpecificOutput"].get("hookEventName") == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_run_hook_asks_on_high_risk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force bypass-mode off; this test pins the DEFAULT-classifier
    # behaviour, not the bypass-mode downshift (which is exercised in
    # its own test below).
    monkeypatch.setenv("QUILL_BYPASS_MODE", "0")
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _stdin_for("Edit", file_path="/x", old_string="a", new_string="b"),
            audit=audit,
        )
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_run_hook_writes_audit_entries(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(_stdin_for("Bash", command="git push --force"), audit=audit)

    lines = [json.loads(line) for line in log.read_text().splitlines()]
    types = [e["type"] for e in lines]
    assert "tool.attempted" in types
    assert "verdict.blocked" in types
    # The verdict line must carry the plain-English reason
    blocked = next(e for e in lines if e["type"] == "verdict.blocked")
    assert "force" in blocked["payload"]["reason"].lower()


def test_run_hook_redacts_long_string_args(tmp_path: Path) -> None:
    """Args > 200 chars must be truncated in the audit log so secrets in
    a tool argument don't end up persisted in full."""
    long = "X" * 5000
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(_stdin_for("Write", file_path="/x", content=long), audit=audit)

    lines = [json.loads(line) for line in log.read_text().splitlines()]
    attempted = next(e for e in lines if e["type"] == "tool.attempted")
    preview = attempted["payload"]["args_preview"]["content"]
    assert len(preview) < 5000
    assert "truncated" in preview


def test_run_hook_fails_closed_on_malformed_input() -> None:
    """A garbled hook payload must DENY, not allow.

    SECURITY: this previously fail-OPENED on malformed input, which was a
    self-service bypass: a prompt-injected agent that could make the hook
    see broken JSON would get an unconditional allow. Now matches the
    classifier self-test's posture (fail-closed); the recovery hatch is
    the bounded, audited `quill off`.
    """
    out = run_hook("not json at all", audit=None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "malformed" in out["hookSpecificOutput"]["permissionDecisionReason"].lower()
    assert "fail-closed" in out["hookSpecificOutput"]["permissionDecisionReason"].lower()


# ---- classification helper -----------------------------------------------


def test_classify_event_for_unknown_tool_falls_back_to_namespace_classifier() -> None:
    risk, reason, suggestion = classify_event("postgres.drop_table", {"table": "users"})
    assert risk is Risk.CRITICAL
    assert "postgres.drop_table" in reason or "namespace" in reason
    # Namespace-classifier path doesn't carry a suggestion (only classify_command
    # does, since it knows the command-specific safer alternative).
    assert isinstance(suggestion, str)


def test_classify_event_returns_suggestion_for_dangerous_bash() -> None:
    """The whole point of suggestions: a paste-able safer alternative goes
    out with every CRITICAL/HIGH bash decision."""
    risk, reason, suggestion = classify_event(
        "Bash",
        {"command": "git push --force origin main"},
    )
    assert risk is Risk.CRITICAL
    assert suggestion, "git push --force should carry a suggestion"
    # Specifically, the canonical fix is --force-with-lease.
    assert "force-with-lease" in suggestion or "rebase" in suggestion


# ---- install helper ------------------------------------------------------


def test_install_writes_settings_when_absent(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    written, already = install_into_settings(p)
    assert written == p
    assert already is False
    parsed = json.loads(p.read_text())
    pre = parsed["hooks"]["PreToolUse"]
    assert any(b.get("matcher") == "Bash|Edit|Write|NotebookEdit" for b in pre)


def test_install_is_idempotent(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    install_into_settings(p)
    install_into_settings(p)
    install_into_settings(p)
    parsed = json.loads(p.read_text())
    blocks = parsed["hooks"]["PreToolUse"]
    quill_blocks = [
        b
        for b in blocks
        if any(h.get("command") == "quill claude-hook" for h in (b.get("hooks") or []))
    ]
    assert len(quill_blocks) == 1


def test_install_preserves_existing_unrelated_hooks(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "MyOtherThing",
                            "hooks": [
                                {"type": "command", "command": "/path/to/somethingelse"},
                            ],
                        },
                    ],
                },
                "theme": "dark",
            }
        )
    )
    install_into_settings(p)
    parsed = json.loads(p.read_text())
    matchers = [b["matcher"] for b in parsed["hooks"]["PreToolUse"]]
    assert "MyOtherThing" in matchers
    assert any("Bash" in m for m in matchers)
    assert parsed["theme"] == "dark"


def test_install_snippet_shape() -> None:
    s = install_snippet()
    pre = s["hooks"]["PreToolUse"][0]
    assert pre["matcher"] == "Bash|Edit|Write|NotebookEdit"
    assert pre["hooks"][0]["command"] == "quill claude-hook"
    assert pre["hooks"][0]["timeout"] == 10


# ---- multi-project + sub-agent tracking ---------------------------------


def _payload(
    *,
    tool_name: str,
    session_id: str,
    transcript: str,
    cwd: str,
    **input_fields: object,
) -> str:
    return json.dumps(
        {
            "session_id": session_id,
            "transcript_path": transcript,
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": dict(input_fields),
        }
    )


def test_root_session_writes_no_parent_session_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-root",
                transcript=str(tmp_path / "t.jsonl"),
                cwd=str(tmp_path / "myproject"),
                command="ls",
            ),
            audit=audit,
        )
    lines = [json.loads(l) for l in log.read_text().splitlines()]
    attempt = next(e for e in lines if e["type"] == "tool.attempted")
    assert attempt["payload"]["parent_session_id"] == ""
    assert attempt["payload"]["cwd"] == str(tmp_path / "myproject")
    assert attempt["agent_id"] == "claude-code"


def test_subagent_spawn_emits_handoff_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a SECOND session_id appears under the same transcript, that's
    a Task-spawned sub-agent. The parent's hook emits agent.handoff.out and
    every subsequent sub-agent event is tagged with parent_session_id."""
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    log = tmp_path / "audit.jsonl"
    transcript = str(tmp_path / "t.jsonl")
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-root",
                transcript=transcript,
                cwd="/x",
                command="ls",
            ),
            audit=audit,
        )
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-sub",
                transcript=transcript,
                cwd="/x",
                command="git status",
            ),
            audit=audit,
        )

    lines = [json.loads(l) for l in log.read_text().splitlines()]
    types = [e["type"] for e in lines]
    assert "agent.handoff.out" in types

    handoff = next(e for e in lines if e["type"] == "agent.handoff.out")
    assert handoff["payload"]["to_agent_id"] == "ses-sub"
    assert "payload_hash" in handoff["payload"]

    sub_attempts = [
        e for e in lines if e["type"] == "tool.attempted" and e["session_id"] == "ses-sub"
    ]
    assert sub_attempts
    assert sub_attempts[0]["payload"]["parent_session_id"] == "ses-root"
    assert sub_attempts[0]["agent_id"] == "claude-code-sub"


def test_trust_scope_downshifts_default_edit_to_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A default-HIGH-risk Edit inside a [trust] paths directory must
    downshift to LOW + auto-allow. This is the fix for approval
    fatigue: 991 noisy Edit/Write asks per week was 92% of the volume.
    """
    trusted = tmp_path / "trusted_repo"
    trusted.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(f'[session]\nintent = "test"\nscope = []\n\n[trust]\npaths = ["{trusted}"]\n')
    monkeypatch.setenv("QUILL_CONFIG", str(config))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s-edit",
                transcript=str(transcript),
                cwd=str(trusted),
                file_path="/x.py",
                old_string="a",
                new_string="b",
            ),
            audit=audit,
        )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "trusted scope" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_trust_scope_does_not_downshift_outside_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Edit outside any trusted path must still gate as ask.

    Note: this test pins the TRUST-SCOPE behaviour specifically, so we
    force bypass-mode off. If bypass mode is on (the operator opted out
    of Claude Code's permission prompts globally), a different
    downshift fires that's tested separately.
    """
    trusted = tmp_path / "trusted_repo"
    trusted.mkdir()
    untrusted = tmp_path / "untrusted_repo"
    untrusted.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(f'[session]\nintent = "test"\nscope = []\n\n[trust]\npaths = ["{trusted}"]\n')
    monkeypatch.setenv("QUILL_CONFIG", str(config))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    monkeypatch.setenv("QUILL_BYPASS_MODE", "0")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Edit",
                session_id="s-outside",
                transcript=str(transcript),
                cwd=str(untrusted),
                file_path="/x.py",
                old_string="a",
                new_string="b",
            ),
            audit=audit,
        )
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_trust_scope_does_not_downshift_critical_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL events MUST still deny even inside a trusted dir.
    Trust scope only downshifts the DEFAULT high-risk classification
    for Edit/Write/MultiEdit/NotebookEdit. Pattern-matched commands
    (vercel --prod, git push --force, etc.) and CRITICAL events fire
    regardless of trust. This is the safety invariant.
    """
    trusted = tmp_path / "trusted_repo"
    trusted.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(f'[session]\nintent = "test"\nscope = []\n\n[trust]\npaths = ["{trusted}"]\n')
    monkeypatch.setenv("QUILL_CONFIG", str(config))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Bash",
                session_id="s-vercel",
                transcript=str(transcript),
                cwd=str(trusted),
                command="vercel deploy --prod --yes",
            ),
            audit=audit,
        )
    # vercel --prod is classified critical/high by pattern; the trust
    # scope must NOT auto-allow it.
    assert out["hookSpecificOutput"]["permissionDecision"] != "allow"


def test_trust_scope_matches_subdirectories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`~/repo` should cover `~/repo/src/app/page.tsx` too."""
    trusted = tmp_path / "trusted_repo"
    (trusted / "src" / "app").mkdir(parents=True)
    config = tmp_path / "config.toml"
    config.write_text(f'[session]\nintent = "test"\nscope = []\n\n[trust]\npaths = ["{trusted}"]\n')
    monkeypatch.setenv("QUILL_CONFIG", str(config))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(
            _payload(
                tool_name="Write",
                session_id="s-sub",
                transcript=str(transcript),
                cwd=str(trusted / "src" / "app"),
                file_path="/y.py",
                content="hi",
            ),
            audit=audit,
        )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "trusted scope" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_session_end_emits_session_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SessionEnd hook must emit a `session.close` audit event so that
    `quill receipts` can derive `closed_at` and `duration_seconds` for
    finished sessions. Without it every receipt reports `closed_at: ""`.
    """
    monkeypatch.setenv("QUILL_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("QUILL_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")

    # Run a session: parent + sub-agent + a couple of calls.
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-A",
                transcript=str(transcript),
                cwd=str(tmp_path),
                command="ls",
            ),
            audit=audit,
        )
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-A",
                transcript=str(transcript),
                cwd=str(tmp_path),
                command="pwd",
            ),
            audit=audit,
        )

    # Now emit session.close (what the SessionEnd hook does).
    from quill.journal import _emit_session_close

    _emit_session_close("ses-A", str(tmp_path), "user_quit")

    lines = [json.loads(line) for line in log.read_text().splitlines()]
    closes = [e for e in lines if e["type"] == "session.close" and e["session_id"] == "ses-A"]
    assert len(closes) == 1, f"expected 1 close, got {len(closes)}"
    close = closes[0]
    assert close["payload"]["reason"] == "user_quit"
    assert close["payload"]["tool_call_count"] == 2
    # duration_seconds is non-negative; exact value depends on wall clock.
    assert close["payload"]["duration_seconds"] >= 0


def test_session_end_close_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Second SessionEnd for the same session must NOT emit a duplicate
    close event (e.g. Claude Code firing SessionEnd twice on exit).
    """
    monkeypatch.setenv("QUILL_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("QUILL_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    monkeypatch.setenv("QUILL_NO_AUTO_WATCH", "1")
    log = tmp_path / "audit.jsonl"
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-B",
                transcript=str(transcript),
                cwd=str(tmp_path),
                command="ls",
            ),
            audit=audit,
        )
    from quill.journal import _emit_session_close

    _emit_session_close("ses-B", str(tmp_path), "user_quit")
    _emit_session_close("ses-B", str(tmp_path), "user_quit")
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    closes = [e for e in lines if e["type"] == "session.close" and e["session_id"] == "ses-B"]
    assert len(closes) == 1, "duplicate session.close emitted; not idempotent"


def test_subagent_spawn_emits_paired_handoff_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: every agent.handoff.out must be paired with an
    agent.handoff.in carrying the same payload_hash and referencing
    the out's mac via from_event_mac. Without the in, `quill bridge show`
    reports every handoff as orphan."""
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    log = tmp_path / "audit.jsonl"
    transcript = str(tmp_path / "t.jsonl")
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-root",
                transcript=transcript,
                cwd="/x",
                command="ls",
            ),
            audit=audit,
        )
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-sub",
                transcript=transcript,
                cwd="/x",
                command="ls",
            ),
            audit=audit,
        )
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    outs = [e for e in lines if e["type"] == "agent.handoff.out"]
    ins = [e for e in lines if e["type"] == "agent.handoff.in"]
    assert len(outs) == 1
    assert len(ins) == 1
    # Same payload_hash on both sides (the bridge.fold pairing key).
    assert outs[0]["payload"]["payload_hash"] == ins[0]["payload"]["payload_hash"]
    # The in references the out's mac (cryptographic edge tie).
    assert ins[0]["payload"]["from_event_mac"] == outs[0]["mac"]
    # The in is recorded under the sub-agent's session_id (receiver side).
    assert ins[0]["session_id"] == "ses-sub"
    # Bridge fold reports the pair as non-orphan.
    from quill.bridge import fold_handoffs

    handoffs = fold_handoffs(lines)
    ph = outs[0]["payload"]["payload_hash"]
    assert not handoffs[ph].is_orphan


def test_subagent_handoff_only_fires_once_per_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple calls from the same sub-agent should NOT emit repeated
    agent.handoff.out events. Handoff fires once per session_id."""
    monkeypatch.setenv("QUILL_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("QUILL_TAINT_FILE", str(tmp_path / "taint.json"))
    log = tmp_path / "audit.jsonl"
    transcript = str(tmp_path / "t.jsonl")
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(
            _payload(
                tool_name="Bash",
                session_id="ses-root",
                transcript=transcript,
                cwd="/x",
                command="ls",
            ),
            audit=audit,
        )
        for _ in range(3):
            run_hook(
                _payload(
                    tool_name="Bash",
                    session_id="ses-sub",
                    transcript=transcript,
                    cwd="/x",
                    command="ls",
                ),
                audit=audit,
            )
    lines = [json.loads(l) for l in log.read_text().splitlines()]
    handoffs = [e for e in lines if e["type"] == "agent.handoff.out"]
    assert len(handoffs) == 1


def test_per_project_log_routing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If <cwd>/.quill/ exists, the hook routes the log there instead of
    the global ~/.quill/audit.log.jsonl."""
    from quill.adapters.claude_code import _resolve_project_paths

    project = tmp_path / "my-saas"
    (project / ".quill").mkdir(parents=True)
    monkeypatch.delenv("QUILL_LOG", raising=False)

    log_path, cfg = _resolve_project_paths(str(project))
    assert log_path == project / ".quill" / "audit.log.jsonl"

    # without per-project dir, falls back
    no_project = tmp_path / "plain"
    no_project.mkdir()
    log_path2, _ = _resolve_project_paths(str(no_project))
    assert log_path2 != project / ".quill" / "audit.log.jsonl"


def test_per_project_config_optional(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quill.adapters.claude_code import _resolve_project_paths

    project = tmp_path / "my-saas"
    (project / ".quill").mkdir(parents=True)
    monkeypatch.delenv("QUILL_LOG", raising=False)

    # no config file = no per-project config
    _, cfg = _resolve_project_paths(str(project))
    assert cfg is None

    # config file present = path returned
    cfg_path = project / ".quill" / "config.toml"
    cfg_path.write_text('[session]\nintent = "test"\n')
    _, cfg2 = _resolve_project_paths(str(project))
    assert cfg2 == cfg_path


def test_quill_log_env_overrides_per_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quill.adapters.claude_code import _resolve_project_paths

    project = tmp_path / "x"
    (project / ".quill").mkdir(parents=True)
    override = tmp_path / "override.jsonl"
    monkeypatch.setenv("QUILL_LOG", str(override))

    log_path, _ = _resolve_project_paths(str(project))
    assert log_path == override
