"""Cursor 1.7+ hook adapter tests.

Cursor's contract is documented at https://cursor.com/docs/hooks.
Pinned here because Cursor versions evolve faster than Notari's release
cadence; if a future Cursor version changes the JSON shape, these tests
catch it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from notari.adapters.cursor import (
    _normalize_input,
    decide,
    install_into_settings,
    run_hook,
)
from notari.audit import AuditLog

# ---------------------------------------------------------------------------
# normalize_input - Cursor's per-event stdin shapes


def test_normalize_before_shell_to_bash() -> None:
    raw = {
        "hook_event_name": "beforeShellExecution",
        "command": "rm -rf /",
        "cwd": "/repo",
    }
    tool, args = _normalize_input(raw)
    assert tool == "Bash"
    assert args["command"] == "rm -rf /"
    assert args["cwd"] == "/repo"


def test_normalize_before_read_file_to_read() -> None:
    raw = {"hook_event_name": "beforeReadFile", "path": "/etc/passwd"}
    tool, args = _normalize_input(raw)
    assert tool == "Read"
    assert args["file_path"] == "/etc/passwd"


def test_normalize_before_mcp_passes_through_tool_name() -> None:
    raw = {
        "hook_event_name": "beforeMCPExecution",
        "tool_name": "github.create_pull_request",
        "tool_input": {"owner": "manumarri-sudo", "repo": "notari"},
    }
    tool, args = _normalize_input(raw)
    assert tool == "github.create_pull_request"
    assert args == {"owner": "manumarri-sudo", "repo": "notari"}


def test_normalize_unknown_event_falls_through_to_allow() -> None:
    """Future Cursor events Notari doesn't know about should not crash."""
    raw = {"hook_event_name": "afterFileEdit", "tool_name": "edit"}
    tool, _ = _normalize_input(raw)
    assert tool == "edit"


# ---------------------------------------------------------------------------
# decide() - Cursor-specific behavior: HIGH risk → deny (not ask) because
# Cursor's allow-list in Auto-Run mode silently overrides "ask"


def test_decide_critical_returns_deny() -> None:
    d = decide("Bash", {"command": "rm -rf /"})
    assert d.permission == "deny"


def test_decide_high_returns_deny_not_ask() -> None:
    """SECURITY: Cursor's Auto-Run allow-list bypasses `ask`. We hard-deny
    and tell the user how to release the call via approval token."""
    d = decide("Edit", {"file_path": "/x", "old_string": "a", "new_string": "b"})
    assert d.permission == "deny"
    assert "approve" in d.reason.lower()


def test_decide_low_returns_allow() -> None:
    d = decide("Bash", {"command": "ls -la"})
    assert d.permission == "allow"


# ---------------------------------------------------------------------------
# run_hook - full stdin → stdout JSON contract


def _payload(**kwargs: object) -> str:
    base = {
        "hook_event_name": "beforeShellExecution",
        "cwd": "/x",
        "conversation_id": "ses-cursor-1",
    }
    base.update(kwargs)
    return json.dumps(base)


def test_run_hook_returns_cursor_shape_not_claude_code_shape() -> None:
    """Cursor uses `permission` at the top level - NOT `hookSpecificOutput`.
    A common bug would be to ship Claude Code's response shape by accident.
    """
    out = run_hook(_payload(command="rm -rf /"))
    assert "permission" in out
    assert "hookSpecificOutput" not in out


def test_run_hook_blocks_critical_command() -> None:
    out = run_hook(_payload(command="rm -rf /"))
    assert out["permission"] == "deny"
    assert "agent_message" in out
    assert "user_message" in out


def test_run_hook_allows_low_risk() -> None:
    out = run_hook(_payload(command="ls -la"))
    assert out["permission"] == "allow"


def test_run_hook_writes_audit_entries(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        run_hook(_payload(command="git push --force origin main"), audit=audit)
    lines = [json.loads(l) for l in log.read_text().splitlines()]
    types = [e["type"] for e in lines]
    assert "tool.attempted" in types
    assert "verdict.blocked" in types
    # audit entry must record this came via the cursor adapter
    blocked = next(e for e in lines if e["type"] == "verdict.blocked")
    assert blocked["payload"]["by"] == "notari.adapters.cursor"


def test_run_hook_fail_open_on_malformed_input() -> None:
    """A parse bug in Cursor's JSON should not make the call fail; allow
    through with an annotated agent_message so the dev can debug."""
    out = run_hook("{ not json }")
    assert out["permission"] == "allow"
    assert "agent_message" in out


def test_run_hook_emits_one_shot_approval_token_id_on_block() -> None:
    """When a call is denied, the audit log records a token ID (sha256
    prefix), NOT the raw approve token. The raw token only goes out-of-band
    via the notification, so an agent reading the log cannot replay it.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "audit.jsonl"
        with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
            run_hook(_payload(command="rm -rf node_modules"), audit=audit)
        lines = [json.loads(l) for l in log.read_text().splitlines()]
        blocked = next(e for e in lines if e["type"] == "verdict.blocked")
        # The new (safe) field is present:
        assert blocked["payload"]["approve_token_id"]
        assert len(blocked["payload"]["approve_token_id"]) == 16
        # And the old (unsafe) field is gone:
        assert "approve_token" not in blocked["payload"]


def test_run_hook_consumes_existing_approval_and_allows(tmp_path: Path) -> None:
    """If `notari approve <token>` was run for this exact (tool, args), the
    next hook invocation consumes the approval and allows the call."""
    from notari.approvals import ApprovalStore

    store = ApprovalStore.load()
    # Issue an approval for the exact call we'll make, then approve it
    # (simulating `notari approve <token>`) - issuance alone is inert.
    ap = store.issue("Bash", {"command": "rm -rf node_modules", "cwd": "/x"})
    store.approve(ap.token)

    log = tmp_path / "audit.jsonl"
    with AuditLog(path=log, hmac_key=b"k" * 32) as audit:
        out = run_hook(_payload(command="rm -rf node_modules"), audit=audit)
    assert out["permission"] == "allow"
    assert "approved one-shot" in out.get("agent_message", "")


# ---------------------------------------------------------------------------
# install_into_settings - idempotent merge of ~/.cursor/hooks.json


def test_install_creates_fresh_hooks_json(tmp_path: Path) -> None:
    p = tmp_path / "hooks.json"
    path, was_already = install_into_settings(p)
    assert path == p
    assert was_already is False
    assert p.exists()
    data = json.loads(p.read_text())
    assert data["version"] == 1
    assert "beforeShellExecution" in data["hooks"]
    cmds = [h["command"] for h in data["hooks"]["beforeShellExecution"]]
    assert "notari cursor-hook" in cmds


def test_install_is_idempotent(tmp_path: Path) -> None:
    p = tmp_path / "hooks.json"
    install_into_settings(p)
    _, was_already = install_into_settings(p)
    assert was_already is True
    # And no duplicate entries piled up.
    data = json.loads(p.read_text())
    cmds = [h["command"] for h in data["hooks"]["beforeShellExecution"]]
    assert cmds.count("notari cursor-hook") == 1


def test_install_preserves_existing_user_hooks(tmp_path: Path) -> None:
    """If the user already has a custom hook, Notari must not clobber it."""
    p = tmp_path / "hooks.json"
    p.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {"command": "my-custom-linter", "type": "command"},
                    ],
                },
            }
        )
    )
    install_into_settings(p)
    data = json.loads(p.read_text())
    cmds = [h["command"] for h in data["hooks"]["beforeShellExecution"]]
    assert "my-custom-linter" in cmds
    assert "notari cursor-hook" in cmds


def test_install_wires_all_three_gate_events(tmp_path: Path) -> None:
    p = tmp_path / "hooks.json"
    install_into_settings(p)
    data = json.loads(p.read_text())
    assert "beforeShellExecution" in data["hooks"]
    assert "beforeMCPExecution" in data["hooks"]
    assert "beforeReadFile" in data["hooks"]


def test_main_fails_closed_when_the_gate_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Red-team finding 10: a crash inside the Cursor hook must DENY, not allow.

    A broken gate that fail-opens is worse than no gate, and `deny` (not `ask`)
    because Cursor's Auto-Run allow-list can silently override an ask.
    """
    import io

    import notari.adapters.cursor as cursor

    monkeypatch.setattr(cursor, "run_hook", _boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))

    rc = cursor.main()
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["permission"] == "deny"
    assert "fails closed" in out["agent_message"]


def _boom(*_a: object, **_k: object) -> dict[str, object]:
    raise RuntimeError("simulated gate crash")
