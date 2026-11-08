"""A refused exposure cannot clear the requirement for human approval."""

import json
from pathlib import Path

import pytest

from notari.adapters import claude_code, cursor
from notari.approvals import ApprovalStore
from notari.audit import AuditLog
from notari.taint import TaintState


@pytest.mark.parametrize("adapter", ["claude", "cursor"])
def test_identical_private_read_remains_denied_until_approved(tmp_path: Path, adapter: str) -> None:
    session = "refused-retry-" + adapter
    state = TaintState(has_seen_untrusted=True, can_exfiltrate=True)
    claude_code._save_taint_state(session, state)
    path = tmp_path / "audit.jsonl"
    if adapter == "claude":
        payload = {
            "session_id": session,
            "tool_name": "Read",
            "tool_input": {"file_path": str(tmp_path / ".env")},
        }
        run = claude_code.run_hook
    else:
        payload = {
            "conversation_id": session,
            "hook_event_name": "beforeReadFile",
            "path": str(tmp_path / ".env"),
        }
        run = cursor.run_hook
    with AuditLog(path=path, hmac_key=b"t" * 32) as audit:
        first = run(json.dumps(payload), audit=audit)
        retry = run(json.dumps(payload), audit=audit)

    def permission(result):
        return (
            result["hookSpecificOutput"]["permissionDecision"]
            if adapter == "claude"
            else result["permission"]
        )

    assert permission(first) == "deny"
    assert permission(retry) == "deny", "a denied first attempt implicitly authorized its retry"
    assert not claude_code._taint_state_for(session).has_accessed_private
    store = ApprovalStore.load()
    approval = store.latest_pending()
    assert approval is not None
    assert store.approve(approval.token) is not None
    with AuditLog(path=path, hmac_key=b"t" * 32) as audit:
        authorized = run(json.dumps(payload), audit=audit)
    assert permission(authorized) == "allow"
    assert claude_code._taint_state_for(session).trifecta_closed
    assert ApprovalStore.load().approvals[approval.token].consumed_at


@pytest.mark.parametrize("adapter", ["claude", "cursor"])
def test_approved_exposure_persists_and_does_not_reescalate(tmp_path: Path, adapter: str) -> None:
    session = "approved-closure-" + adapter
    state = TaintState(has_seen_untrusted=True, has_accessed_private=True)
    claude_code._save_taint_state(session, state)
    args = {"command": "git push --force"}
    if adapter == "claude":
        payload = {"session_id": session, "tool_name": "Bash", "tool_input": args}
        read = {"session_id": session, "tool_name": "Read", "tool_input": {"file_path": ".env"}}
        run = claude_code.run_hook
    else:
        args["cwd"] = ""
        payload = {
            "conversation_id": session,
            "hook_event_name": "beforeShellExecution",
            "command": args["command"],
        }
        read = {
            "conversation_id": session,
            "hook_event_name": "beforeReadFile",
            "path": ".env",
        }
        run = cursor.run_hook
    store = ApprovalStore.load()
    approval = store.issue("Bash", args)
    assert store.approve(approval.token) is not None
    with AuditLog(path=tmp_path / "audit.jsonl", hmac_key=b"t" * 32) as audit:
        approved = run(json.dumps(payload), audit=audit)
        later = run(json.dumps(read), audit=audit)
    if adapter == "claude":
        assert approved["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert later["hookSpecificOutput"]["permissionDecision"] == "allow"
    else:
        assert approved["permission"] == "allow"
        assert later["permission"] == "allow"
    assert claude_code._taint_state_for(session).trifecta_closed
