"""Recognized dummy credentials must never reach persisted argument previews."""

import json
from pathlib import Path

import pytest

from notari.adapters import claude_code, cursor
from notari.adapters.claude_code import _redacted_input
from notari.attest import generate_keypair
from notari.audit import AuditLog
from notari.secrets import redact


def test_preview_redacts_before_truncation_and_recurses() -> None:
    token = "AKIA" + "A" * 16
    args = {"content": "x" * 195 + token, "edits": [{"new_string": token}]}
    preview = json.dumps(_redacted_input(args))
    leaked = token[:12] in preview
    assert not leaked, "recognized credential prefix persisted in preview"


@pytest.mark.parametrize("adapter", ["claude", "cursor"])
def test_denied_write_does_not_copy_credential_to_audit(tmp_path: Path, adapter: str) -> None:
    token = "AKIA" + "A" * 16
    path = tmp_path / "audit.jsonl"
    payload = {
        "session_id": "privacy-test",
        "tool_name": "Write",
        "tool_input": {
            "file_path": str(tmp_path / "app.py"),
            "content": 'key = "' + token + '"',
        },
    }
    if adapter == "cursor":
        payload["hook_event_name"] = "beforeMCPExecution"
    run = claude_code.run_hook if adapter == "claude" else cursor.run_hook
    with AuditLog(path=path, hmac_key=b"p" * 32) as audit:
        result = run(json.dumps(payload), audit=audit)
    permission = (
        result["hookSpecificOutput"]["permissionDecision"]
        if adapter == "claude"
        else result["permission"]
    )
    assert permission == "deny"
    leaked = token in path.read_text()
    assert not leaked, "a blocked write still exposed its recognized credential in the log"


def test_preview_keeps_benign_context() -> None:
    assert _redacted_input({"command": "git status", "count": 2}) == {
        "command": "git status",
        "count": 2,
    }


def test_paused_preview_does_not_copy_credential_to_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "AKIA" + "A" * 16
    path = tmp_path / "paused.jsonl"
    monkeypatch.setattr(claude_code, "_default_load_hmac_key", lambda: b"p" * 32)
    payload = json.dumps({"tool_name": "Write", "tool_input": {"content": token}})
    result = claude_code._handle_paused(payload, path, "unit test")
    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert token not in path.read_text()


def test_preview_omits_excessive_nesting_instead_of_returning_raw_values() -> None:
    token = "AKIA" + "A" * 16
    nested = {"content": token}
    for _ in range(20):
        nested = {"nested": [nested]}
    preview = json.dumps(_redacted_input(nested))
    assert token not in preview
    assert "nesting limit" in preview


def test_preview_bounds_cyclic_containers() -> None:
    cyclic = []
    cyclic.append(cyclic)
    assert "nesting limit" in json.dumps(_redacted_input({"edits": cyclic}))


@pytest.mark.parametrize("terminated", [True, False])
def test_pem_preview_removes_the_private_key_body(terminated: bool) -> None:
    private_pem, _ = generate_keypair()
    body = private_pem.splitlines()[1]
    content = private_pem if terminated else private_pem.split("-----END", 1)[0]
    assert len(content) < 200
    preview = json.dumps(_redacted_input({"content": content}))
    assert body not in preview, "the redacted preview retained reconstructible PEM key material"
    assert "REDACTED:Private Key (PEM block)" in preview


def test_pem_redaction_preserves_surrounding_benign_context() -> None:
    private_pem, _ = generate_keypair()
    assert redact("before\n" + private_pem + "after") == (
        "before\n[REDACTED:Private Key (PEM block)]\nafter"
    )


def test_unterminated_pem_redaction_removes_the_entire_remaining_input() -> None:
    private_pem, _ = generate_keypair()
    unterminated = private_pem.split("-----END", 1)[0]
    assert redact("before\n" + unterminated + "trailing private material") == (
        "before\n[REDACTED:Private Key (PEM block)]"
    )


def test_pem_body_is_redacted_when_assignment_match_overlaps_its_header() -> None:
    private_pem, _ = generate_keypair()
    body = private_pem.splitlines()[1]
    content = 'SIGNING_SECRET = """' + private_pem + '"""'
    preview = json.dumps(_redacted_input({"content": content}))
    assert body not in preview, "an overlapping assignment match suppressed PEM body redaction"
    assert "REDACTED:Private Key (PEM block)" in preview
