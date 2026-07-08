"""Tests for the prepare-commit-msg git hook integration."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

import pytest

from nota.githook import (
    _BLOCK_MARKER,
    find_active_session,
    hook_path,
    install_hook,
    prepare_commit_msg,
    render_commit_block,
    uninstall_hook,
)
from nota.receipt import Receipt


def _receipt(
    sid: str = "ses_abcd1234",
    *,
    opened_at: str | None = None,
    closed_at: str | None = None,
    tool_call_count: int = 10,
    intervention_count: int = 0,
    blocks_summary: list[str] | None = None,
    asks_summary: list[str] | None = None,
    biometric_approvals: int = 0,
    top_changed_dir: str = "",
    intent: str = "",
    tdr_contribution: float = 1.0,
    to_verify: list[str] | None = None,
) -> Receipt:
    now = datetime.now(UTC).isoformat()
    return Receipt(
        session_id=sid,
        opened_at=opened_at if opened_at is not None else now,
        closed_at=closed_at if closed_at is not None else now,
        tool_call_count=tool_call_count,
        intervention_count=intervention_count,
        blocks_summary=blocks_summary or [],
        asks_summary=asks_summary or [],
        biometric_approvals=biometric_approvals,
        top_changed_dir=top_changed_dir,
        intent=intent,
        tdr_contribution=tdr_contribution,
        to_verify=to_verify or [],
    )


# ---------------------------------------------------------------------------
# find_active_session
# ---------------------------------------------------------------------------


def test_find_active_session_returns_none_if_no_receipts():
    assert find_active_session({}) is None


def test_find_active_session_returns_most_recent():
    now = datetime.now(UTC)
    older = now - timedelta(hours=1)
    receipts = {
        "ses_old": _receipt(sid="ses_old", closed_at=older.isoformat(), tool_call_count=20),
        "ses_new": _receipt(sid="ses_new", closed_at=now.isoformat(), tool_call_count=5),
    }
    chosen = find_active_session(receipts, now=now)
    assert chosen is not None
    assert chosen.session_id == "ses_new"


def test_find_active_session_skips_stale_sessions():
    now = datetime.now(UTC)
    stale = now - timedelta(days=3)
    receipts = {
        "ses_old": _receipt(sid="ses_old", closed_at=stale.isoformat()),
    }
    assert find_active_session(receipts, now=now) is None


def test_find_active_session_ignores_sessions_without_timestamps():
    receipts = {"ses_x": _receipt(sid="ses_x", opened_at="", closed_at="")}
    assert find_active_session(receipts) is None


# ---------------------------------------------------------------------------
# render_commit_block
# ---------------------------------------------------------------------------


def test_render_commit_block_minimal():
    r = _receipt(tool_call_count=5)
    block = render_commit_block(r)
    assert _BLOCK_MARKER in block
    assert "ses_abcd1234"[:12] in block
    assert "calls    : 5" in block
    # every non-empty line starts with `#` so git treats them as comments
    for line in block.splitlines():
        if line.strip():
            assert line.startswith("#"), f"non-comment line: {line!r}"


def test_render_commit_block_includes_blocks():
    r = _receipt(
        tool_call_count=20,
        intervention_count=2,
        blocks_summary=["Bash: rm -rf", "Bash: git push --force"],
    )
    block = render_commit_block(r)
    assert "blocked  :" in block
    assert "rm -rf" in block
    assert "git push --force" in block


def test_render_commit_block_truncates_long_block_lists():
    r = _receipt(
        tool_call_count=20,
        intervention_count=10,
        blocks_summary=[f"Bash: blocked-{i}" for i in range(10)],
    )
    block = render_commit_block(r)
    assert "and 5 more" in block


def test_render_commit_block_includes_top_dir():
    r = _receipt(top_changed_dir="src/auth")
    block = render_commit_block(r)
    assert "touched  : src/auth" in block


# ---------------------------------------------------------------------------
# prepare_commit_msg integration
# ---------------------------------------------------------------------------


def test_prepare_commit_msg_no_audit_log_is_noop(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("fix the bug\n")
    rc = prepare_commit_msg(msg, log_path=tmp_path / "missing.jsonl")
    assert rc == 0
    assert msg.read_text() == "fix the bug\n"


def test_prepare_commit_msg_skips_on_merge_source(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("Merge branch foo\n")
    rc = prepare_commit_msg(msg, source_type="merge")
    assert rc == 0
    assert msg.read_text() == "Merge branch foo\n"


def test_prepare_commit_msg_appends_block_when_template_marker_absent(tmp_path):
    """If the commit message has no `# Please enter...` block, append to end."""
    audit = tmp_path / "audit.log.jsonl"
    # Single session with one tool call so derive_from_events produces a Receipt
    import json

    from nota import events as ev

    now = datetime.now(UTC).isoformat()
    audit.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                {"type": ev.SESSION_OPEN, "session_id": "ses_x", "ts": now, "payload": {}},
                {
                    "type": ev.TOOL_ATTEMPTED,
                    "session_id": "ses_x",
                    "ts": now,
                    "payload": {"tool_name": "Edit", "args_preview": {"file_path": "src/x.py"}},
                },
                {"type": ev.VERDICT_ALLOWED, "session_id": "ses_x", "ts": now, "payload": {}},
                {"type": ev.SESSION_CLOSE, "session_id": "ses_x", "ts": now, "payload": {}},
            ]
        )
        + "\n"
    )
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("user wrote this commit message\n")
    rc = prepare_commit_msg(msg, log_path=audit)
    assert rc == 0
    after = msg.read_text()
    assert "user wrote this commit message" in after
    assert _BLOCK_MARKER in after
    assert "ses_x" in after


def test_prepare_commit_msg_idempotent_when_block_already_present(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    original = f"my commit\n\n{_BLOCK_MARKER}\n# already injected\n"
    msg.write_text(original)
    rc = prepare_commit_msg(msg)
    assert rc == 0
    assert msg.read_text() == original


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------


def test_install_hook_creates_executable(tmp_path):
    (tmp_path / ".git").mkdir()
    p, already = install_hook(tmp_path)
    assert not already
    assert p == hook_path(tmp_path)
    assert p.exists()
    assert "nota git-hook" in p.read_text()
    # Should be executable
    import os

    assert os.access(p, os.X_OK)


def test_install_hook_bakes_absolute_nota_binary_path(tmp_path, monkeypatch):
    """Hook should `exec /abs/path/to/nota git-hook` not bare `exec nota`.
    Otherwise commits from outside the venv silently no-op.

    We stage a resolvable `nota` as a sibling of `sys.executable` so
    `_resolve_nota_binary()` deterministically finds an absolute path
    (this is the venv layout it targets). The hook must then bake that
    exact absolute path in, not the bare literal `nota`.
    """
    # Fake venv bin dir with an executable `nota` next to the interpreter.
    fake_bin = tmp_path / "venv" / "bin"
    fake_bin.mkdir(parents=True)
    fake_python = fake_bin / "python"
    fake_python.write_text("#!/bin/sh\n")
    fake_python.chmod(0o755)
    fake_nota = fake_bin / "nota"
    fake_nota.write_text("#!/bin/sh\n")
    fake_nota.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_python))

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    p, _ = install_hook(repo)
    contents = p.read_text()
    # Look for the binary token before `git-hook`. Match `<binary> git-hook`.
    import re

    m = re.search(r"exec\s+(\S+)\s+git-hook", contents)
    assert m is not None, f"no exec line found:\n{contents}"
    binary = m.group(1)
    # Resolution should have found our staged venv-sibling nota and baked
    # its absolute path in. A bare literal `nota` (unresolved) is the
    # regression this test exists to catch.
    assert binary == str(fake_nota), f"expected absolute venv path, got {binary!r}"
    assert binary.startswith("/")


def test_install_hook_idempotent(tmp_path):
    (tmp_path / ".git").mkdir()
    install_hook(tmp_path)
    p, already = install_hook(tmp_path)
    assert already


def test_install_hook_refuses_to_overwrite_existing(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    p = hook_path(tmp_path)
    p.write_text("#!/bin/sh\n# someone else's hook\necho hi\n")
    with pytest.raises(FileExistsError):
        install_hook(tmp_path)


def test_uninstall_hook_removes_nota_hook(tmp_path):
    (tmp_path / ".git").mkdir()
    install_hook(tmp_path)
    p, removed = uninstall_hook(tmp_path)
    assert removed
    assert not p.exists()


def test_uninstall_hook_refuses_non_nota(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    p = hook_path(tmp_path)
    p.write_text("#!/bin/sh\necho 'not nota'\n")
    with pytest.raises(RuntimeError):
        uninstall_hook(tmp_path)


def test_uninstall_hook_noop_when_missing(tmp_path):
    (tmp_path / ".git").mkdir()
    p, removed = uninstall_hook(tmp_path)
    assert not removed
