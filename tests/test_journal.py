"""Tests for nota.journal.

Pinned because the parser silently produced zero-turn stubs for ~3 weeks
when the on-disk Claude Code transcript schema diverged from what
`summarize_transcript` expected. These tests cover both shapes so the
regression cannot recur unnoticed.
"""

from __future__ import annotations

from nota.journal import (
    JournalSummary,
    save_from_transcript,
    slugify,
    summarize_transcript,
    write_journal,
)


def test_slugify_basic():
    assert slugify("Nota Public Launch") == "nota-public-launch"
    assert slugify("") == "session"
    assert slugify("!!! ???") == "session"
    assert slugify("one two three four five six seven") == "one-two-three-four-five"


def test_flat_shape_still_works():
    """The original {role, content, ts} shape must still parse."""
    events = [
        {"role": "user", "content": "fix the bug", "ts": "2026-05-11T10:00:00Z"},
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "/tmp/a.py"}},
            ],
            "ts": "2026-05-11T10:01:00Z",
        },
    ]
    s = summarize_transcript(events)
    assert s.n_user_turns == 1
    assert s.n_assistant_turns == 1
    assert s.headline == "fix the bug"
    assert s.tool_use_counts["Bash"] == 1
    assert s.tool_use_counts["Read"] == 1
    assert s.bash_commands_seen == 1
    assert s.started_at == "2026-05-11T10:00:00Z"
    assert s.ended_at == "2026-05-11T10:01:00Z"


def test_claude_code_shape_user_string_content():
    """Claude Code wraps the chat message under `message` and puts the
    role under `type`. Single user prompt with string content."""
    events = [
        {
            "type": "user",
            "timestamp": "2026-05-11T10:00:00Z",
            "cwd": "/Users/m/repo",
            "message": {"role": "user", "content": "have we been running nota?"},
        },
        {
            "type": "assistant",
            "timestamp": "2026-05-11T10:00:05Z",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Let me check."},
                    {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}},
                ],
            },
        },
    ]
    s = summarize_transcript(events)
    assert s.n_user_turns == 1
    assert s.n_assistant_turns == 1
    assert s.headline == "have we been running nota?"
    assert s.tool_use_counts["Bash"] == 1
    assert s.bash_commands_seen == 1
    assert s.cwd == "/Users/m/repo"


def test_claude_code_shape_user_list_content():
    """Some user turns carry content as a list of blocks (e.g. when the
    user pastes an image alongside text). Headline should fall back to
    the first text block."""
    events = [
        {
            "type": "user",
            "timestamp": "2026-05-11T10:00:00Z",
            "message": {
                "role": "user",
                "content": [
                    {"type": "image", "source": {}},
                    {"type": "text", "text": "look at this screenshot"},
                ],
            },
        }
    ]
    s = summarize_transcript(events)
    assert s.n_user_turns == 1
    assert s.headline == "look at this screenshot"


def test_path_namespacing_strips_home(tmp_path, monkeypatch):
    """File-area extraction must not collapse every absolute home path
    to '//Users' or '/Users'. After stripping $HOME we want the next
    two path segments."""
    monkeypatch.setenv("HOME", "/Users/m")
    # Path.home() reads HOME on POSIX, so the monkeypatch takes effect.
    events = [
        {
            "type": "assistant",
            "timestamp": "2026-05-11T10:00:00Z",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Edit",
                        "input": {"file_path": "/Users/m/nota/src/nota/journal.py"},
                    },
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {"file_path": "/Users/m/agentbrain/AgentOS-Vault/x.md"},
                    },
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {"file_path": "/tmp/scratch.py"},
                    },
                ],
            },
        }
    ]
    s = summarize_transcript(events)
    assert "nota/src" in s.files_touched
    assert "agentbrain/AgentOS-Vault" in s.files_touched
    assert "tmp/scratch.py" in s.files_touched
    # The pathological "//Users" collapse must be gone.
    assert not any(f.startswith("/") for f in s.files_touched)


def test_save_from_transcript_writes_real_counts(tmp_path):
    """End-to-end: a Claude Code-shaped transcript JSONL on disk should
    write a journal with non-zero turn counts (the bug we are fixing)."""
    tx = tmp_path / "session.jsonl"
    lines = [
        '{"type":"user","timestamp":"2026-05-11T10:00:00Z","message":{"role":"user","content":"hi"}}',
        '{"type":"assistant","timestamp":"2026-05-11T10:00:01Z","message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}}',
        '{"type":"user","timestamp":"2026-05-11T10:00:02Z","message":{"role":"user","content":"do a thing"}}',
        '{"type":"assistant","timestamp":"2026-05-11T10:00:03Z","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}',
    ]
    tx.write_text("\n".join(lines) + "\n")
    out = tmp_path / "Sessions"
    written = save_from_transcript(tx, sessions_dir=out)
    body = written.read_text()
    assert "user turns: 2" in body
    assert "assistant turns: 2" in body
    assert "shell commands attempted: 1" in body
    assert "Bash" in body


def test_write_journal_does_not_overwrite(tmp_path):
    """If a same-day slug already exists, we suffix `-2`, never clobber."""
    out = tmp_path / "S"
    s = JournalSummary(
        started_at="2026-05-11T10:00:00Z",
        ended_at="2026-05-11T11:00:00Z",
        headline="my session",
    )
    p1 = write_journal(s, sessions_dir=out)
    p2 = write_journal(s, sessions_dir=out)
    p3 = write_journal(s, sessions_dir=out)
    assert p1.name == "2026-05-11-my-session.md"
    assert p2.name == "2026-05-11-my-session-2.md"
    assert p3.name == "2026-05-11-my-session-3.md"
    assert p1.exists() and p2.exists() and p3.exists()
