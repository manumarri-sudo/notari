"""Tests for session-scoped approval memory (#52).

The bright line: critical/secret/trifecta events never qualify for session
memory. Adapter integration tests assert that; this file tests the storage
layer in isolation.
"""

from __future__ import annotations

import time

import pytest

from quill import session_approvals as sa


@pytest.fixture
def tmp_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("QUILL_SESSION_APPROVALS_DIR", str(tmp_path))
    return tmp_path


def test_remember_then_recall_returns_true(tmp_dir):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py", "old": "a", "new": "b"})
    assert sa.recall("sess-A", "Edit", {"file_path": "/x.py", "old": "a", "new": "b"})


def test_different_args_dont_match(tmp_dir):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py", "old": "a", "new": "b"})
    assert not sa.recall("sess-A", "Edit", {"file_path": "/x.py", "old": "a", "new": "c"})


def test_different_tool_doesnt_match(tmp_dir):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py"})
    assert not sa.recall("sess-A", "Write", {"file_path": "/x.py"})


def test_different_session_doesnt_match(tmp_dir):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py"})
    assert not sa.recall("sess-B", "Edit", {"file_path": "/x.py"})


def test_recall_miss_when_empty(tmp_dir):
    assert not sa.recall("sess-A", "Edit", {"file_path": "/x.py"})


def test_ttl_expiry(tmp_dir, monkeypatch):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py"})
    # Fast-forward beyond the 24h TTL.
    future = time.time() + sa.SESSION_APPROVAL_TTL_SEC + 60
    assert not sa.recall("sess-A", "Edit", {"file_path": "/x.py"}, now=future)


def test_forget_session_wipes(tmp_dir):
    sa.remember("sess-A", "Edit", {"file_path": "/x.py"})
    sa.forget_session("sess-A")
    assert not sa.recall("sess-A", "Edit", {"file_path": "/x.py"})


def test_session_id_path_traversal_resistance(tmp_dir):
    """A malformed session_id (containing slashes / dots) must not let
    the file write escape the configured directory."""
    sa.remember("../../../etc/passwd", "Edit", {"x": 1})
    # Should not have created files outside tmp_dir.
    for f in tmp_dir.iterdir():
        # Each file's name should be sanitized (no slash, no '..')
        assert "/" not in f.name
        assert ".." not in f.name


def test_digest_is_stable_across_call_order(tmp_dir):
    """The digest must be independent of insertion order of keys."""
    d1 = sa.args_digest("Edit", {"a": 1, "b": 2})
    d2 = sa.args_digest("Edit", {"b": 2, "a": 1})
    assert d1 == d2


def test_corrupt_file_recovers_silently(tmp_dir):
    """If the on-disk JSON is malformed, recall returns False; remember
    overwrites cleanly. Memory layer is decoration, never load-bearing."""
    p = sa._session_file("sess-A")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json")
    assert not sa.recall("sess-A", "Edit", {"x": 1})
    sa.remember("sess-A", "Edit", {"x": 1})
    assert sa.recall("sess-A", "Edit", {"x": 1})
