"""Permission decay tests.

Pins the framework's load-bearing claim: actively-used permissions stay
healthy, dormant ones decay, and decayed permissions are ignored at
the gate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from quill.decay import (
    DEFAULT_WINDOWS,
    DecayStore,
    _default_window,
    policy_kind,
)


def test_policy_kind_composes_correctly() -> None:
    assert policy_kind("critical", "low") == "policy.critical_to_low"
    assert policy_kind("high", "medium") == "policy.high_to_medium"


def test_default_window_uses_specific_first_then_fallback() -> None:
    assert _default_window("policy.critical_to_low") == 14
    assert _default_window("policy.unknown_combo") == 60  # policy.default
    assert _default_window("scope.unknown") == 90  # scope.default
    assert _default_window("totally_made_up") == 60


def test_record_use_creates_then_bumps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    p, was_decayed = store.record_use("policy.high_to_low", "fs.delete")
    assert was_decayed is False
    assert p.use_count == 1
    assert p.kind == "policy.high_to_low"
    assert p.decay_after_days == 30  # high_to_low

    # second use bumps count and last_reaffirmed
    p2, _ = store.record_use("policy.high_to_low", "fs.delete")
    assert p2.use_count == 2

    # round-trip through disk
    again = DecayStore.load()
    assert again.permissions["policy.high_to_low:fs.delete"].use_count == 2


def test_decayed_when_age_exceeds_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    store.record_use("policy.high_to_low", "fs.delete")

    # rewrite last_reaffirmed to 60 days ago (> 30d window)
    p = store.permissions["policy.high_to_low:fs.delete"]
    p.last_reaffirmed = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    store.save()

    fresh = DecayStore.load()
    perm = fresh.permissions["policy.high_to_low:fs.delete"]
    assert perm.is_decayed is True
    assert perm.age_days >= 60


def test_record_use_returns_was_decayed_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    store.record_use("policy.high_to_low", "fs.delete")
    p = store.permissions["policy.high_to_low:fs.delete"]
    p.last_reaffirmed = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    store.save()

    # next use should report it WAS decayed at use time, then refresh it
    again = DecayStore.load()
    perm, was_decayed = again.record_use("policy.high_to_low", "fs.delete")
    assert was_decayed is True
    # but now it's freshly reaffirmed
    assert perm.is_decayed is False
    assert perm.use_count == 2


def test_reaffirm_bumps_without_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    store.record_use("policy.high_to_low", "fs.delete")
    use_count_before = store.permissions["policy.high_to_low:fs.delete"].use_count
    store.reaffirm("policy.high_to_low", "fs.delete")
    after = DecayStore.load().permissions["policy.high_to_low:fs.delete"]
    # reaffirm does NOT bump use_count; just last_reaffirmed
    assert after.use_count == use_count_before


def test_forget_removes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    store.record_use("policy.high_to_low", "fs.delete")
    assert store.forget("policy.high_to_low", "fs.delete") is True
    assert "policy.high_to_low:fs.delete" not in DecayStore.load().permissions


def test_decayed_and_approaching_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUILL_DECAY_FILE", str(tmp_path / "perm.json"))
    store = DecayStore.load()
    # one decayed, one approaching, one healthy
    store.record_use("policy.high_to_low", "decayed.tool")
    store.permissions["policy.high_to_low:decayed.tool"].last_reaffirmed = (
        datetime.now(UTC) - timedelta(days=60)
    ).isoformat()
    store.record_use("policy.high_to_low", "approaching.tool")
    store.permissions["policy.high_to_low:approaching.tool"].last_reaffirmed = (
        datetime.now(UTC) - timedelta(days=20)
    ).isoformat()  # 30d window, 10d left
    store.record_use("policy.high_to_low", "healthy.tool")
    store.save()

    fresh = DecayStore.load()
    decayed_names = {p.pattern for p in fresh.decayed()}
    approaching_names = {p.pattern for p in fresh.approaching(within_days=14)}
    assert decayed_names == {"decayed.tool"}
    assert approaching_names == {"approaching.tool"}


def test_permission_file_is_chmod_600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "perm.json"
    monkeypatch.setenv("QUILL_DECAY_FILE", str(p))
    store = DecayStore.load()
    store.record_use("policy.high_to_low", "fs.delete")
    import stat

    mode = stat.S_IMODE(p.stat().st_mode)
    assert mode & 0o077 == 0


def test_default_window_keys_are_documented() -> None:
    """The DEFAULT_WINDOWS table is the framework's policy. Pin it so a
    refactor can't silently change decay behaviour for shipped users."""
    assert DEFAULT_WINDOWS["policy.critical_to_low"] == 14
    assert DEFAULT_WINDOWS["policy.high_to_low"] == 30
    assert DEFAULT_WINDOWS["scope.default"] == 90
    assert DEFAULT_WINDOWS["session_ack.default"] == 1
