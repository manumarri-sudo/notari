"""Tests for the human-presence gate on turning the Nota gate OFF.

Verifies the self-disable defense without a real fingerprint, a real tty, or
touching the real gate state. The defense is two-layered:

  - The HARD guarantee is the hook-layer CRITICAL classification of
    `nota off|pause|night` (see test_self_disable_classifier.py): an AGENT's
    Bash call is denied before it ever reaches the CLI.
  - This module covers the HUMAN path - `_require_disable_auth`'s tiered ladder
    (Touch ID -> /dev/tty typed challenge -> --no-biometric opt-in / refuse) -
    which only runs for a human in their own terminal.

`_human_tty_challenge` is monkeypatched everywhere so the suite never blocks on
/dev/tty, and `_emit_gate_event` is stubbed so tests never write the real log.
"""

from __future__ import annotations

import pytest
import typer

import nota.cli as cli
import nota.touchid as touchid
from nota.cli import _require_disable_auth


class _Console:
    """Minimal stand-in that swallows print() so the helper can run headless."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, *args, **_kwargs) -> None:
        self.messages.append(" ".join(str(a) for a in args))


@pytest.fixture(autouse=True)
def _isolate(monkeypatch) -> None:
    """Never write the real audit log; default the UI-can-present probe to True
    so Touch-ID-tier tests exercise Tier 1 (the real `codesign` probe would say
    False on the ad-hoc test interpreter). Tests that want the skip set it
    False explicitly."""
    monkeypatch.setattr(cli, "_emit_gate_event", lambda *_a, **_k: None)
    monkeypatch.setattr(touchid, "can_present_ui", lambda: True)


def _set_tty(monkeypatch, *, passes: bool) -> None:
    monkeypatch.setattr(cli, "_human_tty_challenge", lambda *_a, **_k: passes)


def test_env_bypass_var_is_removed(monkeypatch) -> None:
    """NOTA_SKIP_DISABLE_AUTH must NOT bypass the prompt. An explicit Touch ID
    cancel refuses outright and must not fall through to the tty challenge."""
    monkeypatch.setenv("NOTA_SKIP_DISABLE_AUTH", "1")
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid, "authenticate", lambda **_k: touchid.TouchIDResult(False, "user_canceled")
    )
    # If the cancel fell through to the tty tier, this would pass; it must not.
    _set_tty(monkeypatch, passes=True)
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_no_biometry_no_tty_refuses_by_default(monkeypatch) -> None:
    """No sensor AND no controlling tty (an agent's own piped process) REFUSES
    by default - a hijacked agent can't self-disable. Regression for the
    `nota off` fall-open hole (audit #1, same class as c9b522a)."""
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    _set_tty(monkeypatch, passes=False)
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_no_biometric_opt_in_proceeds(monkeypatch) -> None:
    """A genuine headless operator can opt in explicitly with --no-biometric;
    it proceeds (and is logged loudly)."""
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    _set_tty(monkeypatch, passes=False)
    c = _Console()
    _require_disable_auth(c, no_biometric=True)  # must not raise
    assert any("--no-biometric" in m for m in c.messages)


def test_tty_challenge_success_proceeds(monkeypatch) -> None:
    """The human-path fallback: no Touch ID dialog, but a human at a real tty
    types the phrase correctly -> the disable proceeds. This is the case that
    makes `nota off` usable on an ad-hoc-signed uv install where Touch ID
    cannot present a dialog."""
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    _set_tty(monkeypatch, passes=True)
    _require_disable_auth(_Console())  # must not raise


def test_adhoc_interpreter_skips_touchid_to_tty(monkeypatch) -> None:
    """The real-world case: hardware can evaluate (is_available True) but the
    ad-hoc-signed uv interpreter can't PRESENT the sheet (can_present_ui False),
    so we skip Touch ID entirely and go straight to the tty challenge - no 30s
    hang. authenticate() must NOT be called."""
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(touchid, "can_present_ui", lambda: False)

    def _explode(**_k):  # pragma: no cover - must never be called
        raise AssertionError("authenticate() called despite can_present_ui False")

    monkeypatch.setattr(touchid, "authenticate", _explode)
    _set_tty(monkeypatch, passes=True)
    _require_disable_auth(_Console())  # must not raise


def test_touchid_timeout_falls_through_to_tty(monkeypatch) -> None:
    """is_available() True but evaluatePolicy never presented (timeout/not_
    available): fall through to the tty challenge rather than hard-refuse a
    human who simply can't get a dialog on this build."""
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid, "authenticate", lambda **_k: touchid.TouchIDResult(False, "timeout")
    )
    _set_tty(monkeypatch, passes=True)
    _require_disable_auth(_Console())  # must not raise


def test_touchid_cancel_does_not_fall_through(monkeypatch) -> None:
    """An EXPLICIT Touch ID deny (cancel/auth_failed/lockout) refuses outright
    and must NOT reach the weaker tty challenge."""
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid, "authenticate", lambda **_k: touchid.TouchIDResult(False, "auth_failed")
    )

    def _explode(*_a, **_k):  # pragma: no cover - must never be called
        raise AssertionError("tty challenge reached after an explicit Touch ID deny")

    monkeypatch.setattr(cli, "_human_tty_challenge", _explode)
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_passes_on_touchid_success(monkeypatch) -> None:
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(touchid, "authenticate", lambda **_k: touchid.TouchIDResult(True, "ok"))
    _require_disable_auth(_Console())  # must not raise


def test_pause_json_is_in_adapter_gate_surface() -> None:
    from nota.adapters.claude_code import _GATE_CONFIG_SUFFIXES

    assert any("pause.json" in s for s in _GATE_CONFIG_SUFFIXES)


# ---------------------------------------------------------------------------
# REAL (un-mocked) boundary tests. Everything above mocks _human_tty_challenge;
# these run the actual /dev/tty open in a process with NO controlling terminal,
# which is exactly the agent/headless case. If the human-presence check ever
# regressed to reading stdin (which an agent could feed) instead of /dev/tty,
# or stopped fail-closing on OSError, these break. They cannot be mocked green.
# ---------------------------------------------------------------------------


def test_human_tty_challenge_failcloses_with_no_controlling_tty() -> None:
    import subprocess
    import sys

    code = (
        "from nota.cli import _human_tty_challenge\n"
        "class C:\n"
        "    def print(self, *a, **k):\n"
        "        pass\n"
        "print('RESULT', _human_tty_challenge(C(), 'test action'))\n"
    )
    # start_new_session=True detaches from the controlling terminal, so
    # open('/dev/tty') raises OSError -> the challenge must return False (and
    # must NOT hang waiting on input). A 15s timeout catches a hang regression.
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=15,
    )
    assert "RESULT False" in proc.stdout, (proc.stdout, proc.stderr)
