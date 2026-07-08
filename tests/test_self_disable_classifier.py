"""The hook-layer half of the self-disable defense.

The HARD guarantee that an AI agent cannot turn the Nota gate off is NOT the
CLI Touch-ID / tty check (that only runs for a human in their own terminal, and
is defense-in-depth). It is this: an agent running `nota off|pause|night`
through its gated Bash tool classifies CRITICAL, so the PreToolUse hook DENIES
it before it runs - even under bypass mode, where HIGH would silently downshift.

These tests pin that classification so a refactor of the pattern set can't
silently re-open the hole. (audit #1/#3, self-disable closure 2026-06-12.)
"""

from __future__ import annotations

import pytest

from nota.policy import Risk, classify_command


@pytest.mark.parametrize(
    "cmd",
    [
        "nota off",
        "nota off --for 24h",
        "nota off --no-biometric",
        "nota pause",
        "nota pause --for 30m --reason x",
        "nota night",
        "NOTA OFF",  # IGNORECASE
        "sudo nota off",
    ],
)
def test_agent_gate_disable_is_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        "nota on",  # turning the gate back ON is never blocked
        "nota audit show",
        "nota receipts",
        "nota doctor",
        "nota version",
    ],
)
def test_non_disable_nota_commands_are_not_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is not Risk.CRITICAL


def test_disable_in_quoted_string_is_masked_not_flagged() -> None:
    """A quoted mention (e.g. echoing docs) is masked by _mask_quoted, so it
    does not false-positive as an agent disabling the gate."""
    assert classify_command("echo 'run nota off to pause'").risk is not Risk.CRITICAL


# ---------------------------------------------------------------------------
# Bypass closures from the 2nd independent security review.
# Gap #1: the CLI-string pattern does not cover the LIBRARY entry point.
# Gap #2: pause.json was protected against Write/Edit but not against a Bash
#         write/redirect (and a quoted path masked the original rule).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        'python -c "from nota import pause; pause.pause(duration_hours=24)"',
        'python3 -c "import nota.pause as m; m.pause()"',
        'python -c "from nota import overnight; overnight.enable()"',
        'uv run python -c "from nota import pause; pause.pause()"',
    ],
)
def test_library_disable_call_is_critical(cmd: str) -> None:
    # Was MEDIUM/auto-allowed before the fix: pausing via the library API
    # neuters the whole gate, so an agent running it via Bash must be denied.
    assert classify_command(cmd).risk is Risk.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        "echo '{}' > ~/.nota/pause.json",
        'cat /tmp/x > "$HOME/.nota/pause.json"',  # quoted path (masking case)
        "cp /tmp/x ~/.nota/pause.json",
        "tee ~/.nota/pause.json",
    ],
)
def test_bash_write_to_pause_json_is_critical(cmd: str) -> None:
    # pause.json is the gate-off switch; writing it via Bash was LOW/allow.
    assert classify_command(cmd).risk is Risk.CRITICAL


def test_benign_python_c_is_not_critical() -> None:
    # The library-disable pattern must not fire on an ordinary one-liner.
    assert classify_command('python -c "print(1 + 1)"').risk is not Risk.CRITICAL
