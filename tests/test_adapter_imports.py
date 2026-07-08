"""Import-guard smoke test for the gate-critical modules.

Why this exists: a NameError introduced in `adapters/claude_code.py` (a
reference to a not-yet-imported module) is invisible to a lint that only
checks the file in isolation, but it crashes the PreToolUse hook's
`self_test()` at runtime - and because the gate fails closed, that crash
denies EVERY subsequent tool call on the machine until an operator pauses
the gate by hand. A missing import must be caught here, as a red test,
not in production as a lockout.

These tests do nothing clever: they import each gate-critical module and
exercise the hook's own `self_test()`, so any import-time or first-call
NameError surfaces as a test failure.
"""

from __future__ import annotations

import importlib

import pytest

# Every module on or adjacent to the gate hot path. If any of these fails to
# import, the gate is at risk of failing closed in production.
GATE_CRITICAL_MODULES = [
    "nota.adapters.claude_code",
    "nota.adapters.cursor",
    "nota.audit",
    "nota.policy",
    "nota.secrets",
    "nota.pause",
    "nota.taint",
    "nota.exports",
    "nota.cli",
]


@pytest.mark.parametrize("module_name", GATE_CRITICAL_MODULES)
def test_gate_critical_module_imports_clean(module_name: str) -> None:
    """The module imports with no NameError / ImportError."""
    importlib.import_module(module_name)


def test_claude_code_hook_self_test_passes() -> None:
    """self_test() is what the live hook runs before every decision; if it
    raises (e.g. a missing import surfaced on first call), the gate fails
    closed and locks the operator out. Assert it returns cleanly."""
    mod = importlib.import_module("nota.adapters.claude_code")
    ok, reason = mod.self_test()
    assert ok, f"claude_code self_test failed: {reason}"


def test_summarize_call_runs_without_nameerror() -> None:
    """The exact path that broke: _summarize_call references the secrets
    module for redaction; a missing import only blows up when called."""
    mod = importlib.import_module("nota.adapters.claude_code")
    out = mod._summarize_call("Bash", {"command": "echo hello"})
    assert "echo hello" in out
