"""The gate's own state must not be writable by the agent it is gating.

A full bypass shipped here. The self-tamper surface was an ENUMERATED list of
filenames, and it listed `pause.json` while omitting `approvals.json` and
`overnight.json`, which are the two files that actually turn a refusal into an allow.
Writing a forged record into `approvals.json` flipped a CRITICAL `git push --force`
from deny to allow, with no Touch ID, no `notari approve`, and no human anywhere:

    A1 baseline                    -> deny
    A2 after forging approvals.json -> allow ("approved one-shot via notari approve")

The asymmetry proves it was an oversight rather than a decision: `notari night` is
CRITICAL as a command and `overnight.turn_on()` is CRITICAL as a python payload, while
writing the file both converge on classified as LOW, meaning silently allowed.

The rule is now the DIRECTORY, not a list of files, on both the command layer and the
write-tool layer, so a state file added next year is covered the day it is added. The
list had already fallen behind twice.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _decide(home: Path, tool: str, args: dict[str, object]) -> str:
    """Drive the real hook in a subprocess so NOTARI_HOME is honoured cleanly."""
    code = (
        "import json,sys;"
        "sys.path.insert(0,'src');"
        "from notari.adapters import claude_code as CC;"
        "o=CC.run_hook(json.dumps(json.loads(sys.argv[1])));"
        "print(o.get('hookSpecificOutput',{}).get('permissionDecision',''))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, json.dumps({"tool_name": tool, "tool_input": args})],
        cwd=Path(__file__).parent.parent,
        env={**os.environ, "NOTARI_HOME": str(home), "NOTARI_RESPECT_BYPASS": "0"},
        capture_output=True,
        text=True,
    )
    return (
        proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else f"ERR:{proc.stderr[-200:]}"
    )


@pytest.mark.parametrize("state_file", ["approvals.json", "overnight.json", "pause.json"])
def test_bash_cannot_write_gate_state(tmp_path: Path, state_file: str) -> None:
    home = tmp_path / "nhome"
    home.mkdir()
    assert _decide(home, "Bash", {"command": f"echo x > {home}/{state_file}"}) == "deny"


@pytest.mark.parametrize("state_file", ["approvals.json", "overnight.json"])
def test_write_tool_cannot_write_gate_state(tmp_path: Path, state_file: str) -> None:
    home = tmp_path / "nhome"
    home.mkdir()
    decision = _decide(home, "Write", {"file_path": str(home / state_file), "content": "{}"})
    assert decision == "deny"


def test_a_state_file_added_later_is_covered_without_a_code_change(tmp_path: Path) -> None:
    """The point of protecting the directory rather than a list."""
    home = tmp_path / "nhome"
    home.mkdir()
    assert (
        _decide(home, "Write", {"file_path": str(home / "invented_later.json"), "content": "x"})
        == "deny"
    )


def test_relocated_notari_home_is_protected_from_a_bash_redirect(tmp_path: Path) -> None:
    """`classify_command` matches on TEXT and only knows the literal name `.notari`,
    so a relocated NOTARI_HOME was unprotected against a redirect while the default
    install was covered."""
    home = tmp_path / "somewhere_else"
    home.mkdir()
    assert _decide(home, "Bash", {"command": f"tee {home}/approvals.json"}) == "deny"


def test_reads_and_ordinary_writes_are_unaffected(tmp_path: Path) -> None:
    """The fix must not turn the gate into a nuisance: reading its own state is fine,
    and writing anywhere else is fine."""
    home = tmp_path / "nhome"
    home.mkdir()
    assert _decide(home, "Bash", {"command": f"cat {home}/approvals.json"}) == "allow"
    assert _decide(home, "Bash", {"command": f"echo hi > {tmp_path}/ordinary.txt"}) == "allow"
    assert _decide(home, "Bash", {"command": "git status"}) == "allow"


def test_symlink_aliasing_does_not_defeat_the_path_check(tmp_path: Path) -> None:
    """The check RESOLVES the path rather than comparing text, so an innocuous-looking
    symlink pointing at the agent's hook settings is still caught."""
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from notari.adapters.claude_code import _is_gate_config_path

    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text("{}")
    alias = tmp_path / "innocuous.json"
    alias.symlink_to(claude / "settings.json")
    assert _is_gate_config_path(str(alias)) is True
    assert _is_gate_config_path(str(tmp_path / "unrelated.json")) is False
