"""The REAL hook, with NOTARI_HOME relocated, against `sed` in both flag
orders, with quoted flags, and a read-only `sed -n` control.

On 0.5.4 the hook denied `sed -n -i.bak -e 's/before/after/p' <gate-file>`;
the first 0.5.5 candidate allowed it because its adapter looked for `-i`
right after `sed`. The adapter now uses the same parsed write targets for the
default and the relocated state directory (Manu's finding 1, 2026-11-08).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _decide(home: Path, command: str) -> str:
    """Drive the real hook in a subprocess so NOTARI_HOME is honoured cleanly."""
    code = (
        "import json,sys;"
        "sys.path.insert(0,'src');"
        "from notari.adapters import claude_code as CC;"
        "o=CC.run_hook(json.dumps(json.loads(sys.argv[1])));"
        "print(o.get('hookSpecificOutput',{}).get('permissionDecision',''))"
    )
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, "-c", code, payload],
        cwd=Path(__file__).parent.parent,
        env={**os.environ, "NOTARI_HOME": str(home), "NOTARI_RESPECT_BYPASS": "0"},
        capture_output=True,
        text=True,
    )
    return (
        proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else f"ERR:{proc.stderr[-300:]}"
    )


@pytest.fixture
def relocated_home(tmp_path: Path) -> Path:
    home = tmp_path / "state"
    home.mkdir()
    (home / "pause.json").write_text(
        json.dumps({"paused": False, "expires_at": "", "reason": "", "allowed_count": 0})
    )
    return home


@pytest.mark.parametrize(
    "shape",
    [
        "sed -n -i.bak -e 's/before/after/p' {gate}",
        "sed -i.bak -n -e 's/before/after/p' {gate}",
        "sed '-n' '-i.bak' -e 's/before/after/p' {gate}",
        "sed -e 's/false/true/' -i '' {gate}",
        "nice -n 1 sed -e 's/false/true/' -i '' {gate}",
        "sed -i 's/false/true/' \"{gate}\"",
    ],
)
def test_in_place_sed_on_relocated_gate_state_is_denied(relocated_home: Path, shape: str) -> None:
    gate = relocated_home / "pause.json"
    assert _decide(relocated_home, shape.format(gate=gate)) == "deny"


def test_read_only_sed_on_relocated_gate_state_is_allowed(relocated_home: Path) -> None:
    gate = relocated_home / "pause.json"
    decision = _decide(relocated_home, f"sed -n -e 's/before/after/p' {gate}")
    assert decision in {"allow", "ask"}, decision


def test_split_path_and_redirect_protections_still_hold(relocated_home: Path) -> None:
    gate = relocated_home / "pause.json"
    parent, name = str(gate.parent), gate.name
    assert _decide(relocated_home, f'echo x > "{parent}"/"{name}"') == "deny"
    assert _decide(relocated_home, f"cp /tmp/x {parent}") == "deny"
    assert _decide(relocated_home, f"cat {gate} | head -1") in {"allow", "ask"}
