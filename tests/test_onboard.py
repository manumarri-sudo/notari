"""Tests for `nota onboard` interactive setup.

The interactive prompts themselves can't be tested without a TTY harness;
these tests cover the pure functions (detection, TOML rendering, install
dispatch) and the non-interactive abort paths.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from nota.onboard import (
    PRESET_DESCRIPTIONS,
    build_config_toml,
    detect_coding_tools,
    run,
)

# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------


def test_detect_returns_full_agent_list():
    detected = detect_coding_tools()
    assert len(detected) == 7
    names = {a.name for a in detected}
    assert names == {
        "claude_code",
        "cursor",
        "cline",
        "aider",
        "continue",
        "windsurf",
        "zed",
    }


def test_each_detected_agent_has_label():
    for agent in detect_coding_tools():
        assert agent.label
        assert isinstance(agent.detected, bool)


# ---------------------------------------------------------------------------
# TOML rendering
# ---------------------------------------------------------------------------


def test_boring_preset_renders_and_parses():
    cfg = build_config_toml(
        intent="exploratory development",
        scope=[],
        audit_path=Path("/tmp/nota/audit.log.jsonl"),
        notify={},
        preset="boring",
        trust_paths=["/tmp/myrepo"],
    )
    parsed = tomllib.loads(cfg)
    assert parsed["session"]["intent"] == "exploratory development"
    assert parsed["session"]["scope"] == []
    assert parsed["audit"]["path"] == "/tmp/nota/audit.log.jsonl"
    assert parsed["trust"]["paths"] == ["/tmp/myrepo"]
    assert parsed["telemetry"]["enabled"] is False
    # boring preset writes only the comment, no real overrides
    assert parsed.get("policy", {}) == {}


def test_paranoid_preset_upgrades_edit_write():
    cfg = build_config_toml(
        intent="paranoid session",
        scope=["fs:write:src/"],
        audit_path=Path("/tmp/nota/audit.log.jsonl"),
        notify={},
        preset="paranoid",
        trust_paths=[],
    )
    parsed = tomllib.loads(cfg)
    pol = parsed["policy"]
    assert pol["Edit"] == "high"
    assert pol["Write"] == "high"
    assert pol["MultiEdit"] == "high"
    assert pol["NotebookEdit"] == "high"


def test_scope_list_serializes_correctly():
    cfg = build_config_toml(
        intent="i",
        scope=["github:read", "fs:write:src/"],
        audit_path=Path("/tmp/a.log"),
        notify={},
        preset="boring",
        trust_paths=[],
    )
    parsed = tomllib.loads(cfg)
    assert parsed["session"]["scope"] == ["github:read", "fs:write:src/"]


def test_notify_section_emitted_when_configured():
    cfg = build_config_toml(
        intent="i",
        scope=[],
        audit_path=Path("/tmp/a.log"),
        notify={"on_blocked": True, "on_ask": False, "macos": True, "sound": "Glass"},
        preset="boring",
        trust_paths=[],
    )
    parsed = tomllib.loads(cfg)
    assert parsed["notify"]["on_blocked"] is True
    assert parsed["notify"]["macos"] is True
    assert parsed["notify"]["sound"] == "Glass"


def test_notify_section_omitted_when_empty():
    cfg = build_config_toml(
        intent="i",
        scope=[],
        audit_path=Path("/tmp/a.log"),
        notify={},
        preset="boring",
        trust_paths=[],
    )
    parsed = tomllib.loads(cfg)
    assert "notify" not in parsed


def test_generated_boring_config_loads_via_load_config(tmp_path):
    """The rendered boring-preset TOML must round-trip through nota.config.load_config."""
    from nota.config import load_config

    cfg_text = build_config_toml(
        intent="exploratory development",
        scope=["github:read"],
        audit_path=tmp_path / "audit.log.jsonl",
        notify={"on_blocked": True, "macos": True, "sound": "Glass"},
        preset="boring",
        trust_paths=[str(tmp_path)],
    )
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(cfg_text)
    config = load_config(cfg_file)
    assert config.session.intent == "exploratory development"
    assert config.session.scope == ["github:read"]
    assert config.trust.paths == [str(tmp_path)]


def test_generated_paranoid_config_loads_with_policy_overrides(tmp_path):
    """Paranoid preset writes [policy] string values; the field_validator must coerce them."""
    from nota.config import load_config
    from nota.policy import Risk

    cfg_text = build_config_toml(
        intent="paranoid session",
        scope=[],
        audit_path=tmp_path / "audit.log.jsonl",
        notify={},
        preset="paranoid",
        trust_paths=[str(tmp_path)],
    )
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(cfg_text)
    config = load_config(cfg_file)
    assert config.policy["Edit"] == Risk.HIGH
    assert config.policy["Write"] == Risk.HIGH
    assert config.policy["MultiEdit"] == Risk.HIGH
    assert config.policy["NotebookEdit"] == Risk.HIGH


def test_preset_descriptions_complete():
    assert set(PRESET_DESCRIPTIONS) == {"boring", "paranoid", "custom"}
    for desc in PRESET_DESCRIPTIONS.values():
        assert desc


# ---------------------------------------------------------------------------
# non-interactive abort
# ---------------------------------------------------------------------------


def test_run_aborts_in_non_tty(capsys, monkeypatch):
    """Non-interactive shells should exit cleanly without touching config."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    rc = run(force=False)
    assert rc == 2
    out = capsys.readouterr().out
    assert "interactive" in out.lower()


# ---------------------------------------------------------------------------
# install dispatch — verify the adapter installer fn signatures match
# ---------------------------------------------------------------------------


def test_claude_code_installer_signature():
    """The onboard module calls cc.install_into_settings(None, matcher=..., timeout=...).
    Verify the adapter's function accepts that signature."""
    import inspect

    from nota.adapters import claude_code as cc

    sig = inspect.signature(cc.install_into_settings)
    params = sig.parameters
    # First positional + matcher + timeout
    assert "matcher" in params
    assert "timeout" in params


def test_cursor_installer_signature():
    import inspect

    from nota.adapters import cursor as cu

    sig = inspect.signature(cu.install_into_settings)
    # accepts at least one positional argument
    assert len(sig.parameters) >= 1
