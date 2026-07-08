"""Tests for `nota integrate` — teaching coding agents to query Nota."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer

from nota.cli import app
from nota.integrate import (
    MARKER_BEGIN,
    MARKER_END,
    Integration,
    all_integrations,
    get_integration,
    install,
    uninstall,
)


def _registered_commands(t: typer.Typer, prefix: str = "") -> set[str]:
    """Every command path the Typer app actually exposes, e.g. ``saves`` and
    ``audit show``. Group names alone (e.g. ``audit``) are NOT included, since
    they are not runnable commands on their own."""
    names: set[str] = set()
    for cmd in t.registered_commands:
        name = cmd.name or cmd.callback.__name__.replace("_", "-")
        names.add((prefix + name).strip())
    for grp in t.registered_groups:
        assert grp.typer_instance is not None
        names |= _registered_commands(grp.typer_instance, prefix=f"{prefix}{grp.name} ")
    return names


def _nota_commands_in_snippet(snippet: str) -> list[str]:
    """Pull every ``nota <subcommand ...>`` reference out of a snippet's
    inline code spans and resolve each to its registered command path
    (1- or 2-token), so a fabricated command surfaces as its raw name."""
    found: list[str] = []
    for span in re.findall(r"`([^`]+)`", snippet):
        tokens = span.split()
        if not tokens or tokens[0] != "nota":
            continue
        # command tokens run until the first flag / placeholder / value arg
        cmd: list[str] = []
        for tok in tokens[1:]:
            if re.fullmatch(r"[a-z][a-z0-9-]*", tok):
                cmd.append(tok)
            else:
                break
        if cmd:
            # prefer the 2-token path (group + subcommand), else the bare command
            found.append(" ".join(cmd[:2]) if len(cmd) >= 2 else cmd[0])
    return found


# ---------------------------------------------------------------------------
# registry


def test_all_integrations_returns_expected_set():
    names = {i.name for i in all_integrations()}
    assert names == {"claude-code", "cursor", "aider"}


def test_get_integration_finds_known():
    assert get_integration("claude-code") is not None
    assert get_integration("cursor") is not None
    assert get_integration("aider") is not None


def test_get_integration_returns_none_for_unknown():
    assert get_integration("not-a-real-agent") is None


def test_each_integration_has_snippet_and_target():
    for integ in all_integrations():
        assert integ.snippet
        assert integ.target_path_project
        assert MARKER_BEGIN not in integ.snippet  # marker added at wrap-time, not in raw snippet


# ---------------------------------------------------------------------------
# install: fresh, repeat, refresh


@pytest.fixture
def fake_integration(tmp_path: Path) -> Integration:
    """An integration that writes into tmp_path, isolated from the real fs."""
    return Integration(
        name="test-agent",
        label="Test Agent",
        detect_paths=(),
        target_path_global=tmp_path / "global-rules.md",
        target_path_project=tmp_path / "rules.md",
        snippet="## Test Nota\n\nRun `nota saves` for stats.",
    )


def test_install_fresh_creates_file_with_block(fake_integration: Integration) -> None:
    path, status = install(fake_integration)
    assert status == "installed"
    assert path.exists()
    text = path.read_text()
    assert MARKER_BEGIN in text
    assert MARKER_END in text
    assert "Run `nota saves`" in text


def test_install_idempotent_when_snippet_unchanged(fake_integration: Integration) -> None:
    install(fake_integration)
    path, status = install(fake_integration)
    assert status == "current"
    # exactly one block, not two
    text = path.read_text()
    assert text.count(MARKER_BEGIN) == 1


def test_install_refreshes_when_snippet_drifted(
    fake_integration: Integration,
    tmp_path: Path,
) -> None:
    install(fake_integration)
    # corrupt the existing block with an old snippet
    text = fake_integration.target_path_project.read_text()
    drifted = text.replace("Run `nota saves`", "Run `nota old-command`")
    fake_integration.target_path_project.write_text(drifted)

    path, status = install(fake_integration)
    assert status == "refreshed"
    text = path.read_text()
    assert "Run `nota saves`" in text
    assert "nota old-command" not in text
    # still exactly one block
    assert text.count(MARKER_BEGIN) == 1


def test_install_preserves_surrounding_content(fake_integration: Integration) -> None:
    """User's existing CLAUDE.md content should not be touched."""
    fake_integration.target_path_project.write_text(
        "# My Project Rules\n\nUse spaces, not tabs.\n\nSomething else here.\n",
    )
    install(fake_integration)
    text = fake_integration.target_path_project.read_text()
    assert "# My Project Rules" in text
    assert "Use spaces, not tabs." in text
    assert "Something else here." in text
    assert MARKER_BEGIN in text


def test_install_appends_at_end_when_no_prior_block(fake_integration: Integration) -> None:
    fake_integration.target_path_project.write_text("existing content\n")
    install(fake_integration)
    text = fake_integration.target_path_project.read_text()
    assert text.startswith("existing content")
    # Nota block is after the existing content
    assert text.index("existing content") < text.index(MARKER_BEGIN)


def test_install_global_scope_writes_to_global_path(fake_integration: Integration) -> None:
    path, status = install(fake_integration, global_scope=True)
    assert status == "installed"
    assert path == fake_integration.target_path_global
    assert path.exists()


def test_install_global_raises_when_no_global_path(tmp_path: Path) -> None:
    """Cursor / Aider have no per-user rules file; global install should error."""
    integ = Integration(
        name="no-global",
        label="No-Global",
        detect_paths=(),
        target_path_global=None,
        target_path_project=tmp_path / "rules.md",
        snippet="test",
    )
    with pytest.raises(ValueError):
        install(integ, global_scope=True)


# ---------------------------------------------------------------------------
# uninstall


def test_uninstall_removes_block_only(fake_integration: Integration) -> None:
    fake_integration.target_path_project.write_text(
        "# header\n\nsome content\n",
    )
    install(fake_integration)
    text_with_block = fake_integration.target_path_project.read_text()
    assert MARKER_BEGIN in text_with_block

    path, removed = uninstall(fake_integration)
    assert removed
    text = path.read_text()
    assert MARKER_BEGIN not in text
    assert MARKER_END not in text
    # user content preserved
    assert "# header" in text
    assert "some content" in text


def test_uninstall_noop_when_block_absent(fake_integration: Integration) -> None:
    fake_integration.target_path_project.write_text("nothing to remove here\n")
    path, removed = uninstall(fake_integration)
    assert not removed


def test_uninstall_noop_when_file_missing(fake_integration: Integration) -> None:
    path, removed = uninstall(fake_integration)
    assert not removed
    assert not path.exists()


# ---------------------------------------------------------------------------
# snippet content sanity


def test_claude_code_snippet_includes_core_commands() -> None:
    integ = get_integration("claude-code")
    assert integ is not None
    s = integ.snippet
    for cmd in ["nota saves", "nota receipts", "nota audit show", "nota audit export"]:
        assert cmd in s, f"snippet should reference {cmd}"


def test_cursor_snippet_includes_core_commands() -> None:
    integ = get_integration("cursor")
    assert integ is not None
    s = integ.snippet
    for cmd in ["nota saves", "nota receipts", "nota audit"]:
        assert cmd in s


def test_aider_snippet_includes_core_commands() -> None:
    integ = get_integration("aider")
    assert integ is not None
    s = integ.snippet
    for cmd in ["nota saves", "nota receipts", "nota audit"]:
        assert cmd in s


def test_snippets_never_invent_unimplemented_commands() -> None:
    """Every ``nota <subcommand>`` a snippet tells the agent to run must be a
    REAL command registered on the CLI. A fabricated command (e.g.
    ``nota nuke-everything``) must fail this test rather than get shipped into
    a user's agent rules file."""
    registered = _registered_commands(app)
    # sanity: introspection actually found the CLI's commands
    assert {"saves", "audit show", "receipts list", "trifecta show"} <= registered

    checked = 0
    for integ in all_integrations():
        referenced = _nota_commands_in_snippet(integ.snippet)
        assert referenced, f"{integ.name} snippet references no nota commands"
        for cmd in referenced:
            checked += 1
            assert cmd in registered, (
                f"{integ.name} snippet references `nota {cmd}`, which is not a "
                f"registered CLI command. Known commands: {sorted(registered)}"
            )
    assert checked  # we actually cross-checked at least one command
