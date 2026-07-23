"""End-to-end Typer CliRunner tests for v0.3-prep commands.

Unit tests in test_onboard.py, test_secrets.py, test_githook.py, and
test_receipt_narrate.py cover the underlying functions. These tests
exercise the full CLI command path so typer-wiring bugs (signature
mismatch, default propagation, exit-code routing) get caught.

Each test isolates HOME / config / audit-log via monkeypatch.setenv
so the test suite can't see or mutate the developer's live Notari
state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari.cli import app


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    # Rich treats GitHub Actions as a color terminal (ANSI codes + line
    # wrapping), which breaks literal substring assertions: CI tmp paths are
    # long enough that a wrap can land mid-phrase. Pin rendering to plain
    # output wide enough that no message ever wraps.
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "500")
    return CliRunner()


def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point every Notari env var at tmp_path so tests don't touch live state."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NOTARI_HOME", str(tmp_path / ".notari"))
    monkeypatch.setenv("NOTARI_CONFIG", str(tmp_path / ".notari" / "config.toml"))
    monkeypatch.setenv("NOTARI_LOG", str(tmp_path / ".notari" / "audit.log.jsonl"))
    monkeypatch.setenv("NOTARI_KEY", str(tmp_path / ".notari" / "key"))


# ---------------------------------------------------------------------------
# top-level help / discoverability
# ---------------------------------------------------------------------------


def test_app_help_shows_grouped_core_and_hides_advanced(runner: CliRunner) -> None:
    """DX 0.3.3: the top-level help shows Core/Safety/Health panels only; the
    advanced surface stays callable but unlisted (progressive disclosure)."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for visible in ("Core", "Safety", "begin", "verify", "explain", "init", "status", "off"):
        assert visible in result.output
    # Boundary-setup primitives are now visible (0.3.4): the users setting up
    # strict mode must be able to discover the commands that make it real.
    for visible in ("Boundary setup", "keygen", "guard", "verify-passport"):
        assert visible in result.output
    # Pre-pivot / advanced surface stays callable but unlisted (progressive
    # disclosure). Assert on command names that never occur in the preamble prose.
    for hidden in ("onboard", "scan-secrets", "commit-hook-install"):
        assert hidden not in result.output
    # Hidden commands still work by name.
    assert runner.invoke(app, ["onboard", "--help"]).exit_code == 0
    assert runner.invoke(app, ["scan-secrets", "--help"]).exit_code == 0


def test_onboard_help(runner: CliRunner) -> None:
    result = runner.invoke(app, ["onboard", "--help"])
    assert result.exit_code == 0
    assert "interactive" in result.output.lower() or "setup" in result.output.lower()
    assert "--force" in result.output


def test_scan_secrets_help(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan-secrets", "--help"])
    assert result.exit_code == 0
    assert "credentials" in result.output.lower() or "secret" in result.output.lower()


def test_audit_export_help_includes_pack_flag(runner: CliRunner) -> None:
    result = runner.invoke(app, ["audit", "export", "--help"])
    assert result.exit_code == 0
    assert "--pack" in result.output
    assert "--nist" in result.output
    assert "--iso-42001" in result.output
    assert "--soc2" in result.output


def test_commit_hook_install_help(runner: CliRunner) -> None:
    result = runner.invoke(app, ["commit-hook-install", "--help"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# onboard: non-TTY abort path (no real TTY in CliRunner -> should abort)
# ---------------------------------------------------------------------------


def test_onboard_aborts_in_non_tty_context(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Without --force in a non-TTY context, onboard should exit non-zero
    rather than silently writing config with no user input."""
    _isolate(monkeypatch, tmp_path)
    # CliRunner provides a non-TTY stdin by default.
    result = runner.invoke(app, ["onboard"])
    assert result.exit_code == 2
    assert "interactive" in result.output.lower()


# ---------------------------------------------------------------------------
# scan-secrets
# ---------------------------------------------------------------------------


def test_scan_secrets_clean_file_exits_zero(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    clean = tmp_path / "clean.py"
    clean.write_text("def add(a, b):\n    return a + b\n")
    result = runner.invoke(app, ["scan-secrets", str(clean)])
    assert result.exit_code == 0
    assert "no secrets" in result.output.lower()


def test_scan_secrets_detects_github_pat_and_exits_non_zero(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    dirty = tmp_path / "dirty.py"
    dirty.write_text("TOKEN = 'ghp_" + "A" * 36 + "'\n")
    result = runner.invoke(app, ["scan-secrets", str(dirty)])
    assert result.exit_code == 1
    assert "GitHub" in result.output
    assert "secret" in result.output.lower()


def test_scan_secrets_walks_directories(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("clean = True\n")
    (src / "b.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    result = runner.invoke(app, ["scan-secrets", str(src)])
    assert result.exit_code == 1
    assert "AWS" in result.output


def test_scan_secrets_handles_missing_path(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    missing = tmp_path / "does_not_exist.py"
    result = runner.invoke(app, ["scan-secrets", str(missing)])
    assert result.exit_code == 0  # treated as skip, not hit
    assert "skip" in result.output.lower() or "no secrets" in result.output.lower()


def test_scan_secrets_skips_gitignored_files_by_default(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Inside a git repo, files matching .gitignore should NOT be scanned."""
    import subprocess

    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "t@t"],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "t"],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    # Set up: clean tracked file, .gitignore'd dir with a fake secret
    (repo / ".gitignore").write_text("ignored/\n")
    (repo / "clean.py").write_text("def add(a, b): return a + b\n")
    (repo / "ignored").mkdir()
    (repo / "ignored" / "leak.py").write_text(
        "TOKEN = 'ghp_" + "A" * 36 + "'\n",
    )
    subprocess.run(
        ["git", "add", ".gitignore", "clean.py"],
        cwd=repo,
        capture_output=True,
        check=True,
    )
    result = runner.invoke(app, ["scan-secrets", str(repo)])
    # The ignored secret should NOT be reported by default
    assert result.exit_code == 0
    assert "ignored/leak.py" not in result.output


def test_scan_secrets_no_gitignore_flag_includes_ignored(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """With --no-gitignore, .gitignore'd files SHOULD be scanned."""
    import subprocess

    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    (repo / ".gitignore").write_text("ignored/\n")
    (repo / "ignored").mkdir()
    (repo / "ignored" / "leak.py").write_text(
        "TOKEN = 'ghp_" + "A" * 36 + "'\n",
    )
    result = runner.invoke(
        app,
        ["scan-secrets", str(repo), "--no-gitignore"],
    )
    assert result.exit_code == 1
    assert "ignored/leak.py" in result.output or "ignored" in result.output


# ---------------------------------------------------------------------------
# audit export
# ---------------------------------------------------------------------------


def _seed_audit_log(path: Path) -> None:
    """Write a small audit log with one tool attempt + one allowed verdict."""
    from notari import events as ev

    path.parent.mkdir(parents=True, exist_ok=True)
    events = [
        {
            "ts": "2026-06-09T10:00:00Z",
            "session_id": "ses_test1234",
            "type": ev.SESSION_OPEN,
            "risk": "low",
            "payload": {"intent": "integration test"},
        },
        {
            "ts": "2026-06-09T10:00:01Z",
            "session_id": "ses_test1234",
            "type": ev.TOOL_ATTEMPTED,
            "risk": "low",
            "payload": {"tool_name": "Bash", "arg_keys": ["command"]},
        },
        {
            "ts": "2026-06-09T10:00:02Z",
            "session_id": "ses_test1234",
            "type": ev.VERDICT_ALLOWED,
            "risk": "low",
            "payload": {"tool_name": "Bash", "reason": "ls is read-only"},
        },
        {
            "ts": "2026-06-09T10:00:03Z",
            "session_id": "ses_test1234",
            "type": ev.SESSION_CLOSE,
            "risk": "low",
            "payload": {},
        },
    ]
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def test_audit_export_md_only(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    log = tmp_path / ".notari" / "audit.log.jsonl"
    _seed_audit_log(log)
    out_dir = tmp_path / "pack-md"
    result = runner.invoke(
        app,
        ["audit", "export", "--log", str(log), "--out", str(out_dir), "--format", "md"],
    )
    assert result.exit_code == 0
    assert (out_dir / "audit-evidence.md").exists()
    assert not (out_dir / "audit-evidence.html").exists()


def test_audit_export_no_standards_selected_fails(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    log = tmp_path / ".notari" / "audit.log.jsonl"
    _seed_audit_log(log)
    result = runner.invoke(
        app,
        ["audit", "export", "--log", str(log), "--no-aiuc-1", "--no-eu-ai-act-art-14"],
    )
    assert result.exit_code == 1
    assert "no standards" in result.output.lower()


def test_audit_export_missing_log_fails_gracefully(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    result = runner.invoke(
        app,
        ["audit", "export", "--log", str(tmp_path / "missing.jsonl")],
    )
    assert result.exit_code == 1
    assert "no log" in result.output.lower()


def test_audit_export_iso_42001_only(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify ISO 42001 can be selected independently of other standards."""
    _isolate(monkeypatch, tmp_path)
    log = tmp_path / ".notari" / "audit.log.jsonl"
    _seed_audit_log(log)
    out_dir = tmp_path / "pack-iso"
    result = runner.invoke(
        app,
        [
            "audit",
            "export",
            "--log",
            str(log),
            "--out",
            str(out_dir),
            "--no-aiuc-1",
            "--no-eu-ai-act-art-14",
            "--iso-42001",
            "--format",
            "md",
        ],
    )
    assert result.exit_code == 0
    md = (out_dir / "audit-evidence.md").read_text()
    # The ISO 42001 A.6.2.8 control should appear in the output
    assert "A.6.2.8" in md or "ISO" in md


# ---------------------------------------------------------------------------
# commit-hook-install / commit-hook-uninstall
# ---------------------------------------------------------------------------


def test_commit_hook_install_in_temp_repo(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    result = runner.invoke(
        app,
        ["commit-hook-install", "--repo", str(repo)],
    )
    assert result.exit_code == 0
    hook = repo / ".git" / "hooks" / "prepare-commit-msg"
    assert hook.exists()
    assert "notari git-hook" in hook.read_text()
    # Hook script must be executable
    assert os.access(hook, os.X_OK)


def test_commit_hook_install_refuses_non_repo(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    result = runner.invoke(
        app,
        ["commit-hook-install", "--repo", str(not_a_repo)],
    )
    assert result.exit_code == 1
    assert "not a git repo" in result.output.lower()


def test_commit_hook_install_idempotent(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo2"
    (repo / ".git").mkdir(parents=True)
    first = runner.invoke(app, ["commit-hook-install", "--repo", str(repo)])
    assert first.exit_code == 0
    second = runner.invoke(app, ["commit-hook-install", "--repo", str(repo)])
    assert second.exit_code == 0
    assert "already installed" in second.output.lower()


def test_commit_hook_uninstall_reverses_install(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo3"
    (repo / ".git").mkdir(parents=True)
    runner.invoke(app, ["commit-hook-install", "--repo", str(repo)])
    hook = repo / ".git" / "hooks" / "prepare-commit-msg"
    assert hook.exists()
    result = runner.invoke(app, ["commit-hook-uninstall", "--repo", str(repo)])
    assert result.exit_code == 0
    assert not hook.exists()


def test_commit_hook_uninstall_refuses_non_notari_hook(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo4"
    (repo / ".git" / "hooks").mkdir(parents=True)
    hook = repo / ".git" / "hooks" / "prepare-commit-msg"
    hook.write_text("#!/bin/sh\necho 'someone else hook'\n")
    result = runner.invoke(app, ["commit-hook-uninstall", "--repo", str(repo)])
    assert result.exit_code == 1
    assert "not a notari hook" in result.output.lower()
    assert hook.exists()


def test_commit_hook_uninstall_noop_when_no_hook(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo5"
    (repo / ".git").mkdir(parents=True)
    result = runner.invoke(app, ["commit-hook-uninstall", "--repo", str(repo)])
    assert result.exit_code == 0
    assert "no hook" in result.output.lower()


# ---------------------------------------------------------------------------
# git-hook shim path
# ---------------------------------------------------------------------------


def test_git_hook_shim_noop_when_no_log(
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The internal `notari git-hook` shim is invoked by the installed
    prepare-commit-msg script. With no audit log present, it should
    exit 0 and leave the commit message untouched."""
    _isolate(monkeypatch, tmp_path)
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text("an authored commit\n")
    # Simulate git invocation: arg 1 is msg file, arg 2 is source type
    result = runner.invoke(app, ["git-hook", str(msg), "message"])
    assert result.exit_code == 0
    assert msg.read_text() == "an authored commit\n"


def test_version_flag_prints_version_and_exits(runner: CliRunner) -> None:
    """`notari --version` (and -V) must print the version and exit 0, not error.
    Regression: the flag was missing and printed a usage error instead."""
    from notari._version import __version__

    for flag in ("--version", "-V"):
        result = runner.invoke(app, [flag])
        assert result.exit_code == 0, result.output
        assert __version__ in result.output


# ── F2: scope is a required, conscious choice ────────────────────────────────
# Red-team finding 2: an omitted --scope used to silently create an unrestricted
# contract that PASSed almost any diff, a signed blank cheque. begin now refuses,
# and --scope '**' is the explicit opt-out.


def test_scope_is_unrestricted_helper() -> None:
    from notari.policy import scope_is_unrestricted

    assert scope_is_unrestricted([])
    assert scope_is_unrestricted(["**"])
    assert scope_is_unrestricted(["."])
    assert scope_is_unrestricted(["src/**", "**"])  # any universal entry counts
    assert not scope_is_unrestricted(["src/**"])
    assert not scope_is_unrestricted(["src/*.py", "tests/**"])


def test_begin_without_scope_is_refused(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _isolate(monkeypatch, tmp_path)
    result = runner.invoke(app, ["begin", "add rate limiting"])
    assert result.exit_code == 2, result.output
    assert "scope is required" in result.output.lower()
    # It must point the user at the explicit opt-out, not just fail.
    assert "'**'" in result.output


def test_begin_with_explicit_star_scope_is_allowed(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import subprocess

    _isolate(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "f.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "i"], cwd=repo, capture_output=True, check=True)
    monkeypatch.chdir(repo)

    result = runner.invoke(app, ["begin", "broad task", "--scope", "**"])
    assert result.exit_code == 0, result.output
    # The explicit opt-out is allowed but must warn it is perimeter-only.
    assert "unrestricted scope" in result.output.lower()
