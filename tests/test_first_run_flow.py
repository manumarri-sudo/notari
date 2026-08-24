"""A new user following the README verbatim must reach a PASS.

This flow was broken in two independent ways, and both produced a BLOCK on the very
first verify, which is the worst possible first impression for a security tool because
the user cannot tell a real finding from a setup mistake:

  1. The README quickstart scoped a task to `src/auth/**`, but `notari init`
     auto-forbids sensitive directory names and `auth` is one of them. Forbidden beats
     contract scope, so the documented example BLOCKed by design.
  2. `notari init` told the user to commit `.notari/` while also writing
     `.github/workflows/notari-change-control.yml` and `.gitignore`. Those landed in
     the first CHANGE commit instead, so verify reported gate-tamper against Notari's
     own workflow, and then an out-of-scope edit to `.gitignore`.

The instruction is now derived from `git status` rather than hand-written, because the
hand-written version was corrected once and was still wrong.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_NOTARI = str(Path(sys.executable).parent / "notari")


def _git(repo: Path, *args: str, env: dict[str, str]) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True, env=env)


@pytest.fixture
def fresh_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "repo"
    (repo / "src" / "api").mkdir(parents=True)
    (tmp_path / "nhome").mkdir()
    (tmp_path / "fakehome").mkdir()
    env = {
        **os.environ,
        "NOTARI_HOME": str(tmp_path / "nhome"),
        "HOME": str(tmp_path / "fakehome"),
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
    }
    _git(repo, "init", "-q", "-b", "main", env=env)
    _git(repo, "config", "user.email", "t@e", env=env)
    _git(repo, "config", "user.name", "t", env=env)
    (repo / "src" / "api" / "app.py").write_text("x = 1\n")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "base", env=env)
    return repo, env


def _run(repo: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_NOTARI, *args], cwd=repo, env=env, capture_output=True, text=True)


def test_init_names_every_path_it_touched(fresh_repo: tuple[Path, dict[str, str]]) -> None:
    """The instruction must cover everything init wrote, or the leftovers land in the
    user's first change commit and are read as tampering."""
    repo, env = fresh_repo
    out = _run(repo, env, "init").stdout
    add_line = next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("git add")), "")
    assert add_line, out
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, env=env, capture_output=True, text=True
    ).stdout
    touched = {ln[3:].strip().split("/", 1)[0] for ln in status.splitlines() if ln[3:].strip()}
    for path in touched:
        assert path in add_line, f"init wrote {path} but did not tell the user to commit it"


def test_readme_quickstart_reaches_pass(fresh_repo: tuple[Path, dict[str, str]]) -> None:
    """Runs the documented flow exactly, including the git command init prints."""
    repo, env = fresh_repo
    out = _run(repo, env, "init").stdout
    add_line = next(ln.strip() for ln in out.splitlines() if ln.strip().startswith("git add"))
    subprocess.run(add_line, cwd=repo, env=env, shell=True, check=True, capture_output=True)
    _git(repo, "commit", "-qm", "add notari change control", env=env)

    _run(repo, env, "begin", "add rate limiting", "--scope", "src/api/**")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "contract", env=env)

    (repo / "src" / "api" / "app.py").write_text("x = 2\n")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "the agent's change", env=env)

    verify = _run(repo, env, "verify")
    combined = verify.stdout + verify.stderr
    assert "✅ PASS" in combined, combined


def test_scoping_into_an_auto_forbidden_directory_blocks(
    fresh_repo: tuple[Path, dict[str, str]],
) -> None:
    """The behaviour the README now warns about, pinned so the warning stays true:
    `auth` is auto-forbidden, and forbidden beats contract scope."""
    repo, env = fresh_repo
    (repo / "src" / "auth").mkdir()
    (repo / "src" / "auth" / "login.py").write_text("x = 1\n")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "add auth", env=env)

    out = _run(repo, env, "init").stdout
    add_line = next(ln.strip() for ln in out.splitlines() if ln.strip().startswith("git add"))
    subprocess.run(add_line, cwd=repo, env=env, shell=True, check=True, capture_output=True)
    _git(repo, "commit", "-qm", "setup", env=env)

    _run(repo, env, "begin", "x", "--scope", "src/auth/**")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "contract", env=env)
    (repo / "src" / "auth" / "login.py").write_text("x = 2\n")
    _git(repo, "add", "-A", env=env)
    _git(repo, "commit", "-qm", "change", env=env)

    combined = "".join(_run(repo, env, "verify").stdout)
    assert "BLOCK" in combined
    assert "forbidden perimeter surface" in combined


def test_readme_does_not_scope_the_quickstart_into_a_forbidden_dir() -> None:
    """The specific documentation defect: the quickstart example must not use a path
    that `notari init` forbids by default."""
    from notari.perimeter import _SENSITIVE_DIR_NAMES

    readme = (Path(__file__).parent.parent / "README.md").read_text()
    quickstart = readme.split("## What you actually get")[0]
    for line in quickstart.splitlines():
        if "notari begin" not in line or "--scope" not in line:
            continue
        for name in _SENSITIVE_DIR_NAMES:
            assert f"/{name}/" not in line, (
                f"quickstart scopes into auto-forbidden {name!r}: {line}"
            )
