"""Control/data separation: candidate-controlled Python must not execute before
(or during) Nota verification.

The recommended workflow checks an untrusted PR out into a data-only directory,
and the Action installs + runs Nota in isolated mode. This test proves the two
mechanisms that make that safe actually work on THIS interpreter, and asserts the
shipped config wires them up:

  1. ``python -I`` (isolated) and ``PYTHONSAFEPATH=1`` both remove the current
     directory from ``sys.path``, so a candidate ``json.py`` / ``sitecustomize.py``
     dropped in the checkout cannot shadow stdlib or run at startup.
  2. ``action.yml`` and ``scripts/nota-passport.sh`` set those flags, and the
     init + secure-workflow templates check the PR out into ``_pr_checkout`` with
     ``persist-credentials: false`` and pass ``checkout-path`` to the Action.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]


def _candidate_dir(tmp_path: Path) -> Path:
    """A fake PR checkout that tries to hijack the interpreter three ways."""
    d = tmp_path / "_pr_checkout"
    d.mkdir()
    # A shadow stdlib module: importing json must NOT pick this up.
    (d / "json.py").write_text(
        "import pathlib, os\npathlib.Path(os.environ['NOTA_MARK']).write_text('json-shadow')\n"
    )
    # sitecustomize runs automatically at interpreter startup if importable.
    (d / "sitecustomize.py").write_text(
        "import pathlib, os\npathlib.Path(os.environ['NOTA_MARK']).write_text('sitecustomize')\n"
    )
    # A fake pip: `python -m pip` must not run this.
    (d / "pip.py").write_text(
        "import pathlib, os\npathlib.Path(os.environ['NOTA_MARK']).write_text('pip-shadow')\n"
    )
    return d


def _run(args: list[str], cwd: Path, mark: Path, extra_env: dict[str, str] | None = None) -> str:
    import os

    env = dict(os.environ)
    env["NOTA_MARK"] = str(mark)
    env.pop("PYTHONSAFEPATH", None)
    env.update(extra_env or {})
    if mark.exists():
        mark.unlink()
    subprocess.run([sys.executable, *args], cwd=cwd, env=env, capture_output=True, text=True)
    return mark.read_text() if mark.exists() else ""


def test_baseline_shadowing_is_real_without_isolation(tmp_path: Path) -> None:
    """Sanity check the THREAT exists: with cwd on sys.path, a candidate json.py
    shadows the stdlib. If this ever stops firing the isolation tests are moot."""
    d = _candidate_dir(tmp_path)
    mark = tmp_path / "mark.txt"
    # -c 'import json' with cwd = candidate dir and no isolation.
    assert _run(["-c", "import json"], d, mark) == "json-shadow"


def test_isolated_mode_blocks_module_shadowing(tmp_path: Path) -> None:
    d = _candidate_dir(tmp_path)
    mark = tmp_path / "mark.txt"
    # python -I: cwd is not on sys.path, so the candidate json.py is not imported.
    assert _run(["-I", "-c", "import json"], d, mark) == ""


def test_pythonsafepath_blocks_module_shadowing(tmp_path: Path) -> None:
    d = _candidate_dir(tmp_path)
    mark = tmp_path / "mark.txt"
    assert _run(["-c", "import json"], d, mark, {"PYTHONSAFEPATH": "1"}) == ""


def test_sitecustomize_not_run_under_isolation(tmp_path: Path) -> None:
    # A candidate sitecustomize.py must never run at interpreter startup when we
    # isolate the interpreter. (The un-isolated baseline is environment-dependent:
    # a site-packages sitecustomize may already sit ahead of cwd on sys.path, so
    # we only assert the security-relevant direction.)
    d = _candidate_dir(tmp_path)
    mark = tmp_path / "mark.txt"
    assert _run(["-I", "-c", "pass"], d, mark) == ""
    assert _run(["-c", "pass"], d, mark, {"PYTHONSAFEPATH": "1"}) == ""


def test_fake_pip_not_executed_in_isolated_mode(tmp_path: Path) -> None:
    d = _candidate_dir(tmp_path)
    mark = tmp_path / "mark.txt"
    # `python -I -m pip --version` must run the real pip, not the candidate pip.py.
    _run(["-I", "-m", "pip", "--version"], d, mark)
    assert not mark.exists() or mark.read_text() != "pip-shadow"


# --- Static assertions: the shipped config wires up the isolation --------------


def test_action_installs_and_runs_in_isolated_mode() -> None:
    action = (_REPO / "action.yml").read_text()
    assert "python -I -m pip install" in action, "install step must use isolated mode"
    assert 'PYTHONSAFEPATH: "1"' in action, "steps must export PYTHONSAFEPATH=1"
    # The privileged (secret-bearing) job must not RUN `pip install --upgrade pip`
    # (a comment explaining why we don't is fine; an actual command line is not).
    active = [
        ln.strip()
        for ln in action.splitlines()
        if not ln.strip().startswith("#") and "install --upgrade pip" in ln
    ]
    assert not active, f"privileged job must not upgrade pip: {active}"


def test_wrapper_exports_safepath() -> None:
    wrapper = (_REPO / "scripts" / "nota-passport.sh").read_text()
    assert "export PYTHONSAFEPATH=1" in wrapper


def test_wrapper_inline_python_is_isolated() -> None:
    """The wrapper runs with cwd inside the candidate checkout, so every inline
    python call must use isolated mode (-I, Python 3.4+) — not rely solely on
    PYTHONSAFEPATH (3.11+). (R10 MEDIUM-2)"""
    wrapper = (_REPO / "scripts" / "nota-passport.sh").read_text()
    bad = [
        ln.strip()
        for ln in wrapper.splitlines()
        if "python3 " in ln and not ln.strip().startswith("#") and "python3 -I" not in ln
    ]
    assert not bad, f"non-isolated python3 invocation(s) in the wrapper: {bad}"


@pytest.mark.parametrize("path", ["docs/secure-workflow.yml"])
def test_secure_workflow_is_isolated(path: str) -> None:
    text = (_REPO / path).read_text()
    assert "pull_request_target:" in text
    assert "path: _pr_checkout" in text
    assert "persist-credentials: false" in text
    assert "checkout-path: _pr_checkout" in text, "wrapper must be told where the candidate lives"


def test_init_template_matches_secure_workflow() -> None:
    from nota.cli import _CONSUMER_WORKFLOW

    for needle in (
        "pull_request_target:",
        "path: _pr_checkout",
        "persist-credentials: false",
        "checkout-path: _pr_checkout",
    ):
        assert needle in _CONSUMER_WORKFLOW, needle
    # SHA-pinned, not a mutable tag (readiness enforces this too).
    import re

    assert re.search(r"uses:\s*[\w.-]+/nota@[0-9a-f]{40}", _CONSUMER_WORKFLOW)
