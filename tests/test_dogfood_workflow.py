"""Notari must run its own boundary gate on its own pull requests.

NOTARI_AUDIT.md launch blocker 6: `.github/workflows/notari-check.yml` was deleted
in ec12614 ("Fix audit pause accounting and gate classifier regressions"), so the
project stopped running Notari on its own PRs.
"""

from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "notari-check.yml"


def test_dogfood_workflow_runs_strict_boundary_mode() -> None:
    assert WORKFLOW.exists(), "the repo no longer runs Notari on its own pull requests"
    text = WORKFLOW.read_text()
    assert "uses: ./" in text
    assert 'mode: "boundary"' in text
    assert 'strict: "true"' in text
    assert 'fail-on-block: "true"' in text
    assert "continue-on-error" not in text
