"""`nota init` must emit a workflow that `nota status` (readiness) accepts, and
readiness must reject the unsafe shapes. These two surfaces previously disagreed:
init emitted a mutable ``@v0`` tag while readiness demanded a 40-hex SHA pin, so a
fresh install produced a workflow its own status command flagged."""

from __future__ import annotations

from pathlib import Path

from nota import readiness
from nota.cli import _CONSUMER_WORKFLOW
from nota.readiness import Level


def _write_wf(root: Path, text: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "nota.yml").write_text(text)


def test_init_workflow_passes_readiness(tmp_path: Path) -> None:
    """The template init writes must satisfy the gate-workflow blocker."""
    _write_wf(tmp_path, _CONSUMER_WORKFLOW)
    check = readiness._workflow_pinning(tmp_path)
    assert check.ok, check.detail


def test_init_workflow_isolation_hardening_passes(tmp_path: Path) -> None:
    _write_wf(tmp_path, _CONSUMER_WORKFLOW)
    hardening = readiness._workflow_hardening(tmp_path)
    by_name = {c.name: c for c in hardening}
    assert by_name["checkout credentials"].ok
    assert by_name["candidate checkout isolation"].ok


def test_readiness_rejects_pull_request_trigger(tmp_path: Path) -> None:
    _write_wf(
        tmp_path,
        "on:\n  pull_request:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n"
        "      - uses: manumarri-sudo/nota@" + "a" * 40 + "\n",
    )
    check = readiness._workflow_pinning(tmp_path)
    assert not check.ok
    assert "pull_request" in check.detail


def test_readiness_rejects_mutable_tag(tmp_path: Path) -> None:
    """A tag (even @v0) is mutable — whoever controls it can swap the gate code."""
    _write_wf(
        tmp_path,
        "on:\n  pull_request_target:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n      - uses: manumarri-sudo/nota@v0\n",
    )
    check = readiness._workflow_pinning(tmp_path)
    assert not check.ok
    assert "SHA-pinned" in check.detail or "SHA" in check.detail


def test_readiness_rejects_install_from_source(tmp_path: Path) -> None:
    _write_wf(
        tmp_path,
        "jobs:\n  cc:\n    steps:\n      - uses: ./\n"
        '        with:\n          install-from-source: "true"\n',
    )
    check = readiness._workflow_pinning(tmp_path)
    assert not check.ok
    assert check.level is Level.BLOCKER


def test_readiness_does_not_launder_pull_request_across_files(tmp_path: Path) -> None:
    """A pull_request_target in an UNRELATED workflow must not make a pull_request
    Nota gate look enforced (cross-file overstatement, R10 MEDIUM-3)."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    # The real Nota gate is on the unsafe pull_request trigger.
    (wf / "nota.yml").write_text(
        "on:\n  pull_request:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n      - uses: manumarri-sudo/nota@" + "a" * 40 + "\n"
    )
    # An unrelated workflow happens to use pull_request_target.
    (wf / "other.yml").write_text(
        "on:\n  pull_request_target:\n    branches: [main]\n"
        "jobs:\n  x:\n    steps:\n      - run: echo hi\n"
    )
    check = readiness._workflow_pinning(tmp_path)
    assert not check.ok, "the pull_request Nota gate must not be laundered as enforced"
    assert "pull_request" in check.detail


def test_readiness_flags_missing_persist_credentials_as_hardening(tmp_path: Path) -> None:
    """A SHA-pinned pull_request_target workflow with no persist-credentials:false
    is still a valid boundary (blocker passes) but hardening surfaces the gap."""
    _write_wf(
        tmp_path,
        "on:\n  pull_request_target:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n      - uses: manumarri-sudo/nota@" + "a" * 40 + "\n",
    )
    assert readiness._workflow_pinning(tmp_path).ok
    hardening = {c.name: c for c in readiness._workflow_hardening(tmp_path)}
    assert not hardening["checkout credentials"].ok
    assert hardening["checkout credentials"].level is Level.HARDENING
