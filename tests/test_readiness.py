"""Tests for the readiness assessment, especially the trap that a local key
file is NOT a boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from notari import attest, readiness
from notari import perimeter as perimeter_mod
from notari import provenance as provenance_mod
from notari.readiness import Posture


def _sign_perimeter(root: Path) -> str:
    """Write + sign a default perimeter; return the approver public PEM."""
    priv_pem, pub_pem = attest.generate_keypair()
    d = provenance_mod.approvers_dir(root)
    d.mkdir(parents=True, exist_ok=True)
    (d / "human.pub").write_text(pub_pem)
    per = perimeter_mod.default_perimeter(approved_by="alice")
    per.write(root)
    provenance_mod.sign_artifact(per.to_dict(), priv_pem, perimeter_mod.signature_path(root))
    return pub_pem


def _pinned_workflow(root: Path) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "notari.yml").write_text(
        "on:\n  pull_request_target:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n"
        "      - uses: manumarri-sudo/notari@" + "a" * 40 + "\n"
    )


def test_unconfigured_when_no_perimeter(tmp_path: Path) -> None:
    assert readiness.assess(tmp_path, env={}).posture is Posture.UNCONFIGURED


def test_cooperative_when_key_is_local_only(tmp_path: Path) -> None:
    """A committed/local approver key with no CI-secret pin is NOT a boundary -
    the agent on the box can read it. Must be COOPERATIVE, not ENFORCED."""
    _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    report = readiness.assess(tmp_path, env={})  # no NOTARI_APPROVER_PUBKEYS
    assert report.posture is Posture.COOPERATIVE
    assert any("approver trust root" in c.name and not c.ok for c in report.checks)


def test_enforced_when_trust_root_is_off_box(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    env = {
        provenance_mod.APPROVER_ENV: pub_pem,  # CI secret pin
        "NOTARI_GATE_KEY": attest.generate_keypair()[0],
    }
    report = readiness.assess(tmp_path, env=env)
    assert report.posture is Posture.ENFORCED
    assert not report.blockers


def test_unpinned_workflow_is_a_blocker(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    # runs the PR's own checkout, a PR could modify its own judge
    (wf / "notari.yml").write_text(
        'jobs:\n  cc:\n    steps:\n      - uses: ./\n        with:\n          install-from-source: "true"\n'
    )
    report = readiness.assess(tmp_path, env={provenance_mod.APPROVER_ENV: pub_pem})
    assert report.posture is Posture.COOPERATIVE
    assert any(c.name == "gate workflow" and not c.ok for c in report.checks)


def test_workflow_that_only_mentions_notari_is_not_a_gate(tmp_path: Path) -> None:
    """A release or docs workflow that says "notari" in a comment or a PyPI URL
    does not run the gate, so it must not be judged as an unpinned gate. Notari's
    own release.yml tripped this: `notari status` reported it as "referenced but
    not pinned" next to a correctly pinned gate workflow."""
    pub_pem = _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    (wf / "release.yml").write_text(
        "# publishes notari to PyPI\n"
        "jobs:\n  publish:\n    environment:\n      url: https://pypi.org/p/notari\n"
        "    steps:\n      - run: python -m build\n"
    )
    assert "release.yml" not in {p.name for p in readiness._notari_workflow_files(tmp_path)}
    report = readiness.assess(tmp_path, env={provenance_mod.APPROVER_ENV: pub_pem})
    gate = [c for c in report.checks if c.name == "gate workflow"]
    assert gate and gate[0].ok, gate


def test_workflow_running_the_cli_is_a_gate(tmp_path: Path) -> None:
    """Wiring Notari in without the action (`pip install notari` + `notari
    verify`) still counts as a gate workflow, so it is still checked."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "gate.yml").write_text(
        "on:\n  pull_request:\njobs:\n  cc:\n    steps:\n"
        "      - run: pip install notari==0.4.3\n      - run: notari verify --strict\n"
    )
    assert [p.name for p in readiness._notari_workflow_files(tmp_path)] == ["gate.yml"]


@pytest.mark.parametrize(
    "text",
    [
        # self-checkout gate that only names itself after Notari
        "name: Notari gate\non:\n  pull_request:\njobs:\n  cc:\n    steps:\n      - uses: ./\n",
        "jobs:\n  cc:\n    steps:\n      - uses: ./.github/actions/notari\n",
        "jobs:\n  cc:\n    steps:\n      - uses: org/notari-action@0123456789abcdef\n",
        "jobs:\n  cc:\n    steps:\n      - run: notari --base main verify\n",
        "jobs:\n  cc:\n    steps:\n      - run: pipx install notari && notari status\n",
        "jobs:\n  cc:\n    steps:\n      - run: uv tool install notari\n",
    ],
)
def test_workflow_wiring_shapes_are_gates(tmp_path: Path, text: str) -> None:
    """Every way a workflow can wire Notari in is still checked (review of the
    first filter, 2026-10-26: it missed `uses: ./`, `-action@`, `pipx`)."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "gate.yml").write_text(text)
    assert [p.name for p in readiness._notari_workflow_files(tmp_path)] == ["gate.yml"]


def test_tampered_perimeter_is_not_enforced(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    # widen the perimeter after signing -> signature no longer matches
    perimeter_mod.default_perimeter(forbidden_paths=()).write(tmp_path)
    report = readiness.assess(tmp_path, env={provenance_mod.APPROVER_ENV: pub_pem})
    assert report.posture is Posture.COOPERATIVE
    assert any(c.name == "perimeter signature" and not c.ok for c in report.checks)


def test_action_manifest_has_no_workflow_only_contexts() -> None:
    """`action.yml` is a composite action MANIFEST, and GitHub evaluates `${{ }}`
    inside it, including inside input `description` prose. `secrets` and `vars` are
    workflow-only contexts, so referencing them anywhere in the manifest makes the
    whole action fail to LOAD with a TemplateValidationException.

    This shipped broken: every run of the change-control workflow failed from at least
    2026-07-10, four for four, and nine adversarial security review passes did not
    catch it because none of them ran the Action on a real runner. Write context names
    as plain prose in descriptions instead.
    """
    import re
    from pathlib import Path

    manifest = (Path(__file__).parent.parent / "action.yml").read_text()
    expressions = re.findall(r"\$\{\{(.*?)\}\}", manifest, flags=re.S)
    offenders = [e.strip() for e in expressions if re.search(r"\b(secrets|vars)\.", e)]
    assert offenders == [], offenders
