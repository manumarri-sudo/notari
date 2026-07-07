"""Tests for the readiness assessment — especially the trap that a local key
file is NOT a boundary."""

from __future__ import annotations

from pathlib import Path

from quill import attest, readiness
from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod
from quill.readiness import Posture


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
    (wf / "quill.yml").write_text(
        "on:\n  pull_request_target:\n    branches: [main]\n"
        "jobs:\n  cc:\n    steps:\n"
        "      - uses: manumarri-sudo/quill@" + "a" * 40 + "\n"
    )


def test_unconfigured_when_no_perimeter(tmp_path: Path) -> None:
    assert readiness.assess(tmp_path, env={}).posture is Posture.UNCONFIGURED


def test_cooperative_when_key_is_local_only(tmp_path: Path) -> None:
    """A committed/local approver key with no CI-secret pin is NOT a boundary —
    the agent on the box can read it. Must be COOPERATIVE, not ENFORCED."""
    _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    report = readiness.assess(tmp_path, env={})  # no QUILL_APPROVER_PUBKEYS
    assert report.posture is Posture.COOPERATIVE
    assert any("approver trust root" in c.name and not c.ok for c in report.checks)


def test_enforced_when_trust_root_is_off_box(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    env = {
        provenance_mod.APPROVER_ENV: pub_pem,  # CI secret pin
        "QUILL_GATE_KEY": attest.generate_keypair()[0],
    }
    report = readiness.assess(tmp_path, env=env)
    assert report.posture is Posture.ENFORCED
    assert not report.blockers


def test_unpinned_workflow_is_a_blocker(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    # runs the PR's own checkout — a PR could modify its own judge
    (wf / "quill.yml").write_text(
        'jobs:\n  cc:\n    steps:\n      - uses: ./\n        with:\n          install-from-source: "true"\n'
    )
    report = readiness.assess(tmp_path, env={provenance_mod.APPROVER_ENV: pub_pem})
    assert report.posture is Posture.COOPERATIVE
    assert any(c.name == "gate workflow" and not c.ok for c in report.checks)


def test_tampered_perimeter_is_not_enforced(tmp_path: Path) -> None:
    pub_pem = _sign_perimeter(tmp_path)
    _pinned_workflow(tmp_path)
    # widen the perimeter after signing -> signature no longer matches
    perimeter_mod.default_perimeter(forbidden_paths=()).write(tmp_path)
    report = readiness.assess(tmp_path, env={provenance_mod.APPROVER_ENV: pub_pem})
    assert report.posture is Posture.COOPERATIVE
    assert any(c.name == "perimeter signature" and not c.ok for c in report.checks)
