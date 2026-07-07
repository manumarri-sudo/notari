"""Readiness: tell the human, in one glance, whether the gate is a *real* boundary.

The trap this guards against is the one that matters most: a key sitting in a
file on the same laptop the agent runs on is NOT off the agent's reach — the
agent runs as you and can read it. So readiness never reports "secure" just
because a key file exists. A control only counts as an enforced boundary when
its trust root lives where the agent cannot go:

  * the CI runner (a different machine) — secrets the laptop agent can't read, or
  * a hardware key (YubiKey / HSM / Secure Enclave) — un-exportable even to root.

This module computes a posture — ``enforced`` / ``cooperative`` / ``unconfigured``
— from what it can actually observe, and says exactly what's missing. It is the
"do the thinking for them" surface: run it and you know if you can stop worrying.
"""

from __future__ import annotations

import enum
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from quill import perimeter as perimeter_mod
from quill import provenance as provenance_mod


class Posture(str, enum.Enum):
    ENFORCED = "enforced"  # a real boundary against an adversarial agent
    COOPERATIVE = "cooperative"  # honest review automation; trust root is reachable
    UNCONFIGURED = "unconfigured"  # no perimeter at all


class Level(str, enum.Enum):
    BLOCKER = "blocker"  # without this it is not an enforced boundary
    HARDENING = "hardening"  # recommended, not strictly required


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    level: Level
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    posture: Posture
    checks: tuple[Check, ...] = field(default_factory=tuple)

    @property
    def blockers(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.ok and c.level is Level.BLOCKER)


def _quill_workflow_files(root: Path) -> list[Path]:
    """Workflow files that actually wire in Quill. Checks are scoped to these so a
    ``pull_request_target`` (or ``persist-credentials: false``) in an UNRELATED
    workflow can't launder a misconfigured Quill gate into an ENFORCED verdict
    (readiness cross-file overstatement)."""
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    return [
        p
        for p in sorted(wf_dir.glob("*.y*ml"))
        if p.is_file() and re.search(r"quill", p.read_text(errors="replace"), re.I)
    ]


def _workflow_issue(text: str) -> str | None:
    """Return a one-line issue for a SINGLE workflow's text, or None if it is a
    safe Quill gate (pinned to a SHA, uses pull_request_target)."""
    from_source = "install-from-source" in text and re.search(
        r'install-from-source:\s*["\']?true', text
    )
    if from_source or re.search(r"uses:\s*\./", text):
        return (
            "gate runs from the PR's own checkout (uses: ./ / install-from-source) — "
            "a PR can modify its own judge. Pin to a published tag: uses: manumarri-sudo/quill@v0"
        )
    if not re.search(r"uses:\s*[\w.-]+/quill@", text):
        return "Quill referenced but not pinned to org/quill@<tag>"
    issues: list[str] = []
    has_prt = re.search(r"pull_request_target:", text)
    has_pr_only = re.search(r"pull_request:", text) and not has_prt
    if has_pr_only:
        issues.append("uses pull_request (not pull_request_target) — the PR controls the workflow")
    if not re.search(r"uses:\s*[\w.-]+/quill@[0-9a-f]{40}", text):
        issues.append("Quill action is not SHA-pinned (use a 40-hex commit SHA, not a tag)")
    return "workflow has issues: " + "; ".join(issues) if issues else None


def _workflow_pinning(root: Path) -> Check:
    """Is the gate run from a pinned published tag (safe) or the PR's own code (unsafe)?

    Running the action from the PR's checkout (``uses: ./`` / ``install-from-source``)
    lets a PR modify the gate that judges it. A pinned tag (``uses: org/quill@v0``)
    runs trusted code the PR can't alter. The SAME file that runs Quill must also use
    ``pull_request_target`` and a SHA pin — the trigger and pin have to co-occur, so an
    unrelated workflow can't supply them.
    """
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return Check(
            "gate workflow",
            False,
            Level.BLOCKER,
            "no .github/workflows — the gate isn't wired into CI (run `quill init`)",
        )
    quill_files = _quill_workflow_files(root)
    if not quill_files:
        return Check("gate workflow", False, Level.BLOCKER, "no Quill step found in any workflow")
    last_issue = "no correctly-configured Quill workflow found"
    for p in quill_files:
        issue = _workflow_issue(p.read_text(errors="replace"))
        if issue is None:
            return Check(
                "gate workflow",
                True,
                Level.BLOCKER,
                f"{p.name}: pinned to a SHA, uses pull_request_target",
            )
        last_issue = f"{p.name}: {issue}"
    return Check("gate workflow", False, Level.BLOCKER, last_issue)


def _workflow_hardening(root: Path) -> tuple[Check, ...]:
    """HARDENING checks for the pull_request_target isolation pattern.

    These are recommended, not blockers: the dominant boundary property is the
    off-box trust root. But a workflow that checks the PR out at the workspace
    root, or persists the write token into that tree, weakens the control/data
    separation, so we surface them as guidance rather than silently blessing them.
    """
    quill_files = _quill_workflow_files(root)
    if not quill_files:
        return ()
    # Scope hardening to the file(s) that run Quill, so an unrelated workflow's
    # persist-credentials/path can't satisfy the check for the gate.
    text = "\n".join(p.read_text(errors="replace") for p in quill_files)
    out: list[Check] = []
    persist_off = re.search(r"persist-credentials:\s*false", text) is not None
    out.append(
        Check(
            "checkout credentials",
            persist_off,
            Level.HARDENING,
            "persist-credentials: false (the write token is not written into the candidate tree)"
            if persist_off
            else "add persist-credentials: false to the checkout so the write token isn't "
            "left in the PR checkout a candidate controls",
        )
    )
    # Data-only candidate checkout: `path: <subdir>` + a matching checkout-path so
    # no trusted process runs with the candidate tree as cwd / sys.path.
    data_only = re.search(r"path:\s*_?\w[\w./-]*", text) and re.search(r"checkout-path:", text)
    out.append(
        Check(
            "candidate checkout isolation",
            bool(data_only),
            Level.HARDENING,
            "PR is checked out into a data-only subdirectory (path: + checkout-path:)"
            if data_only
            else "check the PR out into a subdirectory (checkout `path: _pr_checkout` + action "
            "`checkout-path: _pr_checkout`) so candidate code never becomes the trusted cwd/sys.path",
        )
    )
    return tuple(out)


def assess(root: Path | None = None, env: dict[str, str] | None = None) -> ReadinessReport:
    """Assess whether Change Control is an enforced boundary for the repo at `root`."""
    root = perimeter_mod.perimeter_path(root or Path.cwd()).parent.parent
    env = env if env is not None else dict(os.environ)
    checks: list[Check] = []

    perimeter = perimeter_mod.load(root)
    if perimeter is None:
        return ReadinessReport(
            Posture.UNCONFIGURED,
            (Check("perimeter", False, Level.BLOCKER, "no signed perimeter (run `quill init`)"),),
        )

    # 1. Is the perimeter signed by a trusted approver?
    prov = provenance_mod.verify_artifact(
        perimeter.to_dict(), perimeter_mod.signature_path(root), root, env
    )
    signed_ok = prov.status is provenance_mod.ProvenanceStatus.OK
    checks.append(Check("perimeter signature", signed_ok, Level.BLOCKER, prov.detail))

    # 2. THE key question: is the approver trust root off the agent's reach, or
    #    just a file the agent can read? Env-pinned (CI secret) = off-box.
    #    Committed-only = on the laptop, editable in a PR -> not a boundary.
    env_pinned = bool(env.get(provenance_mod.APPROVER_ENV, "").strip())
    committed = (provenance_mod.approvers_dir(root)).is_dir()
    if env_pinned:
        checks.append(
            Check(
                "approver trust root",
                True,
                Level.BLOCKER,
                f"pinned via {provenance_mod.APPROVER_ENV} (a CI secret a PR can't edit)",
            )
        )
    else:
        checks.append(
            Check(
                "approver trust root",
                False,
                Level.BLOCKER,
                (
                    "approver keys are "
                    + ("committed in-repo only" if committed else "absent")
                    + f"; set {provenance_mod.APPROVER_ENV} as a CI secret so the trust root "
                    "lives where the agent can't reach it (a local/committed key the agent can read "
                    "or a PR can edit is not a boundary)"
                ),
            )
        )

    # 3. Gate signing key for the passport — present as a CI secret (off-box)?
    gate_env = bool(env.get("QUILL_GATE_KEY", "").strip())
    checks.append(
        Check(
            "gate signing key",
            gate_env,
            Level.HARDENING,
            "QUILL_GATE_KEY present (passports are signed)"
            if gate_env
            else "QUILL_GATE_KEY not set — passports won't be gate-signed; "
            "set it as a CI secret so verdicts are independently verifiable",
        )
    )

    # 4. Does the gate run from trusted pinned code, or the PR's own?
    checks.append(_workflow_pinning(root))
    checks.extend(_workflow_hardening(root))

    # Posture: an enforced boundary needs the perimeter trusted AND the trust root
    # off-box AND the gate running trusted code. Anything less is cooperative.
    blocker_failed = any(not c.ok and c.level is Level.BLOCKER for c in checks)
    posture = Posture.COOPERATIVE if blocker_failed else Posture.ENFORCED
    return ReadinessReport(posture, tuple(checks))
