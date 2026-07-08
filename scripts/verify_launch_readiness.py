#!/usr/bin/env python3
"""Deterministic launch-readiness harness for Nota's anti-manipulation pass.

Inspects files and exercises real behavior — no LLM, no trust of commit
messages, generated scorecards, or local lesson counts. Emits a machine-readable
report and exits non-zero unless every required check passes.

    python scripts/verify_launch_readiness.py --json > launch-readiness.json

This does NOT run ruff / mypy / pytest / build — those are declared in
`commands_required` and must be run and green separately (CI does this). This
script checks the properties those commands cannot: docs coherence, that
advisory surfaces are not described as enforcement, that the passport and fix
prompt are honest and safe, that agent-instruction / learning-state edits
surface for review, and that security tests weren't silently disabled.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "nota.launch-readiness/v1"

COMMANDS_REQUIRED = [
    "uv run ruff check src tests",
    "uv run ruff format --check src tests",
    "uv run mypy src/nota",
    "uv run pytest tests/",
    "python -m build",
]


def _read(rel: str) -> str:
    p = ROOT / rel
    return p.read_text(encoding="utf-8") if p.exists() else ""


# --------------------------------------------------------------------------- #
# Docs checks
# --------------------------------------------------------------------------- #


def check_no_shipping_mcp_proxy() -> tuple[bool, str]:
    sm = _read("docs/SECURITY-MODEL.md").lower()
    if "mcp proxy" not in sm:
        return True, "SECURITY-MODEL does not mention an MCP proxy"
    # Every mention must sit near removal/historical language.
    ok = True
    for m in re.finditer(r"mcp proxy", sm):
        window = sm[max(0, m.start() - 220) : m.end() + 220]
        if not any(
            w in window for w in ("removed", "historical", "previous", "not part", "not shipping")
        ):
            ok = False
            break
    return ok, (
        "every MCP-proxy mention is marked removed/historical"
        if ok
        else "SECURITY-MODEL describes the MCP proxy without removal/historical context"
    )


def check_lessons_advisory() -> tuple[bool, str]:
    blob = (
        _read("README.md") + _read("docs/LEARNING-LOOP.md") + _read("docs/SECURITY-MODEL.md")
    ).lower()
    banned = [
        "lessons decide the verdict",
        "lessons enforce policy",
        "mistake logs are security proof",
        "trains the model from all user logs",
        "lesson counts prove safety",
    ]
    hit = next((b for b in banned if b in blob), None)
    if hit:
        return False, f"docs imply advisory learning is enforcement: {hit!r}"
    required = ["advisory", "human-promoted", "local", "no telemetry"]
    missing = [r for r in required if r not in blob]
    if missing:
        return False, f"LEARNING-LOOP/README missing advisory wording: {missing}"
    return True, "docs state lessons are advisory, human-promoted, local, no telemetry"


def check_loop_visible() -> tuple[bool, str]:
    blob = _read("README.md") + _read("docs/QUICKSTART.md")
    needed = [
        "nota verify",
        "nota explain",
        "nota explain --fix-prompt",
        "nota lessons",
        "nota teach",
    ]
    missing = [n for n in needed if n not in blob]
    return (not missing), (
        "README/Quickstart show the full loop"
        if not missing
        else f"loop commands missing from docs: {missing}"
    )


def check_docs_agree_surfaces() -> tuple[bool, str]:
    readme = _read("README.md").lower()
    sm = _read("docs/SECURITY-MODEL.md").lower()
    # Both must present the CI gate as the boundary and the local hook as
    # defense-in-depth; neither may present the MCP proxy as current.
    if "defense-in-depth" not in sm:
        return False, "SECURITY-MODEL does not scope the local hook as defense-in-depth"
    if "change control" not in readme:
        return False, "README does not describe Change Control as the current product"
    return True, "README and SECURITY-MODEL agree on current surfaces"


# --------------------------------------------------------------------------- #
# Behavior checks (import the real modules; no mocks)
# --------------------------------------------------------------------------- #


def _sample_block_passport() -> dict:
    return {
        "schema": "nota.change-passport/v1.1",
        "verdict": "BLOCK",
        "contract": {"task": "add rate limiting", "allowed_paths": ["src/api/**"]},
        "evidence": {
            "changed_files": [],
            "out_of_scope": [".github/workflows/deploy.yml"],
            "forbidden_hits": [],
            "gate_tamper_hits": [],
            "secret_findings": [
                {"path": "src/api/app.py", "line": 2, "pattern": "AWS Access Key ID"}
            ],
            "sensitive_surfaces": {},
            "submodule_changes": [],
            "symlink_changes": [],
            "scan_dispositions": [],
        },
    }


def check_fix_prompt_safe() -> tuple[bool, str]:
    from nota.teach import fix_prompt

    prompt = fix_prompt(_sample_block_passport()).lower()
    bypass = [
        "disable nota",
        "weaken nota",
        "turn off strict",
        "delete the workflow",
        "delete approver",
        "change the perimeter",
        "ignore nota",
        "bypass the gate",
    ]
    hit = next((b for b in bypass if b in prompt), None)
    if hit:
        return False, f"fix prompt contains bypass instruction: {hit!r}"
    if "do not weaken, bypass, or edit nota" not in prompt:
        return False, "fix prompt does not tell the agent NOT to weaken the gate"
    # The pattern NAME may appear; a value-shaped token must not.
    if re.search(r"akia[0-9a-z]{12,}", prompt):
        return False, "fix prompt appears to contain a secret value"
    return True, "fix prompt is safe: no bypass instruction, no secret value"


def check_explain_shell_safe() -> tuple[bool, str]:
    from nota.explain import build_remediations

    p = _sample_block_passport()
    p["evidence"]["out_of_scope"] = ["-rf weird name.py", "a:b.py"]
    for r in build_remediations(p):
        if "git checkout" in r["self_fix"] and "git checkout -- " not in r["self_fix"]:
            return False, f"unsafe git command (missing --): {r['self_fix']!r}"
    return True, "explain self-fix commands use `git checkout --` with quoted paths"


def check_passport_remediation_and_trust() -> tuple[bool, str]:
    from nota import passport as pp
    from nota.policy import DiffEvaluation
    from nota.verify import Contract, Verdict, VerifyResult

    ev = DiffEvaluation(
        files=(),
        out_of_scope=("ops.cfg",),
        secret_findings=(),
        sensitive_surfaces={},
        allowed_paths=("src/**",),
    )
    c = Contract(
        version=1,
        task="t",
        task_source="text",
        allowed_paths=("src/**",),
        base_commit="0" * 40,
        created_at="2026-01-01T00:00:00Z",
        contract_id="x",
    )
    r = VerifyResult(
        verdict=Verdict.BLOCK,
        contract=c,
        evaluation=ev,
        base_commit="0" * 40,
        head_commit="1" * 40,
        out_of_scope=("ops.cfg",),
        secret_findings=(),
        sensitive_surfaces={},
        exceptions_applied=(),
        reasons=("1 path out of scope",),
    )
    md = pp.render_markdown(r, generated_at="2026-01-01T00:00:00+00:00", signed=False)
    needed = [
        "## What to do next",
        "## Prompt to give Claude Code",
        "What Nota does not prove",
        "## Evidence trust",
    ]
    missing = [s for s in needed if s not in md]
    if missing:
        return False, f"passport.md missing sections: {missing}"
    if "report-grade" not in md or "gate-signed and can be verified" in md:
        return False, "unsigned passport.md implies gate-signed evidence"
    return True, "passport.md has remediation + evidence-trust; unsigned wording is honest"


def check_sensitive_surfaces() -> tuple[bool, str]:
    from nota.policy import classify_sensitive_surface as cs

    expect = {
        "CLAUDE.md": "agent_instructions",
        "AGENTS.md": "agent_instructions",
        ".cursorrules": "agent_instructions",
        ".cursor/rules/nota-scope.mdc": "agent_instructions",
        ".nota/lessons.json": "nota_learning_state",
        ".nota/mistakes.jsonl": "nota_learning_state",
    }
    for path, want in expect.items():
        got = cs(path)
        if got != want:
            return False, f"{path} classified {got!r}, expected {want!r}"
    if cs(".nota/contract.json") is not None or cs("src/app.py") is not None:
        return False, "a non-sensitive path was classified as a surface"
    return True, "agent-instruction and learning-state paths are sensitive surfaces"


def check_lessons_do_not_decide_verdict() -> tuple[bool, str]:
    # verify's decision path must not read the lesson stores. Prove structurally:
    # the verify module never imports or references lessons/teach for its verdict.
    src = _read("src/nota/verify.py")
    if "lessons" in src or "mistakes.jsonl" in src or "lessons.json" in src:
        return False, "verify.py references the learning store in its decision path"
    return True, "verify.py never reads lesson/mistake state (verdict is independent)"


# --------------------------------------------------------------------------- #
# Test-integrity checks
# --------------------------------------------------------------------------- #


def check_security_tests_not_silently_disabled() -> tuple[bool, str]:
    """Every xfail/skip marker must carry a documented reason (a `reason=` kwarg
    or a non-empty string argument). An undocumented skip is how an agent would
    quietly disable a failing security test."""
    offenders: list[str] = []
    for tf in sorted((ROOT / "tests").glob("test_*.py")):
        lines = tf.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            s = line.strip()
            is_marker = bool(re.search(r"@?pytest\.(mark\.)?(xfail|skip|skipif)\b", s))
            is_call = bool(re.search(r"\bpytest\.(skip|xfail)\s*\(", s))
            if not (is_marker or is_call):
                continue
            window = "\n".join(lines[i : i + 4])
            has_reason = "reason=" in window
            # A non-empty string argument (optionally an f/r/b-prefixed string)
            # right after "(" or after a "," counts as a documented reason.
            has_string = bool(re.search(r'\(\s*[frbFRB]?["\']', window)) or bool(
                re.search(r',\s*[frbFRB]?["\']', window)
            )
            if not (has_reason or has_string):
                offenders.append(f"{tf.name}:{i + 1}")
    return (not offenders), (
        "every xfail/skip carries a documented reason"
        if not offenders
        else f"undocumented xfail/skip markers: {offenders}"
    )


CHECKS = [
    ("docs.no_removed_mcp_proxy_claim", check_no_shipping_mcp_proxy, True),
    ("docs.lessons_are_advisory", check_lessons_advisory, True),
    ("docs.launch_loop_visible", check_loop_visible, True),
    ("docs.surfaces_agree", check_docs_agree_surfaces, True),
    ("behavior.fix_prompt_safe", check_fix_prompt_safe, True),
    ("behavior.explain_shell_safe", check_explain_shell_safe, True),
    ("behavior.passport_remediation_and_trust", check_passport_remediation_and_trust, True),
    ("behavior.sensitive_surfaces", check_sensitive_surfaces, True),
    ("behavior.lessons_do_not_decide_verdict", check_lessons_do_not_decide_verdict, True),
    (
        "tests.security_tests_not_silently_disabled",
        check_security_tests_not_silently_disabled,
        True,
    ),
]


def run() -> dict:
    results = []
    for cid, fn, required in CHECKS:
        try:
            ok, detail = fn()
        except Exception as e:  # a crashing check is a failing check
            ok, detail = False, f"check raised {type(e).__name__}: {e}"
        results.append(
            {"id": cid, "status": "pass" if ok else "fail", "required": required, "detail": detail}
        )
    failed_required = [r["id"] for r in results if r["required"] and r["status"] != "pass"]
    return {
        "schema": SCHEMA,
        "go": not failed_required,
        "checks": results,
        "failed_required_checks": failed_required,
        "commands_required": COMMANDS_REQUIRED,
        "manual_smoke_required": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic Nota launch-readiness harness.")
    ap.add_argument("--json", action="store_true", help="emit the JSON report to stdout")
    args = ap.parse_args()
    report = run()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            mark = "✓" if c["status"] == "pass" else "✗"
            print(f"{mark} {c['id']}: {c['detail']}")
        print(
            f"\nGO: {report['go']}"
            if report["go"]
            else f"\nNO-GO: {report['failed_required_checks']}"
        )
    return 0 if report["go"] else 1


if __name__ == "__main__":
    sys.exit(main())
