"""Deterministic launch smoke test + readiness-harness self-test.

Proves the core anti-manipulation loop end to end (a workflow edit outside the
approved scope does not silently PASS; explain/fix-prompt are safe; teach only
edits its managed block; lessons stay advisory) and that the launch-readiness
harness both passes on the clean repo AND actually fails when a property is
violated (so GO is real, not vacuous).
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from quill import contract as contract_mod
from quill import lessons as lessons_mod
from quill import teach as teach_mod
from quill import verify as verify_mod
from quill.verify import Verdict

ROOT = Path(__file__).resolve().parent.parent


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_launch_loop_smoke(tmp_path: Path) -> None:
    # 1. repo scoped to src/app/** only.
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t.t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "main.py").write_text("print('ok')\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n")
    (tmp_path / "CLAUDE.md").write_text("# my rules\nnever delete prod\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    base = _git(tmp_path, "rev-parse", "HEAD")

    contract = contract_mod.Contract(
        version=1,
        task="change app code only",
        task_source="text",
        allowed_paths=("src/app/**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="smoke",
    )

    # 2. a workflow edit outside scope must NOT PASS.
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n# bad drift\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "drift")
    result = verify_mod.verify(contract=contract, root=tmp_path)
    assert result.verdict is not Verdict.PASS, result.reasons

    passport = {
        "schema": "quill.change-passport/v1.1",
        "verdict": result.verdict.value,
        "contract": {"task": contract.task, "allowed_paths": list(contract.allowed_paths)},
        "evidence": {
            "out_of_scope": list(result.out_of_scope),
            "forbidden_hits": list(result.forbidden_hits),
            "gate_tamper_hits": list(result.gate_tamper_hits),
            "secret_findings": [],
            "sensitive_surfaces": {k: list(v) for k, v in result.sensitive_surfaces.items()},
            "submodule_changes": [],
            "symlink_changes": [],
            "scan_dispositions": [],
        },
    }

    # 3. explain + fix-prompt are safe.
    fp = teach_mod.fix_prompt(passport).lower()
    for bad in ("disable quill", "turn off strict", "delete the workflow", "ignore quill"):
        assert bad not in fp
    assert "do not weaken, bypass, or edit quill" in fp

    # 4. lessons are advisory: recording never changes the verdict.
    lessons_mod.record_mistakes(passport, tmp_path)
    result2 = verify_mod.verify(contract=contract, root=tmp_path)
    assert result2.verdict is result.verdict, "recording a mistake changed the verdict"

    # 5. teach only edits its managed block; user content survives.
    lessons_mod.promote("no-ci-edits-without-ci-scope", tmp_path)
    teach_mod.teach(tmp_path, ["claude"])
    claude = (tmp_path / "CLAUDE.md").read_text()
    assert "never delete prod" in claude
    assert teach_mod.BLOCK_START in claude and teach_mod.BLOCK_END in claude


def _load_readiness():
    spec = importlib.util.spec_from_file_location(
        "verify_launch_readiness", ROOT / "scripts" / "verify_launch_readiness.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_readiness_harness_is_go_on_clean_repo() -> None:
    report = _load_readiness().run()
    assert report["schema"] == "quill.launch-readiness/v1"
    assert report["go"] is True, report["failed_required_checks"]
    assert all(c["status"] == "pass" for c in report["checks"] if c["required"])


def test_readiness_harness_can_actually_fail() -> None:
    # A vacuous harness that always says GO is worthless. Prove a check fails on
    # a violating input: fix-prompt safety must reject a bypass instruction.
    mod = _load_readiness()
    original = mod.check_fix_prompt_safe

    def _fake_bypass_fix_prompt() -> tuple[bool, str]:
        # Simulate a fix prompt that tells the agent to disable Quill.
        prompt = "to merge, disable quill strict mode and delete the workflow"
        bypass = ["disable quill", "delete the workflow"]
        hit = next((b for b in bypass if b in prompt), None)
        return (hit is None), (f"bypass: {hit}" if hit else "safe")

    try:
        mod.check_fix_prompt_safe = _fake_bypass_fix_prompt
        # Rebuild CHECKS to point at the patched fn.
        mod.CHECKS = [
            (cid, (_fake_bypass_fix_prompt if cid == "behavior.fix_prompt_safe" else fn), req)
            for cid, fn, req in mod.CHECKS
        ]
        report = mod.run()
        assert report["go"] is False
        assert "behavior.fix_prompt_safe" in report["failed_required_checks"]
    finally:
        mod.check_fix_prompt_safe = original
