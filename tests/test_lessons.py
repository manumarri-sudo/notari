"""Tests for the learning loop: mistake events, lesson suggestion/promotion,
managed-block teaching, and the compact agent surfaces.

Non-negotiables under test: no secret VALUE ever appears in an event,
lesson, fix prompt, or brief; promotion is human-gated and idempotent;
`quill teach` never touches user content outside the managed block; and
the compact surfaces stay compact (token discipline).
"""

from __future__ import annotations

import json
from pathlib import Path

from quill.lessons import (
    classify_path,
    events_from_passport,
    load_events,
    load_promoted,
    promote,
    record_mistakes,
    redact_path,
    suggest,
)
from quill.teach import BLOCK_END, BLOCK_START, agent_brief, fix_prompt, teach, update_file

SECRET_VALUE = "AKIA" + "X" * 16  # a value that must never leak into outputs


def _passport(verdict: str = "BLOCK", **evidence) -> dict:
    ev = {
        "changed_files": [],
        "out_of_scope": [],
        "forbidden_hits": [],
        "gate_tamper_hits": [],
        "secret_findings": [],
        "sensitive_surfaces": {},
        "submodule_changes": [],
        "symlink_changes": [],
        "scan_dispositions": [],
    }
    ev.update(evidence)
    return {
        "schema": "quill.change-passport/v1.1",
        "verdict": verdict,
        "contract": {
            "id": "abc123",
            "task": "add rate limiting to login endpoint",
            "allowed_paths": ["src/auth/**", "tests/auth/**"],
        },
        "evidence": ev,
    }


# --- classification / events ------------------------------------------------


def test_classify_path_buckets():
    assert classify_path(".github/workflows/deploy.yml") == "ci_workflow"
    assert classify_path("migrations/001_init.sql") == "migration"
    assert classify_path("uv.lock") == "lockfile"
    assert classify_path("src/auth/login.py") == "auth"
    assert classify_path("tests/test_x.py") == "test"
    assert classify_path(".quill/perimeter.json") == "quill_trust_surface"
    assert classify_path("src/checkout/cart.py") == "other"


def test_redact_path_drops_basename():
    assert redact_path(".github/workflows/deploy.yml") == ".github/workflows/<file>"
    assert redact_path("toplevel.py") == "<file>"


def test_scope_out_ci_workflow_event():
    p = _passport(out_of_scope=[".github/workflows/deploy.yml"])
    (e,) = events_from_passport(p)
    assert e["rule_id"] == "SCOPE_OUT"
    assert e["finding_type"] == "out_of_scope_path"
    assert e["violating_path_kind"] == "ci_workflow"
    assert e["violating_path_redacted"] == ".github/workflows/<file>"
    assert e["schema"] == "quill.mistake/v1"
    assert e["task_hint"] == "auth"


def test_rule_id_mapping_per_finding_type():
    p = _passport(
        forbidden_hits=["src/payments/charge.py"],
        gate_tamper_hits=[".quill/perimeter.json"],
        secret_findings=[{"path": "a.py", "line": 3, "pattern": "AWS Access Key ID"}],
        sensitive_surfaces={"lockfiles": ["uv.lock"]},
        symlink_changes=[{"path": "src/x", "status": "A", "target": "../y"}],
        submodule_changes=[{"path": "vendor/lib", "status": "M"}],
        scan_dispositions=["diff exceeds ceiling"],
    )
    rules = {e["rule_id"] for e in events_from_passport(p)}
    assert rules == {
        "FORBIDDEN_PATH",
        "GATE_TAMPER",
        "SECRET_HIT",
        "SENSITIVE_SURFACE",
        "OPAQUE_CHANGE",
        "SCAN_INCOMPLETE",
    }


def test_secret_event_carries_pattern_name_never_value():
    p = _passport(secret_findings=[{"path": "a.py", "line": 3, "pattern": "AWS Access Key ID"}])
    (e,) = events_from_passport(p)
    assert e["pattern"] == "AWS Access Key ID"
    assert SECRET_VALUE not in json.dumps(e)


def test_pass_produces_no_events():
    assert events_from_passport(_passport(verdict="PASS")) == []


def test_record_and_load_roundtrip(tmp_path: Path):
    p = _passport(out_of_scope=["ops.cfg"])
    assert record_mistakes(p, tmp_path) == 1
    assert record_mistakes(_passport(verdict="PASS"), tmp_path) == 0
    events = load_events(tmp_path)
    assert len(events) == 1
    assert events[0]["rule_id"] == "SCOPE_OUT"


def test_record_is_idempotent_per_commit(tmp_path: Path):
    # Same failing commit re-verified: no double counting.
    p = dict(_passport(out_of_scope=[".github/workflows/a.yml"]))
    p["head_commit"] = "deadbeef"
    assert record_mistakes(p, tmp_path) == 1
    assert record_mistakes(p, tmp_path) == 0
    assert len(load_events(tmp_path)) == 1
    # A new commit with the same pattern still records.
    p2 = dict(p)
    p2["head_commit"] = "cafef00d"
    assert record_mistakes(p2, tmp_path) == 1
    patterns = suggest(load_events(tmp_path))
    assert patterns[0]["count"] == 2


# --- suggestion / promotion --------------------------------------------------


def test_suggest_aggregates_repeats():
    p = _passport(out_of_scope=[".github/workflows/a.yml"])
    events = events_from_passport(p) * 4 + events_from_passport(
        _passport(secret_findings=[{"path": "t.py", "line": 1, "pattern": "JWT"}])
    )
    patterns = suggest(events)
    top = patterns[0]
    assert top["lesson_id"] == "no-ci-edits-without-ci-scope"
    assert top["count"] == 4
    assert "workflows" in top["lesson"]
    assert top["promote_command"].endswith("no-ci-edits-without-ci-scope")
    assert top["headline"] == "CI workflow touched during a non-CI task"
    assert top["severity"] == "policy_candidate"
    assert top["source_rule"] == "SCOPE_OUT"


def test_promote_is_human_gated_and_idempotent(tmp_path: Path):
    newly, text = promote("no-ci-edits-without-ci-scope", tmp_path)
    assert newly and "workflows" in text
    again, _ = promote("no-ci-edits-without-ci-scope", tmp_path)
    assert not again
    stored = load_promoted(tmp_path)
    assert len(stored) == 1
    assert stored[0]["severity"] == "policy_candidate"
    try:
        promote("not-a-lesson", tmp_path)
        raise AssertionError("unknown id must raise")
    except KeyError:
        pass


# --- teach (managed block) ----------------------------------------------------


def test_update_file_preserves_user_content(tmp_path: Path):
    target = tmp_path / "CLAUDE.md"
    target.write_text("# My rules\n\nnever delete prod.\n")
    promoted = [{"id": "x", "text": "Do not edit workflows."}]
    assert update_file(target, promoted)
    text = target.read_text()
    assert text.startswith("# My rules")
    assert "never delete prod." in text
    assert BLOCK_START in text and BLOCK_END in text
    assert "Do not edit workflows." in text
    # idempotent: second run is a no-op
    assert not update_file(target, promoted)
    # updating lessons rewrites ONLY the block
    assert update_file(target, [{"id": "y", "text": "Do not update lockfiles."}])
    text2 = target.read_text()
    assert "never delete prod." in text2
    assert "Do not update lockfiles." in text2
    assert "Do not edit workflows." not in text2
    assert text2.count(BLOCK_START) == 1


def test_teach_writes_selected_targets(tmp_path: Path):
    promote("no-realistic-credentials", tmp_path)
    results = dict(teach(tmp_path, ["claude", "cursor"]))
    assert results["CLAUDE.md"] is True
    assert results[".cursor/rules/quill-scope.mdc"] is True
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / ".cursorrules").exists()  # never created, only updated


# --- compact agent surfaces ----------------------------------------------------


def test_fix_prompt_is_compact_and_leaks_nothing():
    p = _passport(
        out_of_scope=[".github/workflows/deploy.yml"],
        secret_findings=[{"path": "a.py", "line": 3, "pattern": "AWS Access Key ID"}],
    )
    prompt = fix_prompt(p)
    assert "add rate limiting to login endpoint" in prompt
    assert "src/auth/**" in prompt
    assert "do not weaken" in prompt.lower()
    assert "git diff --name-only" in prompt
    assert SECRET_VALUE not in prompt
    assert "verification_run_mac" not in prompt and "provenance" not in prompt
    assert len(prompt) < 3200  # ~800 tokens


# Phrases that would turn the fix prompt into a BYPASS prompt. A fix prompt that
# ever told an agent to defeat the gate would be self-defeating; guard hard.
_BYPASS_PHRASES = [
    "disable quill",
    "weaken quill",
    "turn off strict",
    "remove the quill",
    "delete the workflow",
    "delete approver",
    "change the perimeter",
    "edit .quill",
    "ignore quill",
    "skip quill",
    "bypass the gate",
]


def test_fix_prompt_never_instructs_bypass():
    # Exercise every finding kind so all rendered guidance is covered.
    p = _passport(
        out_of_scope=["ops.cfg"],
        forbidden_hits=["src/pay.py"],
        gate_tamper_hits=[".quill/perimeter.json"],
        secret_findings=[{"path": "a.py", "line": 1, "pattern": "JWT"}],
        sensitive_surfaces={"ci": ["ci.yml"]},
        symlink_changes=[{"path": "l", "status": "A", "target": "../x"}],
        submodule_changes=[{"path": "vendor", "status": "M"}],
    )
    low = fix_prompt(p).lower()
    for phrase in _BYPASS_PHRASES:
        assert phrase not in low, f"fix prompt contains bypass phrase: {phrase!r}"
    # It must positively tell the agent NOT to weaken the gate.
    assert "do not weaken, bypass, or edit quill" in low


def test_agent_brief_never_instructs_bypass():
    brief = agent_brief(
        task="t",
        allowed_paths=["src/**"],
        forbidden_paths=[".github/workflows/**"],
        review_surfaces=["ci"],
        promoted=[{"id": "x", "text": "Do not edit workflows."}],
    ).lower()
    for phrase in _BYPASS_PHRASES:
        assert phrase not in brief, f"agent brief contains bypass phrase: {phrase!r}"


def test_fix_prompt_caps_findings():
    p = _passport(out_of_scope=[f"f{i}.py" for i in range(12)])
    prompt = fix_prompt(p)
    assert "and 7 more" in prompt
    assert len(prompt) < 3200


def test_agent_brief_is_compact():
    brief = agent_brief(
        task="add rate limiting to login endpoint",
        allowed_paths=["src/auth/**", "tests/auth/**"],
        forbidden_paths=[".github/workflows/**", "migrations/**", ".quill/**"],
        review_surfaces=["ci", "lockfiles"],
        promoted=[{"id": "x", "text": "Do not edit workflows."}],
    )
    assert brief.startswith("Task: add rate limiting")
    assert "Never touch: .github/workflows/**" in brief
    assert "Do not edit workflows." in brief
    assert "git diff --name-only" in brief
    assert len(brief) < 1200  # ~300 tokens
