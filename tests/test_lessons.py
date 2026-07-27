"""Tests for the learning loop: mistake events and lesson suggestion/promotion.

Non-negotiables under test: no secret VALUE ever appears in an event or
lesson, and promotion is human-gated and idempotent. The compact agent
surfaces moved to test_teach.py when teach.py lost its lessons half.
"""

from __future__ import annotations

import json
from pathlib import Path

from notari.lessons import (
    classify_path,
    events_from_passport,
    load_events,
    load_promoted,
    promote,
    record_mistakes,
    redact_path,
    suggest,
)

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
        "schema": "notari.change-passport/v1.1",
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
    assert classify_path(".notari/perimeter.json") == "notari_trust_surface"
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
    assert e["schema"] == "notari.mistake/v1"
    assert e["task_hint"] == "auth"


def test_rule_id_mapping_per_finding_type():
    p = _passport(
        forbidden_hits=["src/payments/charge.py"],
        gate_tamper_hits=[".notari/perimeter.json"],
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
    # The finding is fed a RAW secret under several plausible keys, so that a
    # code change which copies ANY finding field into the event (not just the
    # ones we thought of) is caught, the earlier version only checked a value
    # the finding never carried, so it passed vacuously (mutation audit 2026-07).
    p = _passport(
        secret_findings=[
            {
                "path": "a.py",
                "line": 3,
                "pattern": "AWS Access Key ID",
                "value": SECRET_VALUE,
                "match": SECRET_VALUE,
                "secret": SECRET_VALUE,
                "raw": SECRET_VALUE,
            }
        ]
    )
    (e,) = events_from_passport(p)
    assert e["pattern"] == "AWS Access Key ID"
    # No serialized field may carry the raw value, whatever key it hid behind.
    assert SECRET_VALUE not in json.dumps(e)
    # And the event's fields are a known, value-free allowlist.
    assert not ({"value", "match", "secret", "raw"} & set(e)), (
        f"a raw-value key leaked into the event: {set(e)}"
    )


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
