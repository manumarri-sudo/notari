"""Tests for Quill Change Control: contract, diff evaluation, verify, passport."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from quill import contract as contract_mod
from quill import passport as passport_mod
from quill import policy
from quill import verify as verify_mod

# --------------------------------------------------------------------------
# policy.evaluate_diff and its primitives
# --------------------------------------------------------------------------

# Assembled at runtime so no literal credential sits in this source file (the
# scanner still sees the joined value once it lands in the diff text).
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

SAMPLE_DIFF = """diff --git a/src/app/main.py b/src/app/main.py
index 1111111..2222222 100644
--- a/src/app/main.py
+++ b/src/app/main.py
@@ -1,2 +1,4 @@
 import os
+KEY = "__AWSKEY__"
+x = 1
 print("hi")
diff --git a/infra/deploy.tf b/infra/deploy.tf
new file mode 100644
--- /dev/null
+++ b/infra/deploy.tf
@@ -0,0 +1,1 @@
+resource "x" {}
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1,2 @@
 name: ci
+  run: deploy
diff --git a/uv.lock b/uv.lock
--- a/uv.lock
+++ b/uv.lock
@@ -1 +1,2 @@
 [[package]]
+name = "x"
""".replace("__AWSKEY__", _AWS_KEY)


def test_parse_unified_diff_paths_and_status() -> None:
    files = policy.parse_unified_diff(SAMPLE_DIFF)
    by_path = {f.path: f for f in files}
    assert set(by_path) == {
        "src/app/main.py",
        "infra/deploy.tf",
        ".github/workflows/ci.yml",
        "uv.lock",
    }
    assert by_path["infra/deploy.tf"].status == "added"


def test_added_line_numbers_track_new_file() -> None:
    files = {f.path: f for f in policy.parse_unified_diff(SAMPLE_DIFF)}
    added = dict(files["src/app/main.py"].added_lines)
    # KEY is the 2nd line of the new file, x=1 the 3rd.
    assert 2 in added and "KEY" in added[2]
    assert 3 in added


def test_secret_finding_has_real_line_number() -> None:
    ev = policy.evaluate_diff(SAMPLE_DIFF, allowed_paths=["src/"])
    secrets = [(f.path, f.line, f.pattern_name) for f in ev.secret_findings]
    assert ("src/app/main.py", 2, "AWS Access Key ID") in secrets


def test_out_of_scope_detection() -> None:
    ev = policy.evaluate_diff(SAMPLE_DIFF, allowed_paths=["src/"])
    assert "infra/deploy.tf" in ev.out_of_scope
    assert "src/app/main.py" not in ev.out_of_scope


def test_sensitive_surfaces_classified() -> None:
    ev = policy.evaluate_diff(SAMPLE_DIFF, allowed_paths=["src/"])
    assert ev.sensitive_surfaces["ci"] == (".github/workflows/ci.yml",)
    assert ev.sensitive_surfaces["lockfiles"] == ("uv.lock",)


def test_empty_scope_allows_all() -> None:
    assert policy.path_in_scope("anything/here.py", [])
    ev = policy.evaluate_diff(SAMPLE_DIFF, allowed_paths=[])
    assert ev.out_of_scope == ()


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("src/a.py", "src/", True),
        ("src/a/b.py", "src/", True),
        ("docs/a.py", "src/", False),
        ("src/a/b.py", "src/**/*.py", True),
        ("src/a.py", "src/*.py", True),
        ("README.md", "README.md", True),
        ("readme.md", "README.md", False),
    ],
)
def test_path_matching(path: str, pattern: str, expected: bool) -> None:
    assert policy._path_matches(path, pattern) is expected


@pytest.mark.parametrize(
    ("path", "category"),
    [
        ("tests/test_x.py", "tests"),
        ("pkg/test_y.py", "tests"),
        ("pkg/y_test.go", "tests"),
        ("conftest.py", "tests"),
        (".github/workflows/ci.yml", "ci"),
        ("Jenkinsfile", "ci"),
        ("package-lock.json", "lockfiles"),
        ("go.sum", "lockfiles"),
        ("src/app.py", None),
    ],
)
def test_surface_classification(path: str, category: str | None) -> None:
    assert policy.classify_sensitive_surface(path) == category


def test_dot_prefixed_paths_not_mangled() -> None:
    # Regression: lstrip(".") used to turn .github into github.
    ev = policy.evaluate_diff(SAMPLE_DIFF, allowed_paths=[])
    assert ".github/workflows/ci.yml" in ev.changed_paths


def test_quill_metadata_excluded() -> None:
    diff = (
        "diff --git a/.quill/contract.json b/.quill/contract.json\n"
        "--- a/.quill/contract.json\n+++ b/.quill/contract.json\n"
        "@@ -1 +1,2 @@\n {}\n+more\n"
    )
    ev = policy.evaluate_diff(diff, allowed_paths=["src/"])
    assert ev.changed_paths == ()


def test_malformed_diff_does_not_raise() -> None:
    assert policy.parse_unified_diff("not a diff at all") == []
    assert policy.evaluate_diff("", allowed_paths=["src/"]).files == ()


# --------------------------------------------------------------------------
# contract + verify end-to-end with a real git repo
# --------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('v1')\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "base")
    return tmp_path


def test_begin_writes_contract(repo: Path) -> None:
    contract, path = contract_mod.begin("Fix the bug", allowed_paths=["src/"], root=repo)
    assert path == repo / ".quill" / "contract.json"
    data = json.loads(path.read_text())
    assert data["task"] == "Fix the bug"
    assert data["allowed_paths"] == ["src/"]
    assert data["base_commit"]
    loaded = contract_mod.load(repo)
    assert loaded.contract_id == contract.contract_id


def test_verify_pass(repo: Path) -> None:
    contract, _ = contract_mod.begin("tidy", allowed_paths=["src/"], root=repo)
    (repo / "src" / "app.py").write_text("print('v2')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "in-scope edit")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is verify_mod.Verdict.PASS
    assert result.verdict.exit_code == 0


def test_verify_block_on_out_of_scope(repo: Path) -> None:
    contract, _ = contract_mod.begin("scoped", allowed_paths=["src/"], root=repo)
    (repo / "outside.py").write_text("print('x')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "out of scope")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is verify_mod.Verdict.BLOCK
    assert "outside.py" in result.out_of_scope
    assert result.verdict.exit_code == 1


def test_verify_needs_review_on_sensitive_surface(repo: Path) -> None:
    contract, _ = contract_mod.begin("edit tests", allowed_paths=["tests/", "src/"], root=repo)
    tdir = repo / "tests"
    tdir.mkdir()
    (tdir / "test_app.py").write_text("def test_x():\n    assert True\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "add test")
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is verify_mod.Verdict.NEEDS_REVIEW
    assert result.verdict.exit_code == 0  # soft signal, does not fail CI


def test_exceptions_waive_findings(repo: Path) -> None:
    contract, _ = contract_mod.begin("scoped", allowed_paths=["src/"], root=repo)
    (repo / "infra.tf").write_text("resource {}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "infra")
    # Without exception: BLOCK.
    assert verify_mod.verify(contract=contract, root=repo).verdict is verify_mod.Verdict.BLOCK
    # With a scope exception: the out-of-scope path is waived.
    exc = repo / ".quill" / "exceptions.json"
    exc.write_text(
        json.dumps({"exceptions": [{"type": "scope", "path": "infra.tf", "reason": "approved"}]})
    )
    result = verify_mod.verify(contract=contract, root=repo)
    assert result.verdict is verify_mod.Verdict.PASS
    assert len(result.exceptions_applied) == 1


def test_verify_emits_audit_events(repo: Path, tmp_path: Path) -> None:
    from quill.audit import AuditLog

    log = tmp_path / "audit.jsonl"
    key = b"k" * 32
    contract, _ = contract_mod.begin("scoped", allowed_paths=["src/"], root=repo)
    (repo / "src" / "app.py").write_text("print('v2')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "edit")
    with AuditLog(path=log, hmac_key=key) as audit:
        result = verify_mod.verify(contract=contract, root=repo, audit=audit)
    assert result.audit_mac
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(e["type"] == "verification.run" for e in lines)


# --------------------------------------------------------------------------
# passport rendering
# --------------------------------------------------------------------------


def test_passport_json_and_markdown(repo: Path) -> None:
    contract, _ = contract_mod.begin("scoped", allowed_paths=["src/"], root=repo)
    (repo / "outside.py").write_text("print('x')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "oos")
    result = verify_mod.verify(contract=contract, root=repo)

    data = passport_mod.build_passport(result, generated_at="2026-06-17T00:00:00+00:00")
    assert data["verdict"] == "BLOCK"
    assert data["exit_code"] == 1
    assert "outside.py" in data["evidence"]["out_of_scope"]
    assert data["schema"] == "quill.change-passport/v1.1"

    md = passport_mod.render_markdown(result, generated_at="2026-06-17T00:00:00+00:00")
    assert "# Quill Change Passport" in md
    assert "BLOCK" in md
    assert "outside.py" in md
    # Action block leads the document (P0-1): what to do, a paste-ready agent
    # prompt, and the honesty footer — before the raw evidence detail.
    assert "## What to do next" in md
    assert "## Prompt to give Claude Code" in md
    assert "What Quill does not prove" in md
    assert "## Evidence trust" in md
    assert md.index("## What to do next") < md.index("## Evidence")
    # Unsigned markdown must NOT imply gate-signed evidence.
    assert "unsigned" in md and "report-grade" in md
    assert "gate-signed and can be verified" not in md
    # Signed rendering says the opposite.
    md_signed = passport_mod.render_markdown(
        result, generated_at="2026-06-17T00:00:00+00:00", signed=True
    )
    assert "gate-signed and can be verified" in md_signed
    assert "treat it as report-grade" not in md_signed
    # Never claims to prove correctness/security.
    for banned in ("proves the code is correct", "proves security", "guarantees no backdoor"):
        assert banned not in md.lower()

    json_path, md_path = passport_mod.write_passport(result, out_dir=repo / ".quill")
    assert json_path.exists() and md_path.exists()
    assert json.loads(json_path.read_text())["verdict"] == "BLOCK"


def test_passport_markdown_pass_stays_short(repo: Path) -> None:
    contract, _ = contract_mod.begin("scoped", allowed_paths=["**"], root=repo)
    (repo / "in_scope.py").write_text("print('ok')\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "ok")
    result = verify_mod.verify(contract=contract, root=repo)
    md = passport_mod.render_markdown(result, generated_at="2026-06-17T00:00:00+00:00")
    # PASS has nothing to remediate, so no noisy action block.
    assert "## What to do next" not in md
    assert "## Prompt to give Claude Code" not in md
