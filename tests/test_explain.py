"""Tests for the remediation layer (`nota explain`).

Every finding type maps to a three-field record (plain / self_fix /
cc_prompt), duplicates collapse to the most specific reason, PASS and
NEEDS_REVIEW get friendly framing, and the plain-English field never uses
gate jargon.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from nota.explain import (
    build_remediations,
    explain_dict,
    render_github_annotations,
    render_text,
)
from nota.explain_html import render_html

JARGON = ("perimeter", "provenance", "MAC", "surface")


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
        "schema": "nota.change-passport/v1.1",
        "verdict": verdict,
        "contract": {"task": "add coupons to checkout", "allowed_paths": ["src/checkout/**"]},
        "evidence": ev,
    }


def _assert_record(r: dict) -> None:
    assert r["plain"] and r["self_fix"], r
    assert "cc_prompt" in r, r
    for word in JARGON:
        assert word.lower() not in r["plain"].lower(), (
            f"jargon '{word}' leaked into plain text: {r['plain']}"
        )


def test_secret_finding_maps_to_all_three_fields():
    p = _passport(
        secret_findings=[
            {"path": "src/checkout/cart.py", "line": 2, "pattern": "AWS Access Key ID"}
        ]
    )
    (r,) = build_remediations(p)
    _assert_record(r)
    assert r["kind"] == "secret"
    assert "src/checkout/cart.py" in r["cc_prompt"]
    assert "line 2" in r["cc_prompt"]
    assert "environment variable" in r["cc_prompt"]


def test_forbidden_hit_gets_git_undo_command():
    p = _passport(forbidden_hits=["src/auth/login.py"])
    (r,) = build_remediations(p)
    _assert_record(r)
    assert r["kind"] == "forbidden"
    assert "git checkout -- src/auth/login.py" in r["self_fix"]


def test_out_of_scope_references_the_task():
    p = _passport(out_of_scope=["ops/prod.cfg"])
    (r,) = build_remediations(p)
    _assert_record(r)
    assert r["kind"] == "out_of_scope"
    assert "add coupons to checkout" in r["plain"] or "add coupons to checkout" in r["cc_prompt"]
    assert "git checkout -- ops/prod.cfg" in r["self_fix"]


def test_self_fix_commands_are_shell_safe():
    # Path with a leading dash and a space must not be shell-injectable or
    # read as a git option — `--` plus shlex.quote handles both.
    p = _passport(out_of_scope=["-rf weird name.py"])
    (r,) = build_remediations(p)
    assert "git checkout -- '-rf weird name.py'" in r["self_fix"]


def test_gate_tamper_maps():
    p = _passport(gate_tamper_hits=[".nota/perimeter.json"])
    (r,) = build_remediations(p)
    _assert_record(r)
    assert r["kind"] == "gate_tamper"


def test_symlink_and_submodule_map():
    p = _passport(
        symlink_changes=[
            {"path": "src/checkout/alias.py", "status": "A", "target": "../auth/login.py"}
        ],
        submodule_changes=[{"path": "vendor/lib", "status": "M", "old": "a" * 8, "new": "b" * 8}],
    )
    recs = build_remediations(p)
    kinds = {r["kind"] for r in recs}
    assert kinds == {"symlink", "submodule"}
    for r in recs:
        _assert_record(r)
    link = next(r for r in recs if r["kind"] == "symlink")
    assert "../auth/login.py" in link["plain"]


def test_scan_disposition_has_no_cc_prompt():
    p = _passport(scan_dispositions=["diff exceeds 50 MiB ceiling"])
    (r,) = build_remediations(p)
    assert r["kind"] == "scan_incomplete"
    assert r["cc_prompt"] == ""
    assert "smaller" in r["self_fix"]


def test_sensitive_surface_framed_as_review_not_failure():
    p = _passport(verdict="NEEDS_REVIEW", sensitive_surfaces={"auth": ["src/auth/login.py"]})
    (r,) = build_remediations(p)
    _assert_record(r)
    assert r["kind"] == "sensitive"
    text = render_text(p)
    assert "not a failure" in text
    # NEEDS_REVIEW closer asks for a reviewer, not "fix these".
    assert "Ask a reviewer" in text


def test_dedup_prefers_most_specific_reason():
    p = _passport(
        out_of_scope=["src/auth/login.py", ".nota/perimeter.json"],
        forbidden_hits=["src/auth/login.py", ".nota/perimeter.json"],
        gate_tamper_hits=[".nota/perimeter.json"],
    )
    recs = build_remediations(p)
    wheres = [r["where"] for r in recs]
    assert wheres.count("src/auth/login.py") == 1
    assert wheres.count(".nota/perimeter.json") == 1
    by_where = {r["where"]: r["kind"] for r in recs}
    assert by_where["src/auth/login.py"] == "forbidden"
    assert by_where[".nota/perimeter.json"] == "gate_tamper"


def test_pass_is_one_friendly_line():
    text = render_text(_passport(verdict="PASS"))
    assert "You're good" in text
    assert len(text.strip().splitlines()) == 1


def test_text_render_numbers_issues_and_closes():
    p = _passport(
        secret_findings=[{"path": "a.py", "line": 1, "pattern": "JWT"}],
        out_of_scope=["b.py"],
    )
    text = render_text(p)
    assert "Issue 1" in text and "Issue 2" in text
    assert "re-run: nota verify" in text
    # Scannable rollup line names the volume + kinds up top.
    assert "2 issues" in text


def test_explain_dict_shape():
    d = explain_dict(_passport(out_of_scope=["b.py"]))
    assert d["verdict"] == "BLOCK"
    assert d["can_merge"] is False
    assert d["remediations"][0]["cc_prompt"]
    assert d["closer"].startswith("Fix these 1")
    assert d["inspect_first"] == ["b.py"]
    assert "does not check whether the code is" in d["does_not_prove"]


def test_explain_states_what_nota_does_not_prove():
    text = render_text(_passport(out_of_scope=["b.py"]))
    assert "What Nota does not prove" in text
    assert "Reviewer should inspect first: b.py" in text
    # PASS is still a single clean line, no disclaimer noise.
    assert render_text(_passport(verdict="PASS")).strip().count("\n") == 0


def test_github_annotations_target_file_and_line():
    p = _passport(
        secret_findings=[{"path": "src/api/app.py", "line": 2, "pattern": "AWS Access Key ID"}],
        out_of_scope=[".github/workflows/deploy.yml"],
        sensitive_surfaces={"ci": ["ci/build.sh"]},
    )
    anns = render_github_annotations(p)
    # secret → ::error with the exact line
    assert any(
        a.startswith("::error") and "file=src/api/app.py" in a and "line=2" in a for a in anns
    )
    # out-of-scope → ::error, file only
    assert any(a.startswith("::error") and "file=.github/workflows/deploy.yml" in a for a in anns)
    # sensitive surface → ::warning (review, not hard fail)
    assert any(a.startswith("::warning") and "file=ci/build.sh" in a for a in anns)


def test_github_annotations_escape_injection_paths():
    # A malicious path must not be able to inject a second workflow command.
    p = _passport(out_of_scope=["evil.py::error::pwned\nrm -rf /"])
    (ann,) = render_github_annotations(p)
    assert ann.count("::error") == 1  # the leading command only
    assert "\n" not in ann
    assert "%0A" in ann and "%3A%3A" in ann


def test_pass_has_no_annotations():
    assert render_github_annotations(_passport(verdict="PASS")) == []


def test_html_render_is_self_contained_and_honest():
    p = _passport(secret_findings=[{"path": "a.py", "line": 1, "pattern": "JWT"}])
    page = render_html(p)
    assert page.startswith("<!doctype html>")
    assert "http://" not in page and "https://" not in page  # no external resources
    assert "Copy" in page and "cp(this)" in page
    assert "compliant" not in page.lower()  # fix-it view, not a certification
    assert "BLOCK" in page


def test_passport_carries_matching_remediation_block(tmp_path: Path) -> None:
    """nota verify on a BLOCK produces a passport whose remediation array
    matches what explain derives from that same passport."""
    from nota import contract as contract_mod
    from nota import passport as passport_mod
    from nota import verify as verify_mod

    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=tmp_path, capture_output=True, text=True, check=True
        ).stdout.strip()

    _git("init", "-q")
    _git("config", "user.email", "t@t.t")
    _git("config", "user.name", "t")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    _git("add", "-A")
    _git("commit", "-qm", "base")
    base = _git("rev-parse", "HEAD")

    (tmp_path / "outside.py").write_text("y = 2\n")
    _git("add", "-A")
    _git("commit", "-qm", "oos")

    contract = contract_mod.Contract(
        version=1,
        task="tidy src",
        task_source="text",
        allowed_paths=("src/**",),
        base_commit=base,
        created_at="2026-01-01T00:00:00Z",
        contract_id="explain-int",
    )
    result = verify_mod.verify(contract=contract, root=tmp_path, strict=False)
    data = passport_mod.build_passport(result)
    assert data["verdict"] == "BLOCK"
    assert data["remediation"], "BLOCK passport must carry remediation entries"
    assert data["remediation"] == build_remediations(data)


def test_cli_explain_reads_passport_and_formats(tmp_path: Path, monkeypatch) -> None:
    from nota.cli import app

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "500")

    p = _passport(secret_findings=[{"path": "a.py", "line": 1, "pattern": "JWT"}])
    passport_path = tmp_path / "passport.json"
    passport_path.write_text(json.dumps(p))

    runner = CliRunner()
    res = runner.invoke(app, ["explain", "--passport", str(passport_path)])
    assert res.exit_code == 0, res.output
    assert "Issue 1" in res.output

    res = runner.invoke(app, ["explain", "--passport", str(passport_path), "--format", "json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["remediations"][0]["cc_prompt"]

    out_html = tmp_path / "report.html"
    res = runner.invoke(
        app,
        ["explain", "--passport", str(passport_path), "--format", "html", "--out", str(out_html)],
    )
    assert res.exit_code == 0
    assert out_html.read_text().startswith("<!doctype html>")

    res = runner.invoke(app, ["explain", "--passport", str(tmp_path / "missing.json")])
    assert res.exit_code == 2
