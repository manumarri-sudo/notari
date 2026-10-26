"""`notari scan`: the drop-in check with no contract and no keys.

Pins the product narrowing of 2026-10-26: a pull request diff is scanned for
secrets, gate tamper and sensitive surfaces against a synthetic every-path
contract whose base is the merge-base, the passport says `mode: scan`, and the
scan never reads `.notari/contract.json`.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from notari import passport as passport_mod
from notari import scan as scan_mod
from notari.cli import app
from notari.verify import Verdict, VerifyError

# Built at runtime so this file never holds the contiguous key shape.
_VENDOR = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_OPAQUE = "JBSWY" + "3DPEHPK" + "3PXP"


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.fixture
def pr(tmp_path: Path) -> Path:
    """A repo on branch `feature` with one benign commit past `main`."""
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / ".github" / "workflows").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    (r / "src" / "app.py").write_text("x = 1\n")
    (r / ".github" / "workflows" / "ci.yml").write_text("name: ci\n")
    (r / "package-lock.json").write_text("{}\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "checkout", "-qb", "feature")
    (r / "src" / "app.py").write_text("x = 1\ny = 2\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "in-scope change")
    return r


def _commit(repo: Path, rel: str, text: str, *, append: bool = True) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    prev = p.read_text() if append and p.exists() else ""
    p.write_text(prev + text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"edit {rel}")


class TestVerdicts:
    def test_benign_change_passes(self, pr: Path) -> None:
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.PASS
        assert result.base_commit == _git(pr, "rev-parse", "main")
        assert result.out_of_scope == ()
        assert any(r.startswith("scan mode:") for r in result.reasons)
        # no boundary-mode wording leaks into a scan passport
        assert "no secrets, no gate tamper, no sensitive surface touched" in result.reasons
        assert not any("provenance" in r or "approved boundary" in r for r in result.reasons)

    def test_workflow_edit_blocks(self, pr: Path) -> None:
        _commit(pr, ".github/workflows/ci.yml", "# tampered\n")
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.BLOCK
        assert ".github/workflows/ci.yml" in result.gate_tamper_hits

    def test_vendor_secret_blocks(self, pr: Path) -> None:
        _commit(pr, "src/app.py", f'KEY = "{_VENDOR}"\n')
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.BLOCK
        assert result.secret_findings

    def test_loose_secret_shape_reviews(self, pr: Path) -> None:
        _commit(pr, "src/app.py", f'DB_PASSWORD = "{_OPAQUE}"\n')
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.NEEDS_REVIEW

    def test_lockfile_edit_reviews(self, pr: Path) -> None:
        _commit(pr, "package-lock.json", '{"a": 1}\n', append=False)
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.NEEDS_REVIEW
        assert "package-lock.json" in result.sensitive_surfaces.get("lockfiles", ())

    def test_diff_is_measured_from_merge_base(self, pr: Path) -> None:
        """A commit that lands on main after the branch forked is not the
        pull request's change and must not be scanned."""
        _git(pr, "checkout", "-q", "main")
        _commit(pr, "src/app.py", f'KEY = "{_VENDOR}"\n')
        _git(pr, "checkout", "-q", "feature")
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.PASS


class TestNoContractNoKeys:
    def test_scan_ignores_a_contract_on_disk(self, pr: Path) -> None:
        """A contract, signed or forged, present or deleted, is not an input."""
        (pr / ".notari").mkdir()
        (pr / ".notari" / "contract.json").write_text(
            json.dumps({"task": "x", "allowed_paths": ["nothing/**"], "base_commit": "deadbeef"})
        )
        result = scan_mod.scan(root=pr, base="main", env={})
        assert result.verdict is Verdict.PASS
        assert result.contract.task_source == scan_mod.SCAN_TASK_SOURCE
        assert result.contract.allowed_paths == ("**",)

    def test_passport_says_scan(self, pr: Path) -> None:
        result = scan_mod.scan(root=pr, base="main", env={})
        passport = passport_mod.build_passport(result)
        assert passport["mode"] == "scan"
        md = passport_mod.render_markdown(result)
        assert "scan mode" in md
        assert "unrestricted" not in md

    def test_boundary_passport_says_boundary(self, pr: Path) -> None:
        from notari import contract as contract_mod
        from notari import verify as verify_mod

        contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=pr)
        result = verify_mod.verify(contract=contract, root=pr)
        assert passport_mod.build_passport(result)["mode"] == "boundary"


class TestBaseResolution:
    def test_env_base_sha_is_used(self, pr: Path) -> None:
        sha = _git(pr, "rev-parse", "main")
        result = scan_mod.scan(root=pr, env={"NOTARI_BASE_SHA": sha})
        assert result.base_commit == sha

    def test_explicit_base_beats_env(self, pr: Path) -> None:
        bogus = "0" * 40
        result = scan_mod.scan(root=pr, base="main", env={"NOTARI_BASE_SHA": bogus})
        assert result.base_commit == _git(pr, "rev-parse", "main")

    def test_falls_back_to_main(self, pr: Path) -> None:
        result = scan_mod.scan(root=pr, env={})
        assert result.base_commit == _git(pr, "rev-parse", "main")

    def test_no_base_anywhere_is_an_error_not_a_pass(self, pr: Path) -> None:
        _git(pr, "branch", "-m", "main", "trunk")
        with pytest.raises(VerifyError, match="no base ref"):
            scan_mod.scan(root=pr, env={})

    @pytest.mark.parametrize("ref", ["--output=/tmp/x", "-h"])
    def test_option_shaped_refs_are_rejected(self, pr: Path, ref: str) -> None:
        with pytest.raises(VerifyError, match="looks like an option"):
            scan_mod.scan(root=pr, base=ref, env={})


class TestCli:
    def test_pass_exits_zero_and_writes_passport(self, pr: Path, monkeypatch) -> None:
        monkeypatch.chdir(pr)
        out = pr / "out"
        result = CliRunner().invoke(app, ["scan", "--base", "main", "--passport-dir", str(out)])
        assert result.exit_code == 0, result.output
        assert json.loads((out / "passport.json").read_text())["mode"] == "scan"
        assert "PASS" in result.output

    def test_block_exits_one(self, pr: Path, monkeypatch) -> None:
        _commit(pr, ".github/workflows/ci.yml", "# tampered\n")
        monkeypatch.chdir(pr)
        result = CliRunner().invoke(app, ["scan", "--base", "main", "--no-passport"])
        assert result.exit_code == 1
        assert "BLOCK" in result.output

    def test_no_base_exits_two(self, pr: Path, monkeypatch) -> None:
        _git(pr, "branch", "-m", "main", "trunk")
        monkeypatch.chdir(pr)
        monkeypatch.delenv("NOTARI_BASE_SHA", raising=False)
        result = CliRunner().invoke(app, ["scan", "--no-passport"])
        assert result.exit_code == 2
        assert "scan failed" in result.output

    def test_json_output(self, pr: Path, monkeypatch) -> None:
        monkeypatch.chdir(pr)
        result = CliRunner().invoke(app, ["scan", "--base", "main", "--no-passport", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.output)["mode"] == "scan"
