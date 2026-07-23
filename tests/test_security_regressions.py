"""Regression tests for security review findings (rounds 1-5).

Each test covers a specific vulnerability that was found and fixed, ensuring
it cannot silently regress. Tests are named after the finding ID they cover.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from notari import contract as contract_mod
from notari import provenance as provenance_mod
from notari import verify as verify_mod
from notari.policy import _glob_segments
from notari.verify import Verdict


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "app.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


# ── H-1: base_commit option injection ─────────────────────────────────────────


class TestH1BaseCommitOptionInjection:
    """A crafted contract.base_commit like '--output=/tmp/x' must not be
    passed raw to git, where it would be interpreted as an option."""

    def test_option_injection_blocked_strict(self, repo: Path) -> None:
        contract = contract_mod.Contract(
            version=1,
            task="test",
            task_source="text",
            allowed_paths=("**",),
            base_commit="--output=/tmp/exfil",
            created_at="2026-01-01T00:00:00Z",
            contract_id="test-h1",
        )
        result = verify_mod.verify(contract=contract, root=repo, strict=True)
        assert result.verdict is Verdict.BLOCK
        assert any("not a valid commit SHA" in r for r in result.reasons)

    def test_option_injection_tolerated_cooperative(self, repo: Path) -> None:
        contract = contract_mod.Contract(
            version=1,
            task="test",
            task_source="text",
            allowed_paths=("**",),
            base_commit="--output=/tmp/exfil",
            created_at="2026-01-01T00:00:00Z",
            contract_id="test-h1",
        )
        result = verify_mod.verify(contract=contract, root=repo, strict=False)
        assert result.verdict is not None  # doesn't crash

    def test_valid_sha_accepted(self, repo: Path) -> None:
        assert _git(repo, "rev-parse", "HEAD")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        assert contract.base_commit is not None
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.verdict is Verdict.PASS


# ── H-2: strict mode requires contract.repo ──────────────────────────────────


class TestH2StrictRequiresRepo:
    """In strict mode, when the environment identifies a repo (GITHUB_REPOSITORY),
    a contract without a repo binding must BLOCK, prevents cross-repo replay.

    In strict mode, unsigned contracts BLOCK on provenance first (M-1 early exit),
    so repo-binding tests use cooperative mode to isolate the repo check."""

    def test_missing_repo_warns_cooperative(self, repo: Path) -> None:
        contract, _ = contract_mod.begin(
            "test task",
            allowed_paths=["**"],
            root=repo,
        )
        assert contract.repo is None
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract,
            root=repo,
            strict=False,
            env=env,
        )
        # Cooperative mode doesn't block on missing repo, but strict does
        assert result.verdict is not None

    def test_unsigned_contract_blocks_strict(self, repo: Path) -> None:
        """Strict mode blocks unsigned contracts before reaching repo check."""
        contract, _ = contract_mod.begin(
            "test task",
            allowed_paths=["**"],
            root=repo,
        )
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract,
            root=repo,
            strict=True,
            env=env,
        )
        assert result.verdict is Verdict.BLOCK

    def test_mismatched_repo_warns_cooperative(self, repo: Path) -> None:
        contract, _ = contract_mod.begin(
            "test task",
            allowed_paths=["**"],
            root=repo,
            repo="owner/other",
        )
        env = {"GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract,
            root=repo,
            strict=False,
            env=env,
        )
        assert any("repo" in r.lower() for r in result.reasons)


# ── H-4: renamed file secret detection ───────────────────────────────────────


def _fake_openai_key() -> str:
    """Build a string that matches the OpenAI Project API Key pattern without
    embedding a literal secret in the source file."""
    return "sk-" + "proj-" + "a" * 60


class TestH4RenameSecretDetection:
    """A 100% rename produces no added lines in the diff, so secrets in the
    renamed file must be caught via blob-level scanning."""

    def test_renamed_file_with_secret_detected(self, repo: Path) -> None:
        (repo / "src" / "config.py").write_text(f"API_KEY = '{_fake_openai_key()}'\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add config with secret")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "settings.py").write_text((repo / "src" / "config.py").read_text())
        (repo / "src" / "config.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename config to settings")
        result = verify_mod.verify(contract=contract, root=repo)
        has_secret = bool(result.secret_findings)
        assert has_secret, "renamed file's secret should be detected via blob scan"

    def test_renamed_file_without_secret_clean(self, repo: Path) -> None:
        (repo / "src" / "utils.py").write_text("def helper(): pass\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add utils")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "helpers.py").write_text((repo / "src" / "utils.py").read_text())
        (repo / "src" / "utils.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename utils to helpers")
        result = verify_mod.verify(contract=contract, root=repo)
        assert not result.secret_findings


# ── R6-H1: UTF-16 encoded secrets ─────────────────────────────────────────────


class TestR6H1Utf16Secrets:
    """Secrets encoded as UTF-16 must be detected, not silently skipped."""

    def test_utf16le_secret_in_added_file(self, repo: Path) -> None:
        key_line = f"API_KEY = '{_fake_openai_key()}'\n"
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        utf16_content = key_line.encode("utf-16-le")
        (repo / "src" / "creds.py").write_bytes(b"\xff\xfe" + utf16_content)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add utf16 creds")
        result = verify_mod.verify(contract=contract, root=repo)
        has_secret = bool(result.secret_findings)
        assert has_secret, "UTF-16LE encoded secret should be detected"

    def test_utf16be_secret_in_renamed_file(self, repo: Path) -> None:
        key_line = f"API_KEY = '{_fake_openai_key()}'\n"
        utf16_content = key_line.encode("utf-16-be")
        (repo / "src" / "old.py").write_bytes(b"\xfe\xff" + utf16_content)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add utf16 file")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "new.py").write_bytes((repo / "src" / "old.py").read_bytes())
        (repo / "src" / "old.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename utf16 file")
        result = verify_mod.verify(contract=contract, root=repo)
        has_secret = bool(result.secret_findings)
        assert has_secret, "UTF-16BE renamed secret should be detected via blob scan"


# ── R6-H2: candidate blob vs worktree ────────────────────────────────────────


class TestR6H2CandidateBlob:
    """The rename scanner must read from the candidate commit, not the worktree."""

    def test_scan_reads_candidate_not_worktree(self, repo: Path) -> None:
        """When the worktree differs from the candidate commit, the scanner
        should find secrets in the candidate's blob, not the worktree file."""
        key_line = f"API_KEY = '{_fake_openai_key()}'\n"
        (repo / "src" / "config.py").write_text(key_line)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add secret")
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "settings.py").write_text(key_line)
        (repo / "src" / "config.py").unlink()
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename with secret")
        candidate_sha = _git(repo, "rev-parse", "HEAD")
        # Overwrite the worktree file with clean content AFTER committing
        (repo / "src" / "settings.py").write_text("clean = True\n")
        # verify should read the COMMITTED blob, not the worktree
        result = verify_mod.verify(contract=contract, root=repo, head=candidate_sha)
        has_secret = bool(result.secret_findings)
        assert has_secret, "scanner should read candidate blob, not worktree"


# ── R6-M1: contract provenance checked before git work ────────────────────────


class TestR6M1EarlyProvenance:
    """Strict mode should reject a forged contract before doing expensive git work."""

    def test_forged_contract_blocked_early(self, repo: Path) -> None:
        contract = contract_mod.Contract(
            version=1,
            task="forged task",
            task_source="text",
            allowed_paths=("**",),
            base_commit="0" * 40,
            created_at="2026-01-01T00:00:00Z",
            contract_id="forged-contract",
        )
        result = verify_mod.verify(contract=contract, root=repo, strict=True)
        assert result.verdict is Verdict.BLOCK
        assert any("provenance" in r for r in result.reasons)


# ── M-2: deep path glob recursion ────────────────────────────────────────────


class TestM2DeepPathGlob:
    """A very deep path (1600+ segments) with ** patterns must not blow the
    stack; the DP-memoized matcher handles it in O(n*m)."""

    def test_deep_path_does_not_recurse(self) -> None:
        deep = ["a"] * 1600
        pat = ["**", "a"]
        assert _glob_segments(deep, pat) is True

    def test_deep_path_no_match(self) -> None:
        deep = ["a"] * 1600
        pat = ["**", "b"]
        assert _glob_segments(deep, pat) is False

    def test_deep_path_multiple_stars(self) -> None:
        deep = ["a", "b"] * 800
        pat = ["**", "a", "**", "b"]
        assert _glob_segments(deep, pat) is True

    def test_shallow_path_still_works(self) -> None:
        assert _glob_segments(["src", "app.py"], ["src", "**"]) is True
        assert _glob_segments(["src", "app.py"], ["**", "*.py"]) is True
        assert _glob_segments(["src", "app.py"], ["lib", "**"]) is False


# ── H-3: wrapper strict requires head_commit ─────────────────────────────────
# (Covered in test_action_wrapper.py via the fake notari; this is a unit-level
# regression for the verify() function itself.)


class TestH3CandidateBinding:
    """The passport must contain a head_commit that matches the evaluated ref,
    so evidence can't describe a different candidate."""

    def test_head_commit_populated(self, repo: Path) -> None:
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "new.py").write_text("y = 2\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "change")
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.head_commit is not None
        assert len(result.head_commit) >= 7


# ── R7: _block_result → build_passport roundtrip ────────────────────────────


class TestBlockResultPassportRoundtrip:
    """_block_result() must produce a VerifyResult that build_passport() accepts
    without crashing, since every strict-mode early-exit uses this path."""

    def test_block_result_builds_valid_passport(self, repo: Path) -> None:
        from notari import passport as passport_mod

        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        result = verify_mod._block_result(
            contract,
            "test block reason",
            strict=True,
            root=repo,
            head="HEAD",
        )
        passport = passport_mod.build_passport(result)
        assert passport["verdict"] == "BLOCK"
        assert passport["head_commit"] is not None
        assert "test block reason" in passport["reasons"]
        assert passport["evidence"]["changed_files"] == []

    def test_block_result_renders_markdown(self, repo: Path) -> None:
        from notari import passport as passport_mod

        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        result = verify_mod._block_result(
            contract,
            "provenance failure",
            strict=True,
            root=repo,
            head="HEAD",
        )
        md = passport_mod.render_markdown(result)
        assert "BLOCK" in md
        assert "provenance failure" in md


# ── R7: candidate_sha validation ────────────────────────────────────────────


class TestCandidateShaValidation:
    """candidate_sha must be validated as a hex SHA after resolution, so a
    malicious ref that doesn't resolve can't be injected into git commands."""

    def test_bad_ref_blocks(self, repo: Path) -> None:
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        result = verify_mod.verify(
            contract=contract,
            root=repo,
            head="--output=/tmp/evil",
        )
        assert result.verdict is Verdict.BLOCK
        assert any("did not resolve" in r for r in result.reasons)


# ── R7: _decode_blob UTF-8-BOM handling ─────────────────────────────────────


class TestDecodeBlobBom:
    """_decode_blob must strip BOMs from all supported encodings."""

    def test_utf8_bom_stripped(self) -> None:
        content = b"\xef\xbb\xbfhello world"
        decoded = verify_mod._decode_blob(content)
        assert decoded == "hello world"
        assert not decoded.startswith("﻿")

    def test_utf16le_bom_stripped(self) -> None:
        content = b"\xff\xfe" + "secret_key".encode("utf-16-le")
        decoded = verify_mod._decode_blob(content)
        assert decoded == "secret_key"
        assert not decoded.startswith("﻿")

    def test_utf16be_bom_stripped(self) -> None:
        content = b"\xfe\xff" + "secret_key".encode("utf-16-be")
        decoded = verify_mod._decode_blob(content)
        assert decoded == "secret_key"

    def test_plain_utf8_unchanged(self) -> None:
        decoded = verify_mod._decode_blob(b"just ascii")
        assert decoded == "just ascii"

    def test_latin1_fallback(self) -> None:
        decoded = verify_mod._decode_blob(b"\xff\xfe\xfd")
        assert isinstance(decoded, str)


# ── R7: _waived_secret int(line) crash guard ────────────────────────────────


class TestWaivedSecretBadLine:
    """A non-numeric line in exceptions.json must not crash the gate."""

    def test_nonnumeric_line_skips_waiver(self) -> None:
        from notari.policy import SecretFinding

        finding = SecretFinding(path="src/app.py", line=10, pattern_name="test")
        exceptions = [{"type": "secret", "path": "src/app.py", "line": "not-a-number"}]
        result = verify_mod._waived_secret(finding, exceptions)
        assert result is None

    def test_none_line_still_matches(self) -> None:
        from notari.policy import SecretFinding

        finding = SecretFinding(path="src/app.py", line=10, pattern_name="test")
        exceptions = [{"type": "secret", "path": "src/app.py"}]
        result = verify_mod._waived_secret(finding, exceptions)
        assert result is not None


# ── R7: action.yml ↔ pyproject.toml version sync ───────────────────────────


class TestVersionSync:
    """The version pinned in action.yml must match pyproject.toml and _version.py."""

    def test_action_yml_matches_pyproject(self) -> None:
        import tomllib

        root = Path(__file__).parent.parent
        with open(root / "pyproject.toml", "rb") as f:
            pyproject_version = tomllib.load(f)["project"]["version"]
        action_text = (root / "action.yml").read_text()
        assert f"=={pyproject_version}" in action_text, (
            f"action.yml should pin =={pyproject_version}"
        )

    def test_version_py_matches_pyproject(self) -> None:
        import tomllib

        root = Path(__file__).parent.parent
        with open(root / "pyproject.toml", "rb") as f:
            pyproject_version = tomllib.load(f)["project"]["version"]
        from notari._version import __version__

        assert __version__ == pyproject_version


# ── base_commit ancestry: empty-diff false-positive PASS ─────────────────────


class TestBaseCommitAncestry:
    """A contract whose base_commit equals HEAD produces an empty diff, so every
    policy check trivially passes, a false-positive PASS. Strict mode blocks a
    base that isn't an ancestor of the candidate; the empty-diff case (base ==
    head) is the canonical instance."""

    def test_base_equals_head_blocks_strict(self, repo: Path) -> None:
        from notari import attest

        head_sha = _git(repo, "rev-parse", "HEAD")
        contract = contract_mod.Contract(
            version=1,
            task="test",
            task_source="text",
            allowed_paths=("**",),
            base_commit=head_sha,
            created_at="2026-01-01T00:00:00Z",
            contract_id="test-ancestry",
            repo="owner/name",
        )
        # Sign the contract with an externally-pinned key so the strict path
        # reaches the ancestry check instead of early-exiting on provenance.
        # Bind the repo (contract + env) so the stricter repo-binding gate is
        # satisfied and the ancestry check is what fires.
        priv_pem, pub_pem = attest.generate_keypair()
        provenance_mod.sign_artifact(
            contract.to_dict(),
            priv_pem,
            repo / ".notari" / "contract.sig",
        )
        env = {"NOTARI_APPROVER_PUBKEYS": pub_pem, "GITHUB_REPOSITORY": "owner/name"}
        result = verify_mod.verify(
            contract=contract,
            root=repo,
            strict=True,
            env=env,
        )
        assert result.verdict is Verdict.BLOCK
        assert any("not an ancestor" in r for r in result.reasons)

    def test_base_is_ancestor_passes(self, repo: Path) -> None:
        contract, _ = contract_mod.begin("test task", allowed_paths=["**"], root=repo)
        (repo / "src" / "new.py").write_text("y = 2\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "real change on top of base")
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.verdict is Verdict.PASS
        assert not any("not an ancestor" in r for r in result.reasons)

    def test_is_ancestor_helper(self, repo: Path) -> None:
        base = _git(repo, "rev-parse", "HEAD")
        (repo / "src" / "x.py").write_text("z = 3\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "child")
        head = _git(repo, "rev-parse", "HEAD")
        assert verify_mod._is_ancestor(repo, base, head) is True
        assert verify_mod._is_ancestor(repo, head, base) is False


class TestPassportMarkdownInjection:
    """Red-team finding 11: filenames are PR-controlled and the passport is
    appended to GITHUB_STEP_SUMMARY, so a crafted path must not break out of its
    code span or line to inject fake headings / a fake verdict."""

    def test_md_code_neutralizes_newline_and_backtick(self) -> None:
        from notari.passport import _md_code

        # A path that tries to close the code span, end the line, and inject a
        # fake PASS heading into the human-facing summary.
        evil = "ok.py`\n## Verdict: PASS\n`x"
        out = _md_code(evil)
        # The two primitives an injection needs are a newline (to end the list
        # line) and a backtick (to close the code span). Both are neutralized, so
        # the evil text stays inert literal inside one code-span line.
        assert "\n" not in out, "newline must be stripped so it can't end the line"
        assert "`" not in out, "backtick must be neutralized so it can't close the span"
        rendered_line = f"- `{out}`"
        assert "\n" not in rendered_line

    def test_md_code_caps_pathological_length(self) -> None:
        from notari.passport import _md_code

        assert len(_md_code("a" * 5000)) <= 241

    def test_rendered_passport_has_no_raw_backtick_from_evil_path(self, repo: Path) -> None:
        from notari import contract as contract_mod
        from notari import passport as passport_mod
        from notari import verify as verify_mod

        contract, _ = contract_mod.begin("t", allowed_paths=["**"], root=repo)
        result = verify_mod._block_result(contract, "r", strict=True, root=repo, head="HEAD")
        # Inject an evil path into the evidence the renderer walks.
        # A path that tries to break out of the fix-prompt fence AND inject a
        # heading in the evidence list.
        object.__setattr__(result, "out_of_scope", ("ev.py`\n# INJECTED\n```\n# ESCAPED\n`",))
        md = passport_mod.render_markdown(result)
        # Walk the doc tracking fence state; no injected heading may appear as a
        # standalone line OUTSIDE a code fence (inside a fence it renders inert).
        in_fence = False
        for line in md.splitlines():
            if line.strip().startswith("```"):
                in_fence = not in_fence
                continue
            if not in_fence:
                assert not line.lstrip().startswith("# INJECTED"), line
                assert not line.lstrip().startswith("# ESCAPED"), line


class TestUnrestrictedScopeIsSurfaced:
    """Red-team finding 2: an unrestricted contract must never render like a
    scoped one, so a reviewer sees a PASS means 'nothing forbidden', not 'only
    the approved paths'."""

    def test_passport_flags_unrestricted_scope(self, repo: Path) -> None:
        from notari import contract as contract_mod
        from notari import passport as passport_mod
        from notari import verify as verify_mod

        contract, _ = contract_mod.begin("t", allowed_paths=["**"], root=repo)
        result = verify_mod._block_result(contract, "r", strict=True, root=repo, head="HEAD")
        md = passport_mod.render_markdown(result)
        assert "unrestricted" in md.lower()
        assert "perimeter is the only boundary" in md

    def test_passport_scoped_contract_not_flagged(self, repo: Path) -> None:
        from notari import contract as contract_mod
        from notari import passport as passport_mod
        from notari import verify as verify_mod

        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        result = verify_mod._block_result(contract, "r", strict=True, root=repo, head="HEAD")
        md = passport_mod.render_markdown(result)
        assert "unrestricted" not in md.lower()


class TestReleaseToolchainPinned:
    """Red-team finding 7: the OIDC-privileged release job must not resolve an
    unbounded/latest build toolchain. Pins are guarded so they can't regress to
    `--upgrade`."""

    def test_release_build_deps_are_pinned_not_upgraded(self) -> None:
        root = Path(__file__).parent.parent
        rel = (root / ".github" / "workflows" / "release.yml").read_text()
        assert "pip install --upgrade pip build twine" not in rel
        for pin in ("pip==", "build==", "twine=="):
            assert pin in rel, pin

    def test_build_backend_is_pinned_exactly(self) -> None:
        import tomllib

        root = Path(__file__).parent.parent
        with open(root / "pyproject.toml", "rb") as f:
            requires = tomllib.load(f)["build-system"]["requires"]
        assert any(r.startswith("hatchling==") for r in requires), requires
