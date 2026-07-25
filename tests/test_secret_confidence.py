"""Secret findings are split by CONFIDENCE, and precision comes from length plus
expression-shape, not entropy (round-6 findings P2/P3).

The low-confidence inline shapes (`env-secret`, `password-flag`, `mysql-pflag`)
match a loosely-structured value and cannot be made precise enough to hard-block:
before this split, scanning notari's own sources produced 48 findings with no real
credential present, and because verify promotes any unwaived finding to BLOCK, a
repo writing ordinary LLM code could not pass its own gate. They now surface as
review signal while vendor-format matches keep blocking, which is the posture
TruffleHog (`--fail-verified`) and GitHub push protection actually ship.

Deliberately NOT entropy-gated: measured with gitleaks' own Shannon formula, the
base32 seed used below scores 3.375 and `correct-horse-battery-staple` scores
3.495, both under gitleaks' own 3.5 threshold, so an entropy gate would miss real
credentials that length plus expression-shape catches.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from notari import contract as contract_mod
from notari import perimeter as perimeter_mod
from notari import secrets as secrets_mod
from notari import verify as verify_mod
from notari.verify import Verdict

# A base32 TOTP-seed-shaped value: a real credential with no vendor prefix, so
# only the low-confidence inline rules can see it.
_OPAQUE = "JBSWY" + "3DPEHPK" + "3PXP"
# Built at runtime so this source file never holds the contiguous key shape.
_VENDOR = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


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


def _commit_line(repo: Path, line: str) -> contract_mod.Contract:
    contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo)
    (repo / "src" / "app.py").write_text("x = 1\n" + line)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "change")
    return contract


class TestConfidenceSplitComposesTheVerdict:
    def test_low_confidence_secret_reviews_rather_than_blocks(self, repo: Path) -> None:
        contract = _commit_line(repo, f'DB_PASSWORD = "{_OPAQUE}"\n')
        perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="h")
        assert perim.block_secrets is True  # the relaxation is NOT the perimeter's
        result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
        assert result.verdict is Verdict.NEEDS_REVIEW
        # Still fully visible: demoted, never hidden.
        assert result.secret_findings
        assert any("low-confidence" in r for r in result.reasons)

    def test_vendor_format_secret_still_blocks(self, repo: Path) -> None:
        contract = _commit_line(repo, f'aws_key = "{_VENDOR}"\n')
        perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="h")
        result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
        assert result.verdict is Verdict.BLOCK
        assert result.secret_findings

    def test_confidence_predicate_matches_the_rule_set(self) -> None:
        for low in ("env-secret", "password-flag", "mysql-pflag"):
            assert secrets_mod.is_low_confidence(low) is True
        for blocking in ("bearer-token", "aws-secret-key", "dsn-password", "AWS Access Key ID"):
            assert secrets_mod.is_low_confidence(blocking) is False


class TestOwnSourcesProduceNoBlockingFindings:
    """The gate must be able to pass its own repository. This is the measurement
    that failed at 48 findings and is what would regress if the length floor or
    the expression filter were loosened."""

    def test_no_blocking_findings_in_notari_sources(self) -> None:
        src = Path(__file__).parent.parent / "src" / "notari"
        offenders: list[str] = []
        for path in sorted(src.rglob("*.py")):
            for hit in secrets_mod.scan(path.read_text()):
                if not secrets_mod.is_low_confidence(hit.pattern_name):
                    offenders.append(f"{path.relative_to(src)}:{hit.line}:{hit.pattern_name}")
        assert offenders == [], offenders


class TestPrecisionComesFromLengthAndShape:
    @pytest.mark.parametrize(
        "line",
        [
            "max_tokens=1024",
            "secret_findings=()",
            "client = Anthropic(api_key=api_key)",
            'token = data["token"]',
            'password = input("Password: ")',
            "token = request.headers.get('Authorization')",
            "api_key = load_api_key()",
            "api_key = args.api_key",
            "self.token = uuid4",
        ],
    )
    def test_ordinary_code_produces_no_finding(self, line: str) -> None:
        assert secrets_mod.scan(line) == [], line

    @pytest.mark.parametrize(
        "line",
        [
            'DB_PASSWORD = "' + _OPAQUE + '"',
            "--password $uper$ecretP4ssw0rd!x9",
            'API_TOKEN = "A1B2C3D4E5F6G7H8J9K0"',
            'SMTP_PASSWORD = "/Kj8#mQ2vLpXr9"',
            'ADMIN_PASSWORD = "{7Hx#kQ2mVp9zLr}"',
        ],
    )
    def test_real_credentials_still_produce_a_finding(self, line: str) -> None:
        assert secrets_mod.scan(line), line

    def test_short_values_are_floored_only_for_low_confidence_shapes(self) -> None:
        """A DSN password may legitimately be short, so the floor must not reach it."""
        assert secrets_mod.scan("PASSWORD_X = short1") == []
        assert secrets_mod.scan("url = redis://:Xk9#mQ2v@host")

    def test_redact_still_scrubs_below_the_scan_floor(self) -> None:
        """The floor lives in scan() only: over-redacting a log line is harmless,
        so redact() must stay aggressive on values the gate ignores."""
        assert "short1" not in secrets_mod.redact("PASSWORD_X = short1")
