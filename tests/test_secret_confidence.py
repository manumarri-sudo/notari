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


class TestSuppressionHolesFoundByCrossVendorReview:
    """Round-6 wave-3 review: the first cut of the precision work opened five new
    holes of its own. Each is pinned here with the exact shape that defeated it."""

    # Built by concatenation so this file's own text is not credential-shaped.
    SEED_NO_DIGITS = "MFRGG" + "ZDFMZTW" + "QZLK"
    BRACKETED = "Sup3r" + "[Secret]" + "Pass99"
    OPAQUE = "9f8Xk2" + "LpQ7rT4" + "vZmN0bY6"

    def test_digit_free_all_caps_seed_is_not_suppressed(self) -> None:
        """The all-caps rule fullmatched ANY uppercase run up to 40 chars, so a
        digit-free base32 seed was swallowed while the digit-bearing seed used in
        the earlier tests happened to be caught. Now capped at a single short word
        unless underscore-separated."""
        assert secrets_mod.scan("TOTP_SECRET=" + self.SEED_NO_DIGITS)

    @pytest.mark.parametrize("name", ["PASSWORD", "APIKEY", "DB_PASSWORD", "AWS_ACCESS_KEY_ID"])
    def test_env_var_name_references_stay_suppressed(self, name: str) -> None:
        assert secrets_mod._looks_like_nonsecret(name) is True

    def test_trailing_bracket_does_not_defeat_the_expression_check(self) -> None:
        """A regex requiring a closing bracket at the end was defeated by appending
        one: the bracket group must close at the END with nothing trailing, which is
        counted rather than pattern-matched."""
        assert secrets_mod.scan("DB_PASSWORD=" + self.BRACKETED)
        assert secrets_mod.scan("DB_PASSWORD=" + self.BRACKETED + "]")

    def test_subscript_prefix_followed_by_a_real_value_is_not_suppressed(self) -> None:
        """The truncated-call rule used match(), so anything merely STARTING with
        `ident["` was suppressed no matter what followed."""
        payload = 'cfg["' + self.OPAQUE + '"]==REALVALUE'
        assert secrets_mod.scan("DB_PASSWORD=" + payload)

    def test_genuine_expressions_are_still_suppressed(self) -> None:
        for expr in ('data["token"]', "load_api_key()", "request.headers.get('x')"):
            assert secrets_mod._looks_like_nonsecret(expr) is True, expr

    def test_explicit_credential_flags_are_not_length_floored(self) -> None:
        """The floor belongs to `env-secret` alone. A credential CLI flag names its
        argument as a password, so flooring it cost real recall on the most explicit
        shape in the set."""
        assert secrets_mod.scan("--password A1b2C3d4")

    def test_short_bare_assignment_is_a_documented_miss(self) -> None:
        """The residual cost of the floor, asserted so it stays a KNOWN limit rather
        than drifting silently: a sub-10-character value in a bare NAME=value
        assignment is not reported. See docs/SECURITY-MODEL.md."""
        assert secrets_mod.scan("DB_PASSWORD=A1b2C3d4") == []


class TestWideEncodingsCannotHideACredential:
    SOURCE = 'AWS_KEY = "' + _VENDOR + '"\n'

    @pytest.mark.parametrize(
        "encoding,bom",
        [
            ("utf-32-le", b""),
            ("utf-32-be", b""),
            ("utf-32-le", b"\xff\xfe\x00\x00"),
            ("utf-32-be", b"\x00\x00\xfe\xff"),
        ],
    )
    def test_utf32_is_decoded_and_scanned(self, encoding: str, bom: bytes) -> None:
        """UTF-32 is NUL-bearing, so the diff channel is blind to it exactly as it
        is to UTF-16, and decoding it as UTF-16 yields NUL-interleaved text that
        destroys every ASCII pattern. The UTF-32-LE BOM is also a superset of the
        UTF-16-LE BOM, so BOM order matters."""
        decoded = verify_mod._decode_blob(bom + self.SOURCE.encode(encoding))
        found = {h.pattern_name for h in secrets_mod.scan(decoded)}
        assert "AWS Access Key ID" in found, (encoding, decoded[:32])


class TestBracketCountingIsNotFooledByMalformedGroups:
    """Self-attack on the counting rewrite, before Codex saw it: a plain depth
    counter treats `(` and `[` as interchangeable, so a mismatched pair balanced to
    zero at the end and a real password containing one was suppressed. Pairs must
    actually match, which needs a stack."""

    PW = "Xk9" + "mQ2vLpR" + "7wZ4tB"

    @pytest.mark.parametrize(
        "shape",
        [
            "cfg[{pw})",       # mismatched: opens square, closes round
            "cfg({pw}]",       # mismatched the other way
            "cfg[{pw}]{pw}",   # closes early, then continues
            "cfg[{pw}]]",      # one extra closer
            "[{pw}]",          # no leading identifier
            "cfg[{pw}",        # never closes, no quote inside
            "a[b][{pw}]",      # two groups, first closes early
            "cfg[{pw}]=x",     # closes then assigns
            "x({pw})y",        # closes then trails
        ],
    )
    def test_malformed_groups_do_not_suppress_a_real_value(self, shape: str) -> None:
        value = shape.format(pw=self.PW)
        assert secrets_mod._looks_like_nonsecret(value) is False, value

    @pytest.mark.parametrize(
        "expr",
        [
            'data["token"]',
            "load_api_key()",
            "request.headers.get('Authorization')",
            "cfg[nested[inner]]",
            "obj.attr.method(a, b)",
        ],
    )
    def test_well_formed_expressions_are_still_suppressed(self, expr: str) -> None:
        assert secrets_mod._looks_like_nonsecret(expr) is True, expr


class TestCredentialSurvivesMixedScriptEncodings:
    """The ASCII-ratio tiebreak must not lose an ASCII credential embedded in
    genuinely non-ASCII content, which is where a ratio heuristic could plausibly
    pick the wrong width."""

    @pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
    def test_ascii_credential_inside_cjk_content_is_found(self, encoding: str) -> None:
        text = "説明テスト日本語テキスト\nAWS_KEY=" + _VENDOR + "\n"
        decoded = verify_mod._decode_blob(text.encode(encoding))
        assert "AWS Access Key ID" in {h.pattern_name for h in secrets_mod.scan(decoded)}

    def test_a_bom_appearing_mid_file_does_not_break_decoding(self) -> None:
        raw = ("AWS_KEY=" + _VENDOR + "\n").encode("utf-16-le") + "﻿more\n".encode("utf-16-le")
        decoded = verify_mod._decode_blob(raw)
        assert "AWS Access Key ID" in {h.pattern_name for h in secrets_mod.scan(decoded)}
