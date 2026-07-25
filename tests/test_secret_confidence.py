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
                # The HIT's confidence, not the pattern name's: an anchored pattern
                # whose value looks like a placeholder is demoted to review rather
                # than dropped, so the pattern name alone would read as blocking.
                if hit.confidence != "low":
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
            'load_api_key()["prod"]',  # chained groups
            'data["token]"]',  # bracket inside a string literal
            "obj.attr.method(a, b)",
        ],
    )
    def test_well_formed_expressions_are_still_suppressed(self, expr: str) -> None:
        assert secrets_mod._looks_like_nonsecret(expr) is True, expr

    @pytest.mark.parametrize("value", ["hunter2[Prod]", "cfg[nested[inner]]", "cfg[KEY]"])
    def test_ambiguous_bare_subscript_stays_in_scope(self, value: str) -> None:
        """Balanced brackets alone are NOT evidence of code. `hunter2[Prod]` is a
        plausible password, and suppressing the bare `identifier[word]` form on
        bracket structure alone lost it. An expression now needs a positive signal:
        a call group, a quote just inside the opener, or a dotted receiver. The cost
        is an occasional false positive that lands as review signal, not a block."""
        assert secrets_mod._is_expression_value(value) is False, value


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


class TestBlockTierIsNotVoidedByLowConfidenceFilters:
    """Round-6 wave-3b, the most serious finding of the round. Applying the FULL
    nonsecret filter to every inline shape (done to stop the anchored patterns
    firing on documentation prose) let the path rule void an anchored BLOCK-tier
    pattern: a real AWS secret access key is 40 characters of base64 alphabet, so it
    can begin with `/` and contain several more, which read as a filesystem path.
    The credential was never classified at all, so the review-versus-block posture
    never applied to it."""

    AWS_SECRET = "/AbCdEfGhIjKlMnOpQr" + "/RsTuVwXyZ0123456789A"

    def test_slash_bearing_aws_secret_key_is_caught_and_blocks(self) -> None:
        hits = secrets_mod.scan("aws_secret_access_key=" + self.AWS_SECRET)
        assert hits, "anchored aws-secret-key pattern was suppressed"
        assert any(not secrets_mod.is_low_confidence(h.pattern_name) for h in hits)

    def test_the_same_value_is_still_suppressed_on_the_low_confidence_tier(self) -> None:
        """The path rule is correct for a loosely-structured value; it is only wrong
        when applied to an anchored pattern."""
        assert secrets_mod._looks_like_nonsecret(self.AWS_SECRET) is True
        assert secrets_mod._looks_like_placeholder(self.AWS_SECRET) is False

    @pytest.mark.parametrize(
        "prose",
        [
            "# curl -H 'Authorization: Bearer ...'",
            "# connection string: scheme://user:PASSWORD@host",
        ],
    )
    def test_documentation_prose_is_demoted_not_dropped(self, prose: str) -> None:
        """Prose in comments must not BLOCK, which is why these were filtered at all.
        But it must not be deleted either: suppressing anchored findings by their
        VALUE lost real credentials, since a production password can literally be
        `PASSWORD1` and a real token can carry a `your_token_` prefix. Demotion gets
        both, so the assertion is "visible but non-blocking", not "absent"."""
        hits = secrets_mod.scan(prose)
        assert all(h.confidence == "low" for h in hits), [
            (h.pattern_name, h.confidence) for h in hits
        ]


class TestConfidenceReachesTheHumanFacingOutput:
    """Round-6 wave-3b: the exit-code split was right but the prose was not. The
    tier was discarded before rendering, so a keyword match was described with the
    certainty of a matched vendor key format and annotated as ::error::."""

    def test_passport_json_carries_the_confidence_tier(self, repo: Path) -> None:
        from notari import passport as passport_mod

        contract = _commit_line(repo, f'DB_PASSWORD = "{_OPAQUE}"\n')
        result = verify_mod.verify(contract=contract, root=repo)
        findings = passport_mod.build_passport(result)["evidence"]["secret_findings"]
        assert findings and all(f["confidence"] == "low" for f in findings)

    def test_low_confidence_finding_is_hedged_and_annotated_as_a_warning(self) -> None:
        from notari import explain as explain_mod

        passport = {
            "verdict": "NEEDS_REVIEW",
            "contract": {"task": "t"},
            "evidence": {
                "secret_findings": [
                    {"path": "a.py", "line": 3, "pattern": "env-secret", "confidence": "low"}
                ]
            },
        }
        rem = explain_mod.build_remediations(passport)
        assert rem[0]["kind"] == "possible_secret"
        assert "might be" in rem[0]["plain"]
        assert "anyone who sees the file can steal it" not in rem[0]["plain"]
        assert any("::warning" in a for a in explain_mod.render_github_annotations(passport))

    def test_high_confidence_finding_keeps_its_certainty(self) -> None:
        from notari import explain as explain_mod

        passport = {
            "verdict": "BLOCK",
            "contract": {"task": "t"},
            "evidence": {
                "secret_findings": [
                    {
                        "path": "a.py",
                        "line": 3,
                        "pattern": "AWS Access Key ID",
                        "confidence": "high",
                    }
                ]
            },
        }
        rem = explain_mod.build_remediations(passport)
        assert rem[0]["kind"] == "secret"
        assert "anyone who sees the file can steal it" in rem[0]["plain"]
        assert any("::error" in a for a in explain_mod.render_github_annotations(passport))

    def test_a_passport_without_the_field_is_treated_as_high_confidence(self) -> None:
        """Absence must not silently soften existing evidence in older passports."""
        from notari import explain as explain_mod

        passport = {
            "verdict": "BLOCK",
            "contract": {"task": "t"},
            "evidence": {"secret_findings": [{"path": "a.py", "line": 1, "pattern": "env-secret"}]},
        }
        assert explain_mod.build_remediations(passport)[0]["kind"] == "secret"


class TestMixedEncodingBlobDoesNotHideACredential:
    """Round-6 wave-3c. I had claimed this class did not reproduce. It does, and the
    reviewer built the proof: a blob can be a MIXTURE of a wide-encoded region and a
    plain-ASCII region, so no single decoding preserves both, and the ASCII-ratio
    tiebreak picks the wide reading because the wide prefix dominates the score."""

    # Assembled at runtime so this file's own text is not credential-shaped.
    AWS_NAME = "aws_secret" + "_access_key"
    AWS_SEC = "/AbCdEfGhIjKlMnOpQr" + "/RsTuVwXyZ0123456789A"

    @staticmethod
    def _scan_views(raw: bytes) -> set[str]:
        return {
            h.pattern_name
            for view in verify_mod._decode_blob_views(raw)[0]
            for h in secrets_mod.scan(view)
        }

    def test_wide_prefix_then_ascii_credential_is_still_found(self) -> None:
        raw = b"A\x00" * 300 + (self.AWS_NAME + "=" + self.AWS_SEC + "\nX").encode()
        assert "aws-secret-key" in self._scan_views(raw)

    def test_credential_in_the_ascii_region_needs_nul_as_a_space(self) -> None:
        """Deleting NULs glues the wide region's letters onto the ASCII region, so the
        `\\b` the anchored patterns require disappears."""
        raw = b"A\x00" * 8 + (self.AWS_NAME + "=" + self.AWS_SEC).encode()
        assert "aws-secret-key" in self._scan_views(raw)

    def test_credential_inside_the_wide_region_needs_nul_deleted(self) -> None:
        """The opposite failure: interleaved NULs split the credential itself into
        `A K I A ...`, which no pattern matches. Both salvage views are required,
        because neither alone covers both regions. This one also sits past byte 512,
        which the old prefix-only NUL probe never looked at."""
        raw = b"A" * 600 + b"\n" + ('AWS_KEY = "' + _VENDOR + '"\n').encode("utf-16-le")
        assert "AWS Access Key ID" in self._scan_views(raw)

    def test_mixed_endianness_in_one_blob(self) -> None:
        """No single decoding is correct, so every plausible wide decoding is a view."""
        raw = ("A" * 600 + "\n").encode("utf-16-le") + ('AWS_KEY = "' + _VENDOR + '"\n').encode(
            "utf-16-be"
        )
        assert "AWS Access Key ID" in self._scan_views(raw)

    def test_views_are_returned_separately_never_joined(self) -> None:
        """Joining views let an assignment prefix at the end of one bridge to a value
        at the start of the next and synthesise a credential present in NEITHER,
        which would BLOCK a clean change."""
        raw = ("A" * 17 + "\nAuthorization: Bearer ").encode("latin-1") + b"\x00" + b"4f9KzQ2LmN8PrT7"
        views, _complete = verify_mod._decode_blob_views(raw)
        assert len(views) > 1
        assert all(isinstance(v, str) for v in views)

    @pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
    def test_genuine_wide_files_report_the_real_line(self, encoding: str) -> None:
        """The primary decoding comes first and keeps its own numbering, so the line
        reported for a genuine wide-encoded file is the file's own line."""
        text = 'AWS_KEY = "' + _VENDOR + '"\n'
        primary = verify_mod._decode_blob_views(text.encode(encoding))[0][0]
        hits = [h for h in secrets_mod.scan(primary) if h.pattern_name == "AWS Access Key ID"]
        assert [h.line for h in hits] == [1]


class TestAnchoredFindingsAreDemotedNotDeleted:
    """Round-6 wave-3c: suppressing an anchored finding on the strength of its VALUE
    looking placeholder-like deleted real credentials outright. A production password
    can literally be `PASSWORD1`, and an application-issued token can carry a
    readable prefix. These now land as review signal instead of vanishing."""

    @pytest.mark.parametrize(
        "line,pattern",
        [
            ("Authorization: Bearer your_token_4f9KzQ2LmN8PrT7VwX", "bearer-token"),
            ("postgresql://admin:your_password_4f9KzQ2LmN8!@db.example.com/app", "dsn-password"),
            ("postgresql://admin:PASSWORD1@db.example.com/app", "dsn-password"),
        ],
    )
    def test_placeholder_looking_anchored_values_are_still_reported(
        self, line: str, pattern: str
    ) -> None:
        assert pattern in {h.pattern_name for h in secrets_mod.scan(line)}

    def test_a_real_anchored_value_still_blocks(self) -> None:
        hits = secrets_mod.scan("Authorization: Bearer 4f9KzQ2LmN8PrT7VwXyZ")
        assert hits and all(h.confidence == "high" for h in hits)


class TestConfidenceSurvivesEveryChannel:
    """Round-6 wave-3d: the blob-scan path built findings WITHOUT the confidence
    field, so its default flipped a demoted anchored hit back to blocking, and the
    same credential blocked or reviewed depending on which channel saw it. The audit
    record also omitted the tier, making the verdict's reason unrecoverable from the
    evidence."""

    def test_blob_path_carries_confidence(self, repo: Path) -> None:
        # A placeholder-looking anchored value: demoted, must not block.
        contract = _commit_line(repo, "url = postgresql://admin:PASSWORD1@db/app\n")
        result = verify_mod.verify(contract=contract, root=repo)
        assert result.secret_findings
        assert all(f.confidence == "low" for f in result.secret_findings), [
            (f.pattern_name, f.confidence) for f in result.secret_findings
        ]
        assert result.verdict is not Verdict.BLOCK

    def test_audit_record_states_the_tier(self, repo: Path) -> None:
        from notari import passport as passport_mod

        contract = _commit_line(repo, f'DB_PASSWORD = "{_OPAQUE}"\n')
        result = verify_mod.verify(contract=contract, root=repo)
        doc = passport_mod.build_passport(result)
        findings = doc["evidence"]["secret_findings"]
        assert findings and all("confidence" in f for f in findings)

    def test_one_credential_is_reported_once_not_once_per_view(self, repo: Path) -> None:
        """A blob has several views, and the same credential appears in more than one
        of them at different line numbers. Reporting each view separately produced
        duplicates whose lines pointed at a decoding rather than at the file, which
        also broke line-specific waivers."""
        path = repo / "src" / "wide.txt"
        path.write_bytes(b"A" * 600 + b"\n" + ('K = "' + _VENDOR + '"\n').encode("utf-16-le"))
        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "wide")
        result = verify_mod.verify(contract=contract, root=repo)
        aws = [f for f in result.secret_findings if f.pattern_name == "AWS Access Key ID"]
        assert len(aws) == 1, [(f.path, f.line) for f in aws]


class TestViewDedupKeepsEveryDistinctCredential:
    """Round-6 wave-3d self-attack, found before the reviewer got to it. Collapsing
    to one finding per (path, pattern) stopped duplicate reporting across views, but
    it also hid a SECOND distinct credential of the same pattern in a wide-encoded
    file, where the diff channel is blind and the blob channel is the only witness.
    The verdict still blocked, so this was an evidence-completeness defect rather
    than a bypass: a reviewer who fixed the reported line would never learn about
    the other one.

    The rule is now: for each pattern, take the single view that saw the MOST of it,
    earliest view winning ties. Within one view distinct lines are distinct
    credentials; across views they are the same bytes read two ways."""

    K1 = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    K2 = "AKIA" + "1234567890" + "ABCDEF"

    def _verify_file(self, repo: Path, name: str, data: bytes) -> object:
        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        (repo / "src" / name).write_bytes(data)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add")
        return verify_mod.verify(contract=contract, root=repo)

    def _aws(self, result: object) -> list[object]:
        return [f for f in result.secret_findings if f.pattern_name == "AWS Access Key ID"]

    def test_two_distinct_keys_in_a_wide_file_are_both_reported(self, repo: Path) -> None:
        data = f'a = "{self.K1}"\nb = "{self.K2}"\n'.encode("utf-16-le")
        found = self._aws(self._verify_file(repo, "wide.txt", data))
        assert [f.line for f in found] == [1, 2], [(f.path, f.line) for f in found]

    def test_one_key_in_a_wide_file_is_reported_once(self, repo: Path) -> None:
        """The duplicate-across-views case the dedup exists for."""
        data = f'a = "{self.K1}"\n'.encode("utf-16-le")
        assert len(self._aws(self._verify_file(repo, "wide.txt", data))) == 1

    def test_two_distinct_keys_in_a_plain_file_are_both_reported(self, repo: Path) -> None:
        data = f'a = "{self.K1}"\nb = "{self.K2}"\n'.encode()
        found = self._aws(self._verify_file(repo, "plain.txt", data))
        assert [f.line for f in found] == [1, 2]


class TestBaseLineSuppressionSurvivesTheViewsChange:
    """`_base_line_counts` now sums every VIEW of the base blob, which risks
    over-suppressing: if the base's salvage views contribute extra copies of a line,
    a genuinely new candidate copy could be swallowed. Both directions pinned."""

    K = "AKIA" + "IOSFODNN7" + "EXAMPLE"

    def _modify(self, repo: Path, base_text: str, new_text: str) -> object:
        f = repo / "src" / "f.txt"
        f.write_text(base_text)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "base")
        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        f.write_text(new_text)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "change")
        return verify_mod.verify(contract=contract, root=repo)

    def test_duplicated_secret_line_is_still_caught(self, repo: Path) -> None:
        """The (N+1)th identical line is newly introduced and must not hide behind
        its pre-existing twin."""
        result = self._modify(repo, f'a = "{self.K}"\n', f'a = "{self.K}"\nb = "{self.K}"\n')
        assert [f for f in result.secret_findings if f.pattern_name == "AWS Access Key ID"]
        assert result.verdict is Verdict.BLOCK

    def test_untouched_pre_existing_secret_does_not_block_an_unrelated_edit(
        self, repo: Path
    ) -> None:
        """The reason base-line counting exists at all."""
        result = self._modify(repo, f'a = "{self.K}"\n', f'a = "{self.K}"\nunrelated = 1\n')
        assert not [f for f in result.secret_findings if f.pattern_name == "AWS Access Key ID"]


class TestViewBudgetBoundsTheScanCost:
    """Views multiply scanning work, and a candidate controls how many large
    NUL-bearing files a PR touches. Measured before the budget: a 52 MB UTF-16 blob
    produced 3 views, 16.2s of scanning and 288 MB peak RSS, against roughly 5s for
    the single-view path. That only DELAYS a verdict rather than forging one, since
    no verdict means the required check never turns green, but a gate that can be
    stalled for minutes per file is a denial-of-service worth bounding.

    The budget must degrade LOUDLY: dropped views are reported as a disposition so
    an incomplete scan is never presented as a clean pass."""

    def test_small_blobs_keep_every_view(self) -> None:
        raw = ('AWS = "x"\n' * 5).encode("utf-16-le")
        views, complete = verify_mod._decode_blob_views(raw)
        assert complete is True
        assert len(views) > 1

    def test_oversized_blob_drops_views_and_says_so(self) -> None:
        raw = ("hello world\n" * 300_000).encode("utf-16-le")
        views, complete = verify_mod._decode_blob_views(raw, max_chars=1024)
        assert complete is False
        # The primary decoding is always kept: the budget reduces coverage, it never
        # leaves the file unscanned.
        assert len(views) == 1

    def test_dropped_views_are_recorded_as_a_disposition(self, repo: Path) -> None:
        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        (repo / "src" / "big.txt").write_bytes(("hello world\n" * 200_000).encode("utf-16-le"))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "big")
        original = verify_mod.DEFAULT_MAX_VIEW_CHARS
        try:
            verify_mod.DEFAULT_MAX_VIEW_CHARS = 1024
            result = verify_mod.verify(contract=contract, root=repo)
        finally:
            verify_mod.DEFAULT_MAX_VIEW_CHARS = original
        assert any("partial-decoding-coverage" in d for d in result.scan_dispositions), (
            result.scan_dispositions
        )


class TestChannelMergePrefersTheBlockingReading:
    """The diff channel and the blob channel can both report the same (path, line,
    pattern). If they disagree on confidence, keeping whichever ran first would let
    a view that mangled the surrounding syntax downgrade a credential the other
    channel read correctly. The blocking reading wins."""

    def test_high_confidence_upgrade_survives_the_merge(self) -> None:
        import dataclasses

        from notari import policy as policy_mod

        low = policy_mod.SecretFinding(
            path="a.py", line=1, pattern_name="dsn-password", confidence="low"
        )
        high = dataclasses.replace(low, confidence="high")
        # The helper the merge uses must read the carried value, not the pattern.
        assert verify_mod._confidence_of(low) == "low"
        assert verify_mod._confidence_of(high) == "high"

    def test_finding_without_the_field_defaults_to_blocking(self) -> None:
        from notari import policy as policy_mod

        legacy = policy_mod.SecretFinding(path="a.py", line=1, pattern_name="dsn-password")
        assert verify_mod._confidence_of(legacy) == "high"


class TestRedactIsNotNarrowedByScanSuppression:
    """The precision work all lives in `scan()`, which feeds the gate. `redact()`
    feeds the audit log and exports, where over-redacting is harmless and a miss
    leaks a credential, so it must stay aggressive on everything scan() suppresses.
    This asymmetry is the whole reason the filters were not put in the patterns."""

    @pytest.mark.parametrize(
        "text",
        [
            "DB_PASSWORD=short1",  # under the scan length floor
            "DB_PASSWORD=PASSWORD",  # env-var-name reference
            'DB_PASSWORD=data["token"]',  # expression, not a literal
            "DB_PASSWORD=<your-password>",  # placeholder
            "DB_PASSWORD=${DB_PASSWORD}",  # template reference
        ],
    )
    def test_values_scan_ignores_are_still_redacted(self, text: str) -> None:
        assert secrets_mod.scan(text) == [], "precondition: scan suppresses this"
        assert secrets_mod.redact(text) != text, text
        assert "REDACTED" in secrets_mod.redact(text)


class TestBlockersFromCodexPass3:
    """Four release blockers from the third cross-vendor pass, all reproduced before
    fixing. Two of them turned a real credential into a clean PASS."""

    K = "AKIA" + "IOSFODNN7" + "EXAMPLE"

    def _scenario(self, repo: Path, base: bytes, cand: bytes, exceptions: list | None = None):
        import json

        f = repo / "src" / "f.txt"
        f.write_bytes(base)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "base")
        contract, _ = contract_mod.begin("t", allowed_paths=["src/**"], root=repo)
        if exceptions:
            (repo / ".notari").mkdir(exist_ok=True)
            (repo / ".notari" / "exceptions.json").write_text(json.dumps(exceptions))
        f.write_bytes(cand)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "cand")
        return verify_mod.verify(contract=contract, root=repo)

    def test_base_counts_take_the_max_across_views_not_the_sum(self, repo: Path) -> None:
        """Summing inflated the base's count of a secret line by the number of views
        containing it, so a genuinely NEW duplicate was suppressed as pre-existing.
        A UTF-16 file whose base held one copy produced a base count of 3, swallowed
        both candidate copies, and returned a clean PASS."""
        result = self._scenario(
            repo,
            ("header\n" + f"k = {self.K}\n").encode("utf-16"),
            ("header\n" + f"k = {self.K}\n" + f"k = {self.K}\n").encode("utf-16"),
        )
        assert result.verdict is Verdict.BLOCK
        assert [f.pattern_name for f in result.secret_findings] == ["AWS Access Key ID"]

    def test_base_line_counts_uses_max(self) -> None:
        counts = verify_mod.Counter()
        views = verify_mod._decode_blob_views(
            ("header\n" + f"k = {self.K}\n").encode("utf-16")
        )[0]
        line = f"k = {self.K}"
        per_view = [v.splitlines().count(line) for v in views]
        assert sum(per_view) > max(per_view), "precondition: the line appears in several views"
        del counts

    def test_waivers_on_fabricated_salvage_lines_cannot_hide_a_credential(
        self, repo: Path
    ) -> None:
        """An alternate decoding can invent extra matches AND extra line breaks, so
        letting the highest-count view win reported a line-2 credential at lines 1
        and 3. Pre-existing line-specific waivers for those lines then waived it."""
        result = self._scenario(
            repo,
            "x\n".encode("utf-16"),
            ("héader\n" + f"k = {self.K}\n").encode("utf-16"),
            exceptions=[
                {"path": "src/f.txt", "line": 1, "reason": "r", "approved_by": "h"},
                {"path": "src/f.txt", "line": 3, "reason": "r", "approved_by": "h"},
            ],
        )
        assert result.verdict is Verdict.BLOCK
        # Reported at the PRIMARY decoding's line, which is the file's line.
        assert [f.line for f in result.secret_findings] == [2]

    @pytest.mark.parametrize(
        "value,is_code",
        [
            ("hunter2[Prod(2026)]", False),  # paren is password data, not a call
            ('hunter2["Prod("]', False),  # paren inside a string literal
            ('data["token]', False),  # unclosed SUBSCRIPT is ambiguous, report it
            ('input("Password:', True),  # unclosed CALL is code
            ('load_api_key()["prod"]', True),
            ('a("b")["c"]', True),
        ],
    )
    def test_call_signal_comes_from_the_structural_loop(self, value: str, is_code: bool) -> None:
        """`"(" in rest` counted a parenthesis belonging to the password data, so a
        call opener now only counts at the TOP level, outside any string."""
        assert secrets_mod._is_expression_value(value) is is_code, value
