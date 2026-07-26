"""Credential / secret detection for file-write tool arguments.

When an agent's Edit / Write / NotebookEdit call would land a hardcoded
credential in a file (the GitHub PAT leak failure mode, Anthropic's
November 2025 incident class), Notari catches it before the write
executes. The scanner runs deterministically on the new content; no
LLM, no network call.

Patterns are conservative on purpose - false positives here mean
asking the operator to confirm a non-secret, which is acceptable.
False negatives mean shipping a credential, which is not. Each
pattern is documented with its source provider format so a future
maintainer can verify against the vendor's published key shape.

The pattern set is intentionally smaller than truffleHog's 700+ -
this module ships the 26 highest-confidence vendor-format patterns
that cover the bulk of agent-leaked credentials seen in the wild,
with room to grow via the optional `extra_patterns` argument to
`scan`. `redact()` reuses the same patterns to strip secrets from
audit-logged / exported text without persisting the matched value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """One credential type Notari detects."""

    name: str  # "AWS Access Key", "OpenAI API Key", ...
    regex: re.Pattern[str]  # compiled at module load
    description: str = ""


@dataclass(frozen=True, slots=True)
class SecretHit:
    """One match found by scan().

    `line` is 1-indexed line number where the match starts; computed by
    counting newlines up to `matched_at`. Useful for jumping to the
    offending line in an editor without persisting the matched value.
    """

    pattern_name: str
    matched_at: int  # offset in scanned text
    length: int  # match length (we never persist the value)
    line: int = 0  # 1-indexed line where the match starts (0 = unknown)
    # "high" blocks, "low" is review signal. Usually implied by the pattern, but
    # carried per hit because an ANCHORED pattern whose value looks like a
    # placeholder is demoted rather than dropped: a production password can
    # legitimately be `PASSWORD1`, and a real token can carry a readable prefix
    # like `your_token_...`, so deleting those findings lost real credentials.
    confidence: str = "high"


# Vendor-format credential patterns. Each regex is anchored to the
# vendor's published key prefix where possible; ambiguous patterns
# (e.g. JWT) require >= 3 segments to reduce FPs on random base64.
_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS Access Key ID (programmatic IAM credentials)",
    ),
    SecretPattern(
        name="OpenAI API Key (legacy)",
        regex=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
        description="OpenAI API key, classic format",
    ),
    SecretPattern(
        name="OpenAI Project API Key",
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_-]{60,}\b"),
        description="OpenAI project-scoped API key (2024+ format)",
    ),
    SecretPattern(
        name="Anthropic API Key",
        regex=re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"),
        description="Anthropic API key (sk-ant-apiNN- / sk-ant-adminNN-)",
    ),
    SecretPattern(
        name="GitHub Personal Access Token (classic)",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        description="GitHub classic PAT",
    ),
    SecretPattern(
        name="GitHub Personal Access Token (fine-grained)",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        description="GitHub fine-grained PAT",
    ),
    SecretPattern(
        name="GitHub OAuth token",
        regex=re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        description="GitHub OAuth access token",
    ),
    SecretPattern(
        name="GitHub App token",
        regex=re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b"),
        description="GitHub App user / server token",
    ),
    SecretPattern(
        name="Stripe Live Secret Key",
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        description="Stripe production secret key",
    ),
    SecretPattern(
        name="Stripe Test Secret Key",
        regex=re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),
        description="Stripe test-mode secret key",
    ),
    SecretPattern(
        name="Stripe Restricted Key",
        regex=re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        description="Stripe restricted API key",
    ),
    SecretPattern(
        name="Slack Bot Token",
        regex=re.compile(r"\bxoxb-[A-Za-z0-9-]{50,}\b"),
        description="Slack bot user OAuth token",
    ),
    SecretPattern(
        name="Slack User Token",
        regex=re.compile(r"\bxoxp-[A-Za-z0-9-]{50,}\b"),
        description="Slack user OAuth token",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        regex=re.compile(
            r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}\b",
        ),
        description="Slack incoming-webhook URL",
    ),
    SecretPattern(
        name="Google API Key",
        regex=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        description="Google Cloud / Firebase / Maps API key",
    ),
    SecretPattern(
        name="JWT",
        regex=re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ),
        description="JSON Web Token (three base64url segments)",
    ),
    SecretPattern(
        name="Private Key (PEM block)",
        regex=re.compile(
            r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|ENCRYPTED|PGP)?\s*PRIVATE KEY-----",
        ),
        description="PEM-encoded private key header",
    ),
    SecretPattern(
        name="HuggingFace Token",
        regex=re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        description="HuggingFace user access token",
    ),
    SecretPattern(
        name="Twilio Account SID",
        regex=re.compile(r"\bAC[a-f0-9]{32}\b"),
        description="Twilio Account SID (paired with the Auth Token below)",
    ),
    SecretPattern(
        name="Twilio API Key SID",
        regex=re.compile(r"\bSK[a-f0-9]{32}\b"),
        description="Twilio scoped API key SID",
    ),
    SecretPattern(
        name="SendGrid API Key",
        regex=re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
        description="SendGrid API key (SG.XXX.YYY format)",
    ),
    SecretPattern(
        name="Mailgun API Key",
        regex=re.compile(r"\bkey-[a-f0-9]{32}\b"),
        description="Mailgun legacy API key",
    ),
    SecretPattern(
        name="Mailgun Domain Sending Key",
        regex=re.compile(r"\b(?:pubkey|sk)-[a-f0-9]{32}\b"),
        description="Mailgun domain-scoped sending key",
    ),
    SecretPattern(
        name="Stripe Webhook Secret",
        regex=re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b"),
        description="Stripe webhook signing secret",
    ),
    SecretPattern(
        name="Discord Bot Token",
        regex=re.compile(
            r"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b",
        ),
        description="Discord bot token (three base64-ish segments)",
    ),
    SecretPattern(
        name="Notion Integration Secret",
        regex=re.compile(r"\bsecret_[A-Za-z0-9]{43}\b"),
        description="Notion integration secret",
    ),
)


def patterns() -> tuple[SecretPattern, ...]:
    """Read-only view of the built-in pattern set."""
    return _PATTERNS


def is_low_confidence(pattern_name: str) -> bool:
    """True for the inline shapes that match on a loosely-structured VALUE.

    These are keyword-plus-assignment and CLI-flag shapes with no vendor-anchored
    prefix, so they carry real false-positive risk and are reported as review
    signal rather than a hard block. Vendor-format patterns and the anchored
    inline shapes (bearer header, aws_secret_access_key, DSN password) are
    specific enough to block on.

    Mirrors what the mature scanners do: TruffleHog's documented CI pattern
    (`--fail-verified`) fails a build only on credentials verified live, and
    GitHub push protection is confidence-gated precisely to "avoid push
    protection blocking commits unnecessarily when a result may be a false
    positive". Blocking on keyword-plus-entropy alone is not a posture any of
    them ship.
    """
    return pattern_name in _LOW_CONFIDENCE_INLINE


def _line_for_offset(text: str, offset: int) -> int:
    """Return the 1-indexed line number containing `offset`.

    Counts newlines in text[:offset]. O(offset) per call; for many hits
    in one body, prefer batching via _line_index.
    """
    if offset <= 0:
        return 1
    return text.count("\n", 0, offset) + 1


def scan(
    text: str,
    *,
    extra_patterns: Iterable[SecretPattern] = (),
) -> list[SecretHit]:
    """Find every credential match in `text`.

    Conservative: a single text body is scanned against every pattern;
    each match contributes one SecretHit. The matched value is NEVER
    persisted in the hit (only the pattern name, offset, length, and
    line number), so the scanner can be used safely on audit-logged
    content.

    `extra_patterns` lets the caller append custom org-specific patterns
    (e.g. an internal token prefix) without forking this module.
    """
    if not text:
        return []
    hits: list[SecretHit] = []
    for pat in (*_PATTERNS, *extra_patterns):
        for m in pat.regex.finditer(text):
            start = m.start()
            hits.append(
                SecretHit(
                    pattern_name=pat.name,
                    matched_at=start,
                    length=m.end() - start,
                    line=_line_for_offset(text, start),
                ),
            )
    # Inline-credential shapes (bearer headers, aws_secret_access_key, DSN
    # passwords, --password flags, FOO_SECRET= assignments). These lived only in
    # redact() before, so the verdict scanner missed a working credential in any
    # of these forms while the redactor scrubbed them from the log (security
    # red-team 2026-07-22, finding 5). The match points at the credential VALUE
    # (the `secret` group), not the whole line, so the reported location is the
    # secret itself.
    for label, cred_re in _INLINE_CRED_PATTERNS:
        for m in cred_re.finditer(text):
            s, e = m.span("secret")
            if e <= s:
                continue
            # Low-confidence inline shapes gate on the VALUE: skip references,
            # paths, and placeholders so the blocking scanner does not fire on
            # ordinary code (F5 regression, 2026-07-23). Vendor-anchored inline
            # shapes are specific enough to report unconditionally.
            value = text[s:e]
            # The length floor is low-confidence-only: a real DSN password can
            # legitimately be short (a brief password in a redis:// DSN), so floor only the
            # shapes whose match is loosely structured.
            if label in _FLOORED_INLINE and (
                len(value.strip("\"'`")) < _MIN_INLINE_SECRET_LEN
            ):
                continue
            # Two tiers, and they behave DIFFERENTLY on a placeholder-looking value.
            #
            # A low-confidence shape (bare assignment, credential flag) is dropped:
            # it is the noisy tier and a suppressed guess costs little.
            #
            # An ANCHORED shape is DEMOTED, never dropped. Suppressing those was
            # unsound in a way that lost real credentials, because the heuristics
            # judge the value while the pattern's confidence comes from the
            # surrounding syntax: a production password can literally be `PASSWORD1`,
            # and an application-issued token can carry a readable prefix such as
            # `your_token_<entropy>`. Both were being deleted outright. Demotion
            # keeps the finding visible as review signal, which still fixes the
            # documentation-prose noise that motivated filtering these at all.
            if label in _LOW_CONFIDENCE_INLINE:
                if _looks_like_nonsecret(value):
                    continue
                confidence = "low"
            else:
                confidence = "low" if _looks_like_placeholder(value) else "high"
            hits.append(
                SecretHit(
                    confidence=confidence,
                    pattern_name=label,
                    matched_at=s,
                    length=e - s,
                    line=_line_for_offset(text, s),
                ),
            )
    return hits


# Inline-credential CLI / connection-string shapes the vendor-prefix
# patterns above do not catch: password flags, bearer headers, secret env
# assignments, and DSN passwords. Each captures the credential VALUE in a
# named group `secret` so redact() can remove just the value and keep the
# surrounding command legible (`mysql -u root -p[REDACTED:mysql-pflag]`).
# False positives here only cost a little evidentiary legibility in the
# log; false negatives leak a credential, so these lean toward redaction.
_INLINE_CRED_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "bearer-token",
        re.compile(r"(?i)\bauthorization:\s*bearer\s+(?P<secret>[A-Za-z0-9._~+/-]+=*)"),
    ),
    (
        "aws-secret-key",
        re.compile(r"(?i)\baws_secret_access_key\s*[=:]\s*(?P<secret>(?!\[REDACTED:)\S+)"),
    ),
    (
        "password-flag",
        re.compile(
            r"(?i)(?:--password|--pass|--pwd|--token|--secret|--api[-_]?key)"
            r"[=\s]+(?P<secret>(?!\[REDACTED:)\S+)",
        ),
    ),
    # mysql / mariadb / redis style attached short flag: -p<value>. Require
    # >=6 chars with at least one non-lowercase char so plain long flags
    # like `-print` / `-parse` are not corrupted.
    (
        "mysql-pflag",
        re.compile(r"(?<!\S)-p(?P<secret>(?!\[REDACTED:)(?=\S*[^a-z])\S{6,})"),
    ),
    # Connection-string password: scheme://user:PASSWORD@host. The username is
    # OPTIONAL (`*` not `+`) so the userless form redis://:PASSWORD@host is also
    # caught. (audit: 2nd-review gap #4.)
    (
        "dsn-password",
        re.compile(r"://[^:/@\s]*:(?P<secret>(?!\[REDACTED:)[^@/\s]+)@"),
    ),
    # FOO_PASSWORD=... / DB_SECRET=... / X_TOKEN=... inline env assignment.
    # The `(?!\[REDACTED:)` guard keeps redact() idempotent: an already-
    # redacted marker (which contains a space) is not re-matched.
    #
    # The identifier runs on either side of the keyword are length-bounded
    # ({0,64}) rather than unbounded `*`. Two unbounded `[A-Z_]*` around a
    # keyword whose own letters live in the same class made this pattern
    # polynomial-backtracking (ReDoS) on a long keyword-free upper/underscore
    # run with no trailing assignment (security re-review 2026-07-23, F5).
    # Finite bounds cap the per-start work at a constant, so finditer stays
    # linear; 64 identifier chars on each flank is far past any real env-var
    # name. The value is likewise bounded so a pathological line cannot blow
    # the match up.
    (
        "env-secret",
        re.compile(
            r"(?i)\b[A-Z0-9_]{0,64}(?:PASSWORD|PASSWD|SECRET|TOKEN|API[-_]?KEY|PWD)"
            r"[A-Z0-9_]{0,64}\s*=\s*(?P<secret>(?!\[REDACTED:)\S{1,4096})",
        ),
    ),
)

# Inline shapes whose match depends on a loosely-structured VALUE (an assignment
# right-hand side or a CLI flag argument) rather than a vendor-anchored prefix.
# These are the false-positive-prone ones: redact() still applies them
# unconditionally (over-redacting a log line is harmless), but scan() - which
# feeds the BLOCKING gate - first rejects values that are plainly not literal
# credentials (env/command references, filesystem paths, angle-placeholder
# tokens, doc-flag stand-ins). The vendor-anchored inline shapes (bearer header,
# aws_secret_access_key, DSN password) are specific enough that they scan
# unfiltered. Added after F5 regressed usability by BLOCKing ordinary code
# (env lookups, working-directory vars, placeholders, doc flags), 2026-07-23.
_LOW_CONFIDENCE_INLINE: Final[frozenset[str]] = frozenset(
    {"password-flag", "mysql-pflag", "env-secret"}
)

# Minimum length before a low-confidence inline VALUE is treated as credential-
# shaped, applied in scan() only so redact() keeps over-redacting harmlessly.
# gitleaks' shipped `generic-api-key` rule floors its capture group at 10
# characters for this same keyword-plus-assignment class; ours floored at 1
# (`\S{1,4096}`), which is why `max_tokens=1024`, `secret_findings=()` and
# `api_key=api_key` all fired. The floor alone removes those.
#
# Deliberately NOT an entropy gate. Measured with gitleaks' own Shannon-over-
# observed-alphabet formula, the base32 TOTP seed `JBSWY3DPEHPK3PXP` scores
# 3.375 and `correct-horse-battery-staple` scores 3.495, both BELOW gitleaks'
# own 3.5 threshold, because short repetitive strings and passphrases lose to
# entropy. An entropy gate here would miss real credentials that length plus
# expression-shape catches, so do not "improve" this by adding one.
_MIN_INLINE_SECRET_LEN: Final[int] = 10

# The floor applies to `env-secret` ONLY. It is the noisy rule (42 of the original
# 48 self-scan findings) because a bare `NAME = value` assignment says nothing
# about intent. An explicit credential CLI flag does: `--password X` and `-pX`
# name the argument as a password, so flooring them cost real recall (an 8-char
# password on the most explicit shape in the set scanned to nothing) for almost no
# precision, those two rules contributing 3 of the 48. `mysql-pflag` already
# carries its own >= 6 plus non-lowercase requirement in the regex.
_FLOORED_INLINE: Final[frozenset[str]] = frozenset({"env-secret"})

# Lowercased values that are stand-ins, not secrets. Kept small and literal;
# fuzzier stand-ins are caught by the substring list below.
_NONSECRET_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "none", "null", "nil", "true", "false", "na", "n/a", "tbd", "todo",
        "password", "passwd", "secret", "token", "pwd", "apikey", "api_key",
        "key", "xxx", "test", "foo", "bar", "baz", "value", "string",
    }
)

# Whole-value stand-ins (after quote-stripping). These match the ENTIRE value,
# not a substring: a real password may legitimately contain the letters of
# "sample" or "example", so treating those as a substring signal suppressed
# genuine credentials (security re-review 2026-07-23, defect 3). Only a value
# that IS a placeholder counts.
_NONSECRET_WHOLE: Final[frozenset[str]] = frozenset(
    {
        "changeme", "change_me", "change-me", "placeholder", "redacted",
        "example", "sample", "dummy", "todo", "tbd", "value", "string",
    }
)

# Code-reference signals: the value is an env lookup / config read, not a
# literal. These are specific tokens, not "contains a bracket" (a real secret
# can contain brackets or parens).
_CODE_REF_SIGNALS: Final[tuple[str, ...]] = (
    "os.environ", "os.getenv", "getenv(", "process.env", "config.get(",
    "settings.", "secrets.get", "vault.", ".env[",
)


# A WHOLE-value template or shell reference: ${VAR}, $(cmd), $VAR, %VAR%,
# {{ jinja }}, {% tag %}. Matching the whole value (rather than testing one
# leading character) keeps an opaque password that merely STARTS with $, % or {
# in scope, which the leading-character test wrongly suppressed.
_TEMPLATE_REF_RE = re.compile(
    r"\$\{[^}]*\}"
    r"|\$\([^)]*\)"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\{\{.*\}\}"
    r"|\{%.*%\}"
)
# A backtick command substitution anywhere in the value.
_BACKTICK_SUBST_RE = re.compile(r"`[^`]+`")
# A value that READS the credential from somewhere else rather than embedding it:
# a call or a subscript (`input(...`, `data[...`, `request.headers.get(...`), or a
# dotted attribute chain (`args.api_key`, `self.token`). Modelled on
# detect-secrets' `is_indirect_reference` filter, whose docstring names exactly
# this class: "Filters secrets that take the form of: secret = get_secret_key()
# or: secret = request.headers['apikey']".
# A COMPLETE call or subscript: an identifier (or dotted path), an opening
# bracket, and a CLOSING bracket at the very end. Terminality is what separates
# `data["token"]` from the real password `Sup3r[Secret]Pass99`, which has content
# after its bracket; an earlier draft of this rule matched the bare opener and so
# re-introduced the very suppression regression it was meant to avoid.
_IDENT_PREFIX_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\s*")
# A call truncated by the value capture stopping at whitespace, e.g. the value of
# `password = input("Password: ")` is captured as `input("Password:`. Identified by
# a quote immediately inside the opener, which a credential does not have.
_TRUNCATED_CALL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\s*[([]\s*[\"']")
_ATTRIBUTE_CHAIN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
# An unmistakable lower_snake_case Python identifier used as the value. Requires
# an underscore and no uppercase, so a generated credential (which is mixed-case,
# digit-bearing, or punctuated) does not qualify. The residual class this gives up
# on is an all-lowercase underscore-separated password, which these rules now
# surface as review rather than block anyway.
_SNAKE_IDENT_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
# An ALL-CAPS identifier used as the value, meaning a reference to another
# env-var NAME rather than an embedded secret: `--password PASSWORD`. Requires
# word-shaped segments so high-entropy uppercase credentials (base32 TOTP seeds,
# generated recovery codes) do NOT qualify.
# Either multi-word (underscore-separated, which is how env-var names are spelled)
# or a SHORT single word. The length cap is load-bearing: an earlier version
# fullmatched any all-caps run, so a digit-free base32 TOTP seed like a 16-letter
# uppercase string was silently suppressed, while the digit-bearing seed used in
# the tests happened to be caught. Base32 seeds and recovery codes are >= 16
# characters; single-word env-var names (PASSWORD, APIKEY, SECRET, CREDENTIAL) are
# not, so 12 sits in the gap.
_UPPERCASE_REF_MAX_SINGLE_WORD = 12
_UPPERCASE_WORD_RE = re.compile(r"[A-Z]{2,}\d{0,3}")
_UPPERCASE_MULTIWORD_RE = re.compile(r"[A-Z]{2,}\d{0,3}(?:_[A-Z0-9]+)+")


def _is_expression_value(v: str) -> bool:
    """True when `v` is code READING a credential rather than a credential itself.

    Bracket structure is counted, not regex-matched. A regex that merely required
    a closing bracket at the end was defeated by appending one more, so a real
    bracket-bearing password fullmatched it and was silently suppressed. The real
    property is that the bracket group opens immediately after the leading
    identifier and closes exactly at the END of the value, with nothing trailing.
    """
    lead = _IDENT_PREFIX_RE.match(v)
    if not lead:
        return False
    rest = v[lead.end() :]
    if not rest or rest[0] not in "([":
        return False
    # Bracket structure is NOT evidence of code, in any of the forms tried so far.
    # Each of these was a real credential suppressed by a rule that looked structural
    # but was not: `hunter2[Prod]` (balanced brackets), `hunter2[Prod(2026)]` (a paren
    # in the data), `hunter("Prod2026"` (a quote inside an opener), `hunter(Prod2026)`
    # (a balanced top-level call shape).
    #
    # A bare `identifier(...)` or `identifier[...]` is genuinely ambiguous: it is how
    # both a function call and a punctuated password look. These rules feed the
    # LOW-CONFIDENCE tier, where a false positive costs review noise and a false
    # negative ships a credential, so ambiguity now resolves toward reporting and
    # only UNAMBIGUOUS code is suppressed:
    #   - a dotted receiver (`os.environ[...]`, `request.headers.get(...)`)
    #   - an empty call (`load_api_key()`), which no password looks like
    #   - the explicit reference signals already handled by `_CODE_REF_SIGNALS`
    dotted_receiver = "." in v[: lead.end()]
    empty_call = bool(re.match(r"\(\s*\)", rest))
    # A STACK, not a depth counter: a counter treats `(` and `[` as
    # interchangeable, so a mismatched pair (`cfg[value)`) balanced to zero and a
    # real password containing one was suppressed. Brackets must actually pair.
    closer = {"(": ")", "[": "]"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    saw_call = False
    for i, ch in enumerate(rest):
        # Brackets inside a STRING LITERAL are data, not structure: `data["token]"]`
        # was misread as closing early and so read as a literal value rather than
        # code. Skip anything between matching quotes.
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            # An escaped quote does not end the string. Without this, `data["to\"ken]"]`
            # was read as ending its string early, and the `]` inside the literal was
            # then counted as structure, so valid code was reported as a credential.
            escaped = True
            continue
        if quote is not None:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in closer:
            # A call signal means a call ON THE RECEIVER, so the paren must be at the
            # TOP level, outside any string and not nested inside another group. A
            # paren nested inside a subscript is password data: `hunter2[Prod(2026)]`
            # was classified as code on the strength of that inner paren alone.
            if ch == "(" and not stack:
                saw_call = True
            stack.append(closer[ch])
        elif ch in ")]":
            if not stack or stack.pop() != ch:
                return False
            if not stack:
                if i == len(rest) - 1:
                    return (saw_call and empty_call) or dotted_receiver
                # A CHAINED group is still code: `load_api_key()["prod"]` closes its
                # call group and immediately opens a subscript. Only bare text after
                # a closed group means this is a literal value, which is what keeps
                # `<password>[<x>]<password>` in scope.
                if rest[i + 1] in "([":
                    continue
                return False
    # Never closed, so this is a PREFIX and structure proves nothing at all. The
    # unclosed-call fallback is gone: it suppressed `hunter2("Prod2026` and then, once
    # tightened to require a lowercase receiver, still suppressed `hunter("Prod2026`.
    # Both are plausible passwords and both produced a clean PASS. A truncated
    # `input("Password:` now lands as review signal instead, which is noise in a
    # non-blocking tier rather than a missed credential.
    return dotted_receiver


def _strip_one_quote_layer(value: str) -> str:
    v = value.strip()
    # Peel one layer of matching surrounding quotes so a quoted stand-in reads
    # as a stand-in, not a literal.
    if len(v) >= 2 and v[0] in "\"'`" and v[-1] == v[0]:
        v = v[1:-1].strip()
    return v


def _looks_like_placeholder(value: str) -> bool:
    """True when a value is a STAND-IN or an explicit reference, for ANY inline shape.

    This is the subset of suppressions that is safe to apply to the BLOCK tier
    (bearer header, `aws_secret_access_key`, DSN password), which is why it is
    separated out. Those patterns are anchored on their surrounding syntax rather
    than their value, so they fired on documentation prose in comments, and
    suppressing an explicit placeholder there is right. Applying the FULL filter to
    them was not: the path rule voided a real credential (see
    `_looks_like_nonsecret`).
    """
    v = _strip_one_quote_layer(value)
    if not v:
        return True
    low = v.lower()
    # Shell / template / env reference or command substitution (value STARTS as a
    # reference, or contains a command substitution / interpolation).
    if _TEMPLATE_REF_RE.fullmatch(v) or "$(" in v or _BACKTICK_SUBST_RE.search(v):
        return True
    # An angle-bracket placeholder: <token>, <your-password>.
    if v.startswith("<") and v.endswith(">"):
        return True
    # A code expression that reads the value from elsewhere (specific tokens, not
    # "contains any bracket"): os.environ[...], getenv(...), config.get(...). No
    # vendor key format contains these substrings, so this is safe on both tiers.
    if any(sig in low for sig in _CODE_REF_SIGNALS):
        return True
    # The WHOLE value is a known stand-in / placeholder word (not a substring).
    if low in _NONSECRET_TOKENS or low in _NONSECRET_WHOLE:
        return True
    # A template placeholder spelled as a whole value: your-api-key, YOUR_TOKEN.
    if low.startswith(("your_", "your-")):
        return True
    # Repeated filler (xxxx, ****, ----, ....). Also catches the `...` in a
    # documented `Authorization: Bearer ...` example.
    if len(set(v)) == 1:
        return True
    # An env-var NAME used as the value, as in `scheme://user:PASSWORD@host`.
    if _UPPERCASE_MULTIWORD_RE.fullmatch(v) and len(v) <= 40:
        return True
    return len(v) <= _UPPERCASE_REF_MAX_SINGLE_WORD and bool(_UPPERCASE_WORD_RE.fullmatch(v))


def _looks_like_nonsecret(value: str) -> bool:
    """True when a LOW-CONFIDENCE inline value is plainly not a literal secret.

    The placeholder checks above, PLUS shape checks that only make sense for a
    loosely-structured value: is it an expression rather than a literal, is it a
    filesystem path. Those extra checks must NOT reach the BLOCK tier. A real AWS
    secret access key is 40 characters of base64 alphabet, so it can begin with `/`
    and contain several more, and the path rule silently voided the anchored
    `aws-secret-key` pattern on exactly that shape: the credential was never
    classified at all, so the review-versus-block posture never even applied.
    """
    if _looks_like_placeholder(value):
        return True
    v = _strip_one_quote_layer(value)
    if not v:
        return True
    # A QUOTED value is a string literal, full stop, so none of the code-shape tests
    # below may run on it. Stripping the quotes first erased the one fact that settles
    # the question: a quoted password that merely LOOKS like a call (a word followed by
    # empty parens) or like an attribute chain (a dotted word with a bracketed suffix)
    # was classified as code and disappeared into a clean PASS. Placeholder checks
    # still apply above, because a quoted stand-in is still a stand-in.
    if v != value.strip():
        return False
    # The value is an expression, not a literal. A call, a subscript, a dotted
    # attribute chain, or a plain lower_snake_case identifier is code reading a
    # credential, not a credential.
    if _is_expression_value(v):
        return True
    if _ATTRIBUTE_CHAIN_RE.fullmatch(v) or _SNAKE_IDENT_RE.fullmatch(v):
        return True
    # A filesystem path (the working-directory-var class), not a credential. A
    # single leading slash is not enough: `/Kj8#mQ2vLpXr9` is a password, while
    # a real path carries a relative prefix or a second separator.
    return v.startswith(("./", "../", "~/")) or (v.startswith("/") and v.count("/") >= 2)


def redact(text: str, *, extra_patterns: Iterable[SecretPattern] = ()) -> str:
    """Return `text` with detected secrets replaced by ``[REDACTED:<type>]``.

    Two classes are removed:
      1. Vendor-format tokens from the SecretPattern set (whole match).
      2. Inline-credential shapes (password flags, bearer headers, DSN
         passwords, secret env assignments) - only the VALUE is removed so
         the surrounding command stays legible for the audit reader.

    Deterministic and value-free, so the result is safe to write to the
    audit log or hand to an auditor. Idempotent on already-redacted text
    (the ``[REDACTED:...]`` marker matches none of the patterns).
    """
    if not text:
        return text
    spans: list[tuple[int, int, str]] = []
    for pat in (*_PATTERNS, *extra_patterns):
        for m in pat.regex.finditer(text):
            spans.append((m.start(), m.end(), f"[REDACTED:{pat.name}]"))
    for label, cred_re in _INLINE_CRED_PATTERNS:
        for m in cred_re.finditer(text):
            s, e = m.span("secret")
            if e > s:
                spans.append((s, e, f"[REDACTED:{label}]"))
    if not spans:
        return text
    # Apply left-to-right but drop spans overlapping an earlier-kept one,
    # then splice right-to-left so offsets stay valid.
    spans.sort(key=lambda t: (t[0], -t[1]))
    kept: list[tuple[int, int, str]] = []
    last_end = -1
    for s, e, r in spans:
        if s >= last_end:
            kept.append((s, e, r))
            last_end = e
    out = text
    for s, e, r in reversed(kept):
        out = out[:s] + r + out[e:]
    return out


# Which Claude Code / Cursor tool-call args carry file content that
# should be scanned. The keys are tool names, the values are the arg
# names whose string values to scan.
_SCANNABLE_ARGS: Final[Mapping[str, tuple[str, ...]]] = {
    "Edit": ("new_string", "content"),
    "MultiEdit": ("new_string",),
    "Write": ("content", "text"),
    "NotebookEdit": ("new_source", "source"),
}


def scan_args(tool_name: str, args: Mapping[str, Any]) -> list[SecretHit]:
    """Scan a tool-call's args for credential leaks.

    Only file-write tools are scanned (Edit / MultiEdit / Write /
    NotebookEdit). Other tool names return an empty hit list.

    String args are scanned directly; list-valued args (MultiEdit's
    `edits` list) are walked one element at a time. Non-string,
    non-list values are ignored.
    """
    keys = _SCANNABLE_ARGS.get(tool_name)
    if not keys:
        return []
    hits: list[SecretHit] = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            hits.extend(scan(v))
    # MultiEdit's edits is a list[dict] each with old_string + new_string.
    edits = args.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                ns = edit.get("new_string")
                if isinstance(ns, str):
                    hits.extend(scan(ns))
    return hits


def hit_summary(hits: list[SecretHit]) -> str:
    """One-line summary of detected secrets, safe to put in audit log.

    Includes line numbers when available. Format: `Name (line N)`,
    or `Name (lines N, M)` if the same pattern fires twice, or
    `2× Name (lines N, M)` if there are more.
    """
    if not hits:
        return ""
    by_pattern: dict[str, list[int]] = {}
    for h in hits:
        by_pattern.setdefault(h.pattern_name, []).append(h.line)
    parts: list[str] = []
    for name in sorted(by_pattern):
        lines = [n for n in by_pattern[name] if n > 0]
        count = len(by_pattern[name])
        prefix = f"{count}× " if count > 1 else ""
        if lines:
            ln = ", ".join(str(n) for n in lines[:3])
            tail = f" (line{'s' if len(lines) > 1 else ''} {ln})"
            if len(lines) > 3:
                tail = f" (lines {ln}+{len(lines) - 3})"
        else:
            tail = ""
        parts.append(f"{prefix}{name}{tail}")
    return ", ".join(parts)
