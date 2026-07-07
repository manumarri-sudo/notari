"""Credential / secret detection for file-write tool arguments.

When an agent's Edit / Write / NotebookEdit call would land a hardcoded
credential in a file (the GitHub PAT leak failure mode, Anthropic's
November 2025 incident class), Quill catches it before the write
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
    """One credential type Quill detects."""

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
    (
        "env-secret",
        re.compile(
            r"(?i)\b[A-Z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[-_]?KEY|PWD)[A-Z_]*"
            r"\s*=\s*(?P<secret>(?!\[REDACTED:)\S+)",
        ),
    ),
)


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
