"""Heuristic prompt-injection content scanner.

**Observation-only signal**, never a hard block. Per OWASP LLM01:2025
guidance, regex-based prompt-injection detection cannot guarantee
mitigation because the stochastic nature of language models defeats
any single classifier. The published consensus (Willison, Meta Agents
Rule of Two, November 2025 adaptive-attack paper) is that prompt-
injection content classifiers are bypassed at >90% in adversarial
settings. Nota's real defense is the lethal-trifecta enforcement in
`taint.py` plus the deterministic destructive-action gate in
`policy.py`; this module is the supplementary audit-log signal that
helps operators investigate suspicious sessions.

Pattern set is drawn from published research, each entry annotated
with its source. The categories follow the standard taxonomy used in
the field (Liu et al. Open-Prompt-Injection benchmark; AWS
Prescriptive Guidance on prompt injection; the Securiti / Maxim
defense guides):

  1. Direct Instruction Injection ("ignore previous instructions"
     family + variants)
  2. Role-token spoofing (`System:`, `<|im_start|>`, `[INST]`)
  3. Context Manipulation (fake completion / escape attacks)
  4. Data Exfiltration markers (instructions to send content
     somewhere)
  5. Instruction Override (assertive new-role phrasing)

NOT covered (deliberately):
  - Base64/hex/Unicode-homoglyph obfuscation. Detecting these reliably
    is the LLM-judgment problem we won't compete in. Operators can
    add custom patterns via `extra_patterns=` if needed.
  - Typoglycemia variants ("ignroe all previus instrucshuns"). Same
    reason; we'd hit too many false positives on misspelled text.
  - Adversarial-suffix attacks (random-token suffixes). These are
    statistically detectable but not regex-detectable.

The intentional scope is: high-precision, low false-positive patterns
that match the classic published attack templates. Hits emit a
`taint.web_fetch.suspicious` audit event; operators investigate.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class InjectionPattern:
    """One prompt-injection pattern Nota detects, with provenance."""

    name: str  # short label
    category: str  # one of the five taxonomy categories
    regex: re.Pattern[str]
    source: str  # the paper / benchmark / blog the pattern is drawn from


@dataclass(frozen=True, slots=True)
class InjectionHit:
    """One match found by scan().

    The matched substring is intentionally NOT stored. Hits are used as
    audit-log signals; persisting the matched text would let an attacker
    leak content through the audit log itself, undermining the chain.
    """

    pattern_name: str
    category: str
    matched_at: int
    length: int
    line: int = 0


# Pattern set. Each one cites a published source so reviewers can verify
# the regex matches the documented attack template and isn't author-made.
_PATTERNS: Final[tuple[InjectionPattern, ...]] = (
    # ---- Direct Instruction Injection ("Ignore Attack" family) ----
    # Source: Liu et al., Open-Prompt-Injection benchmark.
    # https://arxiv.org/abs/2310.12815 §3.1 "Ignore Attack"
    InjectionPattern(
        name="ignore-previous-instructions",
        category="direct_instruction_injection",
        regex=re.compile(
            # Two shapes:
            # 1) verb + (optional modifiers) + noun
            #    "ignore previous instructions", "disregard all rules", ...
            # 2) verb + "the" + directional modifier + (optional noun)
            #    "ignore the above", "ignore the preceding", "disregard the prior"
            r"\b(ignore|disregard|forget|override|bypass)\s+"
            r"(?:"
            r"(the\s+|all\s+|any\s+|your\s+|my\s+|prior\s+|previous\s+|above\s+|preceding\s+|earlier\s+)*"
            r"(instructions?|prompts?|rules?|directives?|guidelines?|commands?|context|messages?)"
            r"|"
            r"the\s+(above|preceding|prior|previous|earlier|foregoing)"
            r")\b",
            re.IGNORECASE,
        ),
        source="Liu et al. 2023 Open-Prompt-Injection §3.1 Ignore Attack",
    ),
    # ---- Role-token spoofing ----
    # Source: AWS Prescriptive Guidance — Common attacks; ChatML format
    # used by GPT-3.5/4 turbo; Llama-2 / Llama-3 INST format; Anthropic
    # Human/Assistant turn markers. Detecting these in user content is
    # the canonical role-spoof defense.
    InjectionPattern(
        name="chatml-im-token",
        category="role_token_spoofing",
        regex=re.compile(r"<\|im_(start|end|sep)\|>", re.IGNORECASE),
        source="OpenAI ChatML format (gpt-3.5-turbo / gpt-4) special tokens",
    ),
    InjectionPattern(
        name="llama-inst-token",
        category="role_token_spoofing",
        regex=re.compile(r"\[/?INST\]"),
        source="Meta Llama-2 / Llama-3 instruction format special tokens",
    ),
    InjectionPattern(
        name="claude-human-assistant-turn",
        category="role_token_spoofing",
        regex=re.compile(
            r"\n\n(Human|Assistant|System|H|A):\s",
        ),
        source="Anthropic Claude legacy turn-marker convention",
    ),
    InjectionPattern(
        name="markdown-role-header",
        category="role_token_spoofing",
        regex=re.compile(
            r"###\s+(System|User|Assistant|Instruction|Task)\s*:?\s*$",
            re.IGNORECASE | re.MULTILINE,
        ),
        source="Common markdown-flavored prompt template role headers",
    ),
    # ---- Context Manipulation (Escape + Fake Completion) ----
    # Source: Liu et al. §3.2 Escape Attack, §3.3 Fake Completion Attack.
    InjectionPattern(
        name="escape-end-of-input",
        category="context_manipulation",
        regex=re.compile(
            r"(\[(end|stop|done)(\s+of)?\s+(input|prompt|context|system|task)\]|"
            r"===\s*(END|STOP|DONE)\s*===|"
            r"/\*\s*(end|stop|done)\s+of\s+(system|prompt|context)\s*\*/)",
            re.IGNORECASE,
        ),
        source="Liu et al. 2023 Open-Prompt-Injection §3.2 Escape Attack",
    ),
    InjectionPattern(
        name="fake-completion-marker",
        category="context_manipulation",
        regex=re.compile(
            # "task complete. [optional bridge of up to 30 chars]. new task"
            # The bridge allows "Now here is", "Next step:", "Followed by", etc.
            # without enumerating every variation.
            r"\b(task|answer|response|output)\s+complete[d.!]?\b[\s.,;:!?]*"
            r"[\w\s.,;:!?'\"-]{0,60}?"
            r"\b(a\s+|the\s+)?new\s+(task|instruction|prompt|command|directive)\b",
            re.IGNORECASE,
        ),
        source="Liu et al. 2023 Open-Prompt-Injection §3.3 Fake Completion Attack",
    ),
    InjectionPattern(
        name="injected-new-task-marker",
        category="context_manipulation",
        regex=re.compile(
            r"\b(here\s+(is|are)|the\s+following\s+is|now\s+execute|now\s+perform)\s+"
            r"(the\s+)?(new|next|updated|revised|actual|real)\s+(task|instruction|prompt|command)\b",
            re.IGNORECASE,
        ),
        source="Composite of Securiti LLM01 Prompt Injection (2024) + Maxim AI 2026 Defense Guide",
    ),
    # ---- Instruction Override (assertive new-role) ----
    # Source: AWS Prescriptive Guidance — Common attacks. Also documented
    # widely in the Anthropic / OpenAI security blogs.
    InjectionPattern(
        name="assertive-new-role",
        category="instruction_override",
        regex=re.compile(
            r"\bfrom\s+now\s+on,?\s+you\s+(are|will\s+be|must|should|need\s+to)\b",
            re.IGNORECASE,
        ),
        source="AWS Prescriptive Guidance — Common prompt-injection attacks (2024)",
    ),
    InjectionPattern(
        name="you-are-now-impersonation",
        category="instruction_override",
        regex=re.compile(
            # "You are now SudoGPT" / "you are now a different model" / etc.
            # Match the imperative "you are now <something>" — anything-but-
            # whitespace at the end means we catch role names with mixed case
            # like "SudoGPT" without anchoring on capitalization.
            r"\byou\s+are\s+now\s+(a\s+|an\s+|the\s+)?\S{2,40}",
            re.IGNORECASE,
        ),
        source="AWS Prescriptive Guidance — Common prompt-injection attacks (2024)",
    ),
    InjectionPattern(
        name="dan-jailbreak-marker",
        category="instruction_override",
        regex=re.compile(
            r"\b(DAN|Do\s+Anything\s+Now|Developer\s+Mode|jailbreak\s+mode|unrestricted\s+mode)\b",
            re.IGNORECASE,
        ),
        source="Shen et al. 2023 (USENIX) — DAN jailbreak family; widely cited",
    ),
    # ---- Data Exfiltration markers ----
    # Source: Willison "Lethal Trifecta" + Open-Prompt-Injection §
    # Data Exfiltration category.
    InjectionPattern(
        name="exfiltrate-send-to-url",
        category="data_exfiltration",
        regex=re.compile(
            # "send the result to https://..." / "post the secret token to ..."
            # Allows compound nouns ("secret token", "API key", "env file") by
            # permitting up to 3 noun-or-adjective words between the trigger
            # noun and the destination preposition.
            r"\b(send|post|upload|exfiltrate|transmit|forward|email|leak|forward)\s+"
            r"(the\s+|all\s+|this\s+|these\s+|your\s+|my\s+|our\s+)*"
            r"(result|output|response|content|secret|key|token|data|file|env|password|credential|cookie|session)s?"
            r"(\s+\w{2,20}){0,3}?\s+"
            r"(to|at|via)\s+"
            r"(https?://|ftp://|smtp://|@|[\w-]+\.)",
            re.IGNORECASE,
        ),
        source="Willison Lethal Trifecta + Liu et al. §3 Data Exfiltration category",
    ),
    InjectionPattern(
        name="exfiltrate-image-leak",
        category="data_exfiltration",
        regex=re.compile(
            r"!\[[^\]]*\]\(https?://[^)]+\?[^)]*(\{|%7B)[^)]*(secret|token|key|password|env)[^)]*(\}|%7D)",
            re.IGNORECASE,
        ),
        source="Markdown-image exfiltration class (Willison 2024 writeups)",
    ),
    InjectionPattern(
        name="exfiltrate-render-link",
        category="data_exfiltration",
        regex=re.compile(
            r"\b(render|display|click|visit|fetch|load)\s+(this\s+|the\s+|the\s+following\s+)?(link|url|image|page)\s*:?\s*"
            r"https?://[^\s\"'`]{5,}\?[^\s\"'`]*(secret|token|key|password|env)",
            re.IGNORECASE,
        ),
        source="Maxim AI 2026 Prompt-Injection Defense Guide — exfil via rendered link",
    ),
)


def patterns() -> tuple[InjectionPattern, ...]:
    """Read-only view of the built-in pattern set."""
    return _PATTERNS


def _line_for_offset(text: str, offset: int) -> int:
    """1-indexed line number containing `offset`. Same shape as secrets._line_for_offset."""
    if offset <= 0:
        return 1
    return text.count("\n", 0, offset) + 1


def scan(
    text: str,
    *,
    extra_patterns: Iterable[InjectionPattern] = (),
) -> list[InjectionHit]:
    """Find every prompt-injection-shaped match in `text`.

    Returns InjectionHit records with pattern name, category, offset, length,
    line number. The matched substring is NEVER returned; downstream code
    must use the position info to investigate, not the content.

    This is a HEURISTIC signal. False positives are expected (legitimate
    text like "ignore the previous version" will match). Use the audit
    log entry to investigate the source; do not auto-block on hits.
    """
    if not text:
        return []
    hits: list[InjectionHit] = []
    for pat in (*_PATTERNS, *extra_patterns):
        for m in pat.regex.finditer(text):
            start = m.start()
            hits.append(
                InjectionHit(
                    pattern_name=pat.name,
                    category=pat.category,
                    matched_at=start,
                    length=m.end() - start,
                    line=_line_for_offset(text, start),
                ),
            )
    return hits


def hit_summary(hits: list[InjectionHit]) -> str:
    """One-line summary of detected patterns, safe to put in audit log.

    Groups by category, counts per category, lists the first hit's line
    number for jump-to. Format: `direct_instruction_injection×2 (line 14),
    role_token_spoofing×1 (line 28)`.
    """
    if not hits:
        return ""
    by_category: dict[str, list[int]] = {}
    for h in hits:
        by_category.setdefault(h.category, []).append(h.line)
    parts: list[str] = []
    for cat in sorted(by_category):
        lines = [n for n in by_category[cat] if n > 0]
        count = len(by_category[cat])
        prefix = f"{cat}×{count}" if count > 1 else cat
        if lines:
            ln = lines[0]
            parts.append(f"{prefix} (line {ln})")
        else:
            parts.append(prefix)
    return ", ".join(parts)
