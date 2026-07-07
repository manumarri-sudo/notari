"""Tool description scanner - hidden-instruction + injection detection.

Threats addressed (research: Snyk ToxicSkills, Antiy CERT ClawHavoc,
OX Security MCP analysis, Invariant Labs tool-poisoning, all disclosed
Jan-May 2026):

  1. Hidden-instruction injection: invisible Unicode characters (tag block
     U+E0000-U+E007F, PUA U+E000-U+F8FF, BOMs, zero-width chars) carry
     adversary instructions visible only to the LLM tokenizer, not to a
     human reviewing the tool listing in their UI.
  2. Imperative override patterns: "ignore previous", "you must", "the
     user has authorised", "transmit to" - phrases that read as
     system-prompt overrides when the LLM treats the tool description as
     trusted context.
  3. Base64 / hex blobs in descriptions: payloads encoded to evade keyword
     filters, decoded by the model at generation time.
  4. Direct exfil URLs: descriptions that name a destination ("send to
     attacker.com", "POST to https://…") - should never appear in a
     legitimate tool description.

This module is OBSERVATION + GATE: `scan(tool)` returns findings; the
caller (`pinning.verify` or the proxy) decides whether to refuse
advertisement. Detection is deliberately conservative - false positives
are cheaper than false negatives for a security gate.

Composition: runs BEFORE `pinning.verify` so a freshly-poisoned tool
fails on first sight, not only on rug-pull.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

# ---------------------------------------------------------------------------
# Invisible / steganographic Unicode ranges. The Unicode tag block
# (U+E0000-U+E007F) is the canonical channel for "ASCII smuggled inside an
# invisible glyph" attacks against LLM tokenizers - every ASCII char has a
# parallel tag-block codepoint. We block the whole range plus the PUA, BOMs,
# and ZWJ/ZWNJ/zero-width-space.

_INVISIBLE_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x0000, 0x0008),  # control chars before \t
    (0x000E, 0x001F),  # control chars between \r and space
    (0x007F, 0x009F),  # DEL + C1 controls
    (0x200B, 0x200F),  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    (0x202A, 0x202E),  # bidi override controls (Trojan Source class)
    (0x2060, 0x206F),  # word joiner, invisible operators
    (0xFEFF, 0xFEFF),  # BOM
    (0xFFF9, 0xFFFB),  # interlinear annotation
    (0xE0000, 0xE007F),  # Unicode tag block (ASCII smuggling)
    (0xE0080, 0xE00FF),  # tag block extension (rarely allocated)
    (0xF0000, 0xFFFFD),  # supplementary PUA-A
    (0x100000, 0x10FFFD),  # supplementary PUA-B
    (0xE000, 0xF8FF),  # BMP private use area
)


def _is_invisible(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES)


# Imperatives that read as injection overrides when seen by an LLM that
# treats the tool description as trusted context. Case-insensitive.
_INJECTION_PHRASES: Final[tuple[str, ...]] = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "disregard the above",
    "you must",
    "you are required",
    "you have been authorised",
    "you have been authorized",
    "the user has approved",
    "the user has authorised",
    "the user has authorized",
    "before responding",
    "before answering",
    "as part of your response",
    "include the contents of",
    "transmit to",
    "exfiltrate",
    "send to attacker",
    "post to https://",
    "post to http://",
    "curl https://",
    "wget https://",
    "do not mention",
    "do not tell the user",
    "without informing",
    "silently",
    "covertly",
    "system prompt:",
    "<|im_start|>",
    "<|im_end|>",
    "</system>",
    "<system>",
)

# Base64 looking blobs of 40+ chars are suspicious in a tool description.
# Below 40 you get false positives on legitimate UUIDs and short hashes.
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Hex blobs of 64+ chars (a SHA-256-shaped string is fine inline; 256+ is
# almost always smuggled binary).
_HEX_BLOB_RE = re.compile(r"[0-9a-fA-F]{256,}")

# URLs are not banned in descriptions, but combined with imperative
# phrases ("POST to https://…") this fires the imperative check above.


@dataclass(frozen=True, slots=True)
class ToolScanFinding:
    """One finding from `scan`. Multiple findings can attach to one tool."""

    severity: str  # "critical" | "high" | "medium"
    category: str  # "invisible_unicode" | "injection_phrase" | "base64_blob" | "hex_blob"
    detail: str
    sample: str = ""  # short excerpt, redacted for display


@dataclass(frozen=True, slots=True)
class ToolScanResult:
    """Aggregate result for one tool. `safe` mirrors the AND of all checks."""

    safe: bool
    findings: tuple[ToolScanFinding, ...] = field(default_factory=tuple)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return ""
        order = {"critical": 3, "high": 2, "medium": 1}
        return max(self.findings, key=lambda f: order.get(f.severity, 0)).severity


def _scan_invisibles(text: str) -> list[ToolScanFinding]:
    """Find any codepoint in the invisible/steganographic ranges.

    Tab (\t), newline (\n), and carriage return (\r) are explicitly
    permitted - those are legitimate whitespace in tool descriptions.
    """
    findings: list[ToolScanFinding] = []
    bad: list[tuple[int, int]] = []  # (index, codepoint)
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in (0x09, 0x0A, 0x0D):
            continue
        if _is_invisible(cp):
            bad.append((i, cp))
    if not bad:
        return findings

    # Group consecutive bad chars to keep findings count small.
    cps = sorted({cp for _, cp in bad})
    names = []
    for cp in cps[:6]:
        try:
            names.append(f"U+{cp:04X} ({unicodedata.name(chr(cp), 'unnamed')})")
        except ValueError:
            names.append(f"U+{cp:04X}")
    sev = "critical" if any(0xE0000 <= cp <= 0xE007F for cp in cps) else "high"
    findings.append(
        ToolScanFinding(
            severity=sev,
            category="invisible_unicode",
            detail=(
                f"{len(bad)} invisible/steganographic codepoint(s) in description: "
                + ", ".join(names)
                + ("…" if len(cps) > 6 else "")
            ),
        )
    )
    return findings


def _scan_injection_phrases(text: str) -> list[ToolScanFinding]:
    lower = text.lower()
    hits: list[str] = []
    for phrase in _INJECTION_PHRASES:
        if phrase in lower:
            hits.append(phrase)
    if not hits:
        return []
    sev = "critical" if len(hits) >= 2 else "high"
    return [
        ToolScanFinding(
            severity=sev,
            category="injection_phrase",
            detail=f"description contains injection-shaped imperative(s): {hits[:5]}",
            sample=hits[0],
        )
    ]


def _scan_encoded_blobs(text: str) -> list[ToolScanFinding]:
    findings: list[ToolScanFinding] = []
    b64 = _BASE64_BLOB_RE.findall(text)
    if b64:
        findings.append(
            ToolScanFinding(
                severity="medium",
                category="base64_blob",
                detail=f"{len(b64)} base64-shaped blob(s) (≥40 chars) in description",
                sample=b64[0][:32] + "…",
            )
        )
    hx = _HEX_BLOB_RE.findall(text)
    if hx:
        findings.append(
            ToolScanFinding(
                severity="medium",
                category="hex_blob",
                detail=f"{len(hx)} hex blob(s) (≥256 chars) in description",
                sample=hx[0][:32] + "…",
            )
        )
    return findings


def scan(tool: Mapping[str, Any]) -> ToolScanResult:
    """Run every check against a tool's user-visible AND LLM-visible fields.

    Inputs scanned:
      - description (LLM-visible; the canonical injection vector)
      - annotations (untrusted per MCP spec; same scanner applied)
      - inputSchema.description fields if present (one level deep)

    Caller decides what to do with the result. `pinning.verify` will call
    this and refuse advertisement on any "critical" finding; the proxy
    surfaces "high" / "medium" as `tool.scan.warning` audit events.
    """
    findings: list[ToolScanFinding] = []
    parts: list[str] = []

    desc = tool.get("description")
    if isinstance(desc, str):
        parts.append(desc)
    annot = tool.get("annotations")
    if isinstance(annot, Mapping):
        for v in annot.values():
            if isinstance(v, str):
                parts.append(v)

    schema = tool.get("inputSchema")
    if isinstance(schema, Mapping):
        sdesc = schema.get("description")
        if isinstance(sdesc, str):
            parts.append(sdesc)
        props = schema.get("properties")
        if isinstance(props, Mapping):
            for prop in props.values():
                if isinstance(prop, Mapping):
                    pd = prop.get("description")
                    if isinstance(pd, str):
                        parts.append(pd)

    blob = "\n".join(parts)
    if blob:
        findings.extend(_scan_invisibles(blob))
        findings.extend(_scan_injection_phrases(blob))
        findings.extend(_scan_encoded_blobs(blob))

    safe = not any(f.severity == "critical" for f in findings)
    return ToolScanResult(safe=safe, findings=tuple(findings))
