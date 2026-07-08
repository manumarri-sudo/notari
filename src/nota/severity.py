"""ISO 22324 + NIST/CIS-aligned severity-color treatment for Nota CLI output.

The standard mapping is uniform across `nota saves`, `nota insights`,
`nota watch`, and any future surface that needs to communicate "what just
happened, in priority order, at a glance":

  Class            Color    Icon  Label
  -------------    ------   ----  ---------
  CRITICAL         red      blocker     CRITICAL
  HIGH             yellow   warn        HIGH
  MEDIUM           yellow   warn        MEDIUM (dim yellow)
  LOW              dim      .           LOW (dim)
  ALLOW / TRUST    green    check       OK
  TRIFECTA         red      alarm       TRIFECTA
  CHAIN            magenta  link        CHAIN
  SECRET           red      lock        SECRET
  PIN_REFUSAL      red      blocker     PIN-FLIP

ISO 22324:2015 fixes the color half (red=danger, yellow=warning, green=safe).
NIST SP 800-61 r2, CIS Critical Security Controls v8, and the OWASP
risk-rating taxonomy mirror it. The icon half lets the message survive
NO_COLOR terminals + screen readers: color is decoration, icon + text
label carries the meaning.

Output format is Rich markup ([red]...[/red]). Plain mode strips it via
the existing `plain=True` path the renderers already implement.

References (primary):
  - ISO 22324:2015 - Societal security - Emergency management - Guidelines
    for colour-coded alerts.
  - NIST SP 800-61 Rev 2 - Computer Security Incident Handling Guide, section
    3.2.6 Incident Prioritization (red/yellow/green tiers).
  - https://no-color.org/ - the NO_COLOR convention; Rich respects this
    automatically through its Console.
"""

from __future__ import annotations

from typing import Literal

from nota.policy import Risk

SeverityLabel = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "ok",
    "trifecta",
    "chain",
    "secret",
    "pin_refusal",
]


# Single-source mapping. Icons are ASCII-safe so they render in any terminal;
# we deliberately avoid emojis here because not every Mac terminal renders
# them with consistent width (drifts the table alignment in `nota insights`).
_ICONS: dict[SeverityLabel, str] = {
    "critical": "X",
    "high": "!",
    "medium": "~",
    "low": ".",
    "ok": "+",
    "trifecta": "*",
    "chain": "=",
    "secret": "$",
    "pin_refusal": "X",
}

_COLORS: dict[SeverityLabel, str] = {
    "critical": "red",
    "high": "yellow",
    "medium": "yellow",
    "low": "dim",
    "ok": "green",
    "trifecta": "red",
    "chain": "magenta",
    "secret": "red",
    "pin_refusal": "red",
}

_TEXT_LABEL: dict[SeverityLabel, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "ok": "OK",
    "trifecta": "TRIFECTA",
    "chain": "CHAIN",
    "secret": "SECRET",
    "pin_refusal": "PIN-FLIP",
}


def icon(label: SeverityLabel) -> str:
    """Return the single-character text-safe icon for the severity label.
    Same icon in both plain and Rich modes - color is the only thing that
    drops out in plain mode."""
    return _ICONS[label]


def color(label: SeverityLabel) -> str:
    """Return the Rich color spec (e.g., 'red', 'yellow', 'dim')."""
    return _COLORS[label]


def text_label(label: SeverityLabel) -> str:
    """Return the screen-reader-safe text label, e.g. 'CRITICAL'."""
    return _TEXT_LABEL[label]


def from_risk(risk: Risk) -> SeverityLabel:
    """Map a policy.Risk enum to its severity label."""
    mapping: dict[Risk, SeverityLabel] = {
        Risk.CRITICAL: "critical",
        Risk.HIGH: "high",
        Risk.MEDIUM: "medium",
        Risk.LOW: "low",
    }
    return mapping[risk]


def paint(label: SeverityLabel, text: str, *, plain: bool = False) -> str:
    """Wrap `text` in Rich color markup + prepend the icon. Plain mode
    drops the markup but keeps the icon - the icon is the
    NO_COLOR-compatible carrier of meaning."""
    icn = icon(label)
    if plain:
        return f"{icn} {text}"
    col = color(label)
    return f"[{col}]{icn} {text}[/{col}]"


def stat_line(
    label: SeverityLabel,
    count: int,
    body: str,
    *,
    plain: bool = False,
    width: int = 4,
) -> str:
    """Format one numeric stat line for the saves/insights counter blocks.
    Shape: '  {icon} {count:>width}  {body}' with color applied to the
    icon + count when in Rich mode. Body is left uncolored so the eye
    follows the numeric column, not the prose."""
    icn = icon(label)
    if plain:
        return f"  {icn} {count:>{width}}  {body}"
    col = color(label)
    return f"  [{col}]{icn} {count:>{width}}[/{col}]  {body}"
