"""Tests for the severity-color treatment module (#53).

Two invariants:
  1. Color mapping matches ISO 22324 (red=critical, yellow=warning, green=ok).
  2. Accessibility: every output keeps the text-safe icon + text label even
     in plain mode, so NO_COLOR terminals and screen readers still convey
     the severity.
"""

from __future__ import annotations

from nota.policy import Risk
from nota.severity import (
    color,
    from_risk,
    icon,
    paint,
    stat_line,
    text_label,
)


def test_critical_is_red():
    assert color("critical") == "red"
    assert color("trifecta") == "red"
    assert color("secret") == "red"
    assert color("pin_refusal") == "red"


def test_warning_classes_are_yellow():
    assert color("high") == "yellow"
    assert color("medium") == "yellow"


def test_ok_is_green():
    assert color("ok") == "green"


def test_chain_is_magenta():
    assert color("chain") == "magenta"


def test_low_is_dim():
    """Low/informational events use Rich's 'dim' style, not a color, so they
    recede on screen without claiming the safety-green visual slot."""
    assert color("low") == "dim"


def test_from_risk_round_trip():
    assert from_risk(Risk.CRITICAL) == "critical"
    assert from_risk(Risk.HIGH) == "high"
    assert from_risk(Risk.MEDIUM) == "medium"
    assert from_risk(Risk.LOW) == "low"


def test_paint_plain_keeps_icon_drops_color():
    out = paint("critical", "boom", plain=True)
    assert icon("critical") in out
    assert "boom" in out
    assert "[red]" not in out
    assert "[/red]" not in out


def test_paint_rich_includes_color_markup():
    out = paint("critical", "boom", plain=False)
    assert "[red]" in out
    assert "[/red]" in out
    assert icon("critical") in out
    assert "boom" in out


def test_stat_line_plain_alignment():
    """Plain-mode stat lines must produce stable column alignment so they
    can be diffed / piped into other tools."""
    out = stat_line("ok", 7, "auto-allows", plain=True)
    # Shape: '  + 7  auto-allows' (icon, then right-justified count, then body)
    assert out.startswith("  " + icon("ok"))
    assert "auto-allows" in out


def test_stat_line_rich_wraps_count_in_color():
    out = stat_line("critical", 12, "blocked", plain=False)
    assert "[red]" in out
    assert "12" in out
    assert "blocked" in out


def test_text_label_is_screen_reader_safe():
    """Text label is what assistive tech reads when icons + color are
    unavailable. Must be uppercase, no punctuation."""
    for sev in (
        "critical",
        "high",
        "medium",
        "low",
        "ok",
        "trifecta",
        "chain",
        "secret",
        "pin_refusal",
    ):
        label = text_label(sev)
        assert label.isupper() or "-" in label
        assert " " not in label


def test_every_label_has_complete_mapping():
    """Catch the bug where someone adds a label to one of the three dicts
    but forgets the other two. Every label that appears in any dict must
    appear in all three."""
    for sev in (
        "critical",
        "high",
        "medium",
        "low",
        "ok",
        "trifecta",
        "chain",
        "secret",
        "pin_refusal",
    ):
        assert icon(sev)
        assert color(sev)
        assert text_label(sev)
