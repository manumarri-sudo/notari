"""Audit-export tests - the deliverable for the $2,500 AI Agent Risk Audit.

We pin:
- The control crosswalk doesn't drift silently (every Quill event_type
  referenced by a control still exists in events.py).
- Markdown + HTML render without raising on empty / partial / full logs.
- Redaction holds: raw arg values never leak into the export.
- Chain-broken logs surface honestly in the report header.
- KPIs are computed correctly (TDR, intervention rate).
"""

from __future__ import annotations

from pathlib import Path

from quill import events as ev
from quill.exports import (
    CONTROLS,
    aggregate,
    render_html,
    render_markdown,
)


def _evt(t: str, sid: str = "s1", **payload: object) -> dict[str, object]:
    return {
        "type": t,
        "session_id": sid,
        "ts": "2026-05-08T12:00:00Z",
        "risk": payload.pop("__risk", "low"),
        "payload": dict(payload),
    }


def test_every_control_references_real_event_types() -> None:
    """If a refactor renames an event type, the crosswalk shouldn't
    silently keep referring to the old name. Pin every control's
    event-type tuple against the canonical event-type registry."""
    # No exceptions: every control event must be a real, registered event type.
    # (The old allow-list hid stale names like notify.dispatched / tool.pin_refused
    # for events the pivot removed - security review honesty finding.)
    real = ev.ALL_EVENT_TYPES
    for c in CONTROLS:
        for et in c.quill_event_types:
            assert et in real, (
                f"control {c.code} references unknown event_type {et!r}; "
                "either add it to events.py or fix the crosswalk"
            )


def test_change_control_surface_is_covered_with_sampling() -> None:
    """The crosswalk must cover the headline Change-Control events, and every
    Change-Control control must carry auditor-sampling guidance (the explicit
    field practitioners asked for: how would an auditor test this)."""
    cc = [c for c in CONTROLS if "verification.run" in c.quill_event_types]
    assert cc, "no control maps the Change-Control verification.run event"
    assert any("contract.created" in c.quill_event_types for c in CONTROLS)
    for c in cc:
        assert c.auditor_sampling, f"Change-Control control {c.code} has no auditor_sampling"


def test_aggregate_empty_log_produces_no_evidence_for_every_control() -> None:
    rep = aggregate([], log_path=Path("/dev/null"))
    assert rep.total_events == 0
    for ce in rep.by_control:
        assert ce.matching_events == 0
        assert ce.status == "no_evidence"


def test_aggregate_full_session_satisfies_eu_ai_act_controls() -> None:
    """A typical session with attempted/allowed/blocked/asked should produce
    evidence for the human-oversight controls."""
    events = [
        _evt(ev.SESSION_OPEN),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Bash", args_preview={"command": "ls"}),
        _evt(ev.VERDICT_ALLOWED, tool_name="Bash", reason="read-only"),
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Bash",
            __risk="critical",
            args_preview={"command": "rm -rf /etc/passwd"},
        ),
        _evt(ev.VERDICT_BLOCKED, tool_name="Bash", __risk="critical", reason="rm -rf"),
        _evt(ev.TOOL_ATTEMPTED, tool_name="Edit", __risk="high"),
        _evt(ev.VERDICT_ASK, tool_name="Edit", __risk="high"),
        _evt(ev.SESSION_CLOSE),
    ]
    rep = aggregate(events, log_path=Path("/x/audit.jsonl"))
    by_code = {ce.control.code: ce for ce in rep.by_control}
    assert by_code["ART-14-IN-COMMAND"].matching_events >= 1  # blocked
    assert by_code["ART-14-IN-LOOP"].matching_events >= 1  # ask
    assert by_code["ART-14-ON-LOOP"].matching_events >= 1  # allowed
    # ART-12-RETENTION was split into ART-12-AUTO-LOGGING + ART-12-TAMPER-EVIDENT
    # + ART-19-RETENTION (Article 19 owns the retention period; Article 12 owns
    # auto-logging and tamper-evidence).
    assert by_code["ART-12-AUTO-LOGGING"].matching_events >= 2  # tool.attempted x2
    assert by_code["ART-12-TAMPER-EVIDENT"].matching_events >= 2  # tool.attempted x2
    assert by_code["ART-19-RETENTION"].matching_events >= 2  # tool.attempted x2


def test_kpis_compute_tdr_correctly() -> None:
    """TDR = allowed / (allowed + blocked + asked)."""
    events = [
        _evt(ev.VERDICT_ALLOWED, tool_name="Bash"),
        _evt(ev.VERDICT_ALLOWED, tool_name="Bash"),
        _evt(ev.VERDICT_ALLOWED, tool_name="Bash"),
        _evt(ev.VERDICT_BLOCKED, tool_name="Bash", __risk="critical"),
    ]
    rep = aggregate(events, log_path=Path("/x"))
    assert rep.kpis["TDR"] == 0.75
    assert rep.kpis["intervention_rate"] == 0.25


def test_redaction_strips_raw_arg_values() -> None:
    """Customer's auditor sees what was attempted, never the secrets."""
    events = [
        _evt(
            ev.TOOL_ATTEMPTED,
            tool_name="Bash",
            args_preview={"command": "rm -rf /home/me/.ssh/id_rsa"},
            arg_keys=["command"],
        ),
    ]
    rep = aggregate(events, log_path=Path("/x"))
    md = render_markdown(rep)
    html = render_html(rep)
    # Must NOT appear in either rendering.
    assert "/home/me/.ssh/id_rsa" not in md
    assert "/home/me/.ssh/id_rsa" not in html
    # The TOOL NAME is fine to surface.
    assert "Bash" in md or "Bash" in html


def test_chain_broken_status_surfaces_in_report() -> None:
    rep = aggregate(
        [_evt(ev.TOOL_ATTEMPTED, tool_name="Bash")],
        log_path=Path("/x/audit.jsonl"),
        chain_total=10,
        chain_failures=[3, 4],
    )
    assert "broken" in rep.chain_status
    md = render_markdown(rep)
    assert "broken" in md
    html = render_html(rep)
    assert "broken" in html
    assert "chain-broken" in html  # CSS class fires


def test_chain_intact_status_surfaces_in_report() -> None:
    rep = aggregate(
        [_evt(ev.TOOL_ATTEMPTED, tool_name="Bash")],
        log_path=Path("/x/audit.jsonl"),
        chain_total=10,
        chain_failures=[],
    )
    assert "intact" in rep.chain_status
    html = render_html(rep)
    assert "chain-intact" in html


def test_html_is_self_contained_for_offline_print() -> None:
    """Customer's auditor opens the HTML offline (no network), prints to
    PDF. No external CSS / JS / fonts must be required."""
    rep = aggregate(
        [_evt(ev.TOOL_ATTEMPTED, tool_name="Bash")],
        log_path=Path("/x"),
    )
    html = render_html(rep)
    # Inline CSS only (style block).
    assert "<style>" in html
    # No external <link href="http..."> or <script src="http...">.
    assert "<link " not in html.lower()
    assert "<script" not in html.lower()
    assert "fonts.googleapis.com" not in html


def test_markdown_renders_executive_summary_table() -> None:
    rep = aggregate(
        [
            _evt(ev.TOOL_ATTEMPTED, tool_name="Bash"),
            _evt(ev.VERDICT_ALLOWED, tool_name="Bash"),
        ],
        log_path=Path("/x"),
    )
    md = render_markdown(rep)
    assert "# Quill Audit Evidence Pack" in md
    assert "## Executive summary" in md
    assert "## Control mapping" in md
    assert "## Tamper-evidence" in md
    assert "Quill" in md  # branded


def test_aggregate_filters_by_selected_standard() -> None:
    """If only AIUC-1 is selected, no EU AI Act controls show up."""
    rep = aggregate(
        [_evt(ev.TOOL_ATTEMPTED, tool_name="Bash")],
        log_path=Path("/x"),
        standards=["AIUC-1"],
    )
    standards_in_report = {ce.control.standard for ce in rep.by_control}
    for s in standards_in_report:
        assert s.startswith("AIUC-1"), s
    # And inverse: if only Art. 14 selected, no AIUC-1 controls.
    rep2 = aggregate(
        [_evt(ev.TOOL_ATTEMPTED, tool_name="Bash")],
        log_path=Path("/x"),
        standards=["EU AI Act Art. 14"],
    )
    standards2 = {ce.control.standard for ce in rep2.by_control}
    for s in standards2:
        assert s.startswith("EU AI Act"), s
