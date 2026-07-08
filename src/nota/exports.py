"""Audit-log export to AIUC-1 + EU AI Act Article 14 evidence packs.

The deliverable for the "$2,500 5-day AI Agent Risk Audit" SKU. Groups
audit events by compliance control, computes KPIs (TDR, intervention
rate, chain integrity), emits an executive Markdown + HTML report the
customer hands to their auditor.

Standards mapped:
  - **EU AI Act Article 14** (Human Oversight): in-the-loop, on-the-loop,
    in-command. https://artificialintelligenceact.eu/article/14/
  - **EU AI Act Article 12** (Record-keeping): tamper-resistant logs,
    automatic logging, ≥6 months retention.
  - **AIUC-1**: AI Use Case framework. 50+ controls across Safety,
    Security, Reliability, Accountability, Data & Privacy, Society.
    https://www.aiuc-1.com/
  - **OWASP Agentic Top 10 (2026)**: ASI01 Goal Hijack, Tool Misuse,
    Identity Abuse, Human Trust Exploitation, Rogue Agents.
    https://genai.owasp.org/

The output is HTML the customer prints to PDF via browser (Cmd+P) plus
a parallel Markdown the customer can paste into Notion / Google Docs.
Zero new dependencies. PDF-as-binary is deferred to v0.3 with optional
[pdf] extra.
"""

from __future__ import annotations

import html as _html
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


# ---------------------------------------------------------------------------
# Control mapping - every Nota audit event_type → which compliance control
# it produces evidence for. This is the core IP of the export: a defensible
# crosswalk that Manu's audit deliverable hangs on.
#
# The crosswalk lives in controls.toml next to this module. Editing the
# data is a TOML change, not a Python change; new control mappings are
# data entry. The schema is:
#
#   [[controls]]
#   standard = "EU AI Act Art. 14"
#   code = "ART-14-IN-LOOP"
#   title = "Human in-the-loop (...)"
#   description = "..."
#   nota_event_types = ["verdict.ask", "approve.biometric.ok"]


@dataclass(frozen=True)
class Control:
    """One row in a compliance evidence table."""

    standard: str  # "EU AI Act Art. 14", "AIUC-1 Security", etc.
    code: str  # "ART-14-IN-LOOP", "AIUC-SEC-01"
    title: str
    description: str
    nota_event_types: tuple[str, ...]  # which audit events satisfy this
    auditor_sampling: str = ""  # how an auditor would sample/test this evidence


_CONTROLS_TOML = Path(__file__).parent / "controls.toml"


def _load_controls(path: Path = _CONTROLS_TOML) -> tuple[Control, ...]:
    """Parse controls.toml into a tuple of frozen Control records."""
    with path.open("rb") as f:
        raw = tomllib.load(f)
    rows = raw.get("controls", [])
    out: list[Control] = []
    for r in rows:
        out.append(
            Control(
                standard=str(r["standard"]),
                code=str(r["code"]),
                title=str(r["title"]),
                description=str(r["description"]).strip(),
                nota_event_types=tuple(str(e) for e in r["nota_event_types"]),
                auditor_sampling=str(r.get("auditor_sampling", "")).strip(),
            ),
        )
    return tuple(out)


# Load once at module import; the file is small and read-only at runtime.
CONTROLS: tuple[Control, ...] = _load_controls()


# ---------------------------------------------------------------------------
# Aggregation


@dataclass(slots=True)
class ControlEvidence:
    """Evidence collected for one control during the export window."""

    control: Control
    matching_events: int = 0
    sample_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Coarse status string for the report header column."""
        return "satisfied" if self.matching_events > 0 else "no_evidence"


@dataclass(slots=True)
class ExportReport:
    """The full export - emitted to Markdown + HTML."""

    generated_at: str
    log_path: str
    standards: list[str]
    window_start: str
    window_end: str
    total_events: int
    chain_status: str  # "intact" | "broken: N of M" | "empty"
    chain_failures: list[int]
    by_control: list[ControlEvidence]
    kpis: dict[str, Any]
    notes: list[str]


def aggregate(
    events: Iterable[Mapping[str, Any]],
    *,
    log_path: Path,
    standards: list[str] | None = None,
    chain_total: int = 0,
    chain_failures: list[int] | None = None,
) -> ExportReport:
    """Walk events; group by control; compute KPIs."""
    standards = standards or [
        "EU AI Act Art. 14",
        "EU AI Act Art. 12",
        "EU AI Act Art. 19",
        "AIUC-1",
        "NIST AI RMF",
        "NIST GenAI Profile",
        "ISO/IEC 42001",
        "SOC 2 Common Criteria",
        "MITRE ATLAS",
        "NIST SP 800-53",
        "FTC Act Section 5",
        "Colorado AI Act (SB 24-205)",
    ]
    by_type: Counter[str] = Counter()
    risk_dist: Counter[str] = Counter()
    sample_by_type: dict[str, list[dict[str, Any]]] = {}
    first_ts = ""
    last_ts = ""
    total = 0

    for evt in events:
        total += 1
        ts = str(evt.get("ts") or "")
        if ts:
            first_ts = first_ts or ts
            last_ts = ts
        et = str(evt.get("type") or "")
        risk = str(evt.get("risk") or "low")
        if not et:
            continue
        by_type[et] += 1
        risk_dist[risk] += 1
        # Keep up to 3 redacted samples per event_type for the appendix.
        if et not in sample_by_type:
            sample_by_type[et] = []
        if len(sample_by_type[et]) < 3:
            sample_by_type[et].append(_redact_for_export(evt))

    by_control: list[ControlEvidence] = []
    for c in CONTROLS:
        if not any(c.standard.startswith(s) for s in standards):
            continue
        n = sum(by_type.get(et, 0) for et in c.nota_event_types)
        samples: list[dict[str, Any]] = []
        for et in c.nota_event_types:
            samples.extend(sample_by_type.get(et, []))
        by_control.append(
            ControlEvidence(
                control=c,
                matching_events=n,
                sample_events=samples[:3],
            ),
        )

    n_attempts = by_type.get("tool.attempted", 0)
    n_blocked = by_type.get("verdict.blocked", 0) + by_type.get("verdict.scope_violation", 0)
    n_asked = by_type.get("verdict.ask", 0)
    n_allowed = by_type.get("verdict.allowed", 0)
    interventions = n_blocked + n_asked
    denom = n_allowed + interventions
    tdr = (n_allowed / denom) if denom else 1.0

    kpis = {
        "total_events": total,
        "tool_attempts": n_attempts,
        "verdict_allowed": n_allowed,
        "verdict_blocked": by_type.get("verdict.blocked", 0),
        "verdict_asked": n_asked,
        "verdict_scope_violation": by_type.get("verdict.scope_violation", 0),
        "interventions": interventions,
        "TDR": round(tdr, 3),
        "intervention_rate": round(1.0 - tdr, 3),
        "risk_distribution": dict(risk_dist),
        "event_type_counts": dict(by_type),
    }

    if chain_total == 0 and total > 0:
        chain_status = "unknown (chain not verified)"
    elif chain_total == 0:
        chain_status = "empty"
    elif chain_failures:
        chain_status = f"broken: {len(chain_failures)} of {chain_total} entries fail"
    else:
        chain_status = f"intact ({chain_total} entries verified)"

    notes: list[str] = []
    if total == 0:
        notes.append(
            "Audit log is empty. Run Nota against the target system for at "
            "least one full agent session before exporting again.",
        )
    if chain_failures:
        notes.append(
            "Chain failures detected. Investigate with `nota audit verify`. "
            "Pre-0.1.1 logs may have legacy concurrent-write breaks; if so, "
            "run `nota audit repair --legacy --yes`.",
        )

    return ExportReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        log_path=str(log_path),
        standards=standards,
        window_start=first_ts,
        window_end=last_ts,
        total_events=total,
        chain_status=chain_status,
        chain_failures=list(chain_failures or []),
        by_control=by_control,
        kpis=kpis,
        notes=notes,
    )


# Free-text payload fields that can embed a raw command line (and therefore
# an inline credential). The args_preview map is already dropped wholesale;
# these survive into the export, so each is run through the secret redactor.
_FREETEXT_EXPORT_FIELDS = ("reason", "what", "why", "try_instead")


def _redact_for_export(evt: Mapping[str, Any]) -> dict[str, Any]:
    """Strip arg values; keep arg keys + identity-bearing fields.

    Same redaction stance as the audit log itself. The auditor sees what was
    attempted (tool name, risk, reason) but never raw secret material. The
    args_preview map is dropped entirely; the surviving free-text fields
    (``what`` / ``why`` / ``reason`` / ``try_instead``) can each carry a raw
    command line, so they are passed through ``secrets.redact`` and home
    paths in ``what`` are normalised to ``~`` to avoid leaking the username.
    The raw ``approve_token`` is never exported - only a short hash id.
    """
    from nota import secrets as _secrets

    p = evt.get("payload") or {}
    if not isinstance(p, Mapping):
        p = {}
    safe_payload: dict[str, Any] = {}
    for k in (
        "tool_name",
        "by",
        "reason",
        "permission",
        "risk",
        "what",
        "why",
        "try_instead",
        "to_agent_id",
        "from_session_id",
        "kind",
    ):
        v = p.get(k)
        if isinstance(v, (str, int, float, bool)) and v != "":
            if isinstance(v, str) and k in _FREETEXT_EXPORT_FIELDS:
                v = _secrets.redact(v)
                if k == "what":
                    v = v.replace(str(Path.home()), "~")
            safe_payload[k] = v
    if "arg_keys" in p and isinstance(p["arg_keys"], list):
        safe_payload["arg_keys"] = list(p["arg_keys"])
    return {
        "ts": str(evt.get("ts") or ""),
        "type": str(evt.get("type") or ""),
        "risk": str(evt.get("risk") or ""),
        "session_id": str(evt.get("session_id") or "")[:12],
        "payload": safe_payload,
    }


# ---------------------------------------------------------------------------
# Markdown render


def render_markdown(r: ExportReport) -> str:
    """One-page-ish executive report. Print or paste to Notion."""
    lines: list[str] = []
    add = lines.append
    add("# Nota Audit Evidence Pack")
    add("")
    add(f"- **Generated**: {r.generated_at}")
    add(f"- **Source log**: `{r.log_path}`")
    add(f"- **Standards**: {', '.join(r.standards)}")
    if r.window_start:
        add(f"- **Window**: {r.window_start[:19]} → {r.window_end[:19]}")
    add(f"- **Chain status**: {r.chain_status}")
    add("")
    add("## Executive summary")
    add("")
    k = r.kpis
    add(f"- Total events: {k['total_events']}")
    add(f"- Tool attempts: {k['tool_attempts']}")
    add(f"- Allowed: {k['verdict_allowed']}")
    add(f"- Blocked: {k['verdict_blocked']}  ·  Scope-violation: {k['verdict_scope_violation']}")
    add(f"- Asked human: {k['verdict_asked']}")
    add(f"- **Trust Delivery Rate (TDR)**: {k['TDR']}")
    add(f"- **Intervention rate**: {k['intervention_rate']}")
    if k.get("risk_distribution"):
        risks = ", ".join(f"{r_}: {c}" for r_, c in k["risk_distribution"].items())
        add(f"- Risk distribution: {risks}")
    add("")

    if r.notes:
        add("## Notes")
        for n in r.notes:
            add(f"- {n}")
        add("")

    add("## Control mapping")
    add("")
    add("| Standard | Control | Title | Status | Events |")
    add("|---|---|---|---|---|")
    for ce in r.by_control:
        c = ce.control
        status_md = "✓ satisfied" if ce.status == "satisfied" else "- no evidence"
        add(f"| {c.standard} | `{c.code}` | {c.title} | {status_md} | {ce.matching_events} |")
    add("")

    # Per-control detail
    add("## Control evidence (detail)")
    add("")
    for ce in r.by_control:
        c = ce.control
        add(f"### {c.code} - {c.title}")
        add("")
        add(f"**Standard**: {c.standard}  ·  **Matching events**: {ce.matching_events}")
        add("")
        add(c.description)
        add("")
        add("Nota event types: `" + "`, `".join(c.nota_event_types) + "`")
        add("")
        if c.auditor_sampling:
            add(f"**How an auditor samples this**: {c.auditor_sampling}")
            add("")
        if ce.sample_events:
            add("Sample evidence (redacted):")
            add("")
            add("```jsonl")
            for s in ce.sample_events:
                add(json.dumps(s, separators=(",", ":")))
            add("```")
            add("")

    add("## Tamper-evidence")
    add("")
    add(
        f"Nota's audit log is HMAC-SHA256-chained per entry. Verification "
        f"status at export time: **{r.chain_status}**."
    )
    if r.chain_failures:
        add("")
        add(f"Failed line numbers (first 20): {r.chain_failures[:20]}")
    add("")
    add(
        'EU AI Act Article 12 requires logs to be "automatically generated '
        'throughout the lifetime" of high-risk AI systems and retained for '
        "≥6 months. Nota's append-only JSONL with HMAC chaining and "
        "fcntl.flock cross-process serialization satisfies the tamper-"
        "resistance and automatic-generation requirements; retention is the "
        "operator's responsibility (default location `$NOTA_HOME/audit.log.jsonl`, "
        "mode 0o600).",
    )
    add("")
    add("---")
    add("")
    add(
        "*Generated by Nota - the pause button between AI agents and the "
        "things you can't undo. github.com/manumarri-sudo/nota*",
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML render - same content, brand-aligned styling, prints clean.


_HTML_CSS = """
:root { --ink:#1e3a5f; --paper:#fafaf5; --muted:#6b7a8f; --rule:#d8d4c4;
        --allow:#3d6b4a; --block:#c1442f; --ask:#b8862b; --hint:#5e81ac; }
* { box-sizing: border-box; }
body { background: var(--paper); color: var(--ink);
       font: 16px/1.55 "Source Serif 4", Georgia, serif;
       max-width: 880px; margin: 2rem auto; padding: 0 2rem; }
h1 { font-size: 2.2rem; letter-spacing: -.01em; margin-top: 0; }
h2 { border-bottom: 1px solid var(--rule); padding-bottom: .3rem;
     margin-top: 2.5rem; }
h3 { color: var(--ink); margin-top: 2rem; }
.meta { color: var(--muted); font-size: .92rem; }
.kpi { display: inline-block; margin-right: 1.6rem; }
.kpi b { color: var(--ink); }
table { border-collapse: collapse; width: 100%; margin: 1.5rem 0;
        font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Inter", sans-serif; }
th { text-align: left; border-bottom: 2px solid var(--ink);
     padding: .5rem .75rem; }
td { border-bottom: 1px solid var(--rule); padding: .45rem .75rem; }
.satisfied { color: var(--allow); font-weight: 600; }
.no_evidence { color: var(--muted); }
code, pre { font-family: "JetBrains Mono", Menlo, monospace; font-size: 0.86em; }
pre { background: #f0ebd8; padding: 1rem; border-radius: 6px;
      overflow-x: auto; line-height: 1.4; }
.note { background: #fff7d6; border-left: 3px solid var(--ask);
        padding: .75rem 1rem; margin: 1rem 0; }
.chain-broken { color: var(--block); font-weight: 700; }
.chain-intact { color: var(--allow); font-weight: 700; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--rule);
         color: var(--muted); font-size: .85rem; font-style: italic; }
@media print {
  body { max-width: none; margin: 0; padding: 1cm; }
  h2 { page-break-before: auto; }
  pre { white-space: pre-wrap; }
}
"""


def render_html(r: ExportReport) -> str:
    """Brand-aligned HTML; print to PDF via browser Cmd+P."""
    e = _html.escape

    def chain_class() -> str:
        if r.chain_status.startswith("intact"):
            return "chain-intact"
        if r.chain_status.startswith("broken"):
            return "chain-broken"
        return ""

    out: list[str] = []
    add = out.append
    add("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    add("<title>Nota Audit Evidence Pack</title>")
    add(f"<style>{_HTML_CSS}</style>")
    add("</head><body>")
    add("<h1>Nota Audit Evidence Pack</h1>")
    add("<p class='meta'>")
    add(f"<strong>Generated:</strong> {e(r.generated_at)} &middot; ")
    add(f"<strong>Source log:</strong> <code>{e(r.log_path)}</code> &middot; ")
    add(f"<strong>Standards:</strong> {e(', '.join(r.standards))}<br>")
    if r.window_start:
        add(f"<strong>Window:</strong> {e(r.window_start[:19])} → {e(r.window_end[:19])} &middot; ")
    add(f"<strong>Chain:</strong> <span class='{chain_class()}'>{e(r.chain_status)}</span>")
    add("</p>")

    add("<h2>Executive summary</h2>")
    k = r.kpis
    add("<p>")
    for label, key in (
        ("Total events", "total_events"),
        ("Tool attempts", "tool_attempts"),
        ("Allowed", "verdict_allowed"),
        ("Blocked", "verdict_blocked"),
        ("Asked human", "verdict_asked"),
        ("TDR", "TDR"),
        ("Intervention rate", "intervention_rate"),
    ):
        add(f"<span class='kpi'><b>{e(label)}:</b> {e(str(k.get(key, '')))}</span>")
    add("</p>")

    if r.notes:
        for n in r.notes:
            add(f"<div class='note'>{e(n)}</div>")

    add("<h2>Control mapping</h2>")
    add("<table><thead><tr>")
    add("<th>Standard</th><th>Control</th><th>Title</th><th>Status</th><th>Events</th>")
    add("</tr></thead><tbody>")
    for ce in r.by_control:
        c = ce.control
        cls = "satisfied" if ce.status == "satisfied" else "no_evidence"
        status_label = "✓ satisfied" if ce.status == "satisfied" else "- no evidence"
        add(
            f"<tr><td>{e(c.standard)}</td><td><code>{e(c.code)}</code></td>"
            f"<td>{e(c.title)}</td>"
            f"<td class='{cls}'>{status_label}</td>"
            f"<td>{ce.matching_events}</td></tr>",
        )
    add("</tbody></table>")

    add("<h2>Control evidence (detail)</h2>")
    for ce in r.by_control:
        c = ce.control
        add(f"<h3>{e(c.code)} - {e(c.title)}</h3>")
        add(
            f"<p class='meta'><strong>Standard:</strong> {e(c.standard)} "
            f"&middot; <strong>Matching events:</strong> {ce.matching_events}</p>"
        )
        add(f"<p>{e(c.description)}</p>")
        add(
            "<p><strong>Nota event types:</strong> "
            f"<code>{e(', '.join(c.nota_event_types))}</code></p>"
        )
        if c.auditor_sampling:
            add(f"<p><strong>How an auditor samples this:</strong> {e(c.auditor_sampling)}</p>")
        if ce.sample_events:
            add("<p>Sample evidence (redacted):</p>")
            add("<pre>")
            for s in ce.sample_events:
                add(e(json.dumps(s, separators=(",", ":"))))
            add("</pre>")

    add("<h2>Tamper-evidence</h2>")
    add(
        f"<p>Nota's audit log is HMAC-SHA256-chained per entry. "
        f"Verification status at export time: <span class='{chain_class()}'>"
        f"{e(r.chain_status)}</span>.</p>"
    )
    if r.chain_failures:
        add(f"<p>Failed line numbers (first 20): <code>{e(str(r.chain_failures[:20]))}</code></p>")
    add(
        '<p>EU AI Act Article 12 requires logs to be "automatically generated '
        'throughout the lifetime" of high-risk AI systems and retained ≥6 '
        "months. Nota's append-only JSONL with HMAC chaining and "
        "<code>fcntl.flock</code> cross-process serialization satisfies the "
        "tamper-resistance and automatic-generation requirements; retention is "
        "the operator's responsibility (default <code>$NOTA_HOME/audit.log.jsonl</code>, "
        "mode <code>0o600</code>).</p>",
    )

    add(
        "<footer>Generated by Nota - the pause button between AI agents and "
        "the things you can't undo. <code>github.com/manumarri-sudo/nota</code></footer>"
    )
    add("</body></html>")
    return "\n".join(out)
