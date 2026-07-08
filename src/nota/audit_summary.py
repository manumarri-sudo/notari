"""Morning recap aggregation for overnight mode.

Reads the HMAC-chain-signed audit log written by `nota.audit.AuditLog`,
filters events to a `--since` window, and aggregates the rows that matter
for an unattended overnight session into a paste-ready morning report:

  - HIGH actions auto-approved (audit_event_type=verdict.allowed.overnight)
  - CRITICAL actions still blocked under overnight mode
  - LOW/MEDIUM activity logged (volume signal)
  - Active sessions in the window
  - Top tool-name breakdown for the auto-approved bucket
  - Top sessions by event volume
  - Any HIGH events that still asked the operator (overnight was off)
  - Anything that hit verdict.blocked / verdict.scope_violation

The module is pure: parsing, filtering, counting, and rendering live here
so the CLI wrapper in `nota.cli` stays thin and the same code path is
covered by `tests/test_audit_summary.py` directly.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from rich.table import Table

# Audit event type that the overnight gate writes for auto-approved HIGH
# rows. See `src/nota/adapters/claude_code.py` for the producer.
OVERNIGHT_EVENT_TYPE = "verdict.allowed.overnight"

# Risk levels we treat as "the operator would have been asked" when overnight
# was not active. Used for the "what still asked you to approve" lane.
ASK_EVENT_TYPE = "verdict.ask"
BLOCK_EVENT_TYPES = ("verdict.blocked", "verdict.scope_violation")
ALLOWED_PLAIN_EVENT_TYPE = "verdict.allowed"


# ---------------------------------------------------------------------------
# duration parsing
# ---------------------------------------------------------------------------


_DURATION_TOKEN_RE = re.compile(r"(\d+)([smhdw])")


def parse_duration(spec: str | None) -> timedelta:
    """Parse a duration string like ``12h``, ``1d``, ``30m``, ``2h30m``.

    Supported units: ``s`` (seconds), ``m`` (minutes), ``h`` (hours),
    ``d`` (days), ``w`` (weeks). Multiple components compose additively,
    so ``2h30m`` is two and a half hours. Whitespace is tolerated. Bare
    integers raise; the unit must be explicit so a typo never becomes
    "30 of the wrong unit".

    Raises ValueError on empty input, unknown units, or fully unparsed
    leftover characters.
    """
    if spec is None:
        msg = "duration is required"
        raise ValueError(msg)
    s = spec.strip().lower()
    if not s:
        msg = "duration is empty"
        raise ValueError(msg)

    units = {
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
    }
    total = timedelta()
    matched_any = False
    consumed = 0
    for m in _DURATION_TOKEN_RE.finditer(s):
        if m.start() != consumed:
            # something we couldn't parse sits between tokens (e.g. "12x3h")
            msg = f"cannot parse duration {spec!r}: unknown token at index {consumed}"
            raise ValueError(msg)
        consumed = m.end()
        n, unit = int(m.group(1)), m.group(2)
        if unit not in units:  # pragma: no cover - regex already restricts
            msg = f"cannot parse duration {spec!r}: unknown unit {unit!r}"
            raise ValueError(msg)
        total += timedelta(**{units[unit]: n})
        matched_any = True
    if consumed != len(s):
        msg = f"cannot parse duration {spec!r}: trailing characters {s[consumed:]!r}"
        raise ValueError(msg)
    if not matched_any:
        msg = f"cannot parse duration {spec!r}: no recognised tokens (try 12h, 1d, 2h30m)"
        raise ValueError(msg)
    if total.total_seconds() <= 0:
        msg = f"duration {spec!r} must be positive"
        raise ValueError(msg)
    return total


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ToolBreakdown:
    """One row of the per-tool table for HIGH auto-approved actions."""

    tool: str
    count: int
    sample_what: str = ""


@dataclass(slots=True)
class SessionBreakdown:
    """One row of the per-session table (top sessions by event volume)."""

    session_id: str
    tool_calls: int
    cwd: str = ""


@dataclass(slots=True)
class PendingItem:
    """An item that still required operator attention (asked / blocked)."""

    ts: str
    tool: str
    what: str
    why: str


@dataclass(slots=True)
class SummaryStats:
    """Aggregated overnight recap for a given window.

    All counts are scoped to events whose timestamp falls inside the window
    (and, if requested, whose cwd matches the project filter).
    """

    window_seconds: float
    since_label: str
    generated_at: str
    high_overnight_count: int = 0
    critical_blocked_count: int = 0
    low_medium_count: int = 0
    asked_count: int = 0
    blocked_count: int = 0
    total_events: int = 0
    active_sessions: int = 0
    by_tool: list[ToolBreakdown] = field(default_factory=list)
    by_session: list[SessionBreakdown] = field(default_factory=list)
    pending_ask: list[PendingItem] = field(default_factory=list)
    pending_block: list[PendingItem] = field(default_factory=list)
    log_path: str = ""
    cwd_filter: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_seconds": self.window_seconds,
            "since_label": self.since_label,
            "generated_at": self.generated_at,
            "log_path": self.log_path,
            "cwd_filter": self.cwd_filter,
            "summary": {
                "high_overnight_count": self.high_overnight_count,
                "critical_blocked_count": self.critical_blocked_count,
                "low_medium_count": self.low_medium_count,
                "asked_count": self.asked_count,
                "blocked_count": self.blocked_count,
                "total_events": self.total_events,
                "active_sessions": self.active_sessions,
            },
            "by_tool": [
                {"tool": t.tool, "count": t.count, "sample_what": t.sample_what}
                for t in self.by_tool
            ],
            "by_session": [
                {"session_id": s.session_id, "tool_calls": s.tool_calls, "cwd": s.cwd}
                for s in self.by_session
            ],
            "pending_ask": [
                {"ts": p.ts, "tool": p.tool, "what": p.what, "why": p.why} for p in self.pending_ask
            ],
            "pending_block": [
                {"ts": p.ts, "tool": p.tool, "what": p.what, "why": p.why}
                for p in self.pending_block
            ],
        }


# ---------------------------------------------------------------------------
# loading and filtering
# ---------------------------------------------------------------------------


def load_events(log_path: Path) -> list[dict[str, Any]]:
    """Read the JSONL audit log into a list of event dicts.

    Malformed lines are skipped silently (this is the same forgiving
    behaviour `audit_show` and `audit_export` use - we never let a single
    bad row break the recap). Returns an empty list if the file does not
    exist so callers can render "no events" instead of crashing.
    """
    if not log_path.exists():
        return []
    events: list[dict[str, Any]] = []
    with log_path.open() as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                events.append(obj)
    return events


def _parse_ts(ts: str) -> datetime | None:
    """Parse the ISO-8601 timestamp `audit.AuditLog` writes. Returns None
    on malformed input so a corrupt row never aborts a recap."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def filter_events(
    events: Iterable[dict[str, Any]],
    *,
    window: timedelta,
    now: datetime | None = None,
    cwd_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Keep events whose ts is within `window` of `now`, optionally scoped
    to a cwd prefix. `now` defaults to current UTC time."""
    cutoff_now = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = cutoff_now - window

    cwd_norm: str | None = None
    if cwd_filter:
        cwd_norm = str(Path(cwd_filter).expanduser().resolve())

    kept: list[dict[str, Any]] = []
    for evt in events:
        ts = _parse_ts(str(evt.get("ts", "")))
        if ts is None:
            continue
        if ts.astimezone(UTC) < cutoff:
            continue
        if cwd_norm is not None:
            payload = evt.get("payload") or {}
            cwd = payload.get("cwd") if isinstance(payload, dict) else ""
            if not isinstance(cwd, str):
                continue
            if not (
                cwd == cwd_norm or cwd.startswith(cwd_norm + "/") or cwd.startswith(cwd_norm + "\\")
            ):
                continue
        kept.append(evt)
    return kept


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------


def _short_what(payload: dict[str, Any], *, limit: int = 80) -> str:
    """Pick the most useful one-line description out of an audit payload.

    The gate writes a top-level `what` summary plus an `args_preview` map
    that holds the raw tool input. We prefer `what` because it's already
    been redacted by the adapter, falling back to args_preview fields for
    older log rows that don't have `what`.
    """
    candidates: list[str] = []
    w = payload.get("what")
    if isinstance(w, str) and w.strip():
        candidates.append(w)
    ap = payload.get("args_preview")
    if isinstance(ap, dict):
        for k in ("command", "path", "file_path", "url"):
            v = ap.get(k)
            if isinstance(v, str) and v.strip():
                candidates.append(v)
                break
    if not candidates:
        return ""
    out = candidates[0].replace("\n", " ").strip()
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out


def _why(payload: dict[str, Any], *, limit: int = 140) -> str:
    for key in ("why", "reason", "risk_reason"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            out = v.replace("\n", " ").strip()
            if len(out) > limit:
                out = out[: limit - 1] + "…"
            return out
    return ""


def compute_summary(
    events: Iterable[dict[str, Any]],
    *,
    since_label: str,
    window: timedelta,
    now: datetime | None = None,
    cwd_filter: str | None = None,
    log_path: Path | None = None,
    top_tools: int = 10,
    top_sessions: int = 5,
    max_pending: int = 25,
) -> SummaryStats:
    """Aggregate filtered audit events into a `SummaryStats` for rendering.

    Pure function: takes already-loaded events plus the window descriptor
    and returns a fully populated stats object. The CLI layer is
    responsible for I/O (log read, console print).
    """
    in_window = filter_events(
        events,
        window=window,
        now=now,
        cwd_filter=cwd_filter,
    )

    high_overnight = 0
    critical_blocked = 0
    low_medium = 0
    asked = 0
    blocked = 0
    sessions: set[str] = set()

    tool_counter: Counter[str] = Counter()
    tool_sample: dict[str, str] = {}
    session_counter: Counter[str] = Counter()
    session_cwd: dict[str, str] = {}
    pending_ask: list[PendingItem] = []
    pending_block: list[PendingItem] = []

    for evt in in_window:
        etype = str(evt.get("type") or "")
        risk = str(evt.get("risk") or "").lower()
        sid = str(evt.get("session_id") or "")
        payload_raw = evt.get("payload")
        payload = payload_raw if isinstance(payload_raw, dict) else {}

        if sid:
            sessions.add(sid)
            # Treat verdict.* rows as "tool calls" for the session-volume
            # column. Plain tool.attempted is the paired half - counting
            # both would double-count, so we stick to verdicts.
            if etype.startswith("verdict.") or etype == OVERNIGHT_EVENT_TYPE:
                session_counter[sid] += 1
                cwd = payload.get("cwd")
                if isinstance(cwd, str) and cwd and sid not in session_cwd:
                    session_cwd[sid] = cwd

        if etype == OVERNIGHT_EVENT_TYPE:
            high_overnight += 1
            tool = str(payload.get("tool_name") or "-")
            tool_counter[tool] += 1
            if tool not in tool_sample:
                tool_sample[tool] = _short_what(payload)
            continue

        if etype in BLOCK_EVENT_TYPES:
            if risk == "critical":
                critical_blocked += 1
            blocked += 1
            if len(pending_block) < max_pending:
                pending_block.append(
                    PendingItem(
                        ts=str(evt.get("ts") or ""),
                        tool=str(payload.get("tool_name") or "-"),
                        what=_short_what(payload),
                        why=_why(payload),
                    )
                )
            continue

        if etype == ASK_EVENT_TYPE:
            asked += 1
            if len(pending_ask) < max_pending:
                pending_ask.append(
                    PendingItem(
                        ts=str(evt.get("ts") or ""),
                        tool=str(payload.get("tool_name") or "-"),
                        what=_short_what(payload),
                        why=_why(payload),
                    )
                )
            continue

        if etype == ALLOWED_PLAIN_EVENT_TYPE:
            if risk in ("low", "medium", "", "info"):
                low_medium += 1
            continue

    by_tool = [
        ToolBreakdown(tool=t, count=n, sample_what=tool_sample.get(t, ""))
        for t, n in tool_counter.most_common(top_tools)
    ]
    by_session = [
        SessionBreakdown(
            session_id=sid,
            tool_calls=n,
            cwd=session_cwd.get(sid, ""),
        )
        for sid, n in session_counter.most_common(top_sessions)
    ]

    generated_at = (
        (now or datetime.now(UTC))
        .astimezone(
            UTC,
        )
        .isoformat()
    )

    return SummaryStats(
        window_seconds=window.total_seconds(),
        since_label=since_label,
        generated_at=generated_at,
        high_overnight_count=high_overnight,
        critical_blocked_count=critical_blocked,
        low_medium_count=low_medium,
        asked_count=asked,
        blocked_count=blocked,
        total_events=len(in_window),
        active_sessions=len(sessions),
        by_tool=by_tool,
        by_session=by_session,
        pending_ask=pending_ask,
        pending_block=pending_block,
        log_path=str(log_path) if log_path else "",
        cwd_filter=str(cwd_filter) if cwd_filter else "",
    )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _md_escape(s: str) -> str:
    """Minimal escaping for Substack-style markdown table cells.

    Pipes break table layout; backslash-escape them. Newlines collapse to
    spaces so each cell stays on one row. Backticks pass through because
    they are useful for inline code in commands.
    """
    if not s:
        return ""
    return s.replace("|", r"\|").replace("\n", " ").strip()


def _short_sid(sid: str) -> str:
    """Truncate session ids so they fit in a table cell without overflow."""
    if not sid:
        return "-"
    if len(sid) <= 14:
        return sid
    return sid[:8] + "…" + sid[-4:]


def _date_only(iso_ts: str) -> str:
    dt = _parse_ts(iso_ts)
    if dt is None:
        return iso_ts[:10] if iso_ts else ""
    return dt.astimezone().strftime("%Y-%m-%d")


def _time_only(iso_ts: str) -> str:
    dt = _parse_ts(iso_ts)
    if dt is None:
        return iso_ts[11:19] if iso_ts else ""
    return dt.astimezone().strftime("%H:%M:%S")


def render_markdown(stats: SummaryStats) -> str:
    """Render a paste-ready markdown report.

    The output is intentionally plain markdown (no rich markup) so it
    pastes cleanly into Substack, a daily note, or a GitHub comment.
    """
    lines: list[str] = []
    date = _date_only(stats.generated_at)
    title = f"# Overnight Recap - {date} (last {stats.since_label})"
    lines.append(title)
    if stats.cwd_filter:
        lines.append(f"_scope: `{stats.cwd_filter}`_")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- HIGH actions auto-approved: **{stats.high_overnight_count:,}**")
    lines.append(f"- CRITICAL actions still blocked: **{stats.critical_blocked_count:,}**")
    lines.append(f"- LOW/MEDIUM actions logged: **{stats.low_medium_count:,}**")
    lines.append(f"- Sessions active: **{stats.active_sessions:,}**")
    if stats.asked_count:
        lines.append(
            f"- HIGH actions that still asked (overnight was off): **{stats.asked_count:,}**",
        )
    lines.append("")

    # Empty-window short-circuit: still produce the file, but make it
    # obvious there was no traffic. Substack-paste-friendly.
    if stats.total_events == 0:
        lines.append("_no events in window_")
        if stats.log_path:
            lines.append("")
            lines.append(f"<sub>log: `{stats.log_path}`</sub>")
        return "\n".join(lines) + "\n"

    lines.append("## By tool name (HIGH auto-approved)")
    if stats.by_tool:
        lines.append("| Tool | Count | Sample command |")
        lines.append("|------|-------|----------------|")
        for t in stats.by_tool:
            lines.append(
                f"| {_md_escape(t.tool)} | {t.count} | {_md_escape(t.sample_what) or '-'} |",
            )
    else:
        lines.append("_(no HIGH actions auto-approved in window)_")
    lines.append("")

    lines.append("## By session (top 5 by event volume)")
    if stats.by_session:
        lines.append("| Session ID | Tool calls | Cwd |")
        lines.append("|------------|------------|-----|")
        for s in stats.by_session:
            lines.append(
                f"| `{_short_sid(s.session_id)}` | {s.tool_calls} | {_md_escape(s.cwd) or '-'} |",
            )
    else:
        lines.append("_(no session activity in window)_")
    lines.append("")

    lines.append("## What still asked you to approve (not auto-approved)")
    if stats.pending_ask:
        for p in stats.pending_ask:
            tstr = _time_only(p.ts)
            lines.append(
                f"- `{tstr}` **{_md_escape(p.tool)}** - "
                f"{_md_escape(p.what) or '-'}" + (f"  _{_md_escape(p.why)}_" if p.why else ""),
            )
    else:
        lines.append("- (empty - good!)")
    lines.append("")

    lines.append("## What got blocked (CRITICAL / scope)")
    if stats.pending_block:
        for p in stats.pending_block:
            tstr = _time_only(p.ts)
            lines.append(
                f"- `{tstr}` **{_md_escape(p.tool)}** - "
                f"{_md_escape(p.what) or '-'}" + (f"  _{_md_escape(p.why)}_" if p.why else ""),
            )
    else:
        lines.append("- (empty - good!)")
    lines.append("")

    if stats.log_path:
        lines.append(f"<sub>log: `{stats.log_path}`</sub>")

    return "\n".join(lines) + "\n"


def render_json(stats: SummaryStats) -> str:
    """Render the stats object as pretty-printed JSON."""
    return json.dumps(stats.to_dict(), indent=2, sort_keys=False)


def render_table(stats: SummaryStats) -> Table:
    """Build a rich.Table view for terminal rendering.

    Returns a single composite Table (header summary + per-tool rows).
    Callers in `cli.py` print this with `Console.print`.
    """
    date = _date_only(stats.generated_at)
    title = f"Overnight Recap - {date} (last {stats.since_label})"
    if stats.cwd_filter:
        title += f" - scope: {stats.cwd_filter}"

    table = Table(
        title=title,
        title_style="bold",
        show_header=True,
        header_style="dim",
        box=None,
        pad_edge=False,
    )
    table.add_column("metric", no_wrap=True, style="bold")
    table.add_column("count", justify="right")
    table.add_column("notes", style="dim")

    table.add_row(
        "HIGH auto-approved",
        f"{stats.high_overnight_count:,}",
        "verdict.allowed.overnight",
    )
    table.add_row(
        "CRITICAL blocked",
        f"{stats.critical_blocked_count:,}",
        "safety invariant held" if stats.critical_blocked_count == 0 else "review immediately",
    )
    table.add_row(
        "LOW/MEDIUM logged",
        f"{stats.low_medium_count:,}",
        "background volume",
    )
    table.add_row(
        "Sessions active",
        f"{stats.active_sessions:,}",
        f"{stats.total_events:,} total events",
    )
    if stats.asked_count:
        table.add_row(
            "HIGH still asked",
            f"{stats.asked_count:,}",
            "overnight was off for these",
        )

    if stats.by_tool:
        table.add_row("", "", "")
        table.add_row("[bold]by tool[/bold]", "", "(HIGH auto-approved)")
        for t in stats.by_tool:
            table.add_row(f"  {t.tool}", f"{t.count:,}", t.sample_what or "-")

    if stats.by_session:
        table.add_row("", "", "")
        table.add_row("[bold]top sessions[/bold]", "", "(by event volume)")
        for s in stats.by_session:
            table.add_row(
                f"  {_short_sid(s.session_id)}",
                f"{s.tool_calls:,}",
                s.cwd or "-",
            )

    if stats.pending_block:
        table.add_row("", "", "")
        table.add_row(
            "[bold red]blocked[/bold red]",
            f"{len(stats.pending_block):,}",
            "needs review",
        )
        for p in stats.pending_block[:5]:
            table.add_row(
                f"  {_time_only(p.ts)} {p.tool}",
                "",
                (p.what or "-")[:60],
            )

    return table
