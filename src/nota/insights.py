"""Nota insights: per-pattern analysis + tunable-recommendation surface.

Where `nota saves` shows aggregate counts ("Nota caught 32 rm -rf attempts"),
`nota insights` drills per-pattern:

  * Which patterns fired, at what risk class
  * Most recent fire of each
  * Suggested action: keep / downgrade candidate / never fired / promote to trust
  * Trust-path effectiveness ranking
  * Sessions worth reviewing (trifecta closes, chain repairs)

Same streaming + window logic as `saves`; reuses the canonicalization map.
Output is designed to be actionable — every row ends with a concrete next
step the user can take (`nota audit show ...`, `nota trust add ...`,
`nota insights demote <pattern>`).

This is the v0.3 surface for the "use the data to make Nota smarter"
promise. No LLM, no inference; pure aggregation over the audit log.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from nota import events as ev
from nota.saves import _in_window, _iter_events, _parse_ts, canonicalize_pattern

# ---------------------------------------------------------------------------
# data model


@dataclass(slots=True)
class PatternStat:
    """Per-canonical-pattern stats over the window."""

    pattern: str
    blocked_count: int = 0
    asked_count: int = 0
    last_fire_ts: str = ""
    sample_session_id: str = ""

    @property
    def total_fires(self) -> int:
        return self.blocked_count + self.asked_count

    @property
    def recommendation(self) -> str:
        """What the operator should do about this pattern.

        Calibrated heuristics, NOT LLM judgement:

        * blocked_count >= 3 AND asked_count == 0  -> "keep critical"
        * asked_count >= 5 AND blocked_count == 0  -> "trust-path candidate"
        * 0 fires (handled at table-building time, not here)
        * total_fires < 3                           -> "watching (low signal)"
        """
        if self.total_fires == 0:
            return "no fires in window"
        if self.blocked_count >= 3 and self.asked_count == 0:
            return "keep critical"
        if self.asked_count >= 5 and self.blocked_count == 0:
            return "trust-path candidate"
        if self.total_fires < 3:
            return "watching (low signal)"
        return "review (mixed signal)"


@dataclass(slots=True)
class TrustPathStat:
    """How much each [trust] paths entry actually saves."""

    path: str
    auto_allows: int = 0


@dataclass(slots=True)
class ReviewableSession:
    """A session flagged for follow-up review."""

    session_id: str
    reason: str  # "trifecta closed", "chain repaired", "critical block at 2am"
    sample_ts: str = ""


@dataclass(slots=True)
class Insights:
    """Per-pattern + per-trust-path + per-session insights report."""

    window_start: datetime
    window_end: datetime
    log_path: str
    events_scanned: int = 0
    events_in_window: int = 0

    pattern_stats: dict[str, PatternStat] = field(default_factory=dict)
    trust_paths: list[TrustPathStat] = field(default_factory=list)
    reviewable_sessions: list[ReviewableSession] = field(default_factory=list)

    @property
    def top_patterns(self) -> list[PatternStat]:
        """Patterns sorted by total_fires desc, then blocked_count desc."""
        return sorted(
            self.pattern_stats.values(),
            key=lambda s: (s.total_fires, s.blocked_count),
            reverse=True,
        )

    @property
    def downgrade_candidates(self) -> list[PatternStat]:
        return [
            s for s in self.pattern_stats.values() if s.recommendation == "trust-path candidate"
        ]

    @property
    def review_sessions(self) -> list[ReviewableSession]:
        return self.reviewable_sessions


# ---------------------------------------------------------------------------
# trust-path extraction


def _extract_trust_path(reason: str) -> str | None:
    """Parse 'trusted scope: Edit in /path/to/repo' -> '/path/to/repo'.

    Returns None for verdict.allowed events that weren't trust-induced.
    """
    if not reason.lower().startswith("trusted scope"):
        return None
    parts = reason.split(" in ", 1)
    if len(parts) < 2:
        return None
    return parts[1].strip().rstrip(".")


# ---------------------------------------------------------------------------
# compute


def compute_insights(
    log_path: Path,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> Insights:
    """Stream audit log into Insights. O(N) over the log."""
    from datetime import UTC

    now = datetime.now(UTC)
    insights = Insights(
        window_start=window_start or datetime.min.replace(tzinfo=UTC),
        window_end=window_end or now,
        log_path=str(log_path),
    )
    trust_counter: Counter[str] = Counter()
    trifecta_sessions: set[str] = set()
    chain_repair_sessions: set[str] = set()
    critical_block_sessions: dict[str, str] = {}  # session_id -> timestamp of first critical

    for event in _iter_events(log_path):
        insights.events_scanned += 1
        ts = _parse_ts(str(event.get("ts") or ""))
        if not _in_window(ts, window_start, window_end):
            continue
        insights.events_in_window += 1

        etype = str(event.get("type") or "")
        payload = event.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        risk = str(event.get("risk") or "")
        reason = str(payload.get("reason") or "")
        ts_raw = str(event.get("ts") or "")
        session_id = str(event.get("session_id") or "")

        if etype == ev.VERDICT_BLOCKED:
            pattern = canonicalize_pattern(reason)
            stat = insights.pattern_stats.setdefault(pattern, PatternStat(pattern=pattern))
            stat.blocked_count += 1
            stat.last_fire_ts = ts_raw
            if not stat.sample_session_id and session_id:
                stat.sample_session_id = session_id[:12]
            if "trifecta" in reason.lower() and session_id:
                trifecta_sessions.add(session_id)
            if risk == "critical" and session_id and session_id not in critical_block_sessions:
                # capture only first critical per session
                critical_block_sessions[session_id] = ts_raw

        elif etype == ev.VERDICT_ASK:
            # Use the tool_name itself as a proxy for the "pattern" since
            # ask events don't carry a specific match-reason.
            tool_name = str(payload.get("tool_name") or "?")
            pattern = f"{tool_name} (default)"
            stat = insights.pattern_stats.setdefault(pattern, PatternStat(pattern=pattern))
            stat.asked_count += 1
            stat.last_fire_ts = ts_raw

        elif etype == ev.VERDICT_ALLOWED:
            tp = _extract_trust_path(reason)
            if tp:
                trust_counter[tp] += 1

        elif etype == ev.CHAIN_REPAIRED and session_id:
            chain_repair_sessions.add(session_id)

    # Materialize trust-path stats sorted by impact desc
    insights.trust_paths = [
        TrustPathStat(path=p, auto_allows=n) for p, n in trust_counter.most_common(20)
    ]

    # Materialize reviewable sessions, deduped + reasoned
    flagged: dict[str, ReviewableSession] = {}
    for sid in trifecta_sessions:
        flagged.setdefault(
            sid,
            ReviewableSession(
                session_id=sid,
                reason="trifecta closed",
            ),
        )
    for sid in chain_repair_sessions:
        if sid in flagged:
            flagged[sid] = ReviewableSession(
                session_id=sid,
                reason=flagged[sid].reason + " + chain repaired",
            )
        else:
            flagged[sid] = ReviewableSession(sid, "chain repaired")
    # also flag sessions with a critical block at 2-4am local (probable tired-eyes catches)
    for sid, ts_str in critical_block_sessions.items():
        ts = _parse_ts(ts_str)
        if ts and 2 <= ts.hour < 5 and sid not in flagged:
            flagged[sid] = ReviewableSession(
                session_id=sid,
                reason=f"critical block at {ts.hour:02d}:{ts.minute:02d}",
                sample_ts=ts_str,
            )

    insights.reviewable_sessions = list(flagged.values())[:10]
    return insights


# ---------------------------------------------------------------------------
# render


def format_insights(insights: Insights, *, plain: bool = False) -> str:
    """Render an Insights report as a human-readable string."""

    def b(text: str) -> str:
        return text if plain else f"[bold]{text}[/bold]"

    def dim(text: str) -> str:
        return text if plain else f"[dim]{text}[/dim]"

    lines: list[str] = []

    w_start = insights.window_start.strftime("%Y-%m-%d")
    w_end = insights.window_end.strftime("%Y-%m-%d")
    lines.append(b("Nota insights") + f"  ({w_start} to {w_end})")
    lines.append(
        dim(
            f"scanned {insights.events_scanned} events; "
            f"{insights.events_in_window} in window; "
            f"{len(insights.pattern_stats)} distinct patterns observed",
        )
    )
    lines.append("")

    if not insights.pattern_stats:
        lines.append(dim("no gated events in window. run an agent session and come back."))
        return "\n".join(lines)

    # Top patterns table. Each row leads with a severity icon based on the
    # block-vs-ask ratio - rows that mostly BLOCKED render red (critical-
    # behaving pattern), rows that mostly ASKED render yellow (ambiguous),
    # rows that resolved cleanly render green. Same ISO 22324 mapping as
    # `nota saves`; the eye should land on the same colors with the same
    # meaning across surfaces.
    from nota.severity import color as _color
    from nota.severity import icon as _icon

    lines.append(b("top patterns by fire frequency:"))
    lines.append(f"  {'':1} {'pattern':<32} {'fires':>5} {'block':>6} {'ask':>5}  recommendation")
    lines.append("  " + "-" * 78)
    for stat in insights.top_patterns[:12]:
        if stat.total_fires == 0:
            sev = "low"
        elif stat.blocked_count >= max(1, stat.total_fires // 2):
            sev = "critical"
        elif stat.asked_count >= max(1, stat.total_fires // 2):
            sev = "high"
        else:
            sev = "ok"
        icn = _icon(sev)  # type: ignore[arg-type]
        if plain:
            row = (
                f"  {icn} {stat.pattern:<32} {stat.total_fires:>5} "
                f"{stat.blocked_count:>6} {stat.asked_count:>5}  {stat.recommendation}"
            )
        else:
            col = _color(sev)  # type: ignore[arg-type]
            row = (
                f"  [{col}]{icn}[/{col}] {stat.pattern:<32} {stat.total_fires:>5} "
                f"{stat.blocked_count:>6} {stat.asked_count:>5}  {stat.recommendation}"
            )
        lines.append(row)
    lines.append("")

    # Trust-path effectiveness
    if insights.trust_paths:
        lines.append(
            b("trust-path effectiveness:")
            + dim(" (auto-allows that would have prompted otherwise)")
        )
        for tp in insights.trust_paths[:10]:
            display = tp.path
            if len(display) > 60:
                display = "…" + display[-58:]
            lines.append(f"  {tp.auto_allows:>5}  {display}")
        lines.append("")

    # Reviewable sessions
    if insights.reviewable_sessions:
        lines.append(b("sessions worth reviewing:"))
        for rs in insights.reviewable_sessions[:5]:
            lines.append(
                f"  {rs.session_id[:12]}…  {rs.reason}",
            )
        lines.append("")

    # Downgrade candidates explicitly called out
    if insights.downgrade_candidates:
        lines.append(b("downgrade candidates:") + dim(" (asked ≥5 times but never blocked)"))
        for s in insights.downgrade_candidates[:5]:
            # escape [bracketed] words so Rich doesn't try to parse them as markup
            trust_label = "[trust]" if plain else r"\[trust]"
            policy_label = "[policy]" if plain else r"\[policy]"
            lines.append(
                f"  {s.pattern}  asked {s.asked_count} times. "
                f"consider adding to {trust_label} paths or {policy_label} override.",
            )
        lines.append("")

    # next-step hints
    lines.append(b("what's next:"))
    lines.append("  nota audit show --type verdict.blocked --last 30   recent blocks")
    if insights.downgrade_candidates:
        lines.append(
            "  nota trust add <path>                              promote a trust-path candidate"
        )
    if insights.reviewable_sessions:
        sid = insights.reviewable_sessions[0].session_id
        lines.append(f"  nota receipts show {sid[:12]}                drill into a flagged session")
    lines.append(
        "  nota audit export --pack                           compliance PDF (SOC 2 / EU AI Act)"
    )
    return "\n".join(lines)
