"""Nota saves: rigorous, audit-log-grounded value accounting.

The "feel good" command of the rigid menu. Aggregates the audit log into
a structured summary that distinguishes **verified counts** (every event
type the log emits) from **estimated savings** (time-saved estimates
that depend on assumptions about human approval latency).

Design principles:

  * **Streaming.** The log can grow to hundreds of MB on heavy users.
    We iterate line-by-line and never materialize the full event list.
  * **Time-window-aware.** `--today`, `--week`, `--month`, `--all`, or
    `--since YYYY-MM-DD`. The window filter is applied in the streaming
    pass; out-of-window events are skipped before any aggregation work.
  * **Explicit provenance.** Every metric in the output is labeled
    with the audit event types it derives from. Estimated values carry
    the assumption inline so the user can challenge it.
  * **Pattern canonicalization.** Blocked-reason free text is normalized
    into a small set of patterns (`rm -rf`, `git push --force`, ...) so
    the "top blocked" table is meaningful instead of a one-line-per-
    raw-string dump.
  * **No LLM.** Pure regex + counting + aggregation. Free OSS forever.

Tested against synthetic fixtures; the live audit-log integration is
exercised in tests/test_saves_live.py with the actual ~/.nota log.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Final

from nota import events as ev

# ---------------------------------------------------------------------------
# pattern canonicalization
#
# The blocked-reason field is free text like "Nota blocked: rm -rf /tmp/foo."
# Real users want to see "rm -rf: 4" in the top-patterns table, not 4 distinct
# raw strings. Each normalizer below is anchored to a published-policy
# pattern in src/nota/policy.py; if you add a new critical pattern there,
# add the canonicalizer here so the saves output stays meaningful.
#
# Order matters: more specific patterns first (so "git push --force" wins
# over a hypothetical generic "git push" rule).

_PATTERN_NORMALIZERS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"\bsecret detected\b", re.IGNORECASE), "secret in write"),
    (re.compile(r"\btrifecta\b", re.IGNORECASE), "trifecta close"),
    (
        re.compile(r"\bCVE-2025-59536\b|\bsubcommand[- ]chain\b", re.IGNORECASE),
        "subcommand-chain bypass",
    ),
    (re.compile(r"\btool[- ]?poisoning\b|\bpin[- ]?refused\b", re.IGNORECASE), "tool-pin refused"),
    (re.compile(r"\brm\s+-rf?\b", re.IGNORECASE), "rm -rf"),
    (re.compile(r"\bgit\s+push\s+--force\b", re.IGNORECASE), "git push --force"),
    (re.compile(r"\bforce[- ]?push\b", re.IGNORECASE), "git push --force"),
    (re.compile(r"\bDROP\s+TABLE\b|\bTRUNCATE\b", re.IGNORECASE), "DROP TABLE / TRUNCATE"),
    (re.compile(r"\bvercel\s+--prod\b", re.IGNORECASE), "vercel --prod"),
    (re.compile(r"\bnpm\s+publish\b", re.IGNORECASE), "npm publish"),
    (re.compile(r"\bterraform\s+destroy\b", re.IGNORECASE), "terraform destroy"),
    (re.compile(r"\bsudo\b", re.IGNORECASE), "sudo"),
    (re.compile(r"\.env\b", re.IGNORECASE), ".env read"),
    (re.compile(r"\bcurl\s*\|\s*sh\b", re.IGNORECASE), "curl | sh"),
    (re.compile(r"\bdeploy.*\b(prod|production)\b", re.IGNORECASE), "deploy:production"),
    (
        re.compile(r"\bstripe\.\w*(refund|charge|transfer|payout)\b", re.IGNORECASE),
        "stripe payment mutation",
    ),
    (re.compile(r"\bbanking\.\w*send_money\b", re.IGNORECASE), "banking send-money"),
)


def canonicalize_pattern(reason: str) -> str:
    """Map a free-text block reason to a canonical pattern label.

    Returns "other (<truncated reason>)" when no normalizer matches, so the
    top-patterns table doesn't silently bury matches under "other."
    """
    if not reason:
        return "other"
    for rex, label in _PATTERN_NORMALIZERS:
        if rex.search(reason):
            return label
    truncated = reason.strip().split(".")[0][:50]
    return f"other ({truncated})"


# ---------------------------------------------------------------------------
# data model


@dataclass(slots=True)
class Saves:
    """Aggregated saves report. Every field carries its provenance.

    Verified fields (✓) are direct counts of audit event types. Estimated
    fields (≈) compute time-saved from verified counts using documented
    assumptions exposed below as class constants.
    """

    # window metadata
    window_start: datetime
    window_end: datetime
    log_path: str
    events_scanned: int = 0
    events_in_window: int = 0

    # ✓ verified counts
    trust_auto_allows: int = 0  # verdict.allowed with reason ~ "trusted scope"
    critical_blocks: int = 0  # verdict.blocked at risk=critical
    high_blocks: int = 0  # verdict.blocked at risk=high
    secrets_caught: int = 0  # verdict.blocked with reason ~ "secret detected"
    biometric_approvals: int = 0  # approve.biometric.ok
    biometric_denials: int = 0  # approve.biometric.deny
    pin_refusals: int = 0  # tool.pin_refused
    trifecta_enforcements: int = 0  # verdict.blocked with reason ~ "trifecta"
    scope_violations: int = 0  # verdict.scope_violation
    ask_prompts: int = 0  # verdict.ask (informational)
    chain_repairs: int = 0  # chain.repaired

    # pattern aggregations
    top_patterns: Counter[str] = field(default_factory=Counter)
    biggest_catch: dict[str, Any] | None = None  # earliest critical block in window

    # session metrics
    sessions_seen: int = 0  # distinct session_ids in window

    # ≈ estimated time-saved assumptions (configurable via class methods if needed)
    CLICK_LATENCY_LOWER_S: ClassVar[float] = 2.5
    CLICK_LATENCY_UPPER_S: ClassVar[float] = 5.0

    @property
    def total_blocks(self) -> int:
        return self.critical_blocks + self.high_blocks

    @property
    def time_saved_minutes_lower(self) -> float:
        return (self.trust_auto_allows * self.CLICK_LATENCY_LOWER_S) / 60.0

    @property
    def time_saved_minutes_upper(self) -> float:
        return (self.trust_auto_allows * self.CLICK_LATENCY_UPPER_S) / 60.0


# ---------------------------------------------------------------------------
# log streaming + classification


def _parse_ts(raw: str) -> datetime | None:
    """Parse an ISO-8601 ts from an audit event. Returns None on malformed."""
    if not raw:
        return None
    try:
        # The audit log writes ISO-8601 with timezone offset; fromisoformat
        # handles both `Z` and `+00:00` since Python 3.11.
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _iter_events(log_path: Path) -> Iterator[dict[str, Any]]:
    """Yield audit events one at a time. Malformed JSON lines are skipped
    silently; the chain has its own integrity check via `nota audit verify`,
    so we don't double-validate here."""
    if not log_path.exists():
        return
    with log_path.open() as f:
        for raw_line in f:
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _in_window(
    ts: datetime | None,
    start: datetime | None,
    end: datetime | None,
) -> bool:
    """Inclusive on both ends. None bounds mean unbounded."""
    if ts is None:
        return False
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


def _classify(event: dict[str, Any], saves: Saves, session_ids: set[str]) -> None:
    """Update saves in place based on one audit event. O(1) per event."""
    etype = str(event.get("type") or "")
    payload = event.get("payload") or {}
    if not isinstance(payload, Mapping):
        payload = {}
    risk = str(event.get("risk") or "")
    reason = str(payload.get("reason") or "")
    ts_raw = str(event.get("ts") or "")

    session_id = str(event.get("session_id") or "")
    if session_id:
        session_ids.add(session_id)

    if etype == ev.VERDICT_ALLOWED:
        # Trust-scope-induced auto-allows are signaled by the reason text
        # `trusted scope: <tool> in <cwd>` (see adapters/claude_code.py).
        if reason.lower().startswith("trusted scope"):
            saves.trust_auto_allows += 1

    elif etype == ev.VERDICT_BLOCKED:
        if risk == "critical":
            saves.critical_blocks += 1
        elif risk == "high":
            saves.high_blocks += 1
        # secrets escalate to CRITICAL with reason "secret detected in write..."
        if "secret detected" in reason.lower():
            saves.secrets_caught += 1
        if "trifecta" in reason.lower():
            saves.trifecta_enforcements += 1
        # pattern aggregation: only critical blocks count, otherwise the
        # top-patterns table is dominated by routine high-risk asks.
        if risk == "critical":
            saves.top_patterns[canonicalize_pattern(reason)] += 1
            if saves.biggest_catch is None:
                saves.biggest_catch = {
                    "ts": ts_raw,
                    "tool_name": str(payload.get("tool_name") or "?"),
                    "reason": reason,
                    "session_id": session_id[:12],
                }

    elif etype == ev.VERDICT_ASK:
        saves.ask_prompts += 1

    elif etype == ev.VERDICT_SCOPE_VIOLATION:
        saves.scope_violations += 1

    elif etype == ev.APPROVE_BIOMETRIC_OK:
        saves.biometric_approvals += 1

    elif etype == ev.APPROVE_BIOMETRIC_DENY:
        saves.biometric_denials += 1

    elif etype == "tool.pin_refused":
        # Not in the ev module yet; reference by literal string. Adding
        # to events.py is a separate cleanup task.
        saves.pin_refusals += 1

    elif etype == ev.CHAIN_REPAIRED:
        saves.chain_repairs += 1


# ---------------------------------------------------------------------------
# public entry points


def compute_saves(
    log_path: Path,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> Saves:
    """Stream the audit log, classify every event, return aggregated Saves.

    `window_start` and `window_end` are inclusive datetime bounds. Either
    may be None to mean unbounded on that side; passing None for both
    aggregates the whole log.

    O(N) over the log, O(K) memory where K is distinct (pattern, session)
    pairs. Tested against a synthetic fixture in tests/test_saves.py;
    a separate live test exercises the real log shape.
    """
    now = datetime.now(UTC)
    saves = Saves(
        window_start=window_start or datetime.min.replace(tzinfo=UTC),
        window_end=window_end or now,
        log_path=str(log_path),
    )
    session_ids: set[str] = set()

    for event in _iter_events(log_path):
        saves.events_scanned += 1
        ts = _parse_ts(str(event.get("ts") or ""))
        if not _in_window(ts, window_start, window_end):
            continue
        saves.events_in_window += 1
        _classify(event, saves, session_ids)

    saves.sessions_seen = len(session_ids)
    return saves


def parse_window(
    *,
    today: bool = False,
    week: bool = False,
    month: bool = False,
    all_time: bool = False,
    since: str | None = None,
    now: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    """Resolve user-supplied window flags into (start, end) datetime bounds.

    Mutual-exclusion is enforced at the CLI layer; this function trusts
    its caller and returns the first matching window.
    """
    now = now or datetime.now(UTC)
    if all_time:
        return None, None
    if since:
        try:
            start = datetime.fromisoformat(since)
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            return start, now
        except ValueError:
            return None, None
    if today:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now
    if month:
        return now - timedelta(days=30), now
    # default: week
    return now - timedelta(days=7), now


# ---------------------------------------------------------------------------
# render


def format_saves(saves: Saves, *, plain: bool = False) -> str:
    """Render a Saves report as a human-readable string.

    `plain=True` strips Rich markup for piping or CI output.
    """

    def b(text: str) -> str:
        return text if plain else f"[bold]{text}[/bold]"

    def dim(text: str) -> str:
        return text if plain else f"[dim]{text}[/dim]"

    lines: list[str] = []

    # header
    w_start = saves.window_start.strftime("%Y-%m-%d")
    w_end = saves.window_end.strftime("%Y-%m-%d")
    lines.append(b("Nota saves report") + f"  ({w_start} to {w_end})")
    lines.append(
        dim(
            f"scanned {saves.events_scanned} events; {saves.events_in_window} "
            f"in window; {saves.sessions_seen} session(s)",
        )
    )
    lines.append("")

    # verified counts - ISO 22324 / NIST-aligned color treatment + icons.
    # Color carries severity at a glance; icon + text label survive
    # NO_COLOR / screen-reader paths. Bright safety classes (critical,
    # secret, trifecta, pin_refusal) all render red so the eye snaps to
    # them first; trust-path auto-allows render green because they're
    # the "Nota saved you a click" outcome.
    from nota.severity import stat_line as _sl

    lines.append(b("verified from your audit log:"))
    lines.append(
        _sl(
            "ok",
            saves.trust_auto_allows,
            "auto-allows inside trusted scope (would have prompted otherwise)",
            plain=plain,
        )
    )
    lines.append(
        _sl("critical", saves.critical_blocks, "critical-risk operations blocked", plain=plain)
    )
    lines.append(
        _sl("secret", saves.secrets_caught, "hardcoded secrets caught before write", plain=plain)
    )
    lines.append(_sl("ok", saves.biometric_approvals, "Touch ID approvals consumed", plain=plain))
    lines.append(_sl("high", saves.biometric_denials, "Touch ID approvals denied", plain=plain))
    lines.append(
        _sl("pin_refusal", saves.pin_refusals, "tool-description rug-pulls refused", plain=plain)
    )
    lines.append(
        _sl(
            "trifecta",
            saves.trifecta_enforcements,
            "lethal-trifecta sessions escalated to deny",
            plain=plain,
        )
    )
    lines.append(_sl("high", saves.scope_violations, "out-of-scope calls refused", plain=plain))
    lines.append(_sl("chain", saves.chain_repairs, "chain integrity events recorded", plain=plain))
    lines.append("")

    # estimated savings
    if saves.trust_auto_allows > 0:
        lower = saves.time_saved_minutes_lower
        upper = saves.time_saved_minutes_upper
        lines.append(b("estimated time saved:"))
        lines.append(
            f"  {lower:.1f} - {upper:.1f} minutes of approval-click latency",
        )
        lines.append(
            dim(
                f"  assumption: {Saves.CLICK_LATENCY_LOWER_S}-{Saves.CLICK_LATENCY_UPPER_S}s per y/N prompt "
                f"({saves.trust_auto_allows} auto-allows)",
            )
        )
        lines.append("")

    # top patterns
    if saves.top_patterns:
        lines.append(b("top patterns blocked:"))
        for pattern, count in saves.top_patterns.most_common(7):
            lines.append(f"  {count:>4}  {pattern}")
        lines.append("")

    # biggest catch
    if saves.biggest_catch:
        bc = saves.biggest_catch
        lines.append(b("first catch in window:"))
        lines.append(f"  {bc['ts']}")
        lines.append(f"  tool: {bc['tool_name']}")
        lines.append(f"  why : {bc['reason'][:120]}")
        if bc.get("session_id"):
            lines.append(dim(f"  session: {bc['session_id']}..."))
        lines.append("")

    # hints
    lines.append(b("what's next:"))
    if saves.events_in_window == 0:
        lines.append(
            "  run an agent session and come back; nothing in window yet",
        )
    else:
        lines.append("  nota insights        top patterns + suggested overrides")
        lines.append("  nota audit show      pretty-print recent events")
        lines.append("  nota audit export --pack    SOC 2 / EU AI Act PDF")
        if saves.biometric_approvals > 0:
            lines.append("  nota receipts show <session>    drill into a specific session")

    return "\n".join(lines)
