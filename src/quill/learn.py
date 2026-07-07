"""Self-improvement engine.

Reads the audit log and surfaces actionable suggestions back to the
operator. The operator decides whether to apply them. Quill never
auto-applies learning to its own gate config because a security gate
that quietly loosens itself is a category mistake.

Suggestion classes:
  1. Trust-scope candidates - directories where the operator has been
     accumulating default-risk Edit/Write asks without producing any
     real blocks. These are the 991-asks-per-week problem; promoting
     the directory to `[trust] paths` removes the noise.
  2. Decayed permissions - permissions tracked by `decay.py` whose
     window has elapsed. Surfaces a reaffirm / forget decision.
  3. False-positive overrides - patterns whose blocks the operator has
     repeatedly bypassed via `quill approve`. Suggests adding a
     per-tool policy override in config.
  4. Heavy bash patterns - bash command shapes that fire the same
     classifier rule 20+ times in a week. Surfaces a candidate for
     allowlisting via `[bash] allowlist` or a config tighten.
  5. Silent failures - last-N session journals all stub-shaped (0
     turns). The bug class that hid for 3 weeks in May 2026.

The audit log is the source of truth; everything in this module is a
pure derivation over it. No state of its own.

KPIs (`quill kpis`) — three signals that genuinely measure whether
the gate is healthy and useful, NOT how quiet it is:

  1. Noise ratio = asks / max(real_blocks, 1)
     "How many friction prompts the operator paid per real catch."
     The 991/84 = ~12 problem this metric is designed to surface.
     Healthy < 5. Broken > 20.

  2. Override rate, per pattern
     = approved_one_shot / blocks_of_this_pattern
     "When the gate blocked this pattern, how often did the operator
     bypass it." High = misclassified for the operator's context
     (false-positive class). Low = pattern is doing its job.

  3. Trifecta closures
     = absolute count of `session.taint.update` events where
     `trifecta_closed == true`.
     Each one is a real exposure event. Normally 0. Non-zero deserves
     a postmortem; this is the metric that should drive deep work.

Deliberately NOT included: TDR / Intervention Rate / Time-to-Trust.
Those reward a quieter gate (approving everything scores 1.0) which
is the wrong optimisation direction for a safety tool.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from quill import events as ev
from quill.config import default_audit_path

# Thresholds, kept low enough that suggestions appear after a handful
# of days of dogfooding rather than asking the operator to wait a month.
TRUST_SCOPE_MIN_ASKS = 20
TRUST_SCOPE_MIN_DAYS_SPAN = 0  # any time-span counts; volume is what matters
HEAVY_BASH_MIN_HITS = 20
FALSE_POSITIVE_MIN_OVERRIDES = 3


@dataclass(slots=True, frozen=True)
class Suggestion:
    """One actionable recommendation derived from the audit log."""

    severity: str  # "high" | "medium" | "low"
    category: str  # see SuggestionCategory below
    title: str
    rationale: str
    paste_command: str  # operator copy-pastes this to apply
    evidence: tuple[str, ...] = ()


class SuggestionCategory:
    TRUST_SCOPE = "trust_scope"
    DECAYED_PERMISSION = "decayed_permission"
    FALSE_POSITIVE_OVERRIDE = "false_positive_override"
    HEAVY_BASH_PATTERN = "heavy_bash_pattern"
    SILENT_FAILURE = "silent_failure"


@dataclass(slots=True)
class KPIReport:
    """The KPIs that genuinely tell you whether the gate is healthy.

    Designed against the actual shape of your audit log (5500+ events
    as of v0.2.0a1-rc3). Each metric maps to something the data can
    answer concretely; no framework name-drops without data behind them.

    `noise_ratio` is the headline number. The other two are absolute
    incident counters (lower is better; zero is normal).
    """

    window_days: int
    n_events: int
    n_asks: int
    n_blocks: int
    n_allowed: int
    n_taint_closures: int
    n_cascade_events: int
    top_blocked_patterns: list[tuple[str, int]] = field(default_factory=list)
    n_overrides: int = 0  # operator-bypasses via quill approve

    @property
    def noise_ratio(self) -> float:
        """Asks per real block. The 991/84 problem. Under 5 is healthy.
        Over 20 is a sign the gate is training approve-fatigue."""
        if self.n_blocks <= 0:
            # Floor of 1 so a brand-new install (zero blocks) doesn't
            # divide-by-zero. Once any block fires the real ratio applies.
            return float(self.n_asks)
        return self.n_asks / self.n_blocks

    @property
    def health(self) -> str:
        """One-word verdict on the gate's friction load."""
        r = self.noise_ratio
        if r < 5:
            return "healthy"
        if r < 20:
            return "loud"
        return "broken"


def _normalize_block_reason(reason: str) -> str:
    """Collapse the many historical formats of a verdict.blocked reason
    string to a stable pattern key. Without this, the same underlying
    rule (rm -rf) shows up as 4+ distinct top-pattern rows because old
    classifier versions emitted longer suffixes ("Quill blocked: rm
    -rf. To allow, lower the risk..." vs "rm -rf").

    Returns the bare classifier head ("rm -rf", "vercel --prod",
    "DROP TABLE/DATABASE/SCHEMA", "TRUNCATE TABLE", etc.).
    """
    if not reason:
        return ""
    s = reason
    # Old format prefix
    if s.startswith("Quill blocked: "):
        s = s[len("Quill blocked: ") :]
    # Drop the suggestion tail in every known format variant.
    for sep in (" · try", " - try", ".  ↪ try", " ↪ try", ". To allow", " · ", " - "):
        idx = s.find(sep)
        if idx >= 0:
            s = s[:idx]
            break
    return s.strip().rstrip(".").strip()


def _iter_audit_events(path: Path | None = None) -> Iterable[dict[str, Any]]:
    p = path or default_audit_path()
    if not p.exists():
        return
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def _parse_ts(ts: object) -> datetime | None:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _in_window(evt: Mapping[str, Any], since: datetime | None) -> bool:
    if since is None:
        return True
    t = _parse_ts(evt.get("ts"))
    return t is not None and t >= since


def analyze_trust_scope_candidates(
    events: list[dict[str, Any]],
) -> list[Suggestion]:
    """Find cwds with high default-Edit/Write ask volume + no real
    blocks. Each one is a trust-scope candidate."""
    asks_by_cwd: dict[str, int] = {}
    blocks_by_cwd: dict[str, int] = {}
    for e in events:
        etype = e.get("type")
        payload = e.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        cwd = str(payload.get("cwd") or "").strip()
        if not cwd or cwd in ("/", "/tmp"):
            continue
        reason = str(payload.get("reason") or "")
        tool_name = str(payload.get("tool_name") or "")
        if etype == ev.VERDICT_ASK and "default risk for" in reason:
            if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
                asks_by_cwd[cwd] = asks_by_cwd.get(cwd, 0) + 1
        elif etype == ev.VERDICT_BLOCKED:
            blocks_by_cwd[cwd] = blocks_by_cwd.get(cwd, 0) + 1

    out: list[Suggestion] = []
    for cwd, n in sorted(asks_by_cwd.items(), key=lambda kv: -kv[1]):
        if n < TRUST_SCOPE_MIN_ASKS:
            continue
        # A directory with >=20 asks AND many real blocks is NOT a trust
        # candidate; pattern-matched blocks are doing their job.
        # We tolerate small block counts (operator might have tried
        # one bad command once).
        n_blocks = blocks_by_cwd.get(cwd, 0)
        if n_blocks > n // 4:
            continue
        out.append(
            Suggestion(
                severity="high" if n >= 100 else "medium",
                category=SuggestionCategory.TRUST_SCOPE,
                title=f"trust {cwd}",
                rationale=(
                    f"{n} default-risk Edit/Write asks in this directory; "
                    f"{n_blocks} real blocks. The asks are noise that train "
                    f"approve-fatigue. Promoting the directory to a trust "
                    f"scope removes the noise without changing block coverage."
                ),
                paste_command=f"quill trust add {cwd}",
                evidence=(
                    f"asks={n}",
                    f"blocks={n_blocks}",
                ),
            )
        )
    return out


def analyze_decayed_permissions() -> list[Suggestion]:
    """Surface decayed permissions tracked by decay.py."""
    out: list[Suggestion] = []
    try:
        from quill import decay as _decay

        store = _decay.DecayStore.load()
    except Exception:
        return out
    for perm in store.decayed():
        out.append(
            Suggestion(
                severity="medium",
                category=SuggestionCategory.DECAYED_PERMISSION,
                title=f"decayed: {perm.pattern}",
                rationale=(
                    f"Permission '{perm.pattern}' has not been used in "
                    f"{perm.age_days} days (window was {perm.decay_after_days}). "
                    f"Reaffirm it if you still need it, or forget it so the "
                    f"default classifier fires next time."
                ),
                paste_command=f"quill decay reaffirm {perm.pattern}",
                evidence=(f"kind={perm.kind}", f"age_days={perm.age_days}"),
            )
        )
    return out


def analyze_false_positive_overrides(
    events: list[dict[str, Any]],
) -> list[Suggestion]:
    """Find (tool_name, classifier_reason) shapes the operator has
    bypassed >=3 times via one-shot approvals. Repeat overrides on the
    same shape mean either the classifier is wrong about this thing or
    the operator wants a config override.
    """
    # Tally: per (tool_name, reason), how many times verdict.blocked
    # had a non-empty approve_token, indicating user-approved bypass.
    overrides: dict[tuple[str, str], int] = {}
    for e in events:
        if e.get("type") != ev.VERDICT_BLOCKED:
            continue
        payload = e.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        # An issued + consumed approve token shows up later as a verdict
        # being flipped to "allowed" via approve consume. Cheap proxy:
        # look for verdict.allowed with reason starting "approved one-shot".
        # We approximate by counting allows that reference the token.
        # (Full pairing would require event_mac threading; defer.)
        continue
    # First-pass approximation via verdict.allowed reasons:
    for e in events:
        if e.get("type") != ev.VERDICT_ALLOWED:
            continue
        payload = e.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        reason = str(payload.get("reason") or "")
        if not reason.startswith("approved one-shot"):
            continue
        tool_name = str(payload.get("tool_name") or "")
        # Strip the token suffix so similar bypasses collapse together.
        # reason ends with "via quill approve <token-prefix>"; the
        # classifier-original reason isn't carried here, so we group
        # by tool_name alone for the override suggestion.
        key = (tool_name, "operator-bypass")
        overrides[key] = overrides.get(key, 0) + 1

    out: list[Suggestion] = []
    for (tool_name, _), n in sorted(overrides.items(), key=lambda kv: -kv[1]):
        if n < FALSE_POSITIVE_MIN_OVERRIDES:
            continue
        out.append(
            Suggestion(
                severity="medium",
                category=SuggestionCategory.FALSE_POSITIVE_OVERRIDE,
                title=f"repeat bypass: {tool_name}",
                rationale=(
                    f"The gate blocked {tool_name} and the operator approved "
                    f"it via `quill approve` {n} times. Repeated overrides "
                    f"on the same tool either mean the classification is "
                    f"wrong for your context, or this tool is broadly safe "
                    f"in your setup. Consider a per-tool policy override."
                ),
                paste_command=(
                    f'edit ~/.quill/config.toml and set: [policy]\n  "{tool_name}" = "medium"'
                ),
                evidence=(f"overrides={n}",),
            )
        )
    return out


def analyze_heavy_bash_patterns(
    events: list[dict[str, Any]],
) -> list[Suggestion]:
    """Find classifier rules that fire on bash commands 20+ times.
    Heavy-pattern hits aren't necessarily wrong but they're candidates
    for a `[bash] allowlist` entry if the operator has decided the
    pattern is fine in this environment.
    """
    pattern_hits: dict[str, int] = {}
    for e in events:
        etype = e.get("type")
        if etype not in (ev.VERDICT_BLOCKED, ev.VERDICT_ASK):
            continue
        payload = e.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        tool_name = str(payload.get("tool_name") or "")
        if tool_name != "Bash":
            continue
        reason = str(payload.get("reason") or "")
        # Strip the " - try instead: ..." tail so the same shape groups.
        head = reason.split("·", 1)[0].split(" - try", 1)[0].strip()
        if not head:
            continue
        pattern_hits[head] = pattern_hits.get(head, 0) + 1

    out: list[Suggestion] = []
    for head, n in sorted(pattern_hits.items(), key=lambda kv: -kv[1]):
        if n < HEAVY_BASH_MIN_HITS:
            continue
        out.append(
            Suggestion(
                severity="low",
                category=SuggestionCategory.HEAVY_BASH_PATTERN,
                title=f"heavy bash pattern: {head}",
                rationale=(
                    f"`{head}` fired {n} times this window. If the pattern "
                    f"is genuinely safe in your environment, allowlist it "
                    f"so the gate stops surfacing it. If it's not, leave "
                    f"it - the frequency is the alarm working."
                ),
                paste_command=(
                    f"edit ~/.quill/config.toml and add: "
                    f'[bash]\n  allowlist = ["<regex matching {head}>"]'
                ),
                evidence=(f"hits={n}",),
            )
        )
    return out


def analyze_silent_failures(
    sessions_dir: Path | None = None,
) -> list[Suggestion]:
    """Surface silent-failure footprints: last 10 auto-generated session
    journals all reporting 0 turns means the hook is firing but the
    parser is broken. This is the exact bug class that hid for 3 weeks
    in May 2026.
    """
    out: list[Suggestion] = []
    p = sessions_dir or (Path.home() / "agentbrain" / "AgentOS-Vault" / "ClaudeCode" / "Sessions")
    if not p.exists():
        return out
    journals = sorted(p.glob("*.md"), key=lambda f: f.stat().st_mtime, reverse=True)[:10]
    zero_turn = 0
    for j in journals:
        try:
            text = j.read_text()
        except OSError:
            continue
        if "user turns: 0" in text and "assistant turns: 0" in text:
            zero_turn += 1
    if zero_turn >= 5:
        out.append(
            Suggestion(
                severity="high",
                category=SuggestionCategory.SILENT_FAILURE,
                title=f"{zero_turn} of last 10 journals are stub-shaped (0 turns)",
                rationale=(
                    "Auto-journal hook is firing but recording zero activity. "
                    "Likely cause: a transcript-schema mismatch (the bug "
                    "that hid for 3 weeks in May 2026). Inspect "
                    "src/quill/journal.py:summarize_transcript and confirm "
                    "it handles the current Claude Code transcript shape."
                ),
                paste_command="python -m pytest tests/test_journal.py -v",
                evidence=(f"zero_turn_journals={zero_turn}/10",),
            )
        )
    return out


def derive_kpis(
    events: list[dict[str, Any]],
    window_days: int = 7,
) -> KPIReport:
    """Fold events into the three KPIs that genuinely measure gate health.

    See the KPIReport docstring for what each one means and why it was
    picked. Override rate is reported as a count, not a ratio, because
    the data is too sparse to make ratios meaningful yet (most logs
    have a handful of operator-bypasses lifetime).
    """
    n_asks = 0
    n_blocks = 0
    n_allowed = 0
    n_closures = 0
    n_cascades = 0
    n_overrides = 0
    pattern_hits: dict[str, int] = {}
    for e in events:
        et = e.get("type")
        payload = e.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        if et == ev.VERDICT_ASK:
            n_asks += 1
        elif et == ev.VERDICT_BLOCKED:
            n_blocks += 1
            reason = str(payload.get("reason") or "")
            head = _normalize_block_reason(reason)
            if head:
                pattern_hits[head] = pattern_hits.get(head, 0) + 1
        elif et == ev.VERDICT_ALLOWED:
            n_allowed += 1
            reason = str(payload.get("reason") or "")
            if reason.startswith("approved one-shot"):
                n_overrides += 1
        elif et == ev.SESSION_TAINT_UPDATE:
            tri = payload.get("trifecta") or {}
            if isinstance(tri, Mapping) and all(tri.values()):
                n_closures += 1
        elif et == ev.AGENT_CASCADE_AFFECTED:
            n_cascades += 1

    top = sorted(pattern_hits.items(), key=lambda kv: -kv[1])[:8]

    return KPIReport(
        window_days=window_days,
        n_events=len(events),
        n_asks=n_asks,
        n_blocks=n_blocks,
        n_allowed=n_allowed,
        n_taint_closures=n_closures,
        n_cascade_events=n_cascades,
        top_blocked_patterns=top,
        n_overrides=n_overrides,
    )


def analyze(
    path: Path | None = None,
    since_days: int = 7,
) -> tuple[list[Suggestion], KPIReport]:
    """Top-level entry: read audit log, return (suggestions, kpis).

    `since_days=0` means full history; otherwise restrict to the last
    N days. Suggestions are returned sorted by severity then by
    evidence-strength.
    """
    since: datetime | None = None
    if since_days > 0:
        since = datetime.now(UTC) - timedelta(days=since_days)

    events = [e for e in _iter_audit_events(path) if _in_window(e, since)]

    suggestions: list[Suggestion] = []
    suggestions.extend(analyze_trust_scope_candidates(events))
    suggestions.extend(analyze_decayed_permissions())
    suggestions.extend(analyze_false_positive_overrides(events))
    suggestions.extend(analyze_heavy_bash_patterns(events))
    suggestions.extend(analyze_silent_failures())

    sev_order = {"high": 0, "medium": 1, "low": 2}
    suggestions.sort(key=lambda s: (sev_order.get(s.severity, 99), -len(s.evidence)))

    kpis = derive_kpis(events, window_days=since_days)
    return suggestions, kpis
