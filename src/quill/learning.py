"""Autonomous learning loop. Quill reads its own audit data and updates
its behaviour, within safety bounds.

Design constraints from the internal autonomous-learning design notes.
The non-negotiable architectural rules:

  1. Auto-tightening (block more) auto-applies. Auto-loosening (allow
     more) NEVER auto-applies; it surfaces as a suggestion the operator
     must promote explicitly. A security gate that quietly opens
     itself is a category mistake (CrowdStrike July 2024 is the worked
     example of why staged-rollout-with-rollback is non-negotiable).
  2. The hot path (`adapters/claude_code.py:run_hook`) stays
     deterministic. Same input + same on-disk state -> same output.
     This module is called POST-decision so a learning failure cannot
     fail-open or fail-closed the gate.
  3. Updates are persisted via atomic tmp-rename so an interrupted
     write cannot leave a corrupted pattern_stats.json.
  4. Every update appends a timestamped line to ~/.quill/learning.log
     so the operator can tail it and see exactly what changed.

The math is:

  - Beta-binomial conjugate update per pattern. Prior Beta(9, 1)
    encodes "default to 10% baseline approval; require real evidence
    to move." After N fires with K approvals, the posterior is
    Beta(9 + K, 1 + N - K).
  - Wilson 95% interval on the binomial proportion. Beats the normal
    approximation at small N. The lower bound drives loosen-candidate
    surfacing; the upper bound drives auto-tighten.
  - EWMA(0.1) on approval rate. Tracks recent behaviour so a pattern
    that's been auto-approved 100x but suddenly starts getting denied
    shows up before the posterior catches up.

Production exemplar: Falco's auto-tuner. Suggests exceptions daily;
human keeps or discards. https://www.sysdig.com/blog/falco-rule-tuning
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import time
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Constants - tunable but with defensible defaults from the research doc.
# Changes here SHOULD be versioned in git and discussed; arbitrary tuning
# during runtime is what produced the alert-fatigue problem in the first
# place.

PRIOR_ALPHA: float = 1.0  # prior "approvals" (operator-bypasses of blocks)
PRIOR_BETA: float = 9.0  # prior "denies" (block stood)
# Prior mean = alpha / (alpha + beta) = 1 / 10 = 0.10. This encodes
# "by default, the operator approves 10% of blocked attempts; the
# other 90% the block stands." A high approval rate is what surfaces
# a pattern as a loosening candidate. The research doc had this flipped
# (Beta(9, 1) was annotated "10%" but gives 0.9); we encode the meaning,
# not the label.
EWMA_ALPHA: float = 0.1  # recency weight; 10 obs to half-decay

# Auto-tightening triggers (safe - never widens attack surface).
TIGHTEN_DENY_STREAK: int = 5  # 5 consecutive denies -> elevate
TIGHTEN_WILSON_UPPER: float = 0.05  # 95% upper on approval < 5% means
# denials dominate -> upgrade pattern

# Loosen-candidate triggers (surfaced only, NEVER auto-applied).
LOOSEN_WILSON_LOWER: float = 0.65  # 95% lower on approval > 65% means
# approvals dominate -> review
LOOSEN_MIN_FIRES: int = 20  # don't suggest below 20 fires

# Operator-anomaly thresholds (rate-based, no autoencoder).
FATIGUE_INTER_ARRIVAL_SEC: float = 2.0
FATIGUE_STREAK_LEN: int = 20

# Auto-promote ("in-flow approval") thresholds. Simpler/stricter than
# detect_loosen_candidate: a small absolute approval count with NO recent
# denies, all within a recent window. This fires the in-flow promotion
# prompt the moment the threshold is crossed - the operator gets one
# chance to confirm without having to run `quill suggestions promote`.
#
# Why these numbers (NOT statutory; product judgement):
#   - 5 approvals: low enough to feel responsive, high enough to filter
#     noise. Below 5 there's not enough signal to claim a pattern.
#   - 7 days: matches the typical "I came back to my codebase" cycle.
#     A pattern approved 5x in a week is part of the working rhythm.
#   - 0 denies in window: any deny resets the timer. If the operator
#     EVER said "no" to this pattern lately, we don't suggest promotion.
AUTOPROMOTE_MIN_APPROVALS: int = 5
AUTOPROMOTE_WINDOW_SEC: float = 7 * 86400.0
AUTOPROMOTE_MAX_DENIES_IN_WINDOW: int = 0
COMPROMISE_BURST_PER_5MIN: int = 50  # 50 approvals in 5 min = suspect


# ---------------------------------------------------------------------------
# Paths. All env-overridable for test isolation.


def _stats_path() -> Path:
    return Path(
        os.environ.get(
            "QUILL_PATTERN_STATS",
            str(Path.home() / ".quill" / "pattern_stats.json"),
        )
    ).expanduser()


def _suggestions_path() -> Path:
    return Path(
        os.environ.get(
            "QUILL_SUGGESTIONS",
            str(Path.home() / ".quill" / "suggestions.jsonl"),
        )
    ).expanduser()


def _log_path() -> Path:
    return Path(
        os.environ.get(
            "QUILL_LEARNING_LOG",
            str(Path.home() / ".quill" / "learning.log"),
        )
    ).expanduser()


def _overrides_path() -> Path:
    return Path(
        os.environ.get(
            "QUILL_OVERRIDES",
            str(Path.home() / ".quill" / "overrides.toml"),
        )
    ).expanduser()


# ---------------------------------------------------------------------------
# Override reader. `quill suggestions promote` writes blocks into
# overrides.toml; this is the read side that lets the gate consult
# them. Blocks expire automatically when (promoted_at + ttl_days) is
# in the past, so a forgotten override doesn't grant permission
# forever - Permission Decay applied to the loosening side.


def load_active_overrides() -> dict[str, dict[str, Any]]:
    """Return {pattern_id: {ttl_days, promoted_at, evidence, ...}} for
    every override block in overrides.toml that has NOT yet expired.
    Expired blocks are filtered out silently. A missing or unreadable
    file returns {} - the gate falls back to default classification.

    Cheap and pure: caller is expected to cache the result for the
    duration of a single hook invocation.
    """
    p = _overrides_path()
    if not p.exists():
        return {}
    import sys as _sys

    if _sys.version_info >= (3, 11):
        import tomllib as _tomllib
    else:
        import tomli as _tomllib  # type: ignore[no-redef]
    try:
        with p.open("rb") as f:
            data = _tomllib.load(f)
    except (OSError, _tomllib.TOMLDecodeError):
        return {}

    raw = data.get("overrides")
    if not isinstance(raw, dict):
        return {}
    now = datetime.now(UTC)
    out: dict[str, dict[str, Any]] = {}
    for _section_name, block in raw.items():
        if not isinstance(block, dict):
            continue
        pattern_id = str(block.get("pattern_id") or "").strip()
        if not pattern_id:
            continue
        promoted_at = block.get("promoted_at")
        ttl_days = block.get("ttl_days", 30)
        if not isinstance(ttl_days, (int, float)):
            continue
        if isinstance(promoted_at, str):
            try:
                promoted_dt = datetime.fromisoformat(
                    promoted_at.replace("Z", "+00:00"),
                )
            except (ValueError, AttributeError):
                continue
        elif isinstance(promoted_at, datetime):
            promoted_dt = promoted_at
            if promoted_dt.tzinfo is None:
                promoted_dt = promoted_dt.replace(tzinfo=UTC)
        else:
            continue
        # Has the override expired?
        age = now - promoted_dt
        if age.total_seconds() > float(ttl_days) * 86400.0:
            continue
        out[pattern_id] = {
            "ttl_days": int(ttl_days),
            "promoted_at": promoted_at,
            "evidence": str(block.get("evidence") or ""),
            "remaining_days": float(ttl_days) - age.total_seconds() / 86400.0,
        }
    return out


# ---------------------------------------------------------------------------
# PatternStats: the integer state per classifier pattern.


@dataclass
class PatternStats:
    """One pattern's running stats. All counters are integers; floats
    are derived. The dataclass round-trips through asdict()/dict
    cleanly so persistence is just json.dumps.
    """

    pattern_id: str
    fires: int = 0
    approvals: int = 0
    denies: int = 0
    last_fire_ts: float = 0.0
    first_fire_ts: float = 0.0
    ewma_approval_rate: float = 0.0
    inter_arrival_sec: list[float] = field(default_factory=list)
    consecutive_denies: int = 0
    consecutive_approvals: int = 0

    @property
    def beta_alpha(self) -> float:
        return PRIOR_ALPHA + self.approvals

    @property
    def beta_beta(self) -> float:
        return PRIOR_BETA + self.denies

    @property
    def posterior_mean(self) -> float:
        a, b = self.beta_alpha, self.beta_beta
        return a / (a + b)

    def wilson_interval(self, confidence: float = 0.95) -> tuple[float, float]:
        """Wilson score interval for a binomial proportion. Beats the
        normal approximation at small N; tight at the boundaries.

        See https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval
        Returns (low, high) on the unit interval. An empty pattern
        returns (0.0, 1.0) - maximum uncertainty.
        """
        n = self.approvals + self.denies
        if n == 0:
            return (0.0, 1.0)
        if confidence == 0.95:
            z = 1.959964
        elif confidence == 0.90:
            z = 1.644854
        else:
            # erf-based inverse for arbitrary confidence; uncommon path.
            from statistics import NormalDist

            z = NormalDist().inv_cdf(1 - (1 - confidence) / 2)
        p = self.approvals / n
        z2 = z * z
        denom = 1 + z2 / n
        center = (p + z2 / (2 * n)) / denom
        half = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
        return (max(0.0, center - half), min(1.0, center + half))

    def record(self, decision: Literal["approve", "deny"], now: float) -> None:
        """Apply one labelled observation. Updates fire counters,
        inter-arrival history, EWMA, and the streak counters.
        """
        self.fires += 1
        if self.first_fire_ts == 0.0:
            self.first_fire_ts = now
        if self.last_fire_ts > 0:
            gap = now - self.last_fire_ts
            if gap >= 0:
                self.inter_arrival_sec.append(gap)
                # bounded ring: keep last 50 only so the JSON stays small
                if len(self.inter_arrival_sec) > 50:
                    self.inter_arrival_sec = self.inter_arrival_sec[-50:]
        self.last_fire_ts = now

        outcome = 1.0 if decision == "approve" else 0.0
        self.ewma_approval_rate = EWMA_ALPHA * outcome + (1 - EWMA_ALPHA) * self.ewma_approval_rate

        if decision == "approve":
            self.approvals += 1
            self.consecutive_approvals += 1
            self.consecutive_denies = 0
        else:
            self.denies += 1
            self.consecutive_denies += 1
            self.consecutive_approvals = 0


# ---------------------------------------------------------------------------
# Persistence. Atomic via tmp-rename so an interrupted write cannot
# leave a corrupted file. Mode 0o600 because the pattern_id might be
# operator-identifying.

try:
    import fcntl as _fcntl

    _HAS_FLOCK = True
except ImportError:  # pragma: no cover - non-POSIX (Windows) fallback
    _HAS_FLOCK = False


@contextlib.contextmanager
def _file_lock(path: Path, exclusive: bool) -> Iterator[None]:
    """fcntl.flock around a lock file that lives alongside pattern_stats.

    The canonical file gets atomic tmp-rename; the lock prevents two
    concurrent writers from BOTH staging a tmp file that loses the
    interim updates (last writer wins, but read-modify-write semantics
    require the lock around the read too). Lock file is mode 0o600.
    Yields immediately on platforms without fcntl (Windows) - tmp-rename
    still gives atomicity per write, just no read-modify-write safety.
    """
    if not _HAS_FLOCK:
        yield
        return
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX if exclusive else _fcntl.LOCK_SH)
        try:
            yield
        finally:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


def load_stats() -> dict[str, PatternStats]:
    p = _stats_path()
    if not p.exists():
        return {}
    with _file_lock(p, exclusive=False):
        try:
            raw = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            # If the file is corrupted, treat as empty so the learner restarts
            # rather than crashing the hook. The audit log is the source of
            # truth and could be re-derived if needed.
            return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, PatternStats] = {}
    for k, v in raw.items():
        if not isinstance(v, dict):
            continue
        # Defensive: drop fields the dataclass doesn't know about so
        # forward-compatible upgrades don't crash older readers.
        known = {f for f in PatternStats.__dataclass_fields__}
        clean = {kk: vv for kk, vv in v.items() if kk in known}
        clean["pattern_id"] = str(k)
        with contextlib.suppress(TypeError):
            out[str(k)] = PatternStats(**clean)
    return out


def save_stats(stats: dict[str, PatternStats]) -> None:
    """Write under exclusive flock so two concurrent hook subprocesses
    cannot clobber each other's read-modify-write cycle. The flock
    serialises the entire read-modify-write sequence; without it,
    two writers would both load_stats(), both update their in-memory
    copies, both save_stats() - losing the first writer's update.
    """
    p = _stats_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with _file_lock(p, exclusive=True):
        tmp = p.with_suffix(p.suffix + ".tmp")
        payload = {k: asdict(v) for k, v in stats.items()}
        tmp.write_text(json.dumps(payload, indent=2))
        # tmp-rename is atomic on POSIX. A crash between write and rename
        # leaves the .tmp file behind but the canonical file is untouched.
        tmp.replace(p)
        with contextlib.suppress(OSError):
            p.chmod(0o600)


@contextlib.contextmanager
def _read_modify_write_stats() -> Iterator[dict[str, PatternStats]]:
    """Wrap a load-update-save cycle in a single exclusive flock so
    concurrent writers see consistent state. Yields the dict to mutate;
    on exit, saves it back. This is the safe shape for any caller that
    wants to merge with whatever else might be writing at the same time.
    """
    p = _stats_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with _file_lock(p, exclusive=True):
        stats: dict[str, PatternStats] = {}
        if p.exists():
            try:
                raw = json.loads(p.read_text())
                if isinstance(raw, dict):
                    known = {f for f in PatternStats.__dataclass_fields__}
                    for k, v in raw.items():
                        if isinstance(v, dict):
                            clean = {kk: vv for kk, vv in v.items() if kk in known}
                            clean["pattern_id"] = str(k)
                            with contextlib.suppress(TypeError):
                                stats[str(k)] = PatternStats(**clean)
            except (OSError, json.JSONDecodeError):
                stats = {}
        yield stats
        tmp = p.with_suffix(p.suffix + ".tmp")
        payload = {k: asdict(v) for k, v in stats.items()}
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(p)
        with contextlib.suppress(OSError):
            p.chmod(0o600)


# ---------------------------------------------------------------------------
# Append-only logs.


def append_suggestion(payload: dict[str, Any]) -> None:
    """Surface a suggestion to the operator. Never auto-applied;
    `quill suggestions promote <id>` is the apply path."""
    p = _suggestions_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    with p.open("a") as f:
        f.write(line)
    with contextlib.suppress(OSError):
        p.chmod(0o600)


def log_event(line: str) -> None:
    """Timestamped append to ~/.quill/learning.log. The operator tails
    this to watch the learner update itself in real time."""
    p = _log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
    with p.open("a") as f:
        f.write(f"{ts} {line}\n")
    with contextlib.suppress(OSError):
        p.chmod(0o600)


# ---------------------------------------------------------------------------
# Pure-function detectors. Each returns a suggestion dict or None.
# Tightening detectors WILL auto-apply (caller writes the change).
# Loosening detectors NEVER auto-apply (caller only surfaces).


def detect_tightening(p: PatternStats) -> dict[str, Any] | None:
    """Auto-applies. The two triggers are:
      1. consecutive_denies >= TIGHTEN_DENY_STREAK
      2. Wilson 95% upper bound on approval < TIGHTEN_WILSON_UPPER
    Either signals "the operator agrees with this block class; tighten
    rather than keep prompting."
    """
    if p.consecutive_denies >= TIGHTEN_DENY_STREAK:
        return {
            "type": "tightening_auto_applied",
            "pattern_id": p.pattern_id,
            "evidence": f"{p.consecutive_denies} consecutive denies",
            "applied_change": "elevate to operator-attention queue",
        }
    _, wilson_high = p.wilson_interval(0.95)
    if p.fires >= 10 and wilson_high < TIGHTEN_WILSON_UPPER:
        return {
            "type": "tightening_auto_applied",
            "pattern_id": p.pattern_id,
            "evidence": (
                f"Wilson 95% upper on approval = {wilson_high:.3f} "
                f"(fires={p.fires}, approvals={p.approvals})"
            ),
            "applied_change": "candidate for severity upgrade",
        }
    return None


def detect_loosen_candidate(p: PatternStats) -> dict[str, Any] | None:
    """Surfaced only. Never auto-applied. Operator must run
    `quill suggestions promote <id>` to write the override.
    """
    wilson_low, _ = p.wilson_interval(0.95)
    if p.fires < LOOSEN_MIN_FIRES:
        return None
    if wilson_low <= LOOSEN_WILSON_LOWER:
        return None
    return {
        "type": "loosening_candidate",
        "pattern_id": p.pattern_id,
        "evidence": (
            f"approval rate {p.posterior_mean:.0%} (Wilson 95% lower {wilson_low:.0%}, n={p.fires})"
        ),
        "proposal": (
            "Review for per-context override. Promote with "
            "`quill suggestions promote {id}`. Never auto-applied."
        ),
        "expires_ts": time.time() + 30 * 86400,
    }


def detect_auto_promote_candidate(p: PatternStats) -> dict[str, Any] | None:
    """In-flow promotion prompt. Fires the FIRST time a pattern crosses
    `AUTOPROMOTE_MIN_APPROVALS` approvals within the rolling window with
    NO denies in that same window. The hook adapter renders this as a
    one-shot "want to auto-allow this from now on?" prompt at the moment
    of the next ask, instead of forcing the operator to run a separate
    `quill suggestions promote` command later.

    The bright line: bypass mode and critical-class events are NEVER
    candidates for auto-promotion. That gating happens in the adapter,
    not here - this detector just emits the candidate; the adapter
    decides whether to show it. Pattern IDs that begin with `critical:`
    or `secret:` are short-circuited here as defense in depth.

    Why not extend detect_loosen_candidate: that one is Wilson-based
    (20+ fires for statistical confidence) and surfaces to a queue.
    This one is product-judgement based (5 fires for responsiveness)
    and surfaces in-flow. Different jobs; both worth having.
    """
    pid = p.pattern_id or ""
    if pid.startswith(("critical:", "secret:", "trifecta:")):
        return None
    if p.approvals < AUTOPROMOTE_MIN_APPROVALS:
        return None
    if p.denies > AUTOPROMOTE_MAX_DENIES_IN_WINDOW:
        return None
    # Window check: first approval inside the window. We use first_fire_ts
    # as a cheap proxy - if the pattern's been around longer than the
    # window we still fire IFF approvals are stacked in recent history,
    # which `last_fire_ts - first_fire_ts <= window` approximates.
    span = p.last_fire_ts - p.first_fire_ts
    if span > AUTOPROMOTE_WINDOW_SEC:
        return None
    return {
        "type": "policy.promotion_suggested",
        "pattern_id": pid,
        "evidence": (f"{p.approvals} approvals in {max(1, int(span // 86400))} day(s), 0 denies"),
        "proposal": (
            "Auto-allow this pattern from now on? Press once to confirm. "
            "Reverse anytime with `quill suggestions revoke`."
        ),
        "in_flow": True,
        "expires_ts": time.time() + 7 * 86400,
    }


def detect_operator_fatigue(p: PatternStats) -> dict[str, Any] | None:
    """Fires when the operator has been rapid-fire approving a single
    pattern long enough to suggest they're not reading the prompts
    any more. Rate-based; no model needed."""
    if p.consecutive_approvals < FATIGUE_STREAK_LEN:
        return None
    recent = p.inter_arrival_sec[-FATIGUE_STREAK_LEN:]
    if not recent:
        return None
    median = sorted(recent)[len(recent) // 2]
    if median >= FATIGUE_INTER_ARRIVAL_SEC:
        return None
    return {
        "type": "operator_anomaly",
        "subtype": "fatigue",
        "pattern_id": p.pattern_id,
        "evidence": (
            f"streak {p.consecutive_approvals} approvals, "
            f"median inter-arrival {median:.1f}s "
            f"(< {FATIGUE_INTER_ARRIVAL_SEC}s threshold)"
        ),
        "proposal": "Require Touch ID re-auth on next decision",
    }


# ---------------------------------------------------------------------------
# Public entry. Called from the hook adapter AFTER the verdict is
# rendered. Never blocks the hot path. Failure here is non-fatal.


def record_decision_learning(
    tool_name: str,
    decision_reason: str,
    approval_token_used: bool,
) -> None:
    """Fold one post-decision observation into pattern_stats.

    Extracted from the Claude Code and Cursor hot paths, which previously
    inlined the same normalize-reason / build-pattern-id / update sequence
    three times over (audit #46). Stays strictly POST-decision and
    side-effect-only, so a learning failure can never move the gate's
    verdict (module rule 2). Callers wrap this in their own strict-vs-
    suppress policy; this function does not swallow exceptions itself.
    """
    from quill.learn import _normalize_block_reason

    head = _normalize_block_reason(decision_reason) or decision_reason
    pattern_id = f"{tool_name}:{head}"[:80]
    verdict: Literal["approve", "deny"] = "approve" if approval_token_used else "deny"
    post_decision_update(pattern_id, verdict)


def post_decision_update(
    pattern_id: str,
    decision: Literal["approve", "deny"],
    now: float | None = None,
) -> list[dict[str, Any]]:
    """Update pattern_stats for one observation; fire detectors; write
    suggestions; append a log line. Returns the list of suggestions
    emitted (for tests / for the caller to optionally surface inline).

    Errors are caught and logged so the calling hook stays robust. The
    audit log is the source of truth; pattern_stats is a cache that
    can be re-derived if it goes bad.
    """
    try:
        now = now if now is not None else time.time()
        emitted: list[dict[str, Any]] = []
        # Atomic read-modify-write under exclusive flock. Two concurrent
        # hook subprocesses serialise on the lock; neither loses an
        # update. Without this, a fast pair of hooks would both load
        # the same baseline, both increment from it, and the second
        # save would overwrite the first.
        with _read_modify_write_stats() as stats:
            p = stats.get(pattern_id) or PatternStats(pattern_id=pattern_id)
            p.record(decision, now)
            stats[pattern_id] = p

            for detector in (
                detect_tightening,
                detect_loosen_candidate,
                detect_operator_fatigue,
                detect_auto_promote_candidate,
            ):
                sug = detector(p)
                if sug is None:
                    continue
                sug["ts"] = now
                sug["pattern_id"] = sug.get("pattern_id", pattern_id)
                append_suggestion(sug)
                emitted.append(sug)
                log_event(
                    f"suggestion[{sug['type']}] pattern={pattern_id} "
                    f"evidence={sug.get('evidence', '')[:140]}"
                )
        log_event(
            f"update pattern={pattern_id} decision={decision} "
            f"fires={p.fires} approvals={p.approvals} denies={p.denies} "
            f"posterior={p.posterior_mean:.3f}"
        )
        return emitted
    except Exception as exc:
        # Learning failures must never break the hook. Log + move on.
        # Test-only env var QUILL_LEARNING_STRICT raises; production stays soft.
        if os.environ.get("QUILL_LEARNING_STRICT"):
            raise
        with contextlib.suppress(OSError):
            log_event(f"ERROR pattern={pattern_id} {type(exc).__name__}: {exc}")
        return []


# ---------------------------------------------------------------------------
# Drift detection (Page-Hinkley statistic).
#
# Detects a sustained shift in the operator's aggregate approval rate
# at session-end. Per-pattern drift is too sparse to be meaningful at
# our event volume (research doc S5).
#
# Math: maintain a running mean m_t and cumulative deviation. Alert
# when (current cumulative) - (running min/max cumulative) > lambda,
# using `delta` as a tolerated-shift slack so noise doesn't fire it.
#
# Defaults from Viinikka et al. (IDS background-noise EWMA paper) +
# the research doc's recommendation.

PH_DELTA: float = 0.005
PH_LAMBDA: float = 10.0


@dataclass
class PageHinkleyResult:
    detected: bool
    direction: Literal["upward", "downward", "none"]
    statistic: float
    n_observations: int
    rate_now: float
    rate_prior_window: float


def page_hinkley(
    observations: Iterable[float],
    delta: float = PH_DELTA,
    lam: float = PH_LAMBDA,
) -> PageHinkleyResult:
    """Bidirectional Page-Hinkley over a binary outcome stream.

    Each observation should be 0.0 (deny/ask) or 1.0 (operator
    approved). Below 20 observations we report no-detect because
    Page-Hinkley is unreliable in that regime.
    """
    xs = list(observations)
    n = len(xs)
    if n < 20:
        return PageHinkleyResult(False, "none", 0.0, n, 0.0, 0.0)

    # Standard Page-Hinkley construction (both directions):
    #   For UP-shift, accumulate (x - mean - delta); the stream rises
    #   over its current floor by (sum - min(sum)). Alert if > lambda.
    #   For DOWN-shift, accumulate (mean - x - delta) - SIGN-FLIPPED
    #   so a drop in x produces a positive cumulative. Same maths
    #   from there: stat = (sum - min(sum)). Track MIN for both.
    mean = 0.0
    sum_dev_up = 0.0
    min_dev_up = 0.0
    sum_dev_down = 0.0
    min_dev_down = 0.0
    for i, x in enumerate(xs, start=1):
        mean = mean + (x - mean) / i
        sum_dev_up += x - mean - delta
        min_dev_up = min(min_dev_up, sum_dev_up)
        sum_dev_down += mean - x - delta
        min_dev_down = min(min_dev_down, sum_dev_down)

    stat_up = sum_dev_up - min_dev_up
    stat_down = sum_dev_down - min_dev_down
    window = min(20, n)
    rate_now = sum(xs[-window:]) / window
    rate_prior = sum(xs[: max(1, n - window)]) / max(1, n - window)
    if stat_up > lam and rate_now > rate_prior:
        return PageHinkleyResult(True, "upward", stat_up, n, rate_now, rate_prior)
    if stat_down > lam and rate_now < rate_prior:
        return PageHinkleyResult(True, "downward", stat_down, n, rate_now, rate_prior)
    return PageHinkleyResult(False, "none", max(stat_up, stat_down), n, rate_now, rate_prior)


def aggregate_observations_for_session(
    audit_events: Iterable[dict[str, Any]],
    session_id: str,
) -> list[float]:
    """Extract a 0/1 stream for one session. 1=operator approved a
    blocked call via one-shot token; 0=verdict was deny or ask.
    Plain-LOW allows are excluded (no operator signal)."""
    out: list[float] = []
    for e in audit_events:
        if e.get("session_id") != session_id:
            continue
        etype = e.get("type")
        payload = e.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if etype in {"verdict.blocked", "verdict.ask"}:
            out.append(0.0)
        elif etype == "verdict.allowed":
            reason = str(payload.get("reason") or "")
            if reason.startswith("approved one-shot"):
                out.append(1.0)
    return out


def check_drift_for_session(
    audit_events: Iterable[dict[str, Any]],
    session_id: str,
) -> dict[str, Any] | None:
    """Run Page-Hinkley over one session's outcome stream. On detect,
    emit a `drift_detected` suggestion + return it; else None.
    """
    obs = aggregate_observations_for_session(audit_events, session_id)
    result = page_hinkley(obs)
    if not result.detected:
        return None
    sug = {
        "type": "drift_detected",
        "session_id": session_id,
        "direction": result.direction,
        "evidence": (
            f"Page-Hinkley {result.statistic:.2f} > lambda {PH_LAMBDA} "
            f"(n={result.n_observations}, "
            f"rate recent={result.rate_now:.2f}, "
            f"prior={result.rate_prior_window:.2f})"
        ),
        "proposal": (
            f"Approval rate shifted {result.direction}. "
            "Review recent suggestions and pattern_stats; the operator "
            "started behaving differently. Common causes: a new "
            "untrusted repo, a workflow change, or operator fatigue."
        ),
        "ts": time.time(),
    }
    append_suggestion(sug)
    log_event(
        f"drift session={session_id} direction={result.direction} "
        f"stat={result.statistic:.2f} rate_now={result.rate_now:.2f} "
        f"rate_prior={result.rate_prior_window:.2f}"
    )
    return sug


# ---------------------------------------------------------------------------
# Helpers for the CLI.


def read_recent_log(n: int = 50) -> list[str]:
    p = _log_path()
    if not p.exists():
        return []
    lines = p.read_text().splitlines()
    return lines[-n:]


def read_suggestions(limit: int = 100) -> list[dict[str, Any]]:
    p = _suggestions_path()
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out[-limit:]


_STALE_PATTERN_PREFIXES: tuple[str, ...] = ("approved one-shot via quill approve ",)


def find_stale_patterns(
    stats: dict[str, PatternStats] | None = None,
) -> list[str]:
    """Return pattern_ids that look like a per-token bypass row (one of
    the leftover shapes from before pattern_id snapshot-fix landed).

    The bug: prior to rc5, when an approve-token was consumed the
    pattern_id was derived from the FLIPPED reason ("approved one-shot
    via quill approve <token-prefix>") rather than the original deny
    reason. That produced per-token pattern_id rows with unique
    token-prefix suffixes - dead rows that will never accumulate more
    observations and clutter the dashboard.
    """
    s = stats if stats is not None else load_stats()
    stale: list[str] = []
    for pid in s:
        # Strip the leading "Tool:" if present so we test just the
        # reason head.
        _, _, head = pid.partition(":")
        for prefix in _STALE_PATTERN_PREFIXES:
            if prefix in head:
                stale.append(pid)
                break
    return stale


def cleanup_stale_patterns() -> tuple[int, list[str]]:
    """Remove every stale row from pattern_stats.json. Idempotent;
    a second call after the first removes nothing. Atomic via the
    same flock + tmp-rename path the learner uses.

    Returns (n_removed, removed_pattern_ids).
    """
    removed: list[str] = []
    with _read_modify_write_stats() as stats:
        for pid in list(stats.keys()):
            _, _, head = pid.partition(":")
            if any(prefix in head for prefix in _STALE_PATTERN_PREFIXES):
                del stats[pid]
                removed.append(pid)
    if removed:
        log_event(
            f"cleanup_stale_patterns removed {len(removed)} row(s): " + ", ".join(removed[:5])
        )
    return len(removed), removed


def stats_summary(stats: dict[str, PatternStats] | None = None) -> dict[str, Any]:
    """Snapshot for `quill log` and dashboards. Pure read."""
    s = stats if stats is not None else load_stats()
    return {
        "n_patterns": len(s),
        "total_fires": sum(p.fires for p in s.values()),
        "total_approvals": sum(p.approvals for p in s.values()),
        "total_denies": sum(p.denies for p in s.values()),
        "top_by_fires": sorted(
            ((p.pattern_id, p.fires) for p in s.values()),
            key=lambda kv: -kv[1],
        )[:8],
    }
