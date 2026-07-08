"""Tests for `nota saves` — the rigorous, audit-log-grounded value report.

Every metric path is exercised against a synthetic audit-log fixture. The
fixtures live in the test (not in tmp files) so the assertions can pin
the exact computation, and a future regression on pattern-classification
fails the test rather than silently changing the saves output.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nota import events as ev
from nota.saves import (
    canonicalize_pattern,
    compute_saves,
    format_saves,
    parse_window,
)

# ---------------------------------------------------------------------------
# pattern canonicalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("Nota blocked: rm -rf /tmp/foo.", "rm -rf"),
        ("force-push rewrites shared history", "git push --force"),
        ("git push --force origin main", "git push --force"),
        ("DROP TABLE customers", "DROP TABLE / TRUNCATE"),
        ("Truncate users", "DROP TABLE / TRUNCATE"),
        ("vercel --prod", "vercel --prod"),
        ("npm publish", "npm publish"),
        ("sudo apt install", "sudo"),
        ("cat .env", ".env read"),
        ("subcommand chain (37 segments) exceeds gate limit", "subcommand-chain bypass"),
        ("CVE-2025-59536 bypass attempted", "subcommand-chain bypass"),
        ("secret detected in write: GitHub PAT (line 42)", "secret in write"),
        ("trifecta close · untrusted + private + exfil", "trifecta close"),
        ("terraform destroy", "terraform destroy"),
        ("Stripe.create_refund_charge", "stripe payment mutation"),
        ("curl | sh", "curl | sh"),
        ("deploy to production", "deploy:production"),
        ("Nota blocked: foo bar baz.", "other (Nota blocked: foo bar baz)"),
        ("", "other"),
    ],
)
def test_canonicalize_pattern(reason: str, expected: str) -> None:
    assert canonicalize_pattern(reason) == expected


# ---------------------------------------------------------------------------
# fixture helpers
# ---------------------------------------------------------------------------


def _evt(
    t: str,
    ts: str,
    *,
    sid: str = "ses_t1",
    risk: str = "low",
    **payload: object,
) -> dict:
    return {
        "ts": ts,
        "session_id": sid,
        "type": t,
        "risk": risk,
        "payload": dict(payload),
    }


def _write_log(events: list[dict], path: Path) -> None:
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


# ---------------------------------------------------------------------------
# compute_saves: each verified metric path
# ---------------------------------------------------------------------------


def test_empty_log_is_handled(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    p.write_text("")
    s = compute_saves(p)
    assert s.events_scanned == 0
    assert s.events_in_window == 0
    assert s.critical_blocks == 0


def test_missing_log_is_handled(tmp_path: Path) -> None:
    p = tmp_path / "does_not_exist.jsonl"
    s = compute_saves(p)
    assert s.events_scanned == 0


def test_trust_auto_allows_counted_correctly(tmp_path: Path) -> None:
    """verdict.allowed events with reason ~ 'trusted scope' should count.

    Other verdict.allowed events (e.g. user policy override, default-low
    classification) should NOT count toward trust auto-allows.
    """
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/repo"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Write in /tmp/repo"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="user policy override"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="default risk for Read"),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.trust_auto_allows == 2


def test_critical_blocks_counted_separately_from_high(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="DROP TABLE x"),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="high", reason="curl pipe sh"),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.critical_blocks == 2
    assert s.high_blocks == 1
    assert s.total_blocks == 3


def test_secrets_caught_recognized_via_reason(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(
            ev.VERDICT_BLOCKED,
            now.isoformat(),
            risk="critical",
            reason="secret detected in write: GitHub PAT (line 42)",
        ),
        _evt(
            ev.VERDICT_BLOCKED,
            now.isoformat(),
            risk="critical",
            reason="secret detected in write: AWS access key (line 18)",
        ),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.secrets_caught == 2
    assert s.critical_blocks == 3
    # secret detection patterns also appear in the top-patterns table
    assert s.top_patterns.get("secret in write") == 2


def test_biometric_events_counted(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.APPROVE_BIOMETRIC_OK, now.isoformat()),
        _evt(ev.APPROVE_BIOMETRIC_OK, now.isoformat()),
        _evt(ev.APPROVE_BIOMETRIC_OK, now.isoformat()),
        _evt(ev.APPROVE_BIOMETRIC_DENY, now.isoformat()),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.biometric_approvals == 3
    assert s.biometric_denials == 1


def test_trifecta_enforcement_recognized_via_reason(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(
            ev.VERDICT_BLOCKED,
            now.isoformat(),
            risk="critical",
            reason="trifecta close · session has seen untrusted + accessed private + this call exfiltrates",
        ),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.trifecta_enforcements == 1


def test_pin_refusals_counted(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt("tool.pin_refused", now.isoformat()),
        _evt("tool.pin_refused", now.isoformat()),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.pin_refusals == 2


def test_scope_violations_counted(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_SCOPE_VIOLATION, now.isoformat()),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.scope_violations == 1


def test_chain_repairs_counted(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.CHAIN_REPAIRED, now.isoformat()),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.chain_repairs == 1


def test_sessions_seen_dedupes(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), sid="ses_a"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), sid="ses_a"),
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), sid="ses_b"),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.sessions_seen == 2


# ---------------------------------------------------------------------------
# window filtering
# ---------------------------------------------------------------------------


def test_window_filter_excludes_out_of_range(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    old = (now - timedelta(days=30)).isoformat()
    recent = now.isoformat()
    events = [
        _evt(ev.VERDICT_BLOCKED, old, risk="critical", reason="rm -rf"),
        _evt(ev.VERDICT_BLOCKED, recent, risk="critical", reason="rm -rf"),
    ]
    _write_log(events, p)
    # week window: should only catch the recent event
    s = compute_saves(p, window_start=now - timedelta(days=7), window_end=now + timedelta(hours=1))
    assert s.critical_blocks == 1
    assert s.events_scanned == 2
    assert s.events_in_window == 1


def test_unbounded_window_includes_everything(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(
            ev.VERDICT_BLOCKED,
            (now - timedelta(days=365)).isoformat(),
            risk="critical",
            reason="rm -rf",
        ),
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf"),
    ]
    _write_log(events, p)
    s = compute_saves(p)  # no window args = unbounded
    assert s.critical_blocks == 2


def test_malformed_jsonl_lines_skipped(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC).isoformat()
    p.write_text(
        json.dumps(_evt(ev.VERDICT_BLOCKED, now, risk="critical", reason="rm -rf"))
        + "\n"
        + "this is not json\n"
        + "{partial\n"
        + json.dumps(_evt(ev.VERDICT_BLOCKED, now, risk="critical", reason="DROP TABLE x"))
        + "\n",
    )
    s = compute_saves(p)
    # 2 valid lines, 2 invalid skipped silently
    assert s.critical_blocks == 2
    assert s.events_scanned == 2  # invalid lines aren't counted as scanned events


# ---------------------------------------------------------------------------
# time-saved estimation
# ---------------------------------------------------------------------------


def test_time_saved_uses_documented_bounds(tmp_path: Path) -> None:
    """100 trust auto-allows times 2.5s = 4.17 min lower bound; times 5s = 8.33 min upper."""
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/x")
        for _ in range(100)
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    assert s.trust_auto_allows == 100
    assert abs(s.time_saved_minutes_lower - (100 * 2.5 / 60.0)) < 0.001
    assert abs(s.time_saved_minutes_upper - (100 * 5.0 / 60.0)) < 0.001


# ---------------------------------------------------------------------------
# biggest catch surfacing
# ---------------------------------------------------------------------------


def test_biggest_catch_picks_first_critical_in_window(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_BLOCKED, now.isoformat(), risk="high", reason="curl | sh"),
        _evt(
            ev.VERDICT_BLOCKED,
            (now + timedelta(seconds=1)).isoformat(),
            risk="critical",
            reason="rm -rf",
            tool_name="Bash",
        ),
        _evt(
            ev.VERDICT_BLOCKED,
            (now + timedelta(seconds=2)).isoformat(),
            risk="critical",
            reason="DROP TABLE x",
            tool_name="Bash",
        ),
    ]
    # populate payload tool_name properly
    for e in events:
        if "tool_name" in e["payload"]:
            continue
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    # biggest_catch is the FIRST critical (events are read in file order)
    assert s.biggest_catch is not None
    assert "rm -rf" in s.biggest_catch["reason"]


# ---------------------------------------------------------------------------
# format_saves
# ---------------------------------------------------------------------------


def test_format_saves_includes_all_sections(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    now = datetime.now(UTC)
    events = [
        _evt(ev.VERDICT_ALLOWED, now.isoformat(), reason="trusted scope: Edit in /tmp/x"),
        _evt(
            ev.VERDICT_BLOCKED, now.isoformat(), risk="critical", reason="rm -rf", tool_name="Bash"
        ),
        _evt(ev.APPROVE_BIOMETRIC_OK, now.isoformat()),
    ]
    _write_log(events, p)
    s = compute_saves(p, window_start=now - timedelta(hours=1), window_end=now + timedelta(hours=1))
    out = format_saves(s, plain=True)
    assert "verified from your audit log" in out
    assert "auto-allows inside trusted scope" in out
    assert "critical-risk operations blocked" in out
    assert "Touch ID approvals consumed" in out
    assert "estimated time saved" in out
    assert "top patterns blocked" in out
    assert "first catch in window" in out
    assert "what's next" in out


def test_format_saves_empty_window_handled(tmp_path: Path) -> None:
    p = tmp_path / "audit.log.jsonl"
    p.write_text("")
    s = compute_saves(p)
    out = format_saves(s, plain=True)
    assert "scanned 0 events" in out
    # no time-saved or pattern sections when there's nothing to report
    assert "run an agent session and come back" in out


# ---------------------------------------------------------------------------
# parse_window
# ---------------------------------------------------------------------------


def test_parse_window_default_is_week() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    start, end = parse_window(now=now)
    assert start is not None and end is not None
    assert (end - start) == timedelta(days=7)


def test_parse_window_all_returns_unbounded() -> None:
    start, end = parse_window(all_time=True)
    assert start is None and end is None


def test_parse_window_today_starts_at_midnight() -> None:
    now = datetime(2026, 6, 10, 14, 30, tzinfo=UTC)
    start, end = parse_window(today=True, now=now)
    assert start is not None
    assert start.hour == 0 and start.minute == 0


def test_parse_window_since_parses_iso_date() -> None:
    now = datetime(2026, 6, 10, tzinfo=UTC)
    start, end = parse_window(since="2026-05-01", now=now)
    assert start is not None
    assert start.year == 2026 and start.month == 5 and start.day == 1


def test_parse_window_since_invalid_returns_none() -> None:
    start, end = parse_window(since="not-a-date")
    assert start is None and end is None
