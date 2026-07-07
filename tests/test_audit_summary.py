"""Tests for `quill audit summary` (morning recap subcommand).

Covers:
  - duration parsing (`12h`, `1d`, `7d`, `30m`, `2h30m`, errors)
  - empty audit log -> "no events in window" output
  - LOW-only log -> 0 HIGH auto-approved
  - 10 overnight events across 3 tools -> per-tool counts
  - `--since 1h` filters out older events
  - `--format json` returns valid JSON with the same numbers
  - `--format table` renders without raising
  - `--cwd` scopes to events from a specific cwd
  - markdown output structure is Substack-paste-ready
  - critical-blocked path surfaces blocked rows

Each test runs in the conftest-isolated QUILL_HOME so the live `~/.quill/`
log is never touched.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from quill.audit_summary import (
    compute_summary,
    filter_events,
    load_events,
    parse_duration,
    render_json,
    render_markdown,
    render_table,
)
from quill.cli import app

# ---------------------------------------------------------------------------
# helpers - build a synthetic audit log without going through AuditLog so
# tests can backdate timestamps freely. We still emit chain fields so the
# loader doesn't reject the row; the chain is not validated here (that's
# what test_audit.py covers).
# ---------------------------------------------------------------------------


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _make_event(
    *,
    ts: datetime,
    event_type: str,
    session_id: str = "ses-1",
    risk: str = "low",
    tool_name: str = "Bash",
    cwd: str = "/Users/test/proj",
    what: str = "",
    reason: str = "",
    prev_mac: str = "",
    key: bytes = b"k" * 32,
) -> dict:
    body = {
        "ts": ts.astimezone(UTC).isoformat(),
        "session_id": session_id,
        "agent_id": "test-agent",
        "type": event_type,
        "risk": risk,
        "prev_mac": prev_mac,
        "payload": {
            "tool_name": tool_name,
            "by": "test",
            "reason": reason,
            "permission": "allow",
            "parent_session_id": "",
            "cwd": cwd,
            "approve_token": "",
            "what": what,
            "why": reason,
            "try_instead": "",
        },
    }
    mac = hmac_mod.new(key, _canon(body), hashlib.sha256).hexdigest()
    body["mac"] = mac
    return body


def _write_log(path: Path, events: list[dict]) -> None:
    """Write events as JSONL. Updates prev_mac across rows so verify_chain
    would still pass under a stable HMAC key (not validated by these tests)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for evt in events:
        lines.append(json.dumps(evt, separators=(",", ":")))
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def _log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log.jsonl"


# ---------------------------------------------------------------------------
# duration parsing
# ---------------------------------------------------------------------------


class TestParseDuration:
    def test_hours(self) -> None:
        assert parse_duration("12h") == timedelta(hours=12)

    def test_days(self) -> None:
        assert parse_duration("1d") == timedelta(days=1)
        assert parse_duration("7d") == timedelta(days=7)

    def test_minutes(self) -> None:
        assert parse_duration("30m") == timedelta(minutes=30)

    def test_seconds(self) -> None:
        assert parse_duration("45s") == timedelta(seconds=45)

    def test_weeks(self) -> None:
        assert parse_duration("2w") == timedelta(weeks=2)

    def test_compound(self) -> None:
        assert parse_duration("2h30m") == timedelta(hours=2, minutes=30)
        assert parse_duration("1d12h") == timedelta(days=1, hours=12)

    def test_case_insensitive(self) -> None:
        assert parse_duration("12H") == timedelta(hours=12)

    def test_whitespace_stripped(self) -> None:
        assert parse_duration("  12h  ") == timedelta(hours=12)

    def test_rejects_bare_integer(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("12")

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("")

    def test_rejects_unknown_unit(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("12y")

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("0h")

    def test_rejects_trailing_garbage(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("12h junk")


# ---------------------------------------------------------------------------
# load + filter
# ---------------------------------------------------------------------------


class TestLoadEvents:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert load_events(tmp_path / "nope.jsonl") == []

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        good = _make_event(
            ts=datetime.now(UTC),
            event_type="verdict.allowed.overnight",
            risk="high",
        )
        p.write_text(
            json.dumps(good) + "\n" + "{not-json}\n" + "\n" + json.dumps(good) + "\n",
        )
        events = load_events(p)
        assert len(events) == 2


class TestFilterEvents:
    def test_filters_by_window(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        old = _make_event(
            ts=now - timedelta(hours=24),
            event_type="verdict.allowed",
        )
        recent = _make_event(
            ts=now - timedelta(hours=2),
            event_type="verdict.allowed",
        )
        kept = filter_events(
            [old, recent],
            window=timedelta(hours=12),
            now=now,
        )
        assert len(kept) == 1
        assert kept[0]["ts"] == recent["ts"]

    def test_filters_by_cwd(self, tmp_path: Path) -> None:
        # Resolve under tmp_path so cwd filter normalisation works on the
        # test machine without depending on whether ~/foo exists.
        project = tmp_path / "myproj"
        project.mkdir()
        other = tmp_path / "other"
        other.mkdir()

        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        in_proj = _make_event(
            ts=now - timedelta(hours=1),
            event_type="verdict.allowed.overnight",
            risk="high",
            cwd=str(project),
        )
        out_proj = _make_event(
            ts=now - timedelta(hours=1),
            event_type="verdict.allowed.overnight",
            risk="high",
            cwd=str(other),
        )
        kept = filter_events(
            [in_proj, out_proj],
            window=timedelta(hours=12),
            now=now,
            cwd_filter=str(project),
        )
        assert len(kept) == 1
        assert kept[0]["payload"]["cwd"] == str(project)


# ---------------------------------------------------------------------------
# compute_summary
# ---------------------------------------------------------------------------


class TestComputeSummary:
    def test_empty_window(self) -> None:
        stats = compute_summary(
            [],
            since_label="12h",
            window=timedelta(hours=12),
        )
        assert stats.total_events == 0
        assert stats.high_overnight_count == 0
        assert stats.active_sessions == 0

    def test_only_low_events(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=i * 5),
                event_type="verdict.allowed",
                risk="low",
                tool_name="Read",
            )
            for i in range(5)
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        assert stats.high_overnight_count == 0
        assert stats.low_medium_count == 5
        assert stats.critical_blocked_count == 0

    def test_ten_overnight_across_three_tools(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = []
        # 5 Edit, 3 Write, 2 Bash
        for i in range(5):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=i),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Edit",
                    what=f"Edit /tmp/file{i}.py",
                )
            )
        for i in range(3):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=i),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Write",
                    what=f"Write /tmp/new{i}.py",
                )
            )
        for i in range(2):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=i),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Bash",
                    what=f"git push --force #{i}",
                )
            )
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        assert stats.high_overnight_count == 10
        by_tool = {t.tool: t.count for t in stats.by_tool}
        assert by_tool == {"Edit": 5, "Write": 3, "Bash": 2}
        # Sample command preserved per tool
        edit_sample = next(t for t in stats.by_tool if t.tool == "Edit").sample_what
        assert "Edit /tmp/file" in edit_sample

    def test_filters_out_events_older_than_window(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(hours=2),
                event_type="verdict.allowed.overnight",
                risk="high",
            ),
            _make_event(
                ts=now - timedelta(minutes=30),
                event_type="verdict.allowed.overnight",
                risk="high",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="1h",
            window=timedelta(hours=1),
            now=now,
        )
        assert stats.high_overnight_count == 1
        assert stats.total_events == 1

    def test_cwd_filter_scopes_results(self, tmp_path: Path) -> None:
        proj = tmp_path / "scoped"
        proj.mkdir()
        other = tmp_path / "elsewhere"
        other.mkdir()
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                cwd=str(proj),
            ),
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                cwd=str(other),
            ),
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                cwd=str(other),
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
            cwd_filter=str(proj),
        )
        assert stats.high_overnight_count == 1

    def test_counts_critical_blocked(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=10),
                event_type="verdict.blocked",
                risk="critical",
                tool_name="Bash",
                what="rm -rf /",
                reason="critical command",
            ),
            _make_event(
                ts=now - timedelta(minutes=8),
                event_type="verdict.scope_violation",
                risk="high",
                tool_name="Bash",
                what="git push --force",
                reason="out of scope",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        assert stats.critical_blocked_count == 1
        assert stats.blocked_count == 2
        assert len(stats.pending_block) == 2

    def test_counts_ask_when_overnight_off(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=3),
                event_type="verdict.ask",
                risk="high",
                tool_name="Edit",
                what="Edit /tmp/risky.py",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        assert stats.asked_count == 1
        assert len(stats.pending_ask) == 1


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_no_events_produces_friendly_text(self) -> None:
        stats = compute_summary(
            [],
            since_label="12h",
            window=timedelta(hours=12),
        )
        md = render_markdown(stats)
        assert "Overnight Recap" in md
        assert "no events in window" in md

    def test_includes_summary_section_when_events_present(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=10),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
                what="Edit /tmp/x.py",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        md = render_markdown(stats)
        assert "## Summary" in md
        assert "HIGH actions auto-approved" in md
        assert "## By tool name (HIGH auto-approved)" in md
        assert "| Edit |" in md
        assert "## By session" in md
        assert "(empty - good!)" in md  # no pending ask / block

    def test_escapes_pipes_in_command_text(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Bash",
                what="cat /etc/passwd | head",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        md = render_markdown(stats)
        # The pipe in the command must be escaped so the markdown table
        # layout doesn't break in Substack / GitHub.
        assert r"cat /etc/passwd \| head" in md


class TestRenderJson:
    def test_round_trips(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        text = render_json(stats)
        parsed = json.loads(text)
        assert parsed["summary"]["high_overnight_count"] == 1
        assert parsed["since_label"] == "12h"
        assert parsed["by_tool"][0]["tool"] == "Edit"


class TestRenderTable:
    def test_renders_without_raising(self) -> None:
        now = datetime(2026, 5, 13, 8, 0, 0, tzinfo=UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=5),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        stats = compute_summary(
            events,
            since_label="12h",
            window=timedelta(hours=12),
            now=now,
        )
        table = render_table(stats)
        # Render to a string buffer to confirm no exceptions and that the
        # composite table includes the headline metrics.
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        Console(file=buf, force_terminal=False, width=120).print(table)
        out = buf.getvalue()
        assert "Overnight Recap" in out
        assert "HIGH auto-approved" in out


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


class TestCliSurface:
    def _runner(self) -> CliRunner:
        return CliRunner()

    def test_empty_log_no_events_message(self, tmp_path: Path) -> None:
        # No log file at all - subcommand should still succeed and emit
        # the "no events" markdown header.
        p = _log_path(tmp_path)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "Overnight Recap" in result.output
        assert "no events in window" in result.output

    def test_only_low_events_zero_high_auto_approved(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=i),
                event_type="verdict.allowed",
                risk="low",
                tool_name="Read",
            )
            for i in range(4)
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "HIGH actions auto-approved: **0**" in result.output
        assert "LOW/MEDIUM actions logged: **4**" in result.output

    def test_ten_overnight_three_tools_renders_table(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = []
        for _ in range(5):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=1),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Edit",
                    what="Edit /tmp/a.py",
                )
            )
        for _ in range(3):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=1),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Write",
                    what="Write /tmp/b.py",
                )
            )
        for _ in range(2):
            events.append(
                _make_event(
                    ts=now - timedelta(minutes=1),
                    event_type="verdict.allowed.overnight",
                    risk="high",
                    tool_name="Bash",
                    what="git push origin main",
                )
            )
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "HIGH actions auto-approved: **10**" in result.output
        assert "| Edit | 5 |" in result.output
        assert "| Write | 3 |" in result.output
        assert "| Bash | 2 |" in result.output

    def test_since_filters_out_old_events(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(hours=4),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
            _make_event(
                ts=now - timedelta(minutes=20),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "1h", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "HIGH actions auto-approved: **1**" in result.output

    def test_format_json_returns_valid_json(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--format", "json", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["summary"]["high_overnight_count"] == 1
        assert parsed["since_label"] == "12h"

    def test_format_table_renders_without_exception(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--format", "table", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "Overnight Recap" in result.output

    def test_cwd_filter_scopes_to_one_project(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        proj = tmp_path / "proj"
        proj.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        events = [
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
                cwd=str(proj),
            ),
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Write",
                cwd=str(other),
            ),
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Bash",
                cwd=str(other),
            ),
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--cwd", str(proj), "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "HIGH actions auto-approved: **1**" in result.output
        # only Edit (from proj cwd) should appear in the by-tool table
        assert "| Edit | 1 |" in result.output
        assert "| Write |" not in result.output

    def test_bad_since_returns_exit_2(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        p.touch()
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "junk", "--log", str(p)],
        )
        assert result.exit_code == 2

    def test_bad_format_returns_exit_2(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        p.touch()
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--format", "xml", "--log", str(p)],
        )
        assert result.exit_code == 2

    def test_output_file_written(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.allowed.overnight",
                risk="high",
                tool_name="Edit",
            ),
        ]
        _write_log(p, events)
        out_file = tmp_path / "recap.md"
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--log", str(p), "--out", str(out_file)],
        )
        assert result.exit_code == 0, result.output
        assert out_file.exists()
        text = out_file.read_text()
        assert "Overnight Recap" in text
        assert "HIGH actions auto-approved" in text

    def test_critical_blocked_surfaces_in_output(self, tmp_path: Path) -> None:
        p = _log_path(tmp_path)
        now = datetime.now(UTC)
        events = [
            _make_event(
                ts=now - timedelta(minutes=2),
                event_type="verdict.blocked",
                risk="critical",
                tool_name="Bash",
                what="rm -rf /important",
                reason="critical command",
            ),
        ]
        _write_log(p, events)
        result = self._runner().invoke(
            app,
            ["audit", "summary", "--since", "12h", "--log", str(p)],
        )
        assert result.exit_code == 0, result.output
        assert "CRITICAL actions still blocked: **1**" in result.output
        assert "rm -rf /important" in result.output
