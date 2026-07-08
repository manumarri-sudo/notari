"""Telemetry tests - privacy contract is the load-bearing assertion.

These tests pin: (1) the only fields that *can* leave the machine, (2)
that no scope strings, tool args, paths, or intent text ever enter the
event payload, and (3) that opt-out actually opts out.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nota.telemetry import (
    DEFAULT_ENDPOINT,
    SCHEMA_VERSION,
    TelemetryState,
    aggregate_events,
    build_event,
    emit_session_summary,
    opt_in,
    opt_out,
    preview_event_for_user,
)

# ---- state load/save -----------------------------------------------------


def test_load_creates_install_id_when_no_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = TelemetryState.load()
    assert s.install_id  # uuid4 string
    assert s.opted_in is False
    assert s.asked is False


def test_opt_in_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = opt_in()
    assert s.opted_in is True
    again = TelemetryState.load()
    assert again.opted_in is True
    assert again.asked is True


def test_opt_out_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    opt_in()
    s = opt_out()
    assert s.opted_in is False
    assert TelemetryState.load().opted_in is False


def test_state_file_is_chmod_600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "tel.json"
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(p))
    opt_in()
    import stat

    mode = stat.S_IMODE(p.stat().st_mode)
    assert mode & 0o077 == 0


# ---- aggregate computation ------------------------------------------------


def _evt(t: str, **payload: object) -> dict[str, object]:
    out: dict[str, object] = {
        "ts": "2026-05-07T19:00:00+00:00",
        "type": t,
        "session_id": "ses_test",
        "agent_id": "ses_test",
        "risk": payload.pop("risk", "low"),
        "payload": payload,
    }
    return out


def test_aggregate_counts_basic_session() -> None:
    events = [
        _evt("session.start", intent="...", scope=["fs:read"], upstreams=["filesystem", "github"]),
        _evt("tool.attempted", tool_name="filesystem.read_file", risk="low"),
        _evt("verdict.allowed", tool_name="filesystem.read_file"),
        _evt("tool.attempted", tool_name="github.create_pull_request", risk="critical"),
        _evt(
            "verdict.blocked",
            tool_name="github.create_pull_request",
            reason="human_declined",
            risk="critical",
        ),
        _evt("tool.attempted", tool_name="filesystem.delete_file", risk="critical"),
        _evt("verdict.scope_violation", tool_name="filesystem.delete_file"),
        _evt("session.end"),
    ]
    a = aggregate_events(events)
    assert a["n_attempts"] == 3
    assert a["n_allowed"] == 1
    assert a["n_blocked"] == 1
    assert a["n_scope_violations"] == 1
    assert a["n_human_paused"] == 1
    assert a["n_upstreams"] == 2
    assert "filesystem" in a["top_namespaces"]
    assert "github" in a["top_namespaces"]
    # risk distribution captures attempt-time risk
    assert a["risk_dist"].get("low") == 1
    assert a["risk_dist"].get("critical") == 2


def test_aggregate_never_includes_tool_args_or_paths() -> None:
    """The privacy contract: no arg values ever ship.

    We feed events whose payloads carry typical sensitive shapes and
    assert they never end up in the aggregate output.
    """
    events = [
        _evt("session.start", intent="DELETE PROD DATABASE NOW", scope=["secrets:read:c_8e4f"]),
        _evt(
            "tool.attempted",
            tool_name="banking.send_money",
            arg_keys=["recipient", "amount"],
            arg_count=2,
            args_preview={"recipient": "US133...", "amount": 50000},
        ),
        _evt("verdict.allowed", tool_name="banking.send_money"),
    ]
    a = aggregate_events(events)
    serialised = json.dumps(a)
    # nothing identifying must appear
    assert "DELETE PROD" not in serialised
    assert "c_8e4f" not in serialised
    assert "US133" not in serialised
    assert "recipient" not in serialised
    assert "send_money" not in serialised  # only the namespace, not the verb
    # but the namespace can appear (signal we want)
    assert "banking" in serialised


def test_aggregate_top_namespaces_capped_at_5() -> None:
    events = []
    for ns in ("fs", "git", "github", "slack", "calendar", "drive", "stripe"):
        events.append(_evt("tool.attempted", tool_name=f"{ns}.do_thing", risk="low"))
    a = aggregate_events(events)
    assert len(a["top_namespaces"]) <= 5


# ---- event envelope -------------------------------------------------------


def test_build_event_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = TelemetryState.load()
    body = build_event(s, {"n_attempts": 5})
    assert body["schema_version"] == SCHEMA_VERSION
    assert body["install_id"] == s.install_id
    assert "nota_version" in body
    assert "py_version" in body
    assert "os" in body
    assert body["event"] == "session.summary"
    assert body["data"] == {"n_attempts": 5}


def test_preview_is_pretty_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = TelemetryState.load()
    out = preview_event_for_user(s, {"n_attempts": 3})
    parsed = json.loads(out)
    assert parsed["data"]["n_attempts"] == 3
    assert "\n" in out  # indented


# ---- emit -----------------------------------------------------------------


def test_emit_skipped_when_opted_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = TelemetryState.load()
    assert s.opted_in is False
    assert emit_session_summary({"n_attempts": 1}, state=s) is False


def test_emit_swallows_network_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Telemetry must NEVER raise. We point it at an unreachable host and
    assert it returns False rather than blowing up."""
    monkeypatch.setenv("NOTA_TELEMETRY_PATH", str(tmp_path / "tel.json"))
    s = opt_in()
    s.endpoint = "http://127.0.0.1:1/" + "x" * 10  # nothing listening
    s.save()
    s = TelemetryState.load()
    assert emit_session_summary({"n_attempts": 1}, state=s, timeout_s=0.1) is False


def test_default_endpoint_is_nota_dev() -> None:
    """Catch accidental endpoint changes in code review."""
    assert DEFAULT_ENDPOINT == "https://telemetry.nota.dev/v1/events"
