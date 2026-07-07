"""OpenTelemetry GenAI emission tests.

Most users won't have `quill[otel]` installed. We verify:
  - emit_span() is a no-op when OTel isn't importable (the common case)
  - The attribute mapping follows GenAI semconv when OTel IS available
  - audit.emit() never raises if OTel emission fails

The mapping is the security-critical part: if a future refactor breaks
`gen_ai.tool.name` or `gen_ai.conversation.id`, every observability
platform's filtering breaks. Pinning the schema here.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

from quill import otel


def _reset_otel_cache() -> None:
    """Force re-import on the next is_active() / emit_span() call."""
    otel._otel_loaded = False
    otel._otel_tracer = None


def test_emit_span_noop_when_opentelemetry_not_installed() -> None:
    """The 95th-percentile case: quill[otel] not installed."""
    _reset_otel_cache()
    real_import = (
        __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
    )

    def _no_otel(name: str, *args: object, **kwargs: object) -> object:
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            raise ImportError("simulated: not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_no_otel):
        sys.modules.pop("opentelemetry", None)
        # is_active must return False without raising.
        assert otel.is_active() is False
        # emit_span must be a no-op without raising.
        otel.emit_span(
            event_type="tool.attempted",
            session_id="ses_x",
            agent_id="root",
            risk="low",
            payload={"tool_name": "Bash"},
        )


def test_span_name_for_tool_event_uses_genai_semconv() -> None:
    """GenAI semconv §execute_tool: span name is `execute_tool {tool_name}`."""
    name = otel._span_name("verdict.allowed", {"tool_name": "filesystem.read_file"})
    assert name == "execute_tool filesystem.read_file"


def test_span_name_for_session_uses_agent_session() -> None:
    name = otel._span_name("session.open", {})
    assert name == "agent.session"


def test_span_name_for_handoff_uses_agent_handoff() -> None:
    name = otel._span_name("agent.handoff.out", {})
    assert name == "agent.handoff"


def test_span_attributes_carry_required_genai_keys() -> None:
    """Every span MUST have gen_ai.operation.name + gen_ai.conversation.id +
    gen_ai.provider.name. Pinning this - if a future refactor drops any of
    these, every observability platform breaks at once."""
    attrs = otel._span_attributes(
        event_type="verdict.blocked",
        session_id="ses_abc",
        agent_id="claude-code",
        risk="critical",
        payload={"tool_name": "Bash", "reason": "rm -rf"},
    )
    assert attrs["gen_ai.operation.name"] == "verdict.blocked"
    assert attrs["gen_ai.conversation.id"] == "ses_abc"
    assert attrs["gen_ai.provider.name"] == "claude-code"
    assert attrs["gen_ai.tool.name"] == "Bash"
    assert attrs["gen_ai.agent.id"] == "claude-code"
    assert attrs["quill.risk"] == "critical"
    assert attrs["quill.event_type"] == "verdict.blocked"
    assert attrs["quill.reason"] == "rm -rf"


def test_provider_name_extracts_upstream() -> None:
    """An audit event tagged `agent_id="upstream:filesystem"` should
    surface as `gen_ai.provider.name = "filesystem"` so dashboards can
    filter per-MCP-upstream."""
    assert otel._provider_name("upstream:filesystem") == "filesystem"
    assert otel._provider_name("upstream:github") == "github"
    assert otel._provider_name("claude-code") == "claude-code"
    assert otel._provider_name("claude-code-sub") == "claude-code"
    assert otel._provider_name("quill.notify") == "quill"
    assert otel._provider_name("") == "unknown"


def test_span_attributes_redact_raw_args() -> None:
    """Args values must NEVER reach the span - same redaction stance as
    the audit log. Only schema-shape strings (reason, by, etc.) flow."""
    attrs = otel._span_attributes(
        event_type="tool.attempted",
        session_id="s",
        agent_id="root",
        risk="low",
        payload={
            "tool_name": "Bash",
            "args_preview": {"command": "rm -rf /etc/passwd"},  # MUST NOT appear
            "arg_keys": ["command"],  # MUST NOT appear
        },
    )
    serialized = "|".join(f"{k}={v}" for k, v in attrs.items())
    assert "/etc/passwd" not in serialized
    assert "rm -rf" not in serialized


def test_audit_emit_does_not_raise_when_otel_emit_throws() -> None:
    """Observability MUST NOT break the gate. If OTel internals raise,
    the audit chain still completes."""
    import secrets
    import tempfile
    from pathlib import Path

    from quill.audit import AuditLog

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "audit.log.jsonl"
        with (
            patch.object(otel, "emit_span", side_effect=RuntimeError("boom")),
            AuditLog(path=p, hmac_key=secrets.token_bytes(32)) as a,
        ):
            # Must not raise even though OTel emit "fails."
            a.emit(
                event_type="tool.attempted",
                session_id="s",
                agent_id="root",
                risk="low",
                payload={"tool_name": "Bash"},
            )
        # And the audit chain still wrote a row.
        with p.open() as f:
            lines = f.readlines()
        assert len(lines) == 1
