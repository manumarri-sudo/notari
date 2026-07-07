"""OpenTelemetry GenAI emission - dual-write from the audit log.

When `quill[otel]` is installed AND OTel is configured (env var
`OTEL_EXPORTER_OTLP_ENDPOINT` or programmatic setup), every audit-log
event also produces an OpenTelemetry span following the GenAI semantic
conventions. This lets shops that already pay for Datadog / Langfuse /
Phoenix / Honeycomb ingest Quill data without inventing a new format.

Spec: https://opentelemetry.io/docs/specs/semconv/gen-ai/
        https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/

Decisions (from the internal polish-and-launch design notes §3):

- Optional extra (`quill[otel]`), not default-on. Footprint: 3
  Apache-2.0 packages, ~450 KB total. The audit log remains the
  authoritative store; OTel is observability tooling on top.
- Dual-write AFTER chain write so OTel never corrupts the audit log.
  If the OTel call fails, the audit chain is unaffected.
- Span names follow GenAI semconv: `execute_tool {tool_name}` for
  tool calls, `agent.session` for the session frame.
- `gen_ai.conversation.id = session_id`, `gen_ai.tool.name = tool_name`,
  `gen_ai.provider.name = "claude-code"` (or upstream MCP server name
  when the call comes via the proxy).
- `gen_ai.operation.name` = the audit event_type (e.g. "verdict.blocked")
  so observability dashboards can filter by Quill's own taxonomy too.

If the user doesn't `pip install 'quill[otel]'`, the import in this
module fails gracefully and `EmitToOtel.is_active()` returns False -
no behavior change in the audit hot path.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from typing import Any

# Lazy-import OpenTelemetry. Module-level import would force the dep
# even when the user didn't install the extra. We want a clean
# "not installed -> no-op" path, not a hard ImportError.
_otel_tracer: Any = None
_otel_loaded: bool = False

# Dual-write failure tracking. `audit.AuditLog.emit` increments this
# counter on every OTel emission that raises. The first such failure
# also writes a one-shot warning to stderr so a silent misconfiguration
# is visible. `quill doctor` surfaces the count.
_dual_write_failed_count: int = 0
_dual_write_failed_announced: bool = False


def _try_load_otel() -> bool:
    """Initialize an OpenTelemetry tracer if the SDK is available.

    Returns True if OTel is wired up and we should emit spans, False
    otherwise. Idempotent - safe to call from the hot path.
    """
    global _otel_tracer, _otel_loaded
    if _otel_loaded:
        return _otel_tracer is not None
    _otel_loaded = True
    try:
        from opentelemetry import trace

        _otel_tracer = trace.get_tracer("quill", "0.2.0")
    except ImportError:
        _otel_tracer = None
    return _otel_tracer is not None


def is_active() -> bool:
    """True iff the OTel SDK is importable AND a tracer is registered."""
    return _try_load_otel()


# ---------------------------------------------------------------------------
# Mapping from Quill audit events to OTel GenAI span names + attributes


_TOOL_EVENT_TYPES = frozenset(
    {
        "tool.attempted",
        "tool.executed",
        "tool.completed",
        "verdict.allowed",
        "verdict.blocked",
        "verdict.ask",
        "verdict.scope_violation",
    },
)


def _span_attributes(
    event_type: str,
    session_id: str,
    agent_id: str,
    risk: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the OTel attribute dict for one audit event.

    Per GenAI semconv:
        gen_ai.operation.name        - required, the operation kind
        gen_ai.conversation.id       - required, the session-equivalent
        gen_ai.tool.name             - required for tool spans
        gen_ai.provider.name         - required, the agent platform
        gen_ai.agent.id              - recommended
    Plus Quill-specific attributes prefixed `quill.*` so dashboards
    can carry the audit-log taxonomy through unchanged.
    """
    tool_name = str(payload.get("tool_name", "") or "")
    attrs: dict[str, Any] = {
        "gen_ai.operation.name": event_type,
        "gen_ai.conversation.id": session_id,
        "gen_ai.agent.id": agent_id,
        "gen_ai.provider.name": _provider_name(agent_id),
        "quill.risk": risk,
        "quill.event_type": event_type,
    }
    if tool_name:
        attrs["gen_ai.tool.name"] = tool_name
    # Surface a few high-signal, low-risk payload fields. NEVER ship raw
    # arg values - same redaction stance as the audit log itself.
    for k in ("reason", "by", "approve_token", "what", "why", "try_instead"):
        v = payload.get(k)
        if isinstance(v, (str, int, float, bool)) and v != "":
            attrs[f"quill.{k}"] = v
    return attrs


def _provider_name(agent_id: str) -> str:
    """Map Quill's agent_id taxonomy to a GenAI semconv provider name."""
    if agent_id.startswith("upstream:"):
        return agent_id.split(":", 1)[1]
    if agent_id.startswith("claude-code"):
        return "claude-code"
    if agent_id == "quill.notify" or agent_id.startswith("quill."):
        return "quill"
    return agent_id or "unknown"


def _span_name(event_type: str, payload: Mapping[str, Any]) -> str:
    """GenAI semconv: `execute_tool {tool_name}` for tool spans."""
    if event_type in _TOOL_EVENT_TYPES:
        tool_name = str(payload.get("tool_name", "") or "tool")
        return f"execute_tool {tool_name}"
    if event_type.startswith("session."):
        return "agent.session"
    if event_type.startswith("agent.handoff"):
        return "agent.handoff"
    return event_type


def emit_span(
    *,
    event_type: str,
    session_id: str,
    agent_id: str,
    risk: str,
    payload: Mapping[str, Any] | None = None,
) -> None:
    """Emit one OTel span for an audit event. No-op if OTel isn't active.

    Spans are created and ended in the same call (point-in-time events).
    The OTel SDK handles batching + export to the configured collector.
    Failures are swallowed - observability MUST NOT break the gate.
    """
    if not is_active():
        return
    if _otel_tracer is None:
        return
    payload = payload or {}
    name = _span_name(event_type, payload)
    attrs = _span_attributes(event_type, session_id, agent_id, risk, payload)
    with (
        contextlib.suppress(Exception),
        _otel_tracer.start_as_current_span(
            name,
            attributes=attrs,
        ),
    ):
        # Tag failure spans so dashboards can filter by status without
        # relying on quill.event_type substring matching.
        if event_type in (
            "verdict.blocked",
            "verdict.scope_violation",
            "tool.errored",
            "upstream.error",
        ):
            from opentelemetry import trace
            from opentelemetry.trace import Status, StatusCode

            trace.get_current_span().set_status(
                Status(StatusCode.ERROR, description=event_type),
            )
