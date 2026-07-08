"""nota: the pause button between AI agents and the things you can't undo.

An MCP proxy server that:
  - captures the session intent at start of a vibe-coding session,
  - records every tool call with a signed line in an append-only audit log,
  - blocks out-of-scope calls deterministically before the agent can even try,
  - pauses high-risk actions for a human ACK,
  - requires type-to-confirm on critical actions,
  - propagates governance through multi-agent delegation chains.

Place nota between your MCP client (Claude Code, Cursor, Cline) and your
upstream MCP servers (filesystem, GitHub, Postgres, Slack). Once you're inside
the gate, you can breathe.

License: MIT
"""

from nota._version import __version__
from nota.audit import AuditLog
from nota.errors import (
    ConfirmationMismatch,
    HumanDeclined,
    NotaError,
    PolicyDenied,
    ScopeViolation,
)
from nota.policy import (
    CommandClassification,
    Risk,
    Scope,
    SessionIntent,
    classify,
    classify_command,
)

__all__ = [
    "AuditLog",
    "CommandClassification",
    "ConfirmationMismatch",
    "HumanDeclined",
    "NotaError",
    "PolicyDenied",
    "Risk",
    "Scope",
    "ScopeViolation",
    "SessionIntent",
    "__version__",
    "classify",
    "classify_command",
]
