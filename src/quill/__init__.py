"""quill: the pause button between AI agents and the things you can't undo.

An MCP proxy server that:
  - captures the session intent at start of a vibe-coding session,
  - records every tool call with a signed line in an append-only audit log,
  - blocks out-of-scope calls deterministically before the agent can even try,
  - pauses high-risk actions for a human ACK,
  - requires type-to-confirm on critical actions,
  - propagates governance through multi-agent delegation chains.

Place quill between your MCP client (Claude Code, Cursor, Cline) and your
upstream MCP servers (filesystem, GitHub, Postgres, Slack). Once you're inside
the gate, you can breathe.

License: MIT
"""

from quill._version import __version__
from quill.audit import AuditLog
from quill.errors import (
    ConfirmationMismatch,
    HumanDeclined,
    PolicyDenied,
    QuillError,
    ScopeViolation,
)
from quill.policy import (
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
    "PolicyDenied",
    "QuillError",
    "Risk",
    "Scope",
    "ScopeViolation",
    "SessionIntent",
    "__version__",
    "classify",
    "classify_command",
]
