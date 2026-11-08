"""Notari Change Control for AI-authored code changes.

The CLI verifies Git changes against an approved contract and perimeter, then
produces a Change Passport. Strict deployment requires externally trusted keys
and an enforced CI check. Optional Claude Code and Cursor hooks classify tool
calls and retain local audit evidence; these hooks are defense in depth, not
an operating-system sandbox. See docs/SECURITY-MODEL.md for the bounded claims.

License: MIT
"""

from notari._version import __version__
from notari.audit import AuditLog
from notari.errors import (
    ConfirmationMismatch,
    HumanDeclined,
    NotariError,
    PolicyDenied,
    ScopeViolation,
)
from notari.policy import (
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
    "NotariError",
    "PolicyDenied",
    "Risk",
    "Scope",
    "ScopeViolation",
    "SessionIntent",
    "__version__",
    "classify",
    "classify_command",
]
