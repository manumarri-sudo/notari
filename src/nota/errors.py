"""Public exception hierarchy.

Every public-API failure raises a subclass of NotaError. The proxy never lets
a stdlib exception leak across the trust boundary; everything is wrapped here
so audit-log entries always carry structured context.
"""

from __future__ import annotations


class NotaError(Exception):
    """Base for every nota public exception."""


class PolicyDenied(NotaError):
    """A tool call was refused by the policy layer."""


class ScopeViolation(PolicyDenied):
    """A tool call targeted a resource outside the session's declared scope.

    Caught deterministically before the human is even prompted.
    """


class HumanDeclined(PolicyDenied):
    """The operator declined a high-risk tool call at the prompt."""


class ConfirmationMismatch(PolicyDenied):
    """The operator typed the wrong action name on a critical-risk confirm."""


class ConfigError(NotaError):
    """The on-disk config could not be parsed or is invalid."""


class TransportError(NotaError):
    """A failure communicating with an upstream MCP server."""


class AuditError(NotaError):
    """The audit log could not be written or has detected tampering."""
