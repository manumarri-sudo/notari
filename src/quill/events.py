"""Audit-log event types - single source of truth.

Each event written to ~/.quill/audit.log.jsonl carries a `type` field whose
value comes from this module. Centralizing the constants prevents string-typo
drift across writers and readers.

Schema follows the internal A2A event-schema design notes §6. The split:

  Existing (already shipped):
    tool.attempted   tool.executed   verdict.allowed   verdict.blocked
    verdict.ask      verdict.scope_violation     budget.exceeded
    chain.repaired

  New, write-time (introduced here):
    session.open                  frame boundary
    session.close                 frame boundary
    session.receipt               derived; emitted at session-end
    session.taint.update          lethal-trifecta observation
    agent.handoff.out             A2A bridge - sender side
    agent.handoff.in              A2A bridge - receiver side
    agent.cascade.affected        A2A bridge - multi-consumer detection
    agent.flag.uncertain          agent self-flags an uncertainty
    policy.decayed                permission decayed; override fell back
"""

from __future__ import annotations

from typing import Final

# Existing event types (kept here so all writers reference one constant).
TOOL_ATTEMPTED: Final[str] = "tool.attempted"
TOOL_EXECUTED: Final[str] = "tool.executed"
VERDICT_ALLOWED: Final[str] = "verdict.allowed"
VERDICT_BLOCKED: Final[str] = "verdict.blocked"
VERDICT_ASK: Final[str] = "verdict.ask"
VERDICT_SCOPE_VIOLATION: Final[str] = "verdict.scope_violation"
BUDGET_EXCEEDED: Final[str] = "budget.exceeded"
CHAIN_REPAIRED: Final[str] = "chain.repaired"

# New event types (this PR).
SESSION_OPEN: Final[str] = "session.open"
SESSION_CLOSE: Final[str] = "session.close"
SESSION_RECEIPT: Final[str] = "session.receipt"
SESSION_TAINT_UPDATE: Final[str] = "session.taint.update"
AGENT_HANDOFF_OUT: Final[str] = "agent.handoff.out"
AGENT_HANDOFF_IN: Final[str] = "agent.handoff.in"
AGENT_CASCADE_AFFECTED: Final[str] = "agent.cascade.affected"
AGENT_FLAG_UNCERTAIN: Final[str] = "agent.flag.uncertain"
POLICY_DECAYED: Final[str] = "policy.decayed"

# Touch ID / hardware-attested approval gate (macOS-only).
APPROVE_BIOMETRIC_OK: Final[str] = "approve.biometric.ok"
APPROVE_BIOMETRIC_DENY: Final[str] = "approve.biometric.deny"
APPROVE_BIOMETRIC_SKIPPED: Final[str] = "approve.biometric.skipped"

# Gate pause (`quill off` / `quill on`) - the bounded, audited off switch.
# gate.paused / gate.resumed bracket a window during which the gate let
# everything through; verdict.allowed entries inside the window carry
# `gate_paused: true` so the window's contents are reconstructable.
GATE_PAUSED: Final[str] = "gate.paused"
GATE_RESUMED: Final[str] = "gate.resumed"

# Change Control (CI/CD pull-request gate). `quill begin` captures the
# human-approved task into a contract; `quill verify` compares the diff to
# that contract and emits a verdict. Both are audit-chained so a Change
# Passport can cite a tamper-evident record of when the task was approved
# and what the verification saw. Human-readable names: "Contract Created"
# and "Verification Run".
CONTRACT_CREATED: Final[str] = "contract.created"
VERIFICATION_RUN: Final[str] = "verification.run"

# Set of all known event types - useful for validation / filtering.
ALL_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        TOOL_ATTEMPTED,
        TOOL_EXECUTED,
        VERDICT_ALLOWED,
        VERDICT_BLOCKED,
        VERDICT_ASK,
        VERDICT_SCOPE_VIOLATION,
        BUDGET_EXCEEDED,
        CHAIN_REPAIRED,
        SESSION_OPEN,
        SESSION_CLOSE,
        SESSION_RECEIPT,
        SESSION_TAINT_UPDATE,
        AGENT_HANDOFF_OUT,
        AGENT_HANDOFF_IN,
        AGENT_CASCADE_AFFECTED,
        AGENT_FLAG_UNCERTAIN,
        POLICY_DECAYED,
        APPROVE_BIOMETRIC_OK,
        APPROVE_BIOMETRIC_DENY,
        APPROVE_BIOMETRIC_SKIPPED,
        GATE_PAUSED,
        GATE_RESUMED,
        CONTRACT_CREATED,
        VERIFICATION_RUN,
    },
)
