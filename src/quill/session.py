"""Multi-agent session model: parent sessions and sub-agents.

The wedge nobody else has: governance that propagates *through* a delegation
chain. When agent A spawns agent B as a sub-task, B inherits a strictly
attenuated subset of A's scope. B's audit events record both its own
agent_id and parent_agent_id, so the delegation graph is reconstructable
from the log alone.

Attenuation is the rule, not a default. A child cannot ever exceed its
parent's scope. If a config tries to grant a child a scope its parent
doesn't carry, it's rejected at construction time, not at call time.

Usage:

    with SessionTree(intent="Ship the dashboard", scope=["repo:write"]) as root:
        with root.sub_agent(name="planner", intent="break it into PRs",
                            scope=["repo:read"]) as planner:
            # planner can read but not write
            ...

        with root.sub_agent(name="coder", intent="implement",
                            scope=["repo:write:src/dashboard"]) as coder:
            # coder writes, but only inside src/dashboard
            ...
"""

from __future__ import annotations

import contextlib
import secrets
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from quill.audit import AuditLog
from quill.errors import QuillError
from quill.policy import Scope, SessionIntent


@dataclass(slots=True)
class SubAgentExceedsParentScope(QuillError):
    """Raised when a child sub-agent declares a scope its parent doesn't have.

    Attenuation is one of the strongest guarantees Quill provides; violating
    it would make multi-agent governance worthless. We refuse at session
    construction, not at first call.
    """

    parent_scope: tuple[Scope, ...]
    child_scope: tuple[Scope, ...]
    offender: Scope

    def __post_init__(self) -> None:
        super().__init__(
            f"sub-agent scope {self.offender} is not covered by any parent "
            f"scope. attenuation must be a strict subset."
        )


def _scope_subset(child: Scope, parent: Scope) -> bool:
    """True iff `child` is at least as restrictive as `parent`.

    Child must match same namespace, same action (or more specific), and
    if parent has no resource constraint, child can have any resource;
    if parent has a resource, child's resource must contain or equal parent's.
    """
    if child.namespace != parent.namespace:
        return False
    if child.action != parent.action:
        # Allow narrowing only on action prefix (e.g., parent "write" -> child "write:logs")
        # but for v1 we require exact action match. Future: more flexible matching.
        return False
    if parent.resource is None:
        return True
    if child.resource is None:
        return False
    # child.resource must extend (be more specific than) parent's
    return parent.resource in child.resource or child.resource == parent.resource


def _verify_attenuation(
    parent_scope: tuple[Scope, ...],
    child_scope: tuple[Scope, ...],
) -> None:
    """Raise SubAgentExceedsParentScope if any child scope isn't covered."""
    for child in child_scope:
        if not any(_scope_subset(child, p) for p in parent_scope):
            raise SubAgentExceedsParentScope(
                parent_scope=parent_scope,
                child_scope=child_scope,
                offender=child,
            )


@dataclass(slots=True)
class SessionNode:
    """A single node in the delegation tree.

    Each running agent (root or sub) gets one. The audit log references this
    node's id on every event it emits, so the log is graph-reconstructable.
    """

    id: str
    name: str
    intent: SessionIntent
    parent_id: str | None
    started_at: datetime
    children: list[SessionNode] = field(default_factory=list)
    closed_at: datetime | None = None
    # rolling counters for the watchable tree view
    actions_attempted: int = 0
    actions_blocked: int = 0
    spend_usd: float = 0.0
    pending_ack: tuple[str, ...] = ()


@dataclass(slots=True)
class SessionTree:
    """Owns the whole delegation tree for a single quill run.

    One per `quill serve` process. Hands out SessionNode handles and
    enforces scope attenuation when sub-agents are created.
    """

    root: SessionNode
    audit: AuditLog
    _all_nodes: dict[str, SessionNode] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def create(
        cls,
        *,
        intent: str,
        scope: tuple[Scope, ...],
        budget_usd: float | None,
        audit: AuditLog,
        session_id: str | None = None,
    ) -> SessionTree:
        sid = session_id or "ses_" + secrets.token_hex(4)
        root_intent = SessionIntent(
            session_id=sid,
            intent=intent,
            scope=scope,
            budget_usd=budget_usd,
        )
        root = SessionNode(
            id=sid,
            name="root",
            intent=root_intent,
            parent_id=None,
            started_at=datetime.now(UTC),
        )
        tree = cls(root=root, audit=audit)
        tree._all_nodes[sid] = root
        audit.emit(
            event_type="session.start",
            session_id=sid,
            agent_id=sid,
            payload={
                "name": "root",
                "intent": intent,
                "scope": [str(s) for s in scope],
                "budget_usd": budget_usd,
                "parent_id": None,
            },
            force_fsync=True,
        )
        return tree

    def __enter__(self) -> SessionTree:
        return self

    def __exit__(self, *_: object) -> None:
        self.audit.emit(
            event_type="session.end",
            session_id=self.root.id,
            agent_id=self.root.id,
            payload={
                "actions_attempted": self.root.actions_attempted,
                "actions_blocked": self.root.actions_blocked,
                "spend_usd": round(self.root.spend_usd, 4),
            },
            force_fsync=True,
        )
        self.root.closed_at = datetime.now(UTC)

    @contextlib.contextmanager
    def sub_agent(
        self,
        *,
        name: str,
        intent: str,
        scope: tuple[Scope, ...],
        parent_id: str | None = None,
    ) -> Iterator[SessionNode]:
        """Spawn a child agent. Scope is attenuated against the parent.

        Raises SubAgentExceedsParentScope if any declared child scope is not
        covered by the parent's. This is enforced at construction, before
        any tool call.
        """
        with self._lock:
            parent = self._all_nodes[parent_id] if parent_id is not None else self.root
            _verify_attenuation(parent.intent.scope, scope)

            sub_id = "ses_" + secrets.token_hex(4)
            sub_intent = SessionIntent(
                session_id=sub_id,
                intent=intent,
                scope=scope,
                # Budget is shared across the whole tree; child has no separate cap.
                budget_usd=parent.intent.budget_usd,
                parent_session_id=parent.id,
            )
            node = SessionNode(
                id=sub_id,
                name=name,
                intent=sub_intent,
                parent_id=parent.id,
                started_at=datetime.now(UTC),
            )
            parent.children.append(node)
            self._all_nodes[sub_id] = node

        self.audit.emit(
            event_type="agent.spawned",
            session_id=self.root.id,
            agent_id=node.id,
            payload={
                "name": name,
                "intent": intent,
                "scope": [str(s) for s in scope],
                "parent_id": parent.id,
                "parent_name": parent.name,
            },
            force_fsync=True,
        )

        try:
            yield node
        finally:
            node.closed_at = datetime.now(UTC)
            self.audit.emit(
                event_type="agent.closed",
                session_id=self.root.id,
                agent_id=node.id,
                payload={
                    "name": name,
                    "actions_attempted": node.actions_attempted,
                    "actions_blocked": node.actions_blocked,
                    "spend_usd": round(node.spend_usd, 4),
                    "duration_s": round(time.time() - node.started_at.timestamp(), 2),
                },
            )

    # --- bookkeeping helpers, called by the proxy on every tool call ---

    def record_attempt(self, agent_id: str) -> None:
        if (n := self._all_nodes.get(agent_id)) is not None:
            n.actions_attempted += 1

    def record_block(self, agent_id: str) -> None:
        if (n := self._all_nodes.get(agent_id)) is not None:
            n.actions_blocked += 1

    def record_spend(self, agent_id: str, dollars: float) -> None:
        # propagate up the tree so root spend is the rollup
        node = self._all_nodes.get(agent_id)
        while node is not None:
            node.spend_usd += dollars
            node = self._all_nodes.get(node.parent_id) if node.parent_id else None
        # check budget
        budget = self.root.intent.budget_usd
        if budget is not None and self.root.spend_usd > budget:
            self.audit.emit(
                event_type="budget.exceeded",
                session_id=self.root.id,
                agent_id="root",
                risk="critical",
                payload={
                    "spend_usd": round(self.root.spend_usd, 4),
                    "budget_usd": budget,
                },
                force_fsync=True,
            )

    def get_node(self, agent_id: str) -> SessionNode | None:
        return self._all_nodes.get(agent_id)

    def all_nodes(self) -> list[SessionNode]:
        return list(self._all_nodes.values())
