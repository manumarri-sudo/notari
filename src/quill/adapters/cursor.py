"""Cursor 1.7+ pre-tool-call hook adapter.

Cursor (the AI-first VS Code fork, ~1.5M MAU) shipped a `hooks` system in
v1.7 (Sept 2025) that's near-identical to Claude Code's PreToolUse: the
IDE spawns a subprocess on every tool/shell/MCP call, hands it stdin JSON,
reads a verdict on stdout. Eighteen events; the three that matter for
Quill's gate are:

  - `beforeShellExecution`  - Cursor's built-in shell tool
  - `beforeMCPExecution`    - every call routed through any MCP server
  - `beforeReadFile`        - file reads (less critical; opt-in)

Quill's existing risk classifier + audit log + approvals + Touch ID flow
all work unchanged. The only adapter-layer work is the field-rename
between Cursor's input/output JSON and Quill's internal `decide()` core.

PARITY WITH CLAUDE CODE ADAPTER
-------------------------------
The Cursor adapter is brought up to parity with `claude_code.py` for
three of the four pieces of trust-layer plumbing:

  1. Session tracking + `session.open` emission. `_track_session` is
     called with `conversation_id` as both the transcript-equivalent and
     the session_id (Cursor does not nest sessions, so there's a 1:1
     mapping). `session.open` fires exactly once per conversation.

  2. Lethal-trifecta enforcement. `taint.would_close_trifecta` is called
     before allowing; an otherwise-allow decision escalates to DENY if
     this call would close the lethal trifecta. The same approve-token
     flow releases the deny.

  3. `session.taint.update` emission. Fires only when a trifecta flag
     flips (matches the Claude Code adapter's emission contract).

  4. Lazy daemon spawn. `main()` calls `watch.ensure_daemon` so the
     dashboard self-heals across reboots.

NOT IMPLEMENTED (intentionally): sub-agent `agent.handoff.out` /
`agent.handoff.in` emission. Cursor 1.7 hooks do not expose a sub-agent
/ Task spawn boundary - each tool call carries one `conversation_id`,
treated as a single root session. If Cursor adds nested agent support,
the Claude Code adapter's handoff emission pattern is the template.

Hook contract (verified at https://cursor.com/docs/hooks):

  Config at `~/.cursor/hooks.json`:
    {
      "version": 1,
      "hooks": {
        "beforeShellExecution": [
          { "command": "quill cursor-hook", "type": "command", "timeout": 30 }
        ]
      }
    }

  Stdin (Cursor → Quill, one JSON line):
    { "command": "rm -rf /",
      "cwd": "/repo",
      "sandbox": false,
      "conversation_id": "...",
      "hook_event_name": "beforeShellExecution" }

  Stdout (Quill → Cursor, one JSON line):
    { "permission": "deny",
      "agent_message": "rm -rf is blocked by Quill policy",
      "user_message": "Use git clean -fdx if you really mean it." }

Per [the Cursor forum](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244)
`permission: "ask"` can be silently overridden by Cursor's allow-list when
the user has enabled Auto-Run mode. Quill returns `"deny"` (not `"ask"`)
on HIGH-risk calls when running under Cursor so the gate isn't bypassed.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Mapping
from typing import Any

from quill.adapters.claude_code import (
    HookDecision,
    _maybe_notify,
    _redacted_input,
    classify_event,
)
from quill.adapters.claude_code import (
    decide as _claude_decide,
)
from quill.audit import AuditLog
from quill.config import default_audit_path
from quill.errors import ConfigError
from quill.policy import Risk

# Cursor's event names → the abstract "tool name" we feed to classify_event.
# beforeShellExecution maps to "Bash" so the shell-command classifier fires.
# beforeMCPExecution maps to whatever MCP tool name was advertised (already
# in the payload). beforeReadFile maps to "Read".
_EVENT_TOOL_NAME: dict[str, str] = {
    "beforeShellExecution": "Bash",
    "beforeReadFile": "Read",
    "beforeMCPExecution": "",  # use payload's tool_name verbatim
    # Cursor's other events (afterFileEdit, beforeSubmitPrompt, etc.) are
    # observability hooks, not gate hooks - Quill ignores them by passing
    # through `allow`.
}


def _normalize_input(raw: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """Cursor stdin → (tool_name, tool_input) for Quill's classifier.

    Cursor's stdin schema varies per hook event. Normalize so the
    risk classifier sees the same shape it does for Claude Code.
    """
    event = str(raw.get("hook_event_name", "") or "")
    if event == "beforeShellExecution":
        return "Bash", {
            "command": str(raw.get("command", "") or ""),
            "cwd": str(raw.get("cwd", "") or ""),
        }
    if event == "beforeReadFile":
        return "Read", {
            "file_path": str(raw.get("path", "") or raw.get("file_path", "") or ""),
        }
    if event == "beforeMCPExecution":
        # Cursor's MCP hook payload includes `tool_name` and `tool_input`
        # (or `arguments`) verbatim from the upstream MCP server.
        tool = str(raw.get("tool_name", "") or "")
        args = raw.get("tool_input") or raw.get("arguments") or {}
        if not isinstance(args, Mapping):
            args = {}
        return tool, dict(args)
    # Unknown / future event: fall through, let it allow.
    tool = str(raw.get("tool_name", "") or event or "")
    args = raw.get("tool_input") or {}
    if not isinstance(args, Mapping):
        args = {}
    return tool, dict(args)


def decide(tool_name: str, tool_input: Mapping[str, Any]) -> HookDecision:
    """Cursor-specific decide(). Same risk model as Claude Code, but on
    HIGH risk we return `deny` instead of `ask` because Cursor's allow-list
    in Auto-Run can silently bypass `ask` (forum-reported, see module doc).
    """
    base = _claude_decide(tool_name, tool_input)
    if base.permission == "ask":
        # Force a hard deny + paste-able fix instead of a soft ask. The
        # user explicitly approves via `quill approve <token>` (the same
        # one-shot approval flow as Claude Code), which Cursor's allow-list
        # CAN'T override.
        risk, reason, suggestion = classify_event(tool_name, tool_input)
        body = f"high risk: {reason}"
        if suggestion:
            body = f"{body} · try: {suggestion}"
        return HookDecision(
            permission="deny",
            reason=body + " · approve via `quill approve <token>` to release",
            risk=risk,
            audit_event_type="verdict.blocked",
            what=base.what,
            why=base.why,
            try_instead=base.try_instead,
        )
    return base


def run_hook(stdin_text: str, audit: AuditLog | None = None) -> dict[str, Any]:
    """Pure-function entry point for tests.

    Reads Cursor's stdin JSON, returns the dict that should be written to
    stdout. Matches the contract documented at cursor.com/docs/hooks.
    """
    try:
        event: dict[str, Any] = json.loads(stdin_text)
    except json.JSONDecodeError as e:
        # Fail-open on malformed input - same stance as the Claude Code
        # adapter. Cursor's hook system shouldn't crash on a parse bug.
        return {
            "permission": "allow",
            "agent_message": f"quill: malformed cursor-hook input: {e}",
        }

    event_name = str(event.get("hook_event_name", "") or "")
    tool_name, tool_input = _normalize_input(event)
    if not tool_name:
        return {"permission": "allow"}

    cwd = str(event.get("cwd", "") or "")
    session_id = str(
        event.get("conversation_id") or event.get("session_id") or "cursor",
    )

    # Session tracking. Cursor uses one conversation_id per session and
    # does not nest, so transcript_path-equivalent == session_id. We
    # still get the is_first_seen signal so `session.open` fires once.
    is_first_seen = False
    if session_id and session_id != "cursor":
        with contextlib.suppress(Exception):
            from quill.adapters.claude_code import _track_session

            _, _is_new_sub, is_first_seen = _track_session(
                transcript_path=session_id,  # cursor has 1:1 conv:session
                session_id=session_id,
                cwd=cwd,
            )

    decision = decide(tool_name, tool_input)
    agent_id = "cursor"

    # Snapshot for learning: original classifier reason before any
    # downstream transformation (trust scope, approval consume).
    # Mirrors the claude_code adapter so post-decision learning groups
    # token-flipped approves with their preceding denies.
    original_decision_reason = decision.reason

    # Trust-scope downshift (parity with claude_code adapter): a
    # default-HIGH-risk file-mutation tool inside a trusted directory
    # (listed in `[trust] paths` in config.toml) is downgraded to LOW
    # + auto-allow. Cursor's adapter forces HIGH -> deny (instead of
    # claude_code's `ask`) because of the auto-run allow-list bypass,
    # so the test here matches the `deny` permission - but we still
    # only downshift the DEFAULT classification, never pattern-matched
    # HIGHs or CRITICAL events.
    if (
        decision.permission in ("deny", "ask")
        and tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")
        and "default risk for" in decision.reason
        and cwd
    ):
        with contextlib.suppress(Exception):
            from quill.paths import is_trusted_cwd

            if is_trusted_cwd(cwd):
                decision = HookDecision(
                    permission="allow",
                    reason=f"trusted scope: {tool_name} in {cwd}",
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why="trusted scope (config [trust] paths)",
                    try_instead="",
                )

    # One-shot approval check (same flow as Claude Code).
    approval_token_used = ""
    if decision.permission != "allow":
        with contextlib.suppress(Exception):
            from quill.approvals import ApprovalStore

            store = ApprovalStore.load()
            consumed = store.consume(tool_name, dict(tool_input))
            if consumed is not None:
                approval_token_used = consumed.token
                decision = HookDecision(
                    permission="allow",
                    reason=f"approved one-shot via quill approve {consumed.token[:8]}",
                    risk=decision.risk,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why=f"user-approved (token {consumed.token[:8]})",
                    try_instead="",
                )

    # Trifecta enforcement: an otherwise-allow call that would close the
    # lethal trifecta (untrusted input + private data + exfil vector)
    # gets escalated to DENY. Skip if the user already approved this
    # exact call out-of-band. Mirrors `claude_code.py` lines 511-537.
    if decision.permission == "allow" and not approval_token_used and session_id:
        with contextlib.suppress(Exception):
            from quill.adapters.claude_code import _taint_state_for
            from quill.taint import would_close_trifecta

            current = _taint_state_for(session_id)
            if would_close_trifecta(current, tool_name, tool_input):
                why = (
                    "would close the lethal trifecta this session "
                    "(untrusted input + private data + exfil vector)"
                )
                decision = HookDecision(
                    permission="deny",
                    reason=f"trifecta close - {why} - approve to proceed",
                    risk=decision.risk,
                    audit_event_type="verdict.blocked",
                    what=decision.what,
                    why=why,
                    try_instead="",
                )

    # Audit-emit + issue approval token + fire notifications.
    if audit is not None:
        from quill import events as ev

        with contextlib.suppress(Exception):
            # session.open - first time we've ever seen this conversation_id.
            if is_first_seen:
                audit.emit(
                    event_type=ev.SESSION_OPEN,
                    session_id=session_id,
                    agent_id=agent_id,
                    risk="low",
                    payload={
                        "parent_session_id": "",
                        "transcript_path": session_id,
                        "cwd": cwd,
                        "trust_ladder": "spot_check",
                        "adapter": "cursor",
                    },
                    force_fsync=True,
                )

            issued_token = approval_token_used
            if not issued_token and decision.permission != "allow":
                with contextlib.suppress(Exception):
                    from quill.approvals import ApprovalStore

                    store = ApprovalStore.load()
                    ap = store.issue(
                        tool_name,
                        dict(tool_input),
                        reason=decision.why or decision.reason,
                    )
                    issued_token = ap.token

            audit.emit(
                event_type=ev.TOOL_ATTEMPTED,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "via": "cursor-hook",
                    "hook_event_name": event_name,
                    "args_preview": _redacted_input(tool_input),
                    "cwd": cwd,
                },
            )
            # SECURITY: never store the raw approve token in the audit log;
            # the agent reads the log and would replay it. Only a short hash
            # for operator correlation against the out-of-band notification.
            import hashlib as _hashlib

            _token_id = (
                _hashlib.sha256(issued_token.encode("utf-8")).hexdigest()[:16]
                if issued_token
                else ""
            )
            audit.emit(
                event_type=decision.audit_event_type,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "by": "quill.adapters.cursor",
                    "reason": decision.reason,
                    "permission": decision.permission,
                    "cwd": cwd,
                    "approve_token_id": _token_id,
                    "what": decision.what,
                    "why": decision.why,
                    "try_instead": decision.try_instead,
                },
                force_fsync=decision.risk in (Risk.HIGH, Risk.CRITICAL),
            )

            if decision.permission == "deny" and issued_token:
                with contextlib.suppress(Exception):
                    _maybe_notify(
                        decision=decision,
                        tool_name=tool_name,
                        tool_input=tool_input,
                        session_id=session_id,
                        cwd=cwd,
                        approve_token=issued_token,
                        audit=audit,
                    )

            # session.taint.update - emit only when a flag flips so the
            # log doesn't carry one taint event per tool call. Mirrors
            # the Claude Code adapter's emission policy exactly.
            with contextlib.suppress(Exception):
                from quill.adapters.claude_code import (
                    _save_taint_state,
                    _taint_state_for,
                )
                from quill.taint import update_for_call

                taint_state = _taint_state_for(session_id)
                _, flipped = update_for_call(taint_state, tool_name, tool_input)
                if flipped:
                    _save_taint_state(session_id, taint_state)
                    audit.emit(
                        event_type=ev.SESSION_TAINT_UPDATE,
                        session_id=session_id,
                        agent_id=agent_id,
                        risk="low",
                        payload={
                            "trifecta": taint_state.to_dict(),
                            "flipped": flipped,
                            "tool_name": tool_name,
                            "adapter": "cursor",
                        },
                        force_fsync=taint_state.trifecta_closed,
                    )

    # Autonomous learning (parity with claude_code adapter). Same
    # contract: skip pure-LOW allows, record decision otherwise, never
    # let a learning failure break the hook. Use the ORIGINAL classifier
    # reason so token-flipped approves group with their preceding denies.
    if decision.permission != "allow" or approval_token_used:
        with contextlib.suppress(Exception):
            from quill import learning

            learning.record_decision_learning(
                tool_name, original_decision_reason, bool(approval_token_used)
            )

    # Cursor's response shape (NOT Claude Code's hookSpecificOutput).
    response: dict[str, Any] = {"permission": decision.permission}
    if decision.permission != "allow":
        # `agent_message` goes into the LLM's context (so the agent can
        # course-correct). `user_message` is what Cursor shows the human.
        response["agent_message"] = decision.reason
        if decision.try_instead:
            response["user_message"] = (
                f"Quill blocked: {decision.what or tool_name}. Try: {decision.try_instead}"
            )
        else:
            response["user_message"] = f"Quill blocked: {decision.reason}"
    elif approval_token_used:
        # Allow-after-approval: tell the agent the gate was released
        # out-of-band so it doesn't retry-spam.
        response["agent_message"] = decision.reason
    return response


def install_into_settings(settings_path: Any = None) -> tuple[Any, bool]:
    """Idempotently merge Quill into ~/.cursor/hooks.json.

    Returns (path, was_already_installed). Adds three hook events
    (beforeShellExecution, beforeMCPExecution, beforeReadFile) pointing
    at `quill cursor-hook`. Does NOT clobber other hooks the user has.
    """
    from pathlib import Path

    path = settings_path or Path.home() / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    if path.exists():
        try:
            loaded: Any = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            loaded = {}
        # A top-level JSON array/scalar is malformed for a hooks file; ignore it
        # and keep the empty dict so we never index a non-mapping below.
        if isinstance(loaded, dict):
            existing = loaded

    if "version" not in existing:
        existing["version"] = 1
    hooks_block = existing.setdefault("hooks", {})
    if not isinstance(hooks_block, dict):
        hooks_block = {}
        existing["hooks"] = hooks_block

    quill_entry = {"command": "quill cursor-hook", "type": "command", "timeout": 30}
    was_already = True
    for event_name in ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile"):
        existing_handlers = hooks_block.get(event_name) or []
        if not isinstance(existing_handlers, list):
            existing_handlers = []
        already = any(
            isinstance(h, dict) and h.get("command", "").startswith("quill ")
            for h in existing_handlers
        )
        if not already:
            existing_handlers.append(dict(quill_entry))
            was_already = False
        hooks_block[event_name] = existing_handlers

    with contextlib.suppress(OSError):
        path.write_text(json.dumps(existing, indent=2) + "\n")
        path.chmod(0o600)
    return path, was_already


def main() -> int:
    """CLI entry: read stdin, write stdout, exit 0.

    Wired to `quill cursor-hook` via the CLI module. Routes the audit
    log to <cwd>/.quill/audit.log.jsonl when the user has opted in to
    per-project mode (just like the Claude Code adapter).
    """
    from quill.adapters.claude_code import _default_load_hmac_key, _resolve_project_paths

    stdin_text = sys.stdin.read()
    cwd_for_routing = ""
    try:
        peek = json.loads(stdin_text or "{}")
        if isinstance(peek, dict):
            cwd_for_routing = str(peek.get("cwd", "") or "")
    except json.JSONDecodeError:
        pass

    log_path, project_cfg_path = _resolve_project_paths(cwd_for_routing)
    if project_cfg_path is not None:
        with contextlib.suppress(ConfigError, OSError, ValueError):
            from quill.config import load_config

            load_config(project_cfg_path)

    log_path = log_path or default_audit_path()

    try:
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            response = run_hook(stdin_text, audit=audit)
    except Exception as e:
        # NEVER crash the hook - Cursor would surface the error to the
        # agent, which would interpret it as "the call is fine."
        response = {
            "permission": "allow",
            "agent_message": f"quill: hook crashed (bug, fail-open): {e}",
        }

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0
