"""Claude Code PreToolUse hook adapter.

Claude Code's built-in tools (Bash, Edit, Write, Read, ...) do not flow
through any MCP server, so the Nota MCP proxy cannot see them. Claude Code
exposes a `PreToolUse` hook that fires synchronously before each tool call;
this adapter implements that hook contract so Nota can gate the built-ins.

Wiring (one paste into ~/.claude/settings.json):

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash|Edit|Write|NotebookEdit",
            "hooks": [
              { "type": "command", "command": "nota claude-hook", "timeout": 10 }
            ]
          }
        ]
      }
    }

The hook contract (Claude Code → stdin):

    {
      "session_id": "uuid",
      "transcript_path": "/path/to/session.jsonl",
      "cwd": "/current/dir",
      "permission_mode": "auto|plan|acceptEdits|dontAsk|default",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {"command": "rm -rf /"}
    }

The hook reply (stdout, exit 0):

    {
      "hookSpecificOutput": {
        "permissionDecision": "allow|deny|ask",
        "permissionDecisionReason": "<plain English>"
      }
    }

Mapping rules (defaults; per-tool overrides loaded from ~/.nota/config.toml):
    LOW      -> "allow"     (silent; logged)
    MEDIUM   -> "allow"     (silent; logged)
    HIGH     -> "ask"       (delegate confirmation to Claude Code's UI; logged)
    CRITICAL -> "deny"      (with plain-English reason; logged)

Every invocation appends an entry to the audit log regardless of decision,
so you can review what the agent attempted even when Claude Code's UI moved
on. The audit log path defaults to ~/.nota/audit.log.jsonl; override with
NOTA_LOG.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

if TYPE_CHECKING:
    from nota.taint import TaintState

from nota import secrets as _secrets
from nota.audit import AuditLog
from nota.config import default_audit_path, load_config
from nota.errors import ConfigError
from nota.policy import Risk, classify, classify_command

# Map Claude Code's built-in tool names to a default risk *when args do not
# carry enough info to classify by content*. Bash uses classify_command on
# args["command"]; everything else falls back to this table.
DEFAULT_BUILTIN_RISK: Final[Mapping[str, Risk]] = {
    "Bash": Risk.MEDIUM,  # superseded by classify_command on args["command"]
    "BashOutput": Risk.LOW,
    "KillShell": Risk.MEDIUM,
    "Edit": Risk.HIGH,
    "Write": Risk.HIGH,
    "NotebookEdit": Risk.HIGH,
    "Read": Risk.LOW,
    "Glob": Risk.LOW,
    "Grep": Risk.LOW,
    "WebFetch": Risk.MEDIUM,
    "WebSearch": Risk.LOW,
    "Task": Risk.MEDIUM,  # spawns a sub-agent; logged as such
    "TodoWrite": Risk.LOW,
}


# Structured classification SOURCE (audit #21). Defined once as a named alias so
# HookDecision and _classification_source stay in lockstep; the run_hook downshift
# guards gate on this field, never on the display `reason` string.
ClassifiedBy = Literal["default", "pattern", "secret", "namespace", "self_tamper", "override"]


@dataclass(slots=True)
class HookDecision:
    """The gate's verdict for a single Claude Code PreToolUse event.

    Carries the structured triple a notification needs:
      - what:        one-line summary of the call
      - why:         plain-English risk reason
      - try_instead: paste-able safer alternative (if any)

    `reason` is the compact form Claude Code's UI shows; the structured
    fields are passed to the notification dispatcher.
    """

    permission: str  # "allow" | "deny" | "ask"
    reason: str
    risk: Risk
    audit_event_type: str  # written to the audit log
    what: str = ""  # human-readable: "rm -rf node_modules"
    why: str = ""  # human-readable: "matches `rm -rf` rule"
    try_instead: str = ""  # paste-able alternative
    # Structured classification SOURCE. The run_hook downshift guards (trust
    # scope, promoted override, bypass mode) gate on THIS field, never on a
    # substring of the human-readable `reason`. Only "default" is eligible for
    # downshift; "pattern"/"secret"/"namespace"/"self_tamper"/"override" are
    # not, so a reason-wording change can't silently broaden a guard. (audit #21)
    classified_by: ClassifiedBy = "default"


def _default_load_hmac_key() -> bytes:
    """Mirror cli._hmac_key() but importable from the adapter without a circular import."""
    from nota.paths import default_path

    p = default_path("key", env_override="NOTA_KEY")
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    p.chmod(0o600)
    return key


def _detect_bypass_mode(hook_payload: Mapping[str, Any] | None = None) -> bool:
    """True if the user is in Claude Code's --dangerously-skip-permissions mode.

    Detection precedence:
      1. Hook payload field if Anthropic ships one (permission_mode, bypass_mode,
         dangerously_skip_permissions). Forward-compatible, no value as of June 2026
         since Claude Code doesn't expose this in the PreToolUse payload yet.
      2. Environment variable NOTA_BYPASS_MODE=1 — operator-set escape hatch.
      3. CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS=1 — convention some users set.
      4. Default: False (no bypass).

    When bypass mode is active, classify_event downgrades high-risk verdicts to
    silent log (medium with `verdict.allowed`) so the user who explicitly asked
    NOT to be interrupted is not interrupted. Critical class still gates — the
    bright line never softens. Audit log grows fully in both modes.
    """
    import os

    if hook_payload:
        for key in ("permission_mode", "bypass_mode", "dangerously_skip_permissions"):
            v = hook_payload.get(key)
            if v is True or (isinstance(v, str) and v.lower() in ("bypass", "skip", "true", "1")):
                return True
    if os.environ.get("NOTA_BYPASS_MODE", "").strip() in ("1", "true", "yes"):
        return True
    if os.environ.get("CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS", "").strip() in ("1", "true", "yes"):
        return True
    return False


def _writable_payloads(tool_input: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Extract (path, content) pairs from a file-write tool's args.

    Covers Claude Code's Write (``content``), Edit/MultiEdit (``new_string``),
    and NotebookEdit (``new_source``) shapes. Only non-empty string payloads
    are returned, paired with whatever path key the tool used.
    """
    path = ""
    for key in ("file_path", "path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str):
            path = value
            break
    payloads: list[tuple[str, str]] = []
    for key in ("content", "new_string", "new_source", "new_str"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            payloads.append((path, value))
    return payloads


def classify_event(
    tool_name: str,
    tool_input: Mapping[str, Any],
    *,
    bypass_mode: bool = False,
) -> tuple[Risk, str, str]:
    """Decide the risk + plain-English reason + safer-alternative suggestion.

    bypass_mode is the Claude Code --dangerously-skip-permissions signal. When
    True, high-risk verdicts downgrade to low (silent log only); critical
    verdicts still gate. See _detect_bypass_mode() for the source-of-truth
    detection precedence.
    """
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        c = classify_command(cmd)
        risk = c.risk
        reason = c.reason
        # Bypass-mode downshift: high -> low. Critical never softens.
        if bypass_mode and risk is Risk.HIGH:
            return Risk.LOW, f"bypass mode: silent log (was high: {reason})", ""
        return risk, reason, c.suggestion

    # Secret detection on file writes runs FIRST: an agent writing a hardcoded
    # AWS / OpenAI / Anthropic / GitHub / Stripe credential into source is
    # the GitHub-PAT-leak failure mode (Anthropic Nov 2025 incident class).
    # If hits found, escalate to CRITICAL regardless of any policy override.
    from nota.secrets import hit_summary, scan_args

    secret_hits = scan_args(tool_name, tool_input)
    if secret_hits:
        summary = hit_summary(secret_hits)
        return (
            Risk.CRITICAL,
            f"secret detected in write: {summary}",
            "move the value to a secrets manager / env var and reference it by name",
        )

    # Pre-execution AST scan (Phase 2, write-then-run). A Python file the agent
    # writes now and runs later via an already-allowed `python x.py` can carry
    # destructive logic the command classifier never sees. We parse the written
    # payload with the stdlib `ast` module and escalate destructive shapes
    # (shutil.rmtree, os.system, subprocess, exec(base64...)) to CRITICAL, the
    # same posture as a secret hit. Non-Python / unparseable payloads yield
    # nothing, so prose and JSON writes are never blocked.
    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        from nota import code_scan

        for path, content in _writable_payloads(tool_input):
            crit = code_scan.critical_findings(code_scan.scan_write(path, content))
            if crit:
                return (
                    Risk.CRITICAL,
                    f"destructive code in write: {crit[0].as_reason()}",
                    "this file runs destructive logic when executed; remove the "
                    "flagged call or perform the action via an audited command",
                )

    # Gate self-tamper: an Edit/Write targeting Nota's own config or the
    # host agent's hook settings is an attempt to disable the gate from the
    # inside (second-review critique #2). Checked BEFORE the user policy
    # override so a `[policy]` downgrade can't unlock it. Within the
    # app-layer model this only catches writes that flow through a gated
    # tool - a sandbox-escape direct write still bypasses it, which the
    # threat model (docs/SECURITY-MODEL.md) states plainly.
    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        for key in ("file_path", "path", "notebook_path"):
            target = tool_input.get(key)
            if isinstance(target, str) and _is_gate_config_path(target):
                return (
                    Risk.CRITICAL,
                    f"edit targets the gate's own config ({target})",
                    "Changing the gate's config to disable it is a privilege-"
                    "escalation shape. Use `nota` commands to change policy.",
                )

    # User config can override per-tool risk via the [policy] table:
    # ["Bash"] = "high", ["Edit"] = "low", etc. Loaded best-effort: the hook
    # never crashes on a missing/invalid config, it just falls back to defaults.
    user_override: Risk | None = None
    with contextlib.suppress(ConfigError, OSError, ValueError):
        cfg = load_config()
        user_override = cfg.policy.get(tool_name)

    if user_override is not None:
        # Permission Decay: a per-tool policy override is a permission the
        # user granted to themselves. Track it. If it's been dormant past
        # its decay window, ignore the override and let the default fire,
        # AND emit an audit signal so the user sees the fall-back.
        from nota import decay as _decay  # local import to avoid cycles

        store = _decay.DecayStore.load()
        # determine the natural risk of the tool BEFORE the override so
        # we can pick the right decay window (downgrades from critical
        # decay faster than downgrades from medium).
        natural = classify(tool_name)
        kind = _decay.policy_kind(natural.value, user_override.value)
        permission, was_decayed = store.record_use(kind, tool_name)
        if permission.is_decayed:
            # decayed - fall through to default-classifier path. Reason
            # explains why the override didn't apply.
            return (
                natural,
                f"policy override decayed ({permission.age_days}d > "
                f"{permission.decay_after_days}d window) - falling back "
                f"to default {natural.value}; reaffirm with: "
                f"nota decay reaffirm {tool_name}",
                "",
            )
        return user_override, "user policy override", ""

    if tool_name in DEFAULT_BUILTIN_RISK:
        default_risk = DEFAULT_BUILTIN_RISK[tool_name]
        reason = f"default risk for {tool_name}"
        # Bypass-mode downshift on default high-risk built-ins (Edit, Write, etc.)
        # Critical never softens.
        if bypass_mode and default_risk is Risk.HIGH:
            return Risk.LOW, f"bypass mode: silent log (was high: {reason})", ""
        if bypass_mode and default_risk is Risk.MEDIUM:
            return Risk.LOW, f"bypass mode: silent log (was medium: {reason})", ""
        return default_risk, reason, ""

    # Unknown tool name (custom MCP tool surfaced through Claude Code) - use
    # the namespace-based classifier as a last resort.
    natural = classify(tool_name)
    if bypass_mode and natural is Risk.HIGH:
        return Risk.LOW, f"bypass mode: silent log (was high namespace: {tool_name})", ""
    return natural, f"namespace classifier for {tool_name}", ""


# Filenames that, if written/edited, would let an agent disable or weaken
# the gate from the inside. Matched by path SUFFIX so it catches both
# absolute (~/.claude/settings.json) and relative (.nota/config.toml)
# forms, and project-local Claude/Cursor settings too.
_GATE_CONFIG_SUFFIXES: Final[tuple[str, ...]] = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/hooks.json",
    ".nota/config.toml",
    ".nota/overrides.toml",
    ".nota/key",
    ".nota/pause.json",  # the gate-off state; agent must not flip it directly
)


def _is_gate_config_path(raw: str) -> bool:
    """True if `raw` points at Nota's own config or the host agent's hook
    settings - the files an agent would rewrite to neuter the gate.

    Compares on a normalised, forward-slashed path suffix so `~`, relative,
    and absolute forms all match. Best-effort: any error → False (we never
    want a path-parsing quirk to crash the gate)."""
    if not raw or not isinstance(raw, str):
        return False
    try:
        norm = str(Path(raw).expanduser()).replace("\\", "/")
    except (OSError, ValueError):
        norm = raw.replace("\\", "/")
    norm = norm.rstrip("/")
    return any(norm.endswith(suffix) for suffix in _GATE_CONFIG_SUFFIXES)


def _summarize_call(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    """One-line human-readable summary of an attempted tool call.

    Used as the WHAT field on notifications and audit events. Examples:
      Bash + command="rm -rf node_modules"  →  "rm -rf node_modules"
      Edit + file_path="/x/y.py"            →  "Edit /x/y.py"
      Read + file_path=".env"               →  "Read .env"
    """
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        # The command line itself can carry inline credentials
        # (`mysql -phunter2`, `curl -H 'Authorization: Bearer ...'`); the
        # WHAT field lands in the audit log AND the auditor export, so
        # redact before truncating.
        return _secrets.redact(cmd)[:200]
    for key in ("file_path", "path", "filename", "url", "uri"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return f"{tool_name} {_secrets.redact(v)[:160]}"
    return tool_name


def _classification_source(tool_name: str, reason: str) -> ClassifiedBy:
    """Map a classify_event verdict to its structured SOURCE for HookDecision.

    Centralised here, next to where the reason is produced, instead of being
    re-derived by sniffing the display `reason` string in each of the three
    run_hook downshift guards. Only "default" is downshift-eligible. (audit #21)

    (The canonical fix would have classify_event itself return the source, but
    that changes its tuple arity and every unpack site across both adapters and
    the test-suite; this localised map is the safe, behaviour-preserving form.)
    """
    if "secret detected" in reason:
        return "secret"
    if tool_name == "Bash":
        return "pattern"
    if "." in tool_name:  # namespace tool, e.g. "postgres.drop_table"
        return "namespace"
    if reason == f"default risk for {tool_name}":
        return "default"
    return "pattern"


def decide(
    tool_name: str,
    tool_input: Mapping[str, Any],
    *,
    hook_payload: Mapping[str, Any] | None = None,
) -> HookDecision:
    """Risk + decision for a single Claude Code PreToolUse event.

    Reasons are kept TIGHT. No "Nota blocked: " / "Nota allowed: "
    prefix - the Claude Code UI already says which decision it is, and
    the prefix wastes tokens (every blocked call ships ~80 chars of
    boilerplate back into the agent's context window). Just the
    machine-readable reason and the paste-able suggestion when one
    exists.

    Also populates the structured WHAT / WHY / TRY-INSTEAD triple on the
    decision so the notification dispatcher can render it consistently
    across macOS Notification Center, email, Slack, and webhooks.
    """
    bypass = _detect_bypass_mode(hook_payload)
    risk, reason, suggestion = classify_event(tool_name, tool_input, bypass_mode=bypass)
    classified_by = _classification_source(tool_name, reason)
    what = _summarize_call(tool_name, tool_input)
    if risk is Risk.CRITICAL:
        body = reason
        if suggestion:
            body = f"{reason} · try instead: {suggestion}"
        # Overnight mode counter only - decision is unchanged. CRITICAL
        # NEVER auto-approves; safety contract for the rm-rf / drop-table
        # / vercel-prod / sudo / force-push class is load-bearing.
        with contextlib.suppress(Exception):
            from nota import overnight as _ovn

            ovn_active, _ = _ovn.is_active_from_config()
            if ovn_active:
                _ovn.record_event("critical")
        return HookDecision(
            permission="deny",
            reason=body,
            risk=risk,
            audit_event_type="verdict.blocked",
            what=what,
            why=reason,
            try_instead=suggestion,
            classified_by=classified_by,
        )
    if risk is Risk.HIGH:
        body = f"high risk: {reason}"
        if suggestion:
            body = f"{body} · try instead: {suggestion}"
        # Overnight mode: a HIGH-risk action auto-approves WITH a distinct
        # audit_event_type so the morning recap can identify what got
        # through and operators can post-review. The decision string still
        # carries the original reason and the suggestion - none of that
        # context is lost, only the prompt is skipped.
        try:
            from nota import overnight as _ovn

            ovn_active, ovn_reason = _ovn.is_active_from_config()
        except Exception:
            ovn_active, ovn_reason = False, ""
        if ovn_active:
            with contextlib.suppress(Exception):
                from nota import overnight as _ovn2

                _ovn2.record_event("high")
            audit_body = f"{reason} [overnight: {ovn_reason}]"
            return HookDecision(
                permission="allow",
                reason=audit_body,
                risk=risk,
                audit_event_type="verdict.allowed.overnight",
                what=what,
                why=f"auto-approved by overnight mode ({ovn_reason}): {reason}",
                try_instead=suggestion,
                classified_by=classified_by,
            )
        return HookDecision(
            permission="ask",
            reason=body,
            risk=risk,
            audit_event_type="verdict.ask",
            what=what,
            why=f"high risk: {reason}",
            try_instead=suggestion,
            classified_by=classified_by,
        )
    return HookDecision(
        permission="allow",
        reason=reason,
        risk=risk,
        audit_event_type="verdict.allowed",
        what=what,
        why=reason,
        try_instead=suggestion,
        classified_by=classified_by,
    )


def _redacted_input(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Truncate string args so we never log secrets in full.

    Args longer than 200 chars are shown with their length and a 200-char
    head only. Non-string args pass through.
    """
    out: dict[str, Any] = {}
    for k, v in tool_input.items():
        if isinstance(v, str) and len(v) > 200:
            out[k] = f"{v[:200]}…[truncated, {len(v)} chars]"
        else:
            out[k] = v
    return out


# ---- multi-project session tracking ---------------------------------------
# Claude Code's hook payload gives us session_id, transcript_path, and cwd.
# We persist a tiny on-disk index keyed by transcript_path so we can:
#   - notice when a NEW session_id appears under the same transcript
#     (the parent agent spawned a Task sub-agent)
#   - tag every audit event with parent_session_id when applicable
#   - record cwd so audit_show can filter by project
# State file lives at ~/.nota/sessions.json (mode 0o600), schema:
#   { "<transcript_path>": { "root": "<sid>", "seen": ["<sid>", "<sid>", ...],
#                             "cwd": "<path>" } }


def _session_index_path() -> Path:
    from nota.paths import default_path

    return default_path("sessions.json", env_override="NOTA_SESSIONS")


def _taint_path() -> Path:
    from nota.paths import default_path

    return default_path("taint.json", env_override="NOTA_TAINT_FILE")


def _cascade_receivers_path() -> Path:
    from nota.paths import default_path

    return default_path(
        "cascade_receivers.json",
        env_override="NOTA_CASCADE_RECEIVERS",
    )


def _record_handoff_receiver(parent_session_id: str, receiver_session_id: str) -> int:
    """Record a sub-agent receiver for one parent and return the distinct count.

    Keyed by parent_session_id because Claude Code's Task tool gives each
    spawn a UNIQUE payload_hash (the hash includes to_agent_id). The
    research spec's "same payload_hash, >=3 receivers" model maps to
    pub-sub frameworks (LangGraph/CrewAI broadcast). Claude Code's
    spawn-and-fork model produces fan-out instead: one parent, multiple
    distinct sub-agents acting on the same world. Counting sub-agents
    per parent gives the same blast-radius signal under this model.

    Backing file: `{parent_session_id: [sub_session_ids...]}`.
    Returns the new distinct sub-agent count for this parent. The
    `agent.cascade.affected` emission fires the moment this hits 3.
    """
    if not parent_session_id:
        return 0
    p = _cascade_receivers_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(p.read_text()) if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    receivers = data.get(parent_session_id) or []
    if not isinstance(receivers, list):
        receivers = []
    if receiver_session_id not in receivers:
        receivers.append(receiver_session_id)
    data[parent_session_id] = receivers
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(data))
        p.chmod(0o600)
    return len(receivers)


def _taint_state_for(session_id: str) -> TaintState:
    """Load TaintState for one session_id from the per-session taint store."""
    from nota.taint import TaintState

    p = _taint_path()
    if not p.exists():
        return TaintState()
    try:
        all_states = json.loads(p.read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return TaintState()
    raw = all_states.get(session_id) or {}
    return TaintState(
        has_seen_untrusted=bool(raw.get("has_seen_untrusted", False)),
        has_accessed_private=bool(raw.get("has_accessed_private", False)),
        can_exfiltrate=bool(raw.get("can_exfiltrate", False)),
    )


def _save_taint_state(session_id: str, state: TaintState) -> None:
    p = _taint_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        all_states = json.loads(p.read_text() or "{}") if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        all_states = {}
    if not isinstance(all_states, dict):
        all_states = {}
    all_states[session_id] = state.to_dict()
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(all_states))
        p.chmod(0o600)


def _track_session(
    *,
    transcript_path: str,
    session_id: str,
    cwd: str,
) -> tuple[str, bool, bool]:
    """Update the session index, return (parent_session_id, is_new_subagent, is_first_seen).

    parent_session_id is "" if this IS the root session, otherwise the
    root's session_id. is_new_subagent is True the FIRST time we see a
    given non-root session_id under a transcript. is_first_seen is True
    the FIRST time we see this session_id at all (root or sub) - used to
    emit session.open exactly once per session.
    """
    p = _session_index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        index = json.loads(p.read_text()) if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        index = {}
    if not isinstance(index, dict):
        index = {}

    rec = index.get(transcript_path) or {}
    seen = rec.get("seen") or []
    if not isinstance(seen, list):
        seen = []
    root = rec.get("root")
    is_new_sub = False
    is_first_seen = False
    if not root:
        root = session_id
        seen = [session_id]
        is_first_seen = True
    elif session_id not in seen:
        seen.append(session_id)
        is_new_sub = session_id != root
        is_first_seen = True

    index[transcript_path] = {"root": root, "seen": seen, "cwd": cwd}
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(index))
        p.chmod(0o600)

    parent = "" if session_id == root else root
    return parent, is_new_sub, is_first_seen


def _maybe_notify(
    *,
    decision: HookDecision,
    tool_name: str,
    tool_input: Mapping[str, Any],
    session_id: str,
    cwd: str,
    approve_token: str,
    audit: AuditLog,
) -> None:
    """No-op retained for call-site compatibility.

    Out-of-band notification dispatch (macOS / Slack / email / webhook) was
    removed in the Change Control pivot: Nota no longer runs as a live
    developer execution gate, so there is no interactive block to ping a human
    about. The CI verdict surface (passport + GitHub Status Check) replaces it.
    The caller already wraps this in `contextlib.suppress`, so the empty body
    keeps the hot path inert without touching the call site.
    """
    return


def _resolve_project_paths(cwd: str) -> tuple[Path, Path | None]:
    """Given the cwd Claude Code passed us, return:
       (audit_log_path, per_project_config_path or None).

    Per-project audit logs live at <cwd>/.nota/audit.log.jsonl; per-project
    config at <cwd>/.nota/config.toml. Both are opt-in: the user creates
    the .nota/ directory in their project to activate per-project mode.
    Otherwise we fall back to the global ~/.nota/ paths.
    """
    raw = os.environ.get("NOTA_LOG", "").strip()
    if raw:
        return Path(raw).expanduser(), None

    cwd_p = Path(cwd).expanduser() if cwd else None
    if cwd_p and (cwd_p / ".nota").is_dir():
        return (
            cwd_p / ".nota" / "audit.log.jsonl",
            (cwd_p / ".nota" / "config.toml")
            if (cwd_p / ".nota" / "config.toml").exists()
            else None,
        )
    return default_audit_path(), None


def _is_bypass_mode() -> bool:
    """True if the operator has explicitly opted out of permission
    prompts at the Claude Code level (running with
    `--dangerously-skip-permissions` or with
    `skipDangerousModePermissionPrompt: true` in settings.json).

    When this is true, Nota's default-HIGH-risk Edit/Write asks are
    redundant - the operator told Claude Code "stop asking me". The
    downshift only applies to the DEFAULT classification; pattern-
    matched HIGHs (vercel --prod, rm -rf, etc.) and CRITICAL events
    still fire regardless of bypass mode.

    Cached per-process via the NOTA_BYPASS_CACHE module global. Set
    NOTA_RESPECT_BYPASS=0 to force-disable the downshift even when
    settings.json says bypass is on.
    """
    if os.environ.get("NOTA_RESPECT_BYPASS", "1") == "0":
        return False
    # Honor an explicit env override for tests / deterministic CI runs.
    forced = os.environ.get("NOTA_BYPASS_MODE", "").strip()
    if forced:
        return forced.lower() in ("1", "true", "yes", "on")
    try:
        settings = Path("~/.claude/settings.json").expanduser()
        if not settings.exists():
            return False
        data = json.loads(settings.read_text() or "{}")
        if not isinstance(data, dict):
            return False
        return bool(data.get("skipDangerousModePermissionPrompt"))
    except (OSError, json.JSONDecodeError):
        return False


def run_hook(stdin_text: str, audit: AuditLog | None = None) -> dict[str, Any]:
    """Pure-function entry point for tests.

    Reads a JSON event from stdin_text, returns the dict that should be
    written to stdout. If `audit` is given, appends an audit entry; otherwise
    skips logging (used by tests).
    """
    try:
        event: dict[str, Any] = json.loads(stdin_text)
    except json.JSONDecodeError as e:
        # SECURITY: fail-CLOSED on malformed input. An agent that can make the
        # hook see malformed JSON should not get a free pass; matching the
        # classifier self-test's posture, a broken gate refuses rather than
        # allowing. Operators recover via `nota off` (bounded + logged).
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"nota: malformed hook input ({e}); fail-closed. "
                    "Run `nota doctor` to investigate."
                ),
            },
        }

    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    session_id = str(event.get("session_id", "claude-code"))
    transcript_path = str(event.get("transcript_path", "") or "")
    cwd = str(event.get("cwd", "") or "")

    # Track session lineage so we can tag sub-agent calls.
    parent_session_id = ""
    is_new_sub = False
    is_first_seen = False
    if transcript_path and session_id:
        with contextlib.suppress(Exception):
            parent_session_id, is_new_sub, is_first_seen = _track_session(
                transcript_path=transcript_path,
                session_id=session_id,
                cwd=cwd,
            )

    decision = decide(tool_name, tool_input)
    agent_id = "claude-code-sub" if parent_session_id else "claude-code"

    # Snapshot the classifier's original reason BEFORE any downstream
    # transformation (trust scope, bypass mode, approval-token consume)
    # rewrites the HookDecision. Learning uses this so a token consume
    # records the approve under the SAME pattern_id that previously
    # recorded the deny - not under a per-token "approved one-shot"
    # pattern that would split the same underlying rule into N rows.
    original_decision_reason = decision.reason

    # Trust-scope downshift: a default-HIGH-risk Edit/Write inside a
    # trusted directory (listed in `[trust] paths` in config.toml) is
    # downgraded to LOW + auto-allow. This is the fix for the
    # approval-fatigue problem: 991 high-risk Edit/Write asks in a
    # single week of dogfooding, 92% noise. Only the DEFAULT
    # classification is downshifted - pattern-matched HIGHs (Bash
    # commands matching the HIGH regex set, per-tool policy overrides)
    # and all CRITICAL events are NOT affected.
    if (
        decision.permission == "ask"
        and tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")
        and decision.classified_by == "default"
        and cwd
    ):
        with contextlib.suppress(Exception):
            from nota.paths import is_trusted_cwd

            if is_trusted_cwd(cwd):
                # Trust scope yields to trifecta enforcement: if the session
                # is already at 2-of-3 flags and THIS call would close the
                # third, we must not silently auto-allow. The trifecta
                # enforcement block below will turn the ask back into a
                # deny + approve-token. Trust scope still suppresses every
                # other default-risk Edit/Write ask in trusted dirs.
                would_close = False
                if session_id:
                    with contextlib.suppress(Exception):
                        from nota.taint import would_close_trifecta

                        current = _taint_state_for(session_id)
                        would_close = would_close_trifecta(current, tool_name, tool_input)
                if not would_close:
                    decision = HookDecision(
                        permission="allow",
                        reason=f"trusted scope: {tool_name} in {cwd}",
                        risk=Risk.LOW,
                        audit_event_type="verdict.allowed",
                        what=decision.what,
                        why="trusted scope (config [trust] paths)",
                        try_instead="",
                    )

    # Promoted-override downshift: the operator explicitly promoted a
    # loosening_candidate via `nota suggestions promote <key> --ttl-days N`,
    # which wrote a block into ~/.nota/overrides.toml. If THIS call's
    # pattern_id has an active (non-expired) override, downshift the
    # decision. The override is operator-approved and TTL'd; never
    # silent, never permanent.
    #
    # Same safety invariant as trust scope: ONLY downshifts the default
    # ask path. CRITICAL events (decision.permission == "deny" from
    # classify_command pattern match) bypass this check entirely and
    # still fire.
    if decision.permission == "ask" and decision.classified_by == "default":
        with contextlib.suppress(Exception):
            from nota.learn import _normalize_block_reason
            from nota.learning import load_active_overrides

            head = _normalize_block_reason(original_decision_reason) or original_decision_reason
            pattern_id = f"{tool_name}:{head}"[:80]
            overrides = load_active_overrides()
            if pattern_id in overrides:
                ov = overrides[pattern_id]
                decision = HookDecision(
                    permission="allow",
                    reason=(
                        f"operator-promoted override ({ov['remaining_days']:.1f} days remaining)"
                    ),
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why="operator promoted pattern via nota suggestions promote",
                    try_instead="",
                )

    # Bypass-mode downshift: the operator has explicitly opted out of
    # Claude Code's permission prompts (skipDangerousModePermissionPrompt
    # in settings.json, or running with --dangerously-skip-permissions).
    # In that mode, default-HIGH Edit/Write asks are redundant prompts
    # the operator already told the host harness to skip. We respect
    # the operator's setting. Pattern-matched HIGHs and CRITICAL events
    # still fire. Operator can force-disable via NOTA_RESPECT_BYPASS=0.
    if (
        decision.permission == "ask"
        and tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")
        and decision.classified_by == "default"
    ):
        with contextlib.suppress(Exception):
            if _is_bypass_mode():
                decision = HookDecision(
                    permission="allow",
                    reason=f"bypass mode: {tool_name} (skipDangerousModePermissionPrompt=true)",
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why="operator opted into bypass mode at the Claude Code level",
                    try_instead="",
                )

    # Session-scoped approval memory (#52): if THIS exact (session, tool,
    # args) was already approved in this session, allow without re-asking.
    # Critical/secret/trifecta classes never qualify - we re-check here as
    # defense in depth even though session_approvals.remember() only fires
    # on approved verdicts in the first place.
    if (
        decision.permission == "ask"
        and session_id
        and decision.risk is not Risk.CRITICAL
        and "secret" not in (decision.reason or "").lower()
        and "trifecta" not in (decision.reason or "").lower()
    ):
        with contextlib.suppress(Exception):
            from nota import session_approvals as _sa

            if _sa.recall(session_id, tool_name, tool_input):
                decision = HookDecision(
                    permission="allow",
                    reason="session-memory: previously approved this exact call in this session",
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why="session-scoped approval memory hit",
                    try_instead="",
                )

    # One-shot approval check: if the user ran `nota approve <token>` for
    # this exact (tool_name, args) within the TTL, consume the approval
    # and let the call through. This is the "go ahead" path the user
    # walks after seeing a notification.
    approval_token_used = ""
    if decision.permission != "allow":
        with contextlib.suppress(Exception):
            from nota.approvals import ApprovalStore

            store = ApprovalStore.load()
            consumed = store.consume(tool_name, dict(tool_input))
            if consumed is not None:
                approval_token_used = consumed.token
                decision = HookDecision(
                    permission="allow",
                    reason=f"approved one-shot via nota approve {consumed.token[:8]}",
                    risk=decision.risk,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why=f"user-approved (token {consumed.token[:8]})",
                    try_instead="",
                )
                # Remember this approval for the rest of the session so the
                # operator isn't re-asked for the same exact call. Critical
                # class is excluded - the bright line never softens.
                if (
                    session_id
                    and decision.risk is not Risk.CRITICAL
                    and "secret" not in (decision.reason or "").lower()
                    and "trifecta" not in (decision.reason or "").lower()
                ):
                    with contextlib.suppress(Exception):
                        from nota import session_approvals as _sa

                        _sa.remember(session_id, tool_name, tool_input)

    # Trifecta enforcement: if THIS call would close the lethal trifecta
    # (untrusted input + private data + exfil) for the first time, escalate
    # an otherwise-allow decision to a deny so the user can decide. Skip
    # if the user already approved this exact call out-of-band.
    if decision.permission == "allow" and not approval_token_used and session_id:
        with contextlib.suppress(Exception):
            from nota.taint import TaintState as _TaintState
            from nota.taint import would_close_trifecta

            current = _taint_state_for(session_id) if session_id else _TaintState()
            if would_close_trifecta(current, tool_name, tool_input):
                why = (
                    "would close the lethal trifecta this session "
                    "(untrusted input + private data + exfil vector)"
                )
                # Hardcode CRITICAL: a trifecta-close attempt is the worst-
                # case prompt-injection scenario by definition; the
                # underlying call's classification (often LOW for Edit/Write)
                # is irrelevant. Notify dispatcher fans on critical, so this
                # ensures OOB notification fires on trifecta closures.
                decision = HookDecision(
                    permission="deny",
                    reason=f"trifecta close · {why} · approve to proceed",
                    risk=Risk.CRITICAL,
                    audit_event_type="verdict.blocked",
                    what=decision.what,
                    why=why,
                    try_instead="",
                )

    if audit is not None:
        from nota import events as ev
        from nota.bridge import payload_hash as _ph
        from nota.taint import update_for_call

        with contextlib.suppress(Exception):
            # session.open - first time we've ever seen this session_id.
            if is_first_seen:
                audit.emit(
                    event_type=ev.SESSION_OPEN,
                    session_id=session_id,
                    agent_id=agent_id,
                    risk="low",
                    payload={
                        "parent_session_id": parent_session_id,
                        "transcript_path": transcript_path,
                        "cwd": cwd,
                        "trust_ladder": "spot_check",
                    },
                    force_fsync=True,
                )

            # agent.handoff.out / agent.handoff.in - sub-agent spawn.
            # Both sides of the edge are emitted from the receiver's hook
            # invocation (the sub-agent's first tool call); the parent has
            # already returned from Task() and is no longer running. The
            # out is recorded under the parent's session_id, the in under
            # the sub-agent's. The pair is matched by payload_hash;
            # `from_event_mac` ties the in to the specific out for
            # cryptographic edge integrity (see the internal A2A
            # event-schema design notes S6.1).
            if is_new_sub:
                handoff_payload = {
                    "to_agent_id": session_id,
                    "from_session_id": parent_session_id,
                    "transcript_path": transcript_path,
                }
                _ph_value = _ph(handoff_payload)
                out_mac = audit.emit(
                    event_type=ev.AGENT_HANDOFF_OUT,
                    session_id=parent_session_id or session_id,
                    agent_id="claude-code",
                    risk="low",
                    payload={
                        "to_agent_id": session_id,
                        "contract": "task-subagent",
                        "payload_hash": _ph_value,
                        "trust_ladder_inherited": "spot_check",
                    },
                    force_fsync=True,
                )
                # Receiver-side: same payload_hash, ties to the out's mac.
                # Without this, `nota bridge show` reports every handoff
                # as orphan (out with no matching in). The fold-by-hash
                # logic in bridge.py:fold_handoffs depends on this event
                # being present with the same payload_hash.
                in_mac = audit.emit(
                    event_type=ev.AGENT_HANDOFF_IN,
                    session_id=session_id,
                    agent_id="claude-code-sub",
                    risk="low",
                    payload={
                        "from_agent_id": "claude-code",
                        "from_session_id": parent_session_id,
                        "from_event_mac": out_mac,
                        "payload_hash": _ph_value,
                        "accepted": True,
                        "ack_reason": None,
                    },
                    force_fsync=True,
                )

                # agent.cascade.affected - fan-out detection. One parent
                # spawning 3+ distinct sub-agents is the blast-radius
                # signature in Claude Code's spawn-and-fork model. Fires
                # exactly once per parent at the 3rd sub-agent so the
                # log gets one cascade event, not one per subsequent sub.
                with contextlib.suppress(Exception):
                    subagent_count = _record_handoff_receiver(
                        parent_session_id,
                        session_id,
                    )
                    if subagent_count == 3:
                        audit.emit(
                            event_type=ev.AGENT_CASCADE_AFFECTED,
                            session_id=parent_session_id,
                            agent_id="claude-code",
                            risk="high",
                            payload={
                                "upstream_event_mac": out_mac,
                                "parent_session_id": parent_session_id,
                                "distinct_subagents": subagent_count,
                                "latest_in_mac": in_mac,
                                "latest_subagent_session_id": session_id,
                                "transcript_path": transcript_path,
                            },
                            force_fsync=True,
                        )

            audit.emit(
                event_type=ev.TOOL_ATTEMPTED,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "arg_keys": sorted(tool_input.keys()),
                    "arg_count": len(tool_input),
                    "args_preview": _redacted_input(tool_input),
                    "via": "claude-code-hook",
                    "parent_session_id": parent_session_id,
                    "cwd": cwd,
                },
            )
            # Issue a one-shot approval token for blocked / ask decisions
            # so the notification can include `nota approve <token>` -
            # the user's "go ahead" path. Tokens TTL ~10 min.
            issued_token = approval_token_used  # already set if we consumed
            if not issued_token and decision.permission in ("deny", "ask"):
                with contextlib.suppress(Exception):
                    from nota.approvals import ApprovalStore

                    store = ApprovalStore.load()
                    ap = store.issue(
                        tool_name,
                        dict(tool_input),
                        reason=decision.why or decision.reason,
                    )
                    issued_token = ap.token

            # SECURITY: NEVER write the full approve token to the audit log.
            # The agent reads the log (Read is LOW), so storing the token there
            # was a self-approval gateway: the agent could `cat audit.log.jsonl`,
            # find the token for the call it was just blocked on, and run
            # `nota approve <token>` (or write approvals.json directly). We
            # record only a short hash for human correlation against the
            # out-of-band notification, never the recoverable value.
            import hashlib as _hashlib

            token_id = (
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
                    "by": "nota.adapters.claude_code",
                    "reason": decision.reason,
                    "permission": decision.permission,
                    "parent_session_id": parent_session_id,
                    "cwd": cwd,
                    "approve_token_id": token_id,
                    "what": decision.what,
                    "why": decision.why,
                    "try_instead": decision.try_instead,
                },
                force_fsync=decision.risk in (Risk.HIGH, Risk.CRITICAL),
            )

            # Fire out-of-band notifications (macOS, email, Slack, webhook)
            # asynchronously - never blocks the hook's hot path.
            if decision.permission in ("deny", "ask") and issued_token:
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

            # session.taint.update - emit only when a flag flips.
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
                    },
                    force_fsync=taint_state.trifecta_closed,
                )

    # Autonomous learning: record this decision so the learner can
    # update its per-pattern stats and surface auto-tightening or
    # loosen-candidates. Skipped on plain-LOW allows where the
    # operator wasn't involved (those carry no signal). Failures here
    # must NEVER break the hook - the gate verdict is already final.
    # Use the ORIGINAL classifier reason so token-flipped approves
    # group with their preceding denies under the same pattern_id.
    if decision.permission != "allow" or approval_token_used:
        from nota import learning

        if os.environ.get("NOTA_LEARNING_STRICT"):
            learning.record_decision_learning(
                tool_name, original_decision_reason, bool(approval_token_used)
            )
        else:
            with contextlib.suppress(Exception):
                learning.record_decision_learning(
                    tool_name, original_decision_reason, bool(approval_token_used)
                )

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.permission,
            "permissionDecisionReason": decision.reason,
        },
    }


def self_test() -> tuple[bool, str]:
    """Verify the gate's classifier still does its job before processing
    any operator tool call. Two invariants:

      1. A known-CRITICAL payload (DROP TABLE) must DENY.
      2. A known-LOW payload (ls -la) must ALLOW.

    If either invariant fails, something has corrupted the classifier
    (config override, policy table drift, a runtime regression) and
    the hook MUST refuse to start. Failing closed is the safe move -
    a broken gate that fail-opens is worse than no gate.

    Returns (ok, reason). Cheap: two `decide()` calls, sub-millisecond.
    Cached in-process via the NOTA_SELF_TEST_DONE module global so
    subsequent calls are free. Skippable via NOTA_NO_SELF_TEST=1.

    Why this exists: the journal parser was silently broken for ~3
    weeks because nothing checked that the post-condition (real turn
    counts in the journal) was holding. Self-test on startup is the
    fix-loud-not-fix-silent pattern applied to the classifier.
    """
    if os.environ.get("NOTA_NO_SELF_TEST"):
        return True, "skipped via NOTA_NO_SELF_TEST"
    global _SELF_TEST_DONE
    if _SELF_TEST_DONE:
        return True, "cached"
    try:
        # Known-CRITICAL: DROP TABLE in raw form (no quoting, not a
        # commit-message). The quote-masked classifier still matches.
        critical_decision = decide("Bash", {"command": "DROP TABLE users"})
        if critical_decision.permission != "deny":
            return False, (
                f"self-test FAILED: known-critical 'DROP TABLE' returned "
                f"permission={critical_decision.permission} "
                f"(expected 'deny'). Classifier may be misconfigured."
            )
        # Known-LOW: bare ls. classify_command labels as read-only.
        low_decision = decide("Bash", {"command": "ls -la"})
        if low_decision.permission != "allow":
            return False, (
                f"self-test FAILED: known-LOW 'ls -la' returned "
                f"permission={low_decision.permission} (expected 'allow'). "
                f"Classifier may be over-broad."
            )
    except Exception as e:
        return False, f"self-test crashed: {type(e).__name__}: {e}"
    _SELF_TEST_DONE = True
    return True, "ok"


_SELF_TEST_DONE: bool = False


def _emit_resume_if_expired(log_path: Path) -> None:
    """If a pause sits on disk but its window has expired, emit gate.resumed
    (auto-expired) exactly once and clear the flag.

    A pause auto-expires passively - is_paused() just starts returning False.
    Without this, the audit log would show gate.paused with no matching
    gate.resumed, leaving the "when did the gate come back on?" question
    unanswerable. We close the bracket lazily on the next hook invocation
    after expiry. Best-effort: never raises into the gate path.
    """
    from nota import pause as _pause

    with contextlib.suppress(Exception):
        state = _pause.load_state()
        if not state.paused:
            return
        active, _ = _pause.is_paused(state)
        if active:
            return
        # Flag still set on disk but window expired → close the bracket.
        recap = state.allowed_count
        _pause.resume()
        with contextlib.suppress(Exception):
            with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
                audit.emit(
                    event_type="gate.resumed",
                    session_id="nota-cli",
                    agent_id="nota.pause",
                    risk="low",
                    payload={
                        "trigger": "auto-expired",
                        "reason": state.reason,
                        "allowed_while_paused": recap,
                    },
                    force_fsync=True,
                )


def _handle_paused(stdin_text: str, log_path: Path, reason: str) -> dict[str, Any]:
    """Let a tool call through while the gate is paused, but log it.

    Every call allowed during a pause window is written to the audit log as
    a verdict.allowed carrying `gate_paused: true` and the pause reason, so
    the window's contents are reconstructable call-by-call after the fact.
    The classifier is NOT consulted - this path stays alive even when the
    classifier is broken, which is the whole point of pause-as-recovery-hatch.
    """
    from nota import pause as _pause

    event: dict[str, Any] = {}
    with contextlib.suppress(json.JSONDecodeError, TypeError):
        parsed = json.loads(stdin_text or "{}")
        if isinstance(parsed, dict):
            event = parsed
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    session_id = str(event.get("session_id", "claude-code"))
    cwd = str(event.get("cwd", "") or "")

    _pause.record_allowed_while_paused()
    with contextlib.suppress(Exception):
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            audit.emit(
                event_type="verdict.allowed",
                session_id=session_id,
                agent_id="claude-code",
                risk="low",
                payload={
                    "tool_name": tool_name,
                    "what": _summarize_call(tool_name, tool_input),
                    "args_preview": _redacted_input(tool_input),
                    "by": "nota.adapters.claude_code",
                    "permission": "allow",
                    "gate_paused": True,
                    "pause_reason": reason,
                    "cwd": cwd,
                },
            )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": (
                f"nota gate paused ({reason}) - call allowed and logged "
                "with gate_paused. Run `nota on` to re-enable the gate."
            ),
        },
    }


def main() -> int:
    """CLI entry: read stdin, write stdout, exit 0.

    Wired to `nota claude-hook` via the CLI module. Routes the audit
    log to <cwd>/.nota/audit.log.jsonl when the user has opted in to
    per-project mode. ALSO lazily ensures the watch dashboard daemon is
    alive so users never need to re-type `nota watch` after a reboot.

    Order of operations is load-bearing:
      1. Read stdin + resolve the per-project log path.
      2. PAUSE CHECK - if the operator ran `nota off`, let the call
         through (logged with gate_paused) and return BEFORE self_test.
         This is deliberate: pause must work as a recovery hatch even when
         the classifier is broken (the exact lockout that motivated it).
      3. self_test() - only on the gated path. If it fails, fail closed.
      4. run_hook() - normal classification.
    """
    stdin_text = sys.stdin.read()
    # Peek at cwd from the payload so we can route the log per-project.
    cwd_for_routing = ""
    try:
        peek = json.loads(stdin_text or "{}")
        if isinstance(peek, dict):
            cwd_for_routing = str(peek.get("cwd") or "")
    except (json.JSONDecodeError, TypeError):
        pass
    log_path, _ = _resolve_project_paths(cwd_for_routing)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Step 2: pause check, BEFORE self_test, so a paused gate is a working
    # escape hatch even with a broken classifier.
    from nota import pause as _pause

    _emit_resume_if_expired(log_path)
    paused, pause_reason = _pause.is_paused()
    if paused:
        response = _handle_paused(stdin_text, log_path, pause_reason)
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
        return 0

    # Step 3: self-test (gated path only).
    ok, reason = self_test()
    if not ok:
        sys.stderr.write(
            f"nota claude-hook: self-test failed: {reason}\n"
            f"  Refusing to start. The classifier may be misconfigured.\n"
            f"  Run `nota doctor` to investigate, or `nota off` to pause "
            f"the gate (bounded + logged) if you need to keep working.\n"
            f"  Override (NOT RECOMMENDED): NOTA_NO_SELF_TEST=1\n"
        )
        # Fail closed: deny the call. Operator-friendly reason.
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"nota self-test failed: {reason}. "
                    "Run `nota doctor`, or `nota off` to pause the gate."
                ),
            },
        }
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
        return 1

    try:
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            response = run_hook(stdin_text, audit=audit)
    except Exception as e:
        # SECURITY: fail-CLOSED on internal error. An agent that can deliberately
        # crash the hook (large/malformed input, oversized payload) was previously
        # rewarded with an unconditional allow. The classifier self-test already
        # fails closed; this matches. Operators recover via `nota off`.
        sys.stderr.write(f"nota claude-hook: internal error, denying fail-closed: {e}\n")
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"nota internal error ({e}); fail-closed. "
                    "Investigate with `nota doctor` or `nota off` to pause."
                ),
            },
        }
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------
# Install helper: write the settings.json snippet for the user.
# --------------------------------------------------------------------------

DEFAULT_CC_SETTINGS = Path("~/.claude/settings.json").expanduser()


def install_snippet(
    matcher: str = "Bash|Edit|Write|NotebookEdit", timeout: int = 10
) -> dict[str, Any]:
    """Return the JSON fragment that should be merged into Claude Code settings."""
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": "nota claude-hook",
                            "timeout": timeout,
                        },
                    ],
                },
            ],
        },
    }


def install_into_settings(
    settings_path: Path | None = None,
    *,
    matcher: str = "Bash|Edit|Write|NotebookEdit",
    timeout: int = 10,
) -> tuple[Path, bool]:
    """Merge the Nota hook snippet into a Claude Code settings.json.

    Returns (path_written, was_already_installed).

    Conservative behaviour: if a PreToolUse hook with the same matcher and
    command already exists, we don't duplicate. We also never replace
    user-installed unrelated hooks; we append.
    """
    p = settings_path or DEFAULT_CC_SETTINGS
    p.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    if p.exists():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            existing = json.loads(p.read_text() or "{}")

    hooks_root = existing.setdefault("hooks", {})
    pre_list = hooks_root.setdefault("PreToolUse", [])

    new_block = install_snippet(matcher=matcher, timeout=timeout)["hooks"]["PreToolUse"][0]

    for block in pre_list:
        if block.get("matcher") == matcher and any(
            h.get("command") == "nota claude-hook" for h in (block.get("hooks") or [])
        ):
            return p, True  # already installed

    pre_list.append(new_block)
    p.write_text(json.dumps(existing, indent=2) + "\n")
    return p, False


if __name__ == "__main__":
    raise SystemExit(main())
