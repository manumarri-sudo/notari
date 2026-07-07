"""Lethal-trifecta taint tracking (Simon Willison / Meta Rule of Two).

An agent that has, in the same session:
  - seen untrusted tokens (web fetch, email body, attachment), AND
  - accessed private data (.env, secrets, private repo contents), AND
  - has an exfiltration vector (outbound HTTP, email send, PR creation)

is at the worst-case prompt-injection risk: the attacker can read your secrets
AND make you act on them AND send the result somewhere. Two of the three is
recoverable; all three is the lethal trifecta.

This module is observation-only (1-week scope). It tracks the three flags
on a session and emits `session.taint.update` audit events whenever a flag
flips. Enforcement (escalate to type-to-confirm when the third flag would
close) is the 1-month scope.

Heuristic: the classification of a tool call is mechanical, not LLM-driven.
Falsy tool names get classified as nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TaintState:
    """Three-flag taint state for a session.

    Each flag is monotonic - once true in a session, stays true. (Resetting
    requires opening a new session.)
    """

    has_seen_untrusted: bool = False
    has_accessed_private: bool = False
    can_exfiltrate: bool = False
    provenance: list[dict[str, Any]] = field(default_factory=list)

    @property
    def trifecta_closed(self) -> bool:
        return self.has_seen_untrusted and self.has_accessed_private and self.can_exfiltrate

    def to_dict(self) -> dict[str, bool]:
        return {
            "has_seen_untrusted": self.has_seen_untrusted,
            "has_accessed_private": self.has_accessed_private,
            "can_exfiltrate": self.can_exfiltrate,
        }


# Patterns that indicate each kind of taint.
#
# Untrusted = the call brings adversary-controlled bytes into the agent's
# context. This is the "left" side of the lethal trifecta (untrusted input
# + private data + exfil vector).
#
# Local file reads via Claude Code's `Read` tool are NOT inherently
# untrusted - the bytes come from the user's own filesystem, not from a
# network attacker. Marking them untrusted made the trifecta gate too
# aggressive: read a README, then read .env, then run `git push` closed
# the trifecta and triggered DENY for a perfectly normal workflow.
#
# What stays in the set:
#   - WebFetch / WebSearch / fetch          - remote HTTP responses
#   - browser.*                              - rendered web pages
#   - gmail.read / slack.read                - inbox content (anyone can send)
# What was removed:
#   - filesystem.read_file                   - local FS, not adversary-controlled
_UNTRUSTED_TOOLS = frozenset(
    {
        "WebFetch",
        "WebSearch",
        "fetch",
        "browser.read",
        "browser.navigate",
        "gmail.read_message",
        "slack.read_channel",
    }
)

_UNTRUSTED_BASH_PATTERNS = (
    "curl ",
    "wget ",
    "git clone ",
    "cat http",
    "less http",
)

_PRIVATE_PATH_PATTERNS = (
    ".env",
    "secrets",
    "credentials",
    "private_key",
    "id_rsa",
    "id_ed25519",
    ".aws/",
    ".ssh/",
    ".gnupg/",
    "/etc/passwd",
    "/etc/shadow",
)

_EXFIL_TOOLS = frozenset(
    {
        "WebFetch",  # outbound HTTP
        "gmail.send",
        "slack.send_message",
        "discord.send",
        "github.create_pr",
        "github.create_issue",
        "stripe.create_charge",
        "stripe.create_refund",
    }
)

_EXFIL_BASH_PATTERNS = (
    "curl -X POST",
    "curl --data",
    "curl -d ",
    "git push",
    "scp ",
    "rsync ",
    "aws s3 cp",
    "gsutil cp",
)


def _matches_any(s: str, patterns: tuple[str, ...]) -> bool:
    if not s:
        return False
    s_lower = s.lower()
    return any(pat.lower() in s_lower for pat in patterns)


def classify_call_taint(
    tool_name: str,
    args: Mapping[str, Any] | None = None,
) -> tuple[bool, bool, bool]:
    """Return (causes_untrusted, causes_private, causes_exfil) for one call.

    Read-side classification uses the tool name + arg values; write-side
    classification uses the tool name + the kind of action it performs.
    """
    args = args or {}
    untrusted = tool_name in _UNTRUSTED_TOOLS
    private = False
    exfil = tool_name in _EXFIL_TOOLS

    # Bash is the catch-all - inspect the command.
    if tool_name in {"Bash", "Shell", "shell.run"}:
        cmd = str(args.get("command") or "")
        untrusted = untrusted or _matches_any(cmd, _UNTRUSTED_BASH_PATTERNS)
        exfil = exfil or _matches_any(cmd, _EXFIL_BASH_PATTERNS)

    # Path-bearing args might point at private data.
    for key in ("file_path", "path", "filename", "src", "from"):
        v = args.get(key)
        if isinstance(v, str) and _matches_any(v, _PRIVATE_PATH_PATTERNS):
            private = True
            break

    return untrusted, private, exfil


def would_close_trifecta(
    state: TaintState,
    tool_name: str,
    args: Mapping[str, Any] | None = None,
) -> bool:
    """Peek: would this call flip the third flag and close the trifecta?

    Pure read - does NOT mutate state. The gate uses this to escalate an
    otherwise-allow decision to a deny + approval-token flow when applying
    the call's classification would push the session into lethal-trifecta
    for the FIRST time. Once the trifecta is already closed, subsequent
    calls don't escalate (the secrets are already at risk; gating later
    calls in the same session doesn't reduce harm).
    """
    if state.trifecta_closed:
        return False
    untrusted, private, exfil = classify_call_taint(tool_name, args)
    new_untrusted = state.has_seen_untrusted or untrusted
    new_private = state.has_accessed_private or private
    new_exfil = state.can_exfiltrate or exfil
    return new_untrusted and new_private and new_exfil


def update_for_call(
    state: TaintState,
    tool_name: str,
    args: Mapping[str, Any] | None = None,
    *,
    event_mac: str = "",
) -> tuple[TaintState, list[str]]:
    """Apply one tool call to the taint state, return (new_state, flipped_flags).

    flipped_flags is the list of flag names that went false→true on this call;
    callers emit a session.taint.update event when this is non-empty.
    """
    untrusted, private, exfil = classify_call_taint(tool_name, args)
    flipped: list[str] = []

    if untrusted and not state.has_seen_untrusted:
        state.has_seen_untrusted = True
        flipped.append("has_seen_untrusted")
    if private and not state.has_accessed_private:
        state.has_accessed_private = True
        flipped.append("has_accessed_private")
    if exfil and not state.can_exfiltrate:
        state.can_exfiltrate = True
        flipped.append("can_exfiltrate")

    if flipped:
        state.provenance.append(
            {
                "tool_name": tool_name,
                "flipped": flipped,
                "caused_by_event_mac": event_mac,
            }
        )
    return state, flipped


def fold_audit_events(events: list[dict[str, Any]]) -> dict[str, TaintState]:
    """Replay a list of audit events into per-session TaintState.

    Walks tool.attempted events; ignores everything else.
    Returns {session_id: TaintState}.
    """
    from quill.events import TOOL_ATTEMPTED

    by_session: dict[str, TaintState] = {}
    for evt in events:
        if evt.get("type") != TOOL_ATTEMPTED:
            continue
        sid = str(evt.get("session_id") or "")
        if not sid:
            continue
        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        tool_name = str(payload.get("tool_name") or "")
        args = payload.get("args_preview") or {}
        if not isinstance(args, Mapping):
            args = {}
        state = by_session.setdefault(sid, TaintState())
        update_for_call(state, tool_name, args, event_mac=str(evt.get("mac", "")))
    return by_session
