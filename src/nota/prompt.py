"""Terminal-based human-in-the-loop prompt with anti-fatigue.

This module provides the interactive ACK surface. For high-risk actions, it
shows a single y/N. For critical-risk actions, it requires the operator to
type the action name back, which prevents muscle-memory yes-spamming on
destructive calls (rm -rf, DROP TABLE, etc.).

Yes-fatigue detection: if the operator has confirmed FATIGUE_WINDOW prompts
in under FATIGUE_THRESHOLD_S each, the next prompt holds for FATIGUE_PAUSE_S
before accepting input. This is the same anti-pattern Sentry, GitHub, and
Stripe handle in their own dangerous-action UX.

Output uses rich for color + structure, falling back to plain text in
non-TTY environments (CI, subprocess capture).

Non-interactive fallback: under `nota serve` (MCP stdio proxy mode), the
process's stdin is owned by the JSON-RPC reader - `input()` would EOF
immediately. When `confirm()` detects a non-TTY stdin, it issues a one-shot
approval token, fires out-of-band notifications, prints a paste-able
`nota approve <token>` line on stderr, and declines THIS call. The agent's
retry of the same call within the TTL will be allowed automatically by the
approval-consumption path in `nota.adapters.claude_code.run_hook`.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nota.errors import ConfirmationMismatch, HumanDeclined
from nota.policy import Risk

# Anti-fatigue tunables (env-overridable for testing).
FATIGUE_WINDOW: Final[int] = int(os.environ.get("NOTA_FATIGUE_WINDOW", "3"))
FATIGUE_THRESHOLD_S: Final[float] = float(os.environ.get("NOTA_FATIGUE_S", "4.0"))
FATIGUE_PAUSE_S: Final[float] = float(os.environ.get("NOTA_FATIGUE_PAUSE", "3.0"))


@dataclass(slots=True)
class Prompter:
    """Terminal HITL prompt surface.

    Stateful: tracks ACK latencies in a rolling window for fatigue detection.
    One Prompter per nota session. Not thread-safe (intended for a
    single-threaded asyncio/anyio loop).
    """

    console: Console = field(default_factory=lambda: Console(stderr=True))
    _ack_latencies: deque[float] = field(default_factory=lambda: deque(maxlen=FATIGUE_WINDOW))

    def is_fatigued(self) -> bool:
        if len(self._ack_latencies) < FATIGUE_WINDOW:
            return False
        avg = sum(self._ack_latencies) / len(self._ack_latencies)
        return avg < FATIGUE_THRESHOLD_S

    def warn_fatigue(self) -> None:
        self.console.print(
            Panel(
                Text(
                    f"you have approved {FATIGUE_WINDOW} actions in under "
                    f"{FATIGUE_THRESHOLD_S:.0f}s each. holding for "
                    f"{FATIGUE_PAUSE_S:.0f}s so the next one gets a real read.",
                    style="yellow",
                ),
                title="[yellow]nota · slow down[/yellow]",
                border_style="yellow",
            ),
        )
        time.sleep(FATIGUE_PAUSE_S)

    def render_block(
        self,
        *,
        action: str,
        risk: Risk,
        intent: str,
        scope: tuple[str, ...],
        args: Mapping[str, object],
        reason: str,
    ) -> None:
        """Render a deterministic-block notification (no prompt fires).

        Used when the badge layer (scope check) refuses the action without
        even asking the human. The point is: explain why in plain English.
        """
        body = Table.grid(padding=(0, 2))
        body.add_column(style="dim", no_wrap=True)
        body.add_column()
        body.add_row("why", reason)
        body.add_row("session", intent)
        body.add_row("scope", ", ".join(scope) or "[dim](empty)[/dim]")
        body.add_row("action", action)
        for k, v in args.items():
            body.add_row(f"  {k}", repr(v))

        self.console.print(
            Panel(
                body,
                title=f"[bold red]nota · BLOCKED[/bold red]    [dim]{risk.value}[/dim]",
                border_style="red",
            ),
        )

    def _stdin_is_interactive(self) -> bool:
        """Can we actually read from stdin without blocking forever?

        Under `nota serve` the JSON-RPC reader owns stdin → input() would
        EOF immediately AND we'd swallow a JSON-RPC byte if we tried.
        """
        try:
            return bool(sys.stdin and sys.stdin.isatty())
        except (OSError, AttributeError):
            return False

    def _confirm_out_of_band(
        self,
        *,
        action: str,
        risk: Risk,
        args: Mapping[str, object],
        plain_summary: str | None,
        audit: Any | None,
    ) -> None:
        """Non-interactive path: issue approval, fire notification, raise.

        Used when stdin can't be read (proxy mode under stdio). The agent
        retries the same call after the user runs `nota approve <token>`,
        and the adapter's approval-consume path lets it through.
        """
        from nota.approvals import ApprovalStore

        token = ""
        try:
            store = ApprovalStore.load()
            ap = store.issue(
                action,
                dict(args),
                reason=plain_summary or f"{risk.value} risk: {action}",
            )
            token = ap.token
        except Exception:
            pass

        # Out-of-band notification dispatch (macOS / Slack / email / webhook)
        # was removed in the Change Control pivot. The paste-able approve line
        # on stderr below remains the path forward in non-interactive contexts.

        # Surface a paste-able approve line on stderr so the user - even
        # without notifications wired - sees the path forward in their
        # terminal output.
        self.console.print(
            f"  [yellow]non-interactive · approve with:[/yellow] [bold]nota approve {token}[/bold]"
            if token
            else "  [yellow]non-interactive · could not issue approval token[/yellow]",
        )
        decline_msg = (
            f"non-interactive prompter - agent retry will succeed after "
            f"`nota approve {token}` (TTL 10m)"
            if token
            else f"non-interactive prompter declined {action!r}"
        )
        raise HumanDeclined(decline_msg)

    def confirm(
        self,
        *,
        action: str,
        risk: Risk,
        intent: str,
        scope: tuple[str, ...],
        args: Mapping[str, object],
        plain_summary: str | None = None,
        audit: Any | None = None,
    ) -> float:
        """Block until the operator approves.

        Raises HumanDeclined if the operator says no.
        Raises ConfirmationMismatch if a critical-risk type-confirm fails.
        Returns the latency in seconds (used by the audit log + fatigue
        detector).

        If stdin is not a TTY (proxy stdio mode, CI, captured subprocess),
        skip the y/N entirely: issue an out-of-band approval token, fire
        notifications, and decline THIS call with a message telling the
        user how to approve. Agent retries within the TTL succeed via the
        same approval flow used by the Claude Code hook.
        """
        if self.is_fatigued():
            self.warn_fatigue()

        risk_color = {
            Risk.LOW: "green",
            Risk.MEDIUM: "yellow",
            Risk.HIGH: "red",
            Risk.CRITICAL: "bold red",
        }[risk]

        body = Table.grid(padding=(0, 2))
        body.add_column(style="dim", no_wrap=True)
        body.add_column()
        if plain_summary:
            body.add_row("[bold]→[/bold]", f"[bold]{plain_summary}[/bold]")
            body.add_row("", "")
        body.add_row("session", intent)
        body.add_row("action", action)
        body.add_row("scope", ", ".join(scope) or "[dim](empty)[/dim]")
        for k, v in args.items():
            body.add_row(f"  {k}", repr(v))

        self.console.print(
            Panel(
                body,
                title=f"[bold]nota[/bold]    [{risk_color}][{risk.value.upper()}][/{risk_color}]",
                border_style=risk_color,
            ),
        )

        # Non-TTY stdin: take the out-of-band path.
        if not self._stdin_is_interactive():
            self._confirm_out_of_band(
                action=action,
                risk=risk,
                args=args,
                plain_summary=plain_summary,
                audit=audit,
            )

        t0 = time.time()
        try:
            ans = input("  allow? [y/N] ").strip().lower()
        except EOFError:
            ans = ""

        if ans != "y":
            latency = time.time() - t0
            self._ack_latencies.append(latency)
            msg = f"operator declined {action!r}"
            raise HumanDeclined(msg)

        # Critical-risk type-confirm: prevents muscle-memory yes-spamming.
        if risk is Risk.CRITICAL:
            self.console.print(
                "  [bold red]CRITICAL.[/bold red] type the action name to confirm:",
            )
            self.console.print(f"  [dim]> [/dim][bold]{action}[/bold]")
            try:
                typed = input("  ").strip()
            except EOFError:
                typed = ""
            if typed != action:
                latency = time.time() - t0
                self._ack_latencies.append(latency)
                self.console.print("  [red]mismatch - declined.[/red]")
                msg = f"type-confirm mismatch for {action!r}: got {typed!r}"
                raise ConfirmationMismatch(msg)

        latency = time.time() - t0
        self._ack_latencies.append(latency)
        return latency
