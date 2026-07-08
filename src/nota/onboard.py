"""nota onboard - interactive first-run setup.

Replaces the placeholder-filled `nota init` flow with a guided 60-second
setup that auto-detects which coding agents the user has installed,
asks which to gate, prompts for log location, notification channels, and
a risk preset, then writes config.toml and installs hooks for the
selected agents.

Idempotent. If config.toml already exists, onboard offers to overwrite
or exit without changes. Non-TTY contexts exit cleanly without touching
anything. The risk preset writes [policy] overrides, not new code paths.
"""

from __future__ import annotations

import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from nota.config import default_audit_path, default_config_path

PRESET_DESCRIPTIONS: Final[dict[str, str]] = {
    "boring": "default: silent on reads, ask on writes, type-to-confirm on critical",
    "paranoid": "ask on every Edit/Write/Bash; type-to-confirm on every critical",
    "custom": "start from boring and adjust [policy] in config.toml later",
}


@dataclass
class DetectedAgent:
    """One detected coding agent on the user's machine."""

    name: str  # internal id ("claude_code", "cursor", ...)
    label: str  # display name ("Claude Code")
    detected: bool
    installer: str = ""  # which adapter to call ("claude_code", "cursor", "")
    notes: str = ""  # one-line context shown to the user


# ---------------------------------------------------------------------------
# detection (cheap, no network)
# ---------------------------------------------------------------------------


def _detect_claude_code() -> DetectedAgent:
    home = Path.home() / ".claude"
    if home.exists() or shutil.which("claude"):
        return DetectedAgent(
            name="claude_code",
            label="Claude Code",
            detected=True,
            installer="claude_code",
            notes="PreToolUse hook gates Bash, Edit, Write, NotebookEdit",
        )
    return DetectedAgent(name="claude_code", label="Claude Code", detected=False)


def _detect_cursor() -> DetectedAgent:
    if Path("/Applications/Cursor.app").exists() or (Path.home() / ".cursor").exists():
        return DetectedAgent(
            name="cursor",
            label="Cursor (1.7+)",
            detected=True,
            installer="cursor",
            notes="pre-tool-call hook gates Shell, MCP, and ReadFile",
        )
    return DetectedAgent(name="cursor", label="Cursor (1.7+)", detected=False)


def _detect_cline() -> DetectedAgent:
    # Cline is a VS Code extension. Check both VS Code and Cursor's extension dirs.
    candidates = [
        Path.home() / ".vscode" / "extensions",
        Path.home() / ".cursor" / "extensions",
    ]
    for ext_dir in candidates:
        if ext_dir.exists():
            for child in ext_dir.iterdir():
                if "claude-dev" in child.name.lower() or "cline" in child.name.lower():
                    return DetectedAgent(
                        name="cline",
                        label="Cline",
                        detected=True,
                        notes="use Nota's MCP proxy (v0.3 will ship a native adapter)",
                    )
    return DetectedAgent(name="cline", label="Cline", detected=False)


def _detect_aider() -> DetectedAgent:
    if shutil.which("aider"):
        return DetectedAgent(
            name="aider",
            label="Aider",
            detected=True,
            notes="use Nota's MCP proxy or wrap aider via shell function",
        )
    return DetectedAgent(name="aider", label="Aider", detected=False)


def _detect_continue() -> DetectedAgent:
    for ext_dir in (Path.home() / ".vscode" / "extensions", Path.home() / ".cursor" / "extensions"):
        if ext_dir.exists():
            for child in ext_dir.iterdir():
                if child.name.lower().startswith("continue.continue"):
                    return DetectedAgent(
                        name="continue",
                        label="Continue",
                        detected=True,
                        notes="use Nota's MCP proxy (v0.3 will ship a native adapter)",
                    )
    return DetectedAgent(name="continue", label="Continue", detected=False)


def _detect_windsurf() -> DetectedAgent:
    if Path("/Applications/Windsurf.app").exists() or (Path.home() / ".windsurf").exists():
        return DetectedAgent(
            name="windsurf",
            label="Windsurf",
            detected=True,
            notes="use Nota's MCP proxy (v0.3 will ship a native adapter)",
        )
    return DetectedAgent(name="windsurf", label="Windsurf", detected=False)


def _detect_zed() -> DetectedAgent:
    if Path("/Applications/Zed.app").exists() or (Path.home() / ".config" / "zed").exists():
        return DetectedAgent(
            name="zed",
            label="Zed",
            detected=True,
            notes="use Nota's MCP proxy (v0.3 will ship a native adapter)",
        )
    return DetectedAgent(name="zed", label="Zed", detected=False)


def detect_coding_tools() -> list[DetectedAgent]:
    """Detect every supported coding agent on this machine."""
    return [
        _detect_claude_code(),
        _detect_cursor(),
        _detect_cline(),
        _detect_aider(),
        _detect_continue(),
        _detect_windsurf(),
        _detect_zed(),
    ]


# ---------------------------------------------------------------------------
# config rendering
# ---------------------------------------------------------------------------


def _toml_str_list(values: list[str], indent: str = "  ") -> str:
    if not values:
        return "[]"
    body = ",\n".join(f'{indent}"{v}"' for v in values)
    return f"[\n{body},\n]"


def _toml_kv(d: dict[str, Any], indent: str = "") -> list[str]:
    """Serialize a flat dict to TOML key=value lines."""
    out = []
    for k, v in d.items():
        if isinstance(v, bool):
            out.append(f"{indent}{k} = {str(v).lower()}")
        elif isinstance(v, (int, float)):
            out.append(f"{indent}{k} = {v}")
        else:
            out.append(f'{indent}{k} = "{v}"')
    return out


def build_config_toml(
    *,
    intent: str,
    scope: list[str],
    audit_path: Path,
    notify: dict[str, Any],
    preset: str,
    trust_paths: list[str],
) -> str:
    """Render a complete config.toml from the user's answers."""
    parts: list[str] = [
        "# nota config - generated by `nota onboard`",
        "# https://github.com/manumarri-sudo/nota",
        "",
        "[session]",
        f'intent = "{intent}"',
        f"scope = {_toml_str_list(scope)}",
        "",
        "[audit]",
        f'path = "{audit_path}"',
        "",
        "[trust]",
        f"paths = {_toml_str_list(trust_paths)}",
        "",
        "[policy]",
    ]
    if preset == "paranoid":
        parts += [
            "# paranoid preset: every Edit/Write asks; every Bash high-classifies",
            '"Edit" = "high"',
            '"Write" = "high"',
            '"MultiEdit" = "high"',
            '"NotebookEdit" = "high"',
        ]
    else:
        parts.append('# add per-tool risk overrides here, e.g. \'"fs.delete" = "critical"\'')
    parts.append("")
    if notify:
        parts.append("[notify]")
        parts += _toml_kv(notify)
        parts.append("")
    parts += [
        "[telemetry]",
        "enabled = false",
        "",
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------


def _print_detected(console: Console, detected: list[DetectedAgent]) -> None:
    table = Table(title="detected coding agents", show_lines=False, title_style="bold")
    table.add_column("agent")
    table.add_column("status")
    table.add_column("notes", overflow="fold")
    for a in detected:
        status = "[green]found[/green]" if a.detected else "[dim]not found[/dim]"
        table.add_row(a.label, status, a.notes or "—")
    console.print(table)


def _prompt_choose_agents(
    console: Console,
    detected: list[DetectedAgent],
) -> list[DetectedAgent]:
    found = [a for a in detected if a.detected and a.installer]
    if not found:
        console.print(
            "\n[yellow]no native-hook coding agent detected.[/yellow] "
            "Nota can still gate any MCP-using tool via [bold]nota serve[/bold] "
            "(MCP proxy mode).",
        )
        return []
    chosen = []
    console.print()
    for a in found:
        if Confirm.ask(f"  gate [bold]{a.label}[/bold]?", default=True):
            chosen.append(a)
    return chosen


def _prompt_log_location(console: Console) -> Path:
    default = default_audit_path()
    console.print(
        "\n[bold]where should the audit log live?[/bold]\n"
        "  [dim]tamper-evident HMAC-chained JSONL, mode 0o600[/dim]",
    )
    raw = Prompt.ask("  path", default=str(default))
    return Path(raw).expanduser().resolve()


def _prompt_notifications(console: Console) -> dict[str, Any]:
    is_mac = platform.system() == "Darwin"
    notify: dict[str, Any] = {"on_blocked": True, "on_ask": False}
    console.print(
        "\n[bold]notifications for blocked calls[/bold]\n"
        "  [dim]each block fans WHAT/WHY/TRY/APPROVE out of the terminal[/dim]",
    )
    if is_mac and Confirm.ask("  macOS notification center?", default=True):
        notify["macos"] = True
        notify["sound"] = "Glass"
    if Confirm.ask("  Slack webhook?", default=False):
        url = Prompt.ask("    webhook url", default="")
        if url.startswith("http"):
            notify["slack_webhook_url"] = url
    if Confirm.ask("  generic JSON webhook?", default=False):
        url = Prompt.ask("    endpoint url", default="")
        if url.startswith("http"):
            notify["webhook_url"] = url
    # only macos key is enough by itself; if no channels, return empty dict
    if not any(k in notify for k in ("macos", "slack_webhook_url", "webhook_url")):
        return {}
    return notify


def _prompt_risk_preset(console: Console) -> str:
    console.print("\n[bold]risk preset[/bold]")
    for name, desc in PRESET_DESCRIPTIONS.items():
        console.print(f"  [cyan]{name:9}[/cyan] {desc}")
    return Prompt.ask("  pick one", choices=list(PRESET_DESCRIPTIONS), default="boring")


def _prompt_intent_and_scope(console: Console) -> tuple[str, list[str]]:
    console.print(
        "\n[bold]session intent[/bold]\n"
        "  [dim]a one-line description of what the agent is supposed to do[/dim]",
    )
    intent = Prompt.ask("  intent", default="exploratory development")
    scope: list[str] = []
    console.print(
        "\n[bold]session scope[/bold] [dim](optional; out-of-scope calls get refused)[/dim]\n"
        "  [dim]format: namespace:action[:resource]  e.g. github:read  fs:write:src/[/dim]",
    )
    if Confirm.ask("  declare scopes now?", default=False):
        while True:
            s = Prompt.ask("    scope (blank to finish)", default="")
            if not s:
                break
            scope.append(s)
    return intent, scope


def _prompt_trust_paths(console: Console) -> list[str]:
    """Ask which directories the operator considers their working trees.

    Default-HIGH-risk Edit / Write / NotebookEdit calls inside a trusted
    path auto-allow rather than prompting; this is THE fix for approval-
    prompt fatigue. Pattern-matched HIGHs (curl, pip install, etc.) and
    every CRITICAL event still fire regardless of trust scope.
    """
    cwd = str(Path.cwd().resolve())
    console.print(
        "\n[bold]trusted directories[/bold]\n"
        "  [dim]inside these paths, default Edit/Write asks become auto-allow.[/dim]\n"
        "  [dim]critical events (rm -rf, force-push, deploy, secrets in diffs) still gate regardless.[/dim]",
    )
    paths: list[str] = []
    if Confirm.ask(f"  trust current directory ([cyan]{cwd}[/cyan])?", default=True):
        paths.append(cwd)
    if Confirm.ask("  add other trusted paths?", default=False):
        console.print(
            "    [dim]one path per line, blank to finish (~ is expanded)[/dim]",
        )
        while True:
            raw = Prompt.ask("    path", default="")
            if not raw:
                break
            p = Path(raw).expanduser().resolve()
            paths.append(str(p))
    return paths


# ---------------------------------------------------------------------------
# install dispatch
# ---------------------------------------------------------------------------


def _install_hook(console: Console, agent: DetectedAgent) -> None:
    """Call the existing adapter installer for an agent."""
    try:
        if agent.installer == "claude_code":
            from nota.adapters import claude_code as cc

            p, already = cc.install_into_settings(
                None,
                matcher="Bash|Edit|Write|NotebookEdit",
                timeout=10,
            )
            status = "already wired" if already else "installed"
            console.print(f"  [green]✓[/green] {agent.label}: {status} ({p})")
        elif agent.installer == "cursor":
            from nota.adapters import cursor as cu

            p, already = cu.install_into_settings(None)
            status = "already wired" if already else "installed"
            console.print(f"  [green]✓[/green] {agent.label}: {status} ({p})")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] {agent.label} install failed: {e}")


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------


def run(force: bool = False, console: Console | None = None) -> int:
    """Run the onboard wizard. Returns 0 on success, non-zero on abort."""
    out = console or Console()
    cfg_path = default_config_path()

    if not sys.stdin.isatty() and not force:
        out.print(
            "[red]onboard is interactive.[/red] "
            "Run it in a real terminal, or use `nota init` for a non-interactive starter.",
        )
        return 2

    out.print(
        Panel.fit(
            "[bold]nota onboard[/bold]\n"
            "[dim]the pause button between your AI agent and the things you can't undo.[/dim]\n"
            "[dim]this takes about 60 seconds.[/dim]",
            border_style="cyan",
        )
    )

    if cfg_path.exists() and not force:
        out.print(f"\n[yellow]existing config at[/yellow] {cfg_path}")
        if not Confirm.ask("  overwrite with a fresh onboard?", default=False):
            out.print("[dim]exited without changes.[/dim]")
            return 0

    detected = detect_coding_tools()
    _print_detected(out, detected)
    chosen = _prompt_choose_agents(out, detected)
    audit_path = _prompt_log_location(out)
    notify = _prompt_notifications(out)
    preset = _prompt_risk_preset(out)
    intent, scope = _prompt_intent_and_scope(out)
    trust_paths = _prompt_trust_paths(out)

    config_text = build_config_toml(
        intent=intent,
        scope=scope,
        audit_path=audit_path,
        notify=notify,
        preset=preset,
        trust_paths=trust_paths,
    )

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(config_text)
    cfg_path.chmod(0o600)
    out.print(f"\n[green]✓[/green] wrote config to {cfg_path}")

    if chosen:
        out.print("\n[bold]installing hooks[/bold]")
        for agent in chosen:
            _install_hook(out, agent)

    out.print(
        Panel.fit(
            "[bold]you're set.[/bold]\n"
            "  [dim]restart your coding agent to pick up the hook[/dim]\n"
            "  [dim]then run [bold]nota watch[/bold] for the live dashboard[/dim]\n"
            "  [dim]or [bold]nota audit show[/bold] to review what's been logged[/dim]\n"
            "  [dim]docs:[/dim] https://github.com/manumarri-sudo/nota",
            border_style="green",
        )
    )
    return 0
