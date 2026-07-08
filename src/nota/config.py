"""Configuration loading.

Nota config lives at ~/.nota/config.toml by default. Format:

  [session]
  intent = "Help customer c_8e4f, refund cap $100"
  scope = [
    "payments:refund:customer:c_8e4f",
    "customer:c_8e4f:read",
  ]
  budget_usd = 50

  [audit]
  path = "~/.nota/audit.log.jsonl"

  [[upstream]]
  name = "filesystem"
  command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"]
  env = { NODE_ENV = "production" }

  [[upstream]]
  name = "github"
  command = ["docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]
  env_pass = ["GITHUB_TOKEN"]

  [policy]
  # Per-tool risk overrides. Default classification (see policy.classify) is
  # used when not specified here.
  "fs.delete" = "critical"
  "fs.read_file" = "low"
  "github.list_issues" = "low"

  [telemetry]
  enabled = false   # opt-in only

The config is loaded ONCE at process start, validated through Pydantic, and
then frozen. Hot-path policy code never re-parses TOML.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nota.errors import ConfigError
from nota.policy import Risk, Scope

# Stdlib tomllib (3.11+); fall back to tomli on older interpreters.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


def default_config_path() -> Path:
    from nota.paths import default_path

    return default_path("config.toml", env_override="NOTA_CONFIG")


def default_audit_path() -> Path:
    from nota.paths import default_path

    return default_path("audit.log.jsonl", env_override="NOTA_LOG")


class UpstreamConfig(BaseModel):
    """One upstream MCP server that Nota proxies."""

    model_config = ConfigDict(strict=True, extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    # TOML arrays become Python lists; strict mode would reject tuple, so we
    # accept list at the schema boundary and only convert to tuple at the
    # internal usage site.
    command: list[str] = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    env_pass: list[str] = Field(
        default_factory=list,
        description="Names of env vars to forward from Nota's environ "
        "(e.g. GITHUB_TOKEN). NEVER includes Nota's own secrets.",
    )
    allow_sampling: bool = Field(
        default=False,
        description="Opt-in: let this upstream call `sampling/createMessage` "
        "to drive the downstream client's LLM. DEFAULT-DENY because the "
        "channel can launder secrets through the client's context. Only "
        "enable for upstreams you fully trust.",
    )

    @field_validator("env_pass")
    @classmethod
    def _check_env_pass(cls, v: list[str]) -> list[str]:
        # Refuse to forward anything that smells like Nota's signing key.
        forbidden = {"NOTA_HMAC_KEY", "NOTA_SIGNING_KEY"}
        bad = [e for e in v if e in forbidden]
        if bad:
            msg = f"env_pass cannot include nota secrets: {bad}"
            raise ValueError(msg)
        return v


class SessionConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    intent: str = Field(min_length=1, max_length=2000)
    scope: list[str] = Field(default_factory=list)
    budget_usd: float | None = Field(default=None, ge=0)

    def parsed_scope(self) -> tuple[Scope, ...]:
        return tuple(Scope.parse(s) for s in self.scope)


class AuditConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    # If None, fall through to NOTA_HOME-aware default at resolve time.
    path: str | None = Field(default=None)

    def resolved_path(self) -> Path:
        if self.path:
            return Path(self.path).expanduser()
        return default_audit_path()


class TelemetryConfig(BaseModel):
    """Telemetry is OPT-IN. Default false. Even when enabled, only aggregate
    counts and timings ship; never tool args, never intent contents, never
    file paths."""

    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: bool = False
    endpoint: str | None = None


class OvernightConfig(BaseModel):
    """Overnight mode - auto-approve HIGH-risk actions so unattended agents
    do not stall on Edit/Write prompts overnight.

    Safety contract: CRITICAL risk is NEVER auto-approved by overnight mode.
    rm -rf, DROP TABLE, vercel --prod, git push --force, sudo, etc. all
    continue to gate regardless of overnight state.

    Active when either:
      - `nota night` is manually toggled on (time-bounded, default 12h expiry)
      - `enabled = true` here AND current local time is within the window

      [overnight]
      enabled = true
      window_start = "22:00"
      window_end = "08:00"

    Window crosses midnight when start > end (the default 22:00-08:00 does).
    Times are local. The whole point of overnight mode is operator sleep
    schedule, which is wall-clock-local by nature.
    """

    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: bool = False
    window_start: str = "22:00"
    window_end: str = "08:00"


class TrustConfig(BaseModel):
    """Per-directory trust scopes - the fix for approval-prompt fatigue.

    Edit/Write/MultiEdit/NotebookEdit fire as default-HIGH-risk inside
    Claude Code. In a repo the operator has already chosen to work in,
    every such call would otherwise produce an `ask` prompt and train
    the operator to mash "approve" - which then defeats the gate on
    the calls that actually matter. The fix: list trusted paths here;
    while cwd is inside one, the DEFAULT high-risk classification for
    Edit/Write is downshifted to LOW (auto-allow). Pattern-matched
    HIGHs (curl, pip install in non-venv etc.) and all CRITICAL events
    are NOT affected - they fire regardless of trust scope.

    Format: list of paths. `~` is expanded. A cwd matches a trusted
    path if it equals it or is inside it (.resolve() + is_relative_to).

      [trust]
      paths = ["~/projects/my-app", "~/nota"]
    """

    model_config = ConfigDict(strict=True, extra="forbid")
    paths: list[str] = Field(default_factory=list)


class NotaConfig(BaseModel):
    # Allow extra top-level sections (e.g. [bash], [tools]) so operators can
    # add config-driven extensions (Bash allowlist patterns, etc.) without
    # forking the schema. Validated sections are still strict.
    model_config = ConfigDict(strict=True, extra="allow")
    session: SessionConfig
    audit: AuditConfig = Field(default_factory=AuditConfig)
    upstream: list[UpstreamConfig] = Field(default_factory=list)
    policy: dict[str, Risk] = Field(default_factory=dict)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    overnight: OvernightConfig = Field(default_factory=OvernightConfig)

    @field_validator("policy", mode="before")
    @classmethod
    def _coerce_policy_risk_strings(cls, v: Any) -> Any:
        # TOML stores Risk overrides as strings ("critical", "high", ...).
        # Strict pydantic mode otherwise rejects these because Risk is a
        # str-enum and isinstance("high", Risk) is False. Coerce here so
        # the documented `[policy]` section works as advertised.
        if not isinstance(v, dict):
            return v
        return {k: Risk(val) if isinstance(val, str) else val for k, val in v.items()}


def load_config(path: Path | None = None) -> NotaConfig:
    """Read TOML, validate, return a frozen-shape NotaConfig.

    Raises ConfigError on read or validation failure (never lets a stdlib
    exception leak - keeps the public surface clean for callers).
    """
    p = path or default_config_path()
    if not p.exists():
        msg = f"no config at {p}. write one (see nota init) or set NOTA_CONFIG."
        raise ConfigError(msg)
    try:
        with p.open("rb") as f:
            data = tomllib.load(f)
        return NotaConfig.model_validate(data)
    except (OSError, tomllib.TOMLDecodeError) as e:
        msg = f"could not read config at {p}: {e}"
        raise ConfigError(msg) from e
    except ValueError as e:
        msg = f"invalid config at {p}: {e}"
        raise ConfigError(msg) from e


def render_starter_config() -> str:
    """Return a starter TOML for `nota init`."""
    return """\
# nota config - see https://github.com/manumarri-sudo/nota

[session]
# What is the human telling the agent to do? Captured at session start.
intent = "describe what the agent should be doing"
# Granted scopes. Format: "namespace:action[:resource]"
scope = []
# Optional dollar ceiling that propagates across all sub-agents.
# budget_usd = 20

[audit]
# Where the signed JSONL audit log lives. Mode 0o600.
# Defaults to $NOTA_HOME/audit.log.jsonl (or ~/.nota/audit.log.jsonl).
# Override per-project by setting `path` here or with NOTA_LOG.
# path = "~/.nota/audit.log.jsonl"

# One [[upstream]] block per MCP server you want nota to proxy.
# Tool calls advertised by these upstreams are protected by the gate.
# [[upstream]]
# name = "filesystem"
# command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe"]

# Per-tool risk overrides. Defaults handle the obvious dangerous actions
# (rm, delete, drop table, force-push, deploy:production, stripe.*) as
# critical, requiring type-to-confirm.
[policy]
# "fs.delete" = "critical"
# "github.list_issues" = "low"

# Trust scopes - the fix for approval-prompt fatigue. List the absolute
# paths of repositories you actively work in. Default-HIGH-risk Edit /
# Write / MultiEdit / NotebookEdit calls inside one of these paths
# auto-allow instead of asking for approval. Pattern-matched HIGHs
# (curl, pip install, etc.) and all CRITICAL events still fire
# regardless of trust. Manage with `nota trust add/remove/list/check`.
[trust]
paths = [
  # "~/projects/my-app",
  # "~/nota",
]

[telemetry]
# Anonymous aggregate counts only. Never tool args, intent contents, or
# file paths. Off by default; turn on if you want to help shape v0.2.
enabled = false

# Out-of-band notifications when a call is blocked or asks for confirmation.
# Off by default. Uncomment + configure the channels you want.
# Each notification carries: WHAT was attempted, WHY it was blocked,
# WHAT TO TRY INSTEAD, and a one-shot `nota approve <token>` command.
# [notify]
# macos = true                          # macOS Notification Center banner
# sound = "Glass"                       # optional, macOS only
# email_to = "you@example.com"          # SMTP via [notify.email]; needs $NOTA_SMTP_PASS
# slack_webhook_url = "https://hooks.slack.com/..."
# webhook_url = "https://your.endpoint/nota"  # generic JSON POST
# on_blocked = true                     # fire on critical-risk denials (default true)
# on_ask = false                        # fire on high-risk ask-the-human events (default false)
# on_critical_only = false              # if true, fire only on CRITICAL
#
# [notify.email]
# smtp_host = "smtp.gmail.com"
# smtp_port = 587
# smtp_user = "you@example.com"
# smtp_password_env = "NOTA_SMTP_PASS" # password loaded from this env var
"""
