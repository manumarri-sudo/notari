"""`quill doctor` - first-run-friction killer.

Runs deterministic checks against the user's installation and reports a
green/yellow/red status for each. Designed to answer the question every
new user asks: "did I install this right?"

Each check is independent, fast, and produces a one-line summary. No
external network calls; the doctor never decides for the user, only
shows the state and points at the fix.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from quill._version import __version__
from quill.config import (
    QuillConfig,
    default_audit_path,
    default_config_path,
    load_config,
)
from quill.errors import ConfigError

# Symbols & colours expected to be wrapped by the caller (rich tags).
PASS: Final[str] = "[green]PASS[/green]"
WARN: Final[str] = "[yellow]WARN[/yellow]"
FAIL: Final[str] = "[red]FAIL[/red]"


@dataclass(slots=True)
class CheckResult:
    """One row of doctor output."""

    name: str
    status: str  # PASS | WARN | FAIL (rich tags above)
    detail: str
    fix: str = ""  # one-line remediation hint shown on WARN/FAIL


@dataclass(slots=True)
class DoctorReport:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    @property
    def has_failures(self) -> bool:
        return any(r.status == FAIL for r in self.results)

    @property
    def has_warnings(self) -> bool:
        return any(r.status == WARN for r in self.results)


# ---------------------------------------------------------------------------
# individual checks
# ---------------------------------------------------------------------------


def check_python_version() -> CheckResult:
    v = sys.version_info
    if (v.major, v.minor) < (3, 11):
        return CheckResult(
            "python",
            FAIL,
            f"Python {v.major}.{v.minor}.{v.micro} (need >= 3.11)",
            fix="Upgrade Python to 3.11+ (recommended: 3.12 or 3.13).",
        )
    return CheckResult(
        "python",
        PASS,
        f"Python {v.major}.{v.minor}.{v.micro}",
    )


def check_quill_version() -> CheckResult:
    return CheckResult(
        "quill",
        PASS,
        f"quill {__version__} (installed at {Path(__file__).resolve().parent})",
    )


def check_config(config_path: Path | None = None) -> tuple[CheckResult, QuillConfig | None]:
    p = config_path or default_config_path()
    if not p.exists():
        return (
            CheckResult(
                "config",
                WARN,
                f"no config at {p}",
                fix="Run `quill init` to write a starter config.",
            ),
            None,
        )
    try:
        cfg = load_config(p)
    except ConfigError as e:
        return (
            CheckResult(
                "config",
                FAIL,
                f"{p}: {e}",
                fix="Fix the TOML errors above. Run `quill init --force` to reset.",
            ),
            None,
        )
    n_upstreams = len(cfg.upstream)
    n_scopes = len(cfg.session.scope)
    detail = (
        f"{p} ({n_upstreams} upstream{'' if n_upstreams == 1 else 's'}, "
        f"{n_scopes} scope{'' if n_scopes == 1 else 's'})"
    )
    return CheckResult("config", PASS, detail), cfg


def check_audit_log(audit_path: Path | None = None) -> CheckResult:
    p = audit_path or default_audit_path()
    parent = p.parent
    if not parent.exists():
        return CheckResult(
            "audit log",
            WARN,
            f"directory does not exist yet: {parent}",
            fix=f"Will be created on first emit. To pre-create: mkdir -p {parent}",
        )
    if not os.access(parent, os.W_OK):
        return CheckResult(
            "audit log",
            FAIL,
            f"directory not writable: {parent}",
            fix="chmod the directory or use QUILL_LOG=path/to/your/audit.log.jsonl",
        )
    if p.exists():
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            return CheckResult(
                "audit log",
                FAIL,
                f"{p} is world/group readable (mode {oct(mode)})",
                fix=f"chmod 600 {p}",
            )
        size_kb = p.stat().st_size / 1024
        return CheckResult("audit log", PASS, f"{p} ({size_kb:.1f} KB, mode 0o600)")
    return CheckResult("audit log", PASS, f"writable: {p} (no log yet)")


def check_hmac_key() -> CheckResult:
    from quill.paths import default_path

    p = default_path("key", env_override="QUILL_KEY")
    if not p.exists():
        return CheckResult(
            "hmac key",
            WARN,
            f"no key yet at {p}",
            fix="Will be auto-generated on first quill start / claude-hook invocation.",
        )
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        return CheckResult(
            "hmac key",
            FAIL,
            f"{p} is too permissive (mode {oct(mode)})",
            fix=f"chmod 600 {p}  -- the signing key must not be world-readable.",
        )
    if p.stat().st_size != 32:
        return CheckResult(
            "hmac key",
            WARN,
            f"{p} is {p.stat().st_size} bytes (expected 32)",
            fix="Rotate the key: rm the file and let quill regenerate it.",
        )
    return CheckResult("hmac key", PASS, f"{p} (32 bytes, mode 0o600)")


def _hook_command_from_settings(
    settings_path: Path | None = None,
) -> str | None:
    """Return the hook command string from settings.json, or None.

    Recognizes both bare `quill claude-hook` and any absolute-path form
    like `/Users/foo/.venv/bin/quill claude-hook`. The check is
    suffix-based on `quill claude-hook` so future-proofing across
    installation locations is automatic.
    """
    p = settings_path or Path("~/.claude/settings.json").expanduser()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text() or "{}")
    except json.JSONDecodeError:
        return None
    pre_list = (data.get("hooks") or {}).get("PreToolUse") or []
    for block in pre_list:
        for h in block.get("hooks") or []:
            cmd: str = h.get("command", "")
            if cmd.endswith("quill claude-hook"):
                return cmd
    return None


def check_claude_hook_installed(
    settings_path: Path | None = None,
) -> CheckResult:
    p = settings_path or Path("~/.claude/settings.json").expanduser()
    if not p.exists():
        return CheckResult(
            "claude code hook",
            WARN,
            f"no Claude Code settings at {p}",
            fix="Run `quill claude-hook-install` once Claude Code is installed.",
        )
    try:
        json.loads(p.read_text() or "{}")
    except json.JSONDecodeError as e:
        return CheckResult(
            "claude code hook",
            FAIL,
            f"{p} is not valid JSON: {e}",
            fix="Fix the JSON, then re-run quill claude-hook-install.",
        )
    cmd = _hook_command_from_settings(p)
    if cmd is None:
        return CheckResult(
            "claude code hook",
            WARN,
            f"hook not installed in {p}",
            fix="Run `quill claude-hook-install` to enable gating Claude Code's built-in tools.",
        )
    return CheckResult(
        "claude code hook",
        PASS,
        f"installed in {p} (command: {cmd})",
    )


def check_quill_on_path(
    settings_path: Path | None = None,
) -> CheckResult:
    """Verify that whichever quill the hook uses is actually executable.

    Three cases:
      1. Hook uses an absolute path that exists + is executable -> PASS
         (no PATH lookup needed because the hook bypasses PATH)
      2. Hook uses a bare `quill claude-hook` -> requires `quill` on PATH
      3. Hook is not installed -> not our problem here; the hook check
         already reported that
    """
    cmd = _hook_command_from_settings(settings_path)
    if cmd is None:
        # Falls back to the legacy "is quill on PATH?" check so a fresh
        # install without a hook still gets a useful answer.
        found = shutil.which("quill")
        if not found:
            return CheckResult(
                "quill on PATH",
                WARN,
                "the `quill` command is not on PATH and no hook is installed yet",
                fix="Install with `pipx install quillx` or activate the venv, "
                "then run `quill onboard` or `quill claude-hook-install`.",
            )
        return CheckResult("quill on PATH", PASS, found)

    # Hook command is `<binary path> claude-hook`. Extract the binary.
    binary_token = cmd.split()[0]
    binary_path = Path(binary_token)
    if binary_path.is_absolute():
        if binary_path.exists() and os.access(binary_path, os.X_OK):
            return CheckResult(
                "quill binary",
                PASS,
                f"hook resolves to {binary_path} (executable)",
            )
        return CheckResult(
            "quill binary",
            FAIL,
            f"hook points at {binary_path} which is missing or not executable",
            fix="Re-run `quill claude-hook-install` from the correct venv, "
            "or edit the absolute path in ~/.claude/settings.json.",
        )

    # Bare command (e.g. "quill"). Falls back to PATH lookup.
    found = shutil.which(binary_token)
    if not found:
        return CheckResult(
            "quill on PATH",
            FAIL,
            f"hook uses bare `{binary_token}` but it is not on PATH",
            fix="Either install quill on PATH (`pipx install quillx`) OR "
            "re-run `quill claude-hook-install` from your venv to bake "
            "the absolute path into settings.json.",
        )
    return CheckResult("quill on PATH", PASS, f"hook resolves to {found}")


def check_upstream_executables(cfg: QuillConfig | None) -> list[CheckResult]:
    """Check each [[upstream]] block's first command-token resolves on PATH."""
    if cfg is None or not cfg.upstream:
        return []
    out: list[CheckResult] = []
    for up in cfg.upstream:
        token = up.command[0]
        if Path(token).is_absolute():
            ok = Path(token).exists()
            out.append(
                CheckResult(
                    f"upstream/{up.name}",
                    PASS if ok else FAIL,
                    f"command[0]: {token}" if ok else f"command[0] does not exist: {token}",
                    fix="" if ok else "Fix the path or install the executable.",
                ),
            )
        else:
            found = shutil.which(token)
            out.append(
                CheckResult(
                    f"upstream/{up.name}",
                    PASS if found else WARN,
                    f"command[0]: {token} -> {found}"
                    if found
                    else f"command[0] not on PATH: {token}",
                    fix="" if found else f"Install {token} or use an absolute path.",
                ),
            )
    return out


def check_audit_chain_intact(audit_path: Path | None = None) -> CheckResult:
    """Verify the existing audit log's HMAC chain.

    Conservative on missing files: a missing log is fine (no entries yet).
    """
    p = audit_path or default_audit_path()
    if not p.exists() or p.stat().st_size == 0:
        return CheckResult("audit chain", PASS, f"{p} is empty")

    from quill.paths import default_path

    key_path = default_path("key", env_override="QUILL_KEY")
    if not key_path.exists():
        return CheckResult(
            "audit chain",
            WARN,
            "log exists but no HMAC key at default path; can't verify",
            fix="Set QUILL_KEY to the key that wrote this log, or check ~/.quill/key.",
        )
    try:
        key = key_path.read_bytes()
        from quill.audit import verify_chain  # local import

        total, failures = verify_chain(p, key)
    except (OSError, ValueError) as e:
        return CheckResult(
            "audit chain",
            FAIL,
            f"{p}: {e}",
            fix="The log may be corrupted. Stop quill and investigate.",
        )
    if failures:
        return CheckResult(
            "audit chain",
            FAIL,
            f"chain BROKEN: {len(failures)} of {total} entries fail",
            fix=f"Inspect: quill audit verify --log {p}. Possible tampering.",
        )
    return CheckResult("audit chain", PASS, f"{total} entries verified")


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------


def check_stale_pattern_stats() -> CheckResult:
    """Surface stale per-token pattern rows from a pre-rc5 bug so the
    operator can run `quill suggestions cleanup` to remove them."""
    try:
        from quill.learning import find_stale_patterns

        stale = find_stale_patterns()
    except Exception as e:
        return CheckResult(
            "stale pattern rows",
            PASS,
            f"learning module not loaded ({type(e).__name__})",
        )
    if not stale:
        return CheckResult("stale pattern rows", PASS, "none")
    return CheckResult(
        "stale pattern rows",
        WARN,
        f"{len(stale)} per-token row(s) from a pre-rc5 bug",
        fix="quill suggestions cleanup",
    )


def check_self_improvement_signals() -> CheckResult:
    """Surface the highest-severity `quill learn` suggestion as a
    doctor check so silent self-improvement signals don't sit unread.
    Returns PASS when there's nothing actionable; WARN with a pointer
    to `quill learn` when there is.
    """
    try:
        from quill.learn import analyze

        suggestions, _ = analyze(since_days=7)
    except Exception as e:
        return CheckResult(
            "self-improvement",
            PASS,
            f"learn module not loaded ({type(e).__name__})",
        )
    if not suggestions:
        return CheckResult("self-improvement", PASS, "no actionable signals in the last 7d")
    high = [s for s in suggestions if s.severity == "high"]
    if high:
        top = high[0]
        return CheckResult(
            "self-improvement",
            WARN,
            f"{len(suggestions)} suggestion(s); top: {top.title}",
            fix=f"see all: quill learn  ·  top action: {top.paste_command}",
        )
    top = suggestions[0]
    return CheckResult(
        "self-improvement",
        PASS,
        f"{len(suggestions)} medium/low suggestion(s); top: {top.title}",
        fix="see all: quill learn",
    )


def check_otel_dual_write() -> CheckResult:
    """Surface OTel dual-write failures, if any, since process start.

    The dual-write path swallows OTel errors so a misconfigured endpoint
    can't crash the audit log. But silent swallow used to mean "we never
    notice the OTel ingest is broken." We now count failures and expose
    them here.
    """
    try:
        from quill import otel as _otel

        n = getattr(_otel, "_dual_write_failed_count", 0)
    except Exception:
        return CheckResult("otel dual-write", PASS, "module not loaded")
    if n == 0:
        return CheckResult("otel dual-write", PASS, "no failures recorded")
    return CheckResult(
        "otel dual-write",
        WARN,
        f"{n} dual-write failure(s) since process start",
        fix="Check OTEL_EXPORTER_OTLP_ENDPOINT / collector connectivity. "
        "Audit chain is unaffected; only OTel spans are dropping.",
    )


def check_permission_decay() -> CheckResult:
    """Surface decayed Quill permissions if any exist."""
    try:
        from quill import decay as _decay  # local import; optional path

        store = _decay.DecayStore.load()
    except Exception as e:
        return CheckResult(
            "permission decay",
            WARN,
            f"could not read decay store: {e}",
            fix="Inspect ~/.quill/permissions.json manually.",
        )
    decayed = store.decayed()
    approaching = store.approaching()
    if decayed:
        names = ", ".join(p.pattern for p in decayed[:5])
        more = "" if len(decayed) <= 5 else f", +{len(decayed) - 5} more"
        return CheckResult(
            "permission decay",
            WARN,
            f"{len(decayed)} decayed: {names}{more}",
            fix="Run `quill decay show` for the full list, "
            "`quill decay reaffirm <pattern>` to refresh, or "
            "`quill decay forget <pattern>` to retire.",
        )
    if approaching:
        return CheckResult(
            "permission decay",
            PASS,
            f"healthy · {len(approaching)} approaching window",
        )
    total = len(store.all())
    if total == 0:
        return CheckResult(
            "permission decay",
            PASS,
            "no tracked permissions yet (auto-registered on first override)",
        )
    return CheckResult("permission decay", PASS, f"{total} healthy")


def run_doctor(
    config_path: Path | None = None,
) -> DoctorReport:
    """Run every check and collect the results."""
    report = DoctorReport()
    report.add(check_python_version())
    report.add(check_quill_version())
    report.add(check_quill_on_path())
    cfg_result, cfg = check_config(config_path=config_path)
    report.add(cfg_result)
    audit_path = cfg.audit.resolved_path() if cfg else None
    report.add(check_audit_log(audit_path=audit_path))
    report.add(check_hmac_key())
    report.add(check_audit_chain_intact(audit_path=audit_path))
    report.add(check_claude_hook_installed())
    report.add(check_otel_dual_write())
    report.add(check_permission_decay())
    report.add(check_stale_pattern_stats())
    report.add(check_self_improvement_signals())
    for r in check_upstream_executables(cfg):
        report.add(r)
    return report
