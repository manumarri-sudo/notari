"""Resolve on-disk paths for Nota state.

A single NOTA_HOME env var scopes everything (config, audit log, key,
permissions, telemetry, sessions, watch pid). Individual per-file env
vars still override (NOTA_LOG, NOTA_KEY, etc.) for surgical control.
Default home is ~/.nota.
"""

from __future__ import annotations

import os
from pathlib import Path


def nota_home() -> Path:
    return Path(os.environ.get("NOTA_HOME", "~/.nota")).expanduser()


def default_path(filename: str, env_override: str | None = None) -> Path:
    """Resolve `<NOTA_HOME>/<filename>`, with optional per-file override.

    If env_override is set and that env var is non-empty, use it directly.
    Otherwise fall back to <NOTA_HOME>/<filename>.
    """
    if env_override:
        raw = os.environ.get(env_override, "").strip()
        if raw:
            return Path(raw).expanduser()
    return nota_home() / filename


def is_trusted_cwd(cwd: str) -> bool:
    """True if `cwd` sits inside any path listed in `[trust] paths`.

    Reads the user config best-effort: missing config, malformed config,
    or a non-existent cwd all return False so the gate stays safe-default.
    Matches both exact (cwd == trusted_path) and inside (cwd is a
    descendant of trusted_path); `~` is expanded and symlinks resolved
    before comparison so operator-written paths Just Work.
    """
    if not cwd:
        return False
    try:
        cwd_resolved = Path(cwd).expanduser().resolve()
    except (OSError, ValueError):
        return False
    try:
        from nota.config import load_config

        cfg = load_config()
    except Exception:
        return False
    paths = list(getattr(cfg.trust, "paths", []) or [])
    for raw in paths:
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            trusted = Path(raw).expanduser().resolve()
        except (OSError, ValueError):
            continue
        try:
            if cwd_resolved == trusted or cwd_resolved.is_relative_to(trusted):
                return True
        except ValueError:
            # is_relative_to raises on different anchors (e.g. cross-drive).
            continue
    return False
