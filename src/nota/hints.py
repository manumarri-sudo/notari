"""Block-message hints: one rotating line per block teaches users one feature.

Block messages are the highest-attention moment in the user's day. They
literally cannot proceed without reading the message. This module adds a
single hint line under each block that points at one of Nota's other
features (`nota saves`, `nota insights`, `nota audit export --pack`,
etc.). The selector picks based on:

  1. Pattern-specific match  e.g. `rm -rf` block surfaces an rm-rf-
     specific hint with high priority
  2. Risk class               e.g. critical blocks suggest verifying the
     audit chain
  3. State                    e.g. first-ever block prompts `nota
     integrate` to wire up agent-side discovery
  4. Generic rotation         if nothing matches, a generic hint rotates
     in

Cooldowns are per-hint, tracked in `~/.nota/hints_seen.json`, default
24h. Disable entirely via `[notify] hints = false` in config.toml.

No LLM. Pure data file + selector. ~140 lines.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


_HINTS_TOML = Path(__file__).parent / "hints.toml"


@dataclass(frozen=True, slots=True)
class Hint:
    """One block-message hint with its triggers and cooldown."""

    name: str
    text: str
    triggers: tuple[str, ...] = ()
    cooldown_h: int = 24


@dataclass(slots=True)
class HintContext:
    """The signals the selector uses to pick a hint.

    Populated by the adapter at block time, then passed to `select`.
    """

    pattern: str = ""  # canonical pattern, from saves.canonicalize_pattern
    reason: str = ""  # raw block reason text
    risk: str = ""  # critical / high / medium / low
    is_first_block: bool = False  # has the user ever been blocked before?


def _load_hints(path: Path = _HINTS_TOML) -> list[Hint]:
    """Parse hints.toml into a list of Hint records."""
    if not path.exists():
        return []
    with path.open("rb") as f:
        raw = tomllib.load(f)
    out: list[Hint] = []
    for row in raw.get("hints", []):
        out.append(
            Hint(
                name=str(row["name"]),
                text=str(row["text"]),
                triggers=tuple(str(t) for t in row.get("triggers", [])),
                cooldown_h=int(row.get("cooldown_h", 24)),
            ),
        )
    return out


def _seen_path() -> Path:
    """Where per-hint last-shown timestamps are persisted."""
    override = os.environ.get("NOTA_HOME")
    base = Path(override) if override else (Path.home() / ".nota")
    return base / "hints_seen.json"


def _load_seen(path: Path | None = None) -> dict[str, str]:
    p = path or _seen_path()
    if not p.exists():
        return {}
    try:
        with p.open() as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_seen(seen: dict[str, str], path: Path | None = None) -> None:
    p = path or _seen_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        with p.open("w") as f:
            json.dump(seen, f, indent=2)
        p.chmod(0o600)
    except OSError:
        pass  # cooldowns are best-effort; never fail the block path


def _matches_trigger(trigger: str, ctx: HintContext) -> bool:
    """True if `ctx` satisfies this single trigger token."""
    if trigger == "generic":
        return True
    if trigger == "first_block":
        return ctx.is_first_block
    if trigger.startswith("pattern:"):
        return trigger.removeprefix("pattern:") == ctx.pattern
    if trigger.startswith("risk:"):
        return trigger.removeprefix("risk:") == ctx.risk
    if trigger.startswith("reason_contains:"):
        needle = trigger.removeprefix("reason_contains:").lower()
        return needle in ctx.reason.lower()
    return False


def _is_eligible(hint: Hint, ctx: HintContext, now: datetime, seen: dict[str, str]) -> bool:
    """Is this hint allowed to surface for this block?"""
    # Cooldown check
    last_shown = seen.get(hint.name)
    if last_shown:
        try:
            last_dt = datetime.fromisoformat(last_shown.replace("Z", "+00:00"))
        except ValueError:
            last_dt = None
        if last_dt and (now - last_dt) < timedelta(hours=hint.cooldown_h):
            return False

    # Trigger check
    if not hint.triggers:
        # No triggers declared = generic. Eligible.
        return True
    return any(_matches_trigger(t, ctx) for t in hint.triggers)


def select(
    ctx: HintContext,
    *,
    hints: list[Hint] | None = None,
    now: datetime | None = None,
    seen_path: Path | None = None,
    record: bool = True,
) -> Hint | None:
    """Pick one hint for this block. Returns None if no eligible hint.

    Hints with pattern-specific triggers are preferred over generic
    ones, so a `rm -rf` block gets the rm-specific suggestion before
    falling back to the rotating set.
    """
    hints = hints if hints is not None else _load_hints()
    if not hints:
        return None
    now = now or datetime.now(UTC)
    seen = _load_seen(seen_path)

    eligible = [h for h in hints if _is_eligible(h, ctx, now, seen)]
    if not eligible:
        return None

    # Prefer hints with specific triggers (pattern: / reason_contains: /
    # risk:) over generic ones. Sort key: 0 for specific, 1 for generic.
    def specificity(h: Hint) -> int:
        if not h.triggers or all(t == "generic" for t in h.triggers):
            return 1
        return 0

    eligible.sort(key=lambda h: (specificity(h), seen.get(h.name, "")))
    chosen = eligible[0]

    if record:
        seen[chosen.name] = now.isoformat()
        _save_seen(seen, seen_path)

    return chosen
