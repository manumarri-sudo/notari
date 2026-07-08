"""The standing perimeter: sign the boundary once, enforce it on every PR.

A human should not have to approve every change an agent makes - especially not
across a fleet of a hundred agents. The perimeter is the answer: a human signs
*the boundary* one time (what agents may touch, what they may never touch, that
secrets are always blocked), and from then on every pull request from every
agent is checked against that signed boundary automatically. A human is paged
only when a change crosses the line, never on routine in-bounds work.

The perimeter lives at ``<repo>/.nota/perimeter.json`` and is signed via
``provenance`` into ``.nota/perimeter.sig``. Because the signature covers the
exact perimeter content, an agent cannot widen ``allowed_paths`` or delete a
``forbidden_paths`` entry without invalidating it - and only the human approver's
off-box private key can re-sign.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import unicodedata
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nota.errors import NotaError

PERIMETER_VERSION = 1

# Surfaces that protect the gate itself. Editing any of these from a PR is a
# self-tamper attempt (rewrite the boundary, add your own approver key, neuter
# the workflow that runs the check), so a diff that touches them is always a
# BLOCK - these change out-of-band via an approver, never inside a gated PR.
#
# The per-task contract (.nota/contract.json / .sig) is deliberately NOT here:
# its commit legitimately lands inside the base..head range, so gate-tamper would
# always fire on it. Its integrity is protected by its SIGNATURE instead - the
# contract supplies the base commit and scope, so `verify --strict` requires it
# to be signed by a trusted approver (security review P0-1), which is what makes
# a PR-rewritten or forged contract fail (the signature no longer matches).
GATE_TAMPER_GLOBS: tuple[str, ...] = (
    ".github/workflows/**",
    ".github/actions/**",
    "action.yml",
    "action.yaml",
    ".nota/perimeter.json",
    ".nota/perimeter.sig",
    ".nota/approvers/**",
)


class PerimeterError(NotaError):
    """Raised when a perimeter cannot be read or parsed."""


def perimeter_path(root: Path) -> Path:
    return root / ".nota" / "perimeter.json"


def signature_path(root: Path) -> Path:
    return root / ".nota" / "perimeter.sig"


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Perimeter:
    """A standing, signed boundary enforced on every diff.

    - ``allowed_paths``: the outer bound agents may work in. Empty means
      "anywhere not forbidden".
    - ``forbidden_paths``: paths no change may touch. A hit is always a BLOCK.
    - ``review_surfaces``: sensitive-surface categories ("ci", "lockfiles",
      "tests") that downgrade to NEEDS_REVIEW (page a human) rather than pass.
    - ``block_secrets``: a secret on an added line is always a BLOCK.
    """

    version: int
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    review_surfaces: tuple[str, ...]
    block_secrets: bool
    created_at: str
    perimeter_id: str
    approved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("allowed_paths", "forbidden_paths", "review_surfaces"):
            d[k] = list(d[k])
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Perimeter:
        try:
            return cls(
                version=int(data.get("version", PERIMETER_VERSION)),
                allowed_paths=tuple(data.get("allowed_paths", ())),
                forbidden_paths=tuple(data.get("forbidden_paths", ())),
                review_surfaces=tuple(data.get("review_surfaces", ())),
                block_secrets=bool(data.get("block_secrets", True)),
                created_at=str(data.get("created_at", "")),
                perimeter_id=str(data.get("perimeter_id", "")),
                approved_by=data.get("approved_by"),
            )
        except (KeyError, TypeError, ValueError) as e:
            msg = f"malformed perimeter: {e}"
            raise PerimeterError(msg) from e

    def write(self, root: Path) -> Path:
        p = perimeter_path(root)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        return p

    def forbids(self, path: str) -> bool:
        """True if `path` matches any forbidden glob (the gate-tamper set is
        always included, even if a hand-edited perimeter dropped it)."""
        globs = set(self.forbidden_paths) | set(GATE_TAMPER_GLOBS)
        return any(deny_hit(path, g) for g in globs)


# Common Cyrillic / Greek (and a few Latin) glyphs that are visually identical to
# an ASCII letter. An attacker uses one (e.g. Cyrillic "а") to name `src/аuth/`
# so it reads as the forbidden `src/auth/` but is a distinct codepoint a naive
# matcher misses. We fold these to their ASCII look-alike on the DENY side only,
# so a homoglyph of a forbidden surface still matches. (Not exhaustive - Unicode
# has thousands of confusables; this covers the realistic, demonstrated set.)
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "ԁ": "d",
    "ӏ": "l",
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Х": "X",
    "Β": "B",
    "Α": "A",
    "Ε": "E",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "α": "a",
    "ο": "o",
    "ν": "v",
    "ι": "i",
    "κ": "k",
    "ρ": "p",
    "τ": "t",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Υ": "Y",
    "Χ": "X",
    "Ѕ": "S",
    "Ӏ": "I",
}


def _fold(s: str) -> str:
    """Normalize the way a case-insensitive filesystem effectively does: NFKC to
    collapse compatibility forms, then casefold for Unicode-aware case folding.
    `fnmatch` uses os.path.normcase, which is identity on macOS/Linux, so it is
    case-SENSITIVE even on a case-insensitive FS - this makes folding explicit
    and deterministic across platforms."""
    return unicodedata.normalize("NFKC", s).casefold()


def _confusable_skeleton(s: str) -> str:
    return "".join(_CONFUSABLES.get(c, c) for c in s)


def _glob_hit(path: str, glob: str, *, casefold: bool = False) -> bool:
    # Deny-side match (forbidden + gate-tamper). Inclusive by design.
    if casefold:
        path, glob = _fold(path), _fold(glob)
    if glob.endswith("/**"):
        prefix = glob[:-3]
        return path == prefix or path.startswith(prefix + "/")
    # A bare directory or exact path (no glob metachars) covers itself AND
    # everything under it, so `--forbid src/auth` denies `src/auth/login.py` -
    # matching the scope side's directory semantics rather than the surprising
    # "exact file only" fnmatch gave (security review M-8).
    if not any(ch in glob for ch in "*?["):
        g = glob.rstrip("/")
        return path == g or path.startswith(g + "/")
    return fnmatch.fnmatch(path, glob)


def deny_hit(path: str, glob: str) -> bool:
    """Deny-side path match (forbidden + gate-tamper surfaces).

    Deliberately over-matches, because a deny check must fail safe: it folds case
    + compatibility forms (`src/Auth` == `src/auth` on a case-insensitive FS) AND
    maps common homoglyphs to ASCII (`src/аuth` -> `src/auth`), so a variant that
    resolves to - or is meant to pass for - a protected path still BLOCKs. The
    ALLOW side stays strict (see policy._path_matches / the perimeter allow-list),
    so the two asymmetries squeeze a case/lookalike attack from both ends: it is
    caught here, or it falls out of the allow-list as out-of-scope. (Security
    red-team: case-fold + homoglyph escape of the forbid glob.)"""
    if _glob_hit(path, glob, casefold=True):
        return True
    skel = _confusable_skeleton(path)
    return skel != path and _glob_hit(skel, glob, casefold=True)


def _perimeter_id(allowed: Sequence[str], forbidden: Sequence[str], created: str) -> str:
    blob = json.dumps({"a": sorted(allowed), "f": sorted(forbidden), "t": created}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def default_perimeter(
    *,
    allowed_paths: Sequence[str] = (),
    forbidden_paths: Sequence[str] = (),
    approved_by: str | None = None,
) -> Perimeter:
    """A secure-by-default standing perimeter.

    Forbids the gate's own trust surfaces out of the box, blocks secrets, and
    sends CI/lockfile edits to human review. Callers add project-specific
    forbidden paths (auth, migrations, infra) on top.
    """
    created = _now()
    forbidden = tuple(dict.fromkeys((*GATE_TAMPER_GLOBS, *forbidden_paths)))
    return Perimeter(
        version=PERIMETER_VERSION,
        allowed_paths=tuple(allowed_paths),
        forbidden_paths=forbidden,
        review_surfaces=("ci", "lockfiles", "gitconfig"),
        block_secrets=True,
        created_at=created,
        perimeter_id=_perimeter_id(allowed_paths, forbidden, created),
        approved_by=approved_by,
    )


def load(root: Path) -> Perimeter | None:
    """Read the perimeter for `root`, or None if the repo has no perimeter."""
    p = perimeter_path(root)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        msg = f"cannot read perimeter at {p}: {e}"
        raise PerimeterError(msg) from e
    return Perimeter.from_dict(data)
