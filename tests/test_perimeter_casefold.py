"""Deny-side matching must resist case-fold and homoglyph escape (red-team).

On a case-insensitive filesystem (macOS/Windows CI runners, many deploy targets)
`src/Auth/login.py` IS `src/auth/login.py` on disk, yet a case-sensitive glob
match lets it slip past a forbid of `src/auth/**` while a wildcard scope `src/**`
still covers it -> a should-BLOCK change PASSes. The same flaw let a case-folded
`.github/Workflows/ci.yml` escape the gate-tamper set. The deny side now folds
case + compatibility forms and maps common homoglyphs to ASCII, while the allow
side stays strict.
"""

from __future__ import annotations

import pytest

from nota import perimeter as perim

FORBID = "src/auth/**"


@pytest.fixture
def p() -> perim.Perimeter:
    return perim.default_perimeter(
        allowed_paths=("src/**",), forbidden_paths=(FORBID,), approved_by="human"
    )


@pytest.mark.parametrize(
    "path",
    [
        "src/auth/login.py",  # exact (control)
        "src/Auth/login.py",  # capital A
        "src/AUTH/login.py",  # all caps
        "src/AuTh/login.py",  # mixed
        "src/аuth/login.py",  # Cyrillic 'а' homoglyph
        "src/auth",  # the dir itself
    ],
)
def test_forbidden_variants_all_block(p: perim.Perimeter, path: str) -> None:
    assert p.forbids(path) is True, f"{path!r} escaped the forbid"


@pytest.mark.parametrize(
    "gate_path",
    [
        ".github/workflows/ci.yml",  # exact (control)
        ".github/Workflows/ci.yml",  # capital W
        ".GitHub/workflows/ci.yml",  # capital GitHub
        ".nota/Approvers/human.pub",  # capital A on approvers
        "Action.yml",  # capital A on the action file
    ],
)
def test_gate_tamper_variants_all_block(p: perim.Perimeter, gate_path: str) -> None:
    assert p.forbids(gate_path) is True, f"{gate_path!r} escaped gate-tamper"


@pytest.mark.parametrize(
    "path",
    [
        "src/api/handler.py",  # genuinely different dir
        "src/authentication/x.py",  # superstring, not under src/auth/
        "tests/auth_helpers.py",  # 'auth' in name but outside src/
        "café.env",  # legit unicode, not forbidden
    ],
)
def test_legitimate_paths_not_overblocked(p: perim.Perimeter, path: str) -> None:
    assert p.forbids(path) is False, f"{path!r} was wrongly forbidden"


def test_allow_side_stays_strict() -> None:
    """The allow matcher must NOT fold case: a case-variant of a scoped path
    should fall OUT of the allow-list (-> out-of-scope BLOCK), never widen it."""
    # _glob_hit is the allow-side matcher; default (casefold=False) is strict.
    assert perim._glob_hit("SRC/evil.py", "src/**") is False
    assert perim._glob_hit("src/evil.py", "src/**") is True
