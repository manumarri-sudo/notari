"""F2 re-review (2026-07-23): the unrestricted-scope detector must agree with
the enforcement matcher.

`scope_is_unrestricted` previously did a literal spelling check (`**` / `.`
only), so universal globs written any other way (`**/**`, `*/**`, `./**`,
`**/`) slipped past the flag while `path_in_scope` still admitted every path
under them. A wide-open contract then read as a scoped one on the CLI warning
and the passport. The detector now decides with `path_in_scope` itself, so the
two can no longer disagree.
"""

from __future__ import annotations

import pytest

from notari.policy import path_in_scope, scope_is_unrestricted

# Universal spellings: each admits every path through the segment matcher.
_UNIVERSAL = [
    [],
    ["**"],
    ["."],
    ["**/**"],
    ["*/**"],
    ["./**"],
    ["src/**", "**"],  # one universal entry makes the whole allow-list universal
]

# Genuinely restrictive scopes: each excludes at least one real path.
_RESTRICTIVE = [
    ["src/**"],
    ["*.py"],
    ["**/*.py"],
    ["docs/"],
    ["src/main.py"],
    ["src/**", "docs/**"],
    ["*"],  # segment-aware `*` matches root files only, not nested paths
]

_SAMPLE_PATHS = [
    "src/main.py",
    "README.md",
    ".env",
    ".github/workflows/ci.yml",
    "a/b/c/d/e.txt",
    "lib/vendor/thing.min.js",
]


@pytest.mark.parametrize("scope", _UNIVERSAL)
def test_universal_spellings_are_flagged(scope: list[str]) -> None:
    assert scope_is_unrestricted(scope), scope
    # And the enforcement matcher agrees: every sample path is in scope.
    if scope:  # empty means "no restriction", path_in_scope short-circuits True
        assert all(path_in_scope(p, scope) for p in _SAMPLE_PATHS), scope


@pytest.mark.parametrize("scope", _RESTRICTIVE)
def test_restrictive_scopes_are_not_flagged(scope: list[str]) -> None:
    assert not scope_is_unrestricted(scope), scope
    # And the matcher agrees: at least one real path is excluded.
    assert not all(path_in_scope(p, scope) for p in _SAMPLE_PATHS), scope


def test_detector_never_disagrees_with_enforcement() -> None:
    # The property that motivated the fix: if the detector says "restricted",
    # there must be a real path the gate would reject; if it says "unrestricted",
    # the gate admits everything we probe.
    for scope in _UNIVERSAL + _RESTRICTIVE:
        flagged = scope_is_unrestricted(scope)
        admits_all = all(path_in_scope(p, scope) for p in _SAMPLE_PATHS)
        if flagged:
            assert admits_all, f"{scope} flagged unrestricted but excludes a sample path"
        else:
            assert not admits_all, f"{scope} flagged restricted but admits every sample path"
