"""git C-quoted paths must decode to the real filename (differential-fuzz finding).

When a path holds a byte >= 0x80 (any non-ASCII), a control char, a quote, or a
backslash, `git diff` wraps it in double quotes and emits the bytes as octal/`\\x`
escapes (`"a/caf\\303\\251.env"`). If the parser leaves those escapes literal, an
EXACT forbidden / gate-tamper path with a non-ASCII byte slips past the checks
that compare the path string - a silent fail-open. These pin the decode.
"""

from __future__ import annotations

from quill import perimeter as perim
from quill import policy

# Exactly what `git diff` (core.quotepath=true, the default) emits for a new
# file named café.env containing one secret-shaped line.
QUOTED_UNICODE_ADD = (
    'diff --git "a/caf\\303\\251.env" "b/caf\\303\\251.env"\n'
    "new file mode 100644\n"
    "index 0000000..d00491f\n"
    "--- /dev/null\n"
    '+++ "b/caf\\303\\251.env"\n'
    "@@ -0,0 +1 @@\n"
    "+AKIA_SECRET\n"
)


def test_quoted_unicode_path_decodes() -> None:
    files = policy.parse_unified_diff(QUOTED_UNICODE_ADD)
    assert [f.path for f in files] == ["café.env"]


def test_quoted_forbidden_exact_path_is_caught() -> None:
    """The HIGH fail-open: a perimeter forbidding the exact path `café.env` must
    match the change, not see a mangled `caf\\303\\251.env`."""
    p = perim.default_perimeter(forbidden_paths=("café.env",), approved_by="human")
    path = policy.parse_unified_diff(QUOTED_UNICODE_ADD)[0].path
    assert p.forbids(path) is True


def test_quoted_path_reported_with_real_name_out_of_scope() -> None:
    ev = policy.evaluate_diff(QUOTED_UNICODE_ADD, ["src/**"])
    assert "café.env" in ev.out_of_scope


def test_git_unquote_escape_forms() -> None:
    # octal byte pair -> é, plus the named C escapes
    assert policy._git_unquote("caf\\303\\251.env") == "café.env"
    assert policy._git_unquote("a\\tb") == "a\tb"
    assert policy._git_unquote('a\\"b') == 'a"b'
    assert policy._git_unquote("a\\\\b") == "a\\b"
