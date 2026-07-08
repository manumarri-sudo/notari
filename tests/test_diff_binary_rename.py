"""Binary files and renames must not slip past the diff inventory (re-review P0-4).

`git diff` (without --binary) renders a changed binary as a one-line
``Binary files a/x and b/y differ`` stanza with NO ``---``/``+++`` lines, and a
rename as ``rename from``/``rename to`` with no hunks. The earlier parser keyed
off ``---``/``+++`` only, so a binary blob written anywhere was invisible to both
the scope check and the gate-tamper surfaces, and a rename was scope-checked on
the new path alone. These tests pin the closed behavior using the exact text
real git emits.
"""

from __future__ import annotations

from nota import policy
from nota.perimeter import GATE_TAMPER_GLOBS, _glob_hit

BINARY_NEW = """diff --git a/blob.bin b/blob.bin
new file mode 100644
index 0000000..e59aa70
Binary files /dev/null and b/blob.bin differ
"""

RENAME = """diff --git a/src/keep.py b/vendor/moved.py
similarity index 100%
rename from src/keep.py
rename to vendor/moved.py
"""

BINARY_INTO_WORKFLOWS = """diff --git a/.github/workflows/evil.bin b/.github/workflows/evil.bin
new file mode 100644
index 0000000..e59aa70
Binary files /dev/null and b/.github/workflows/evil.bin differ
"""


def test_binary_new_file_is_inventoried() -> None:
    files = policy.parse_unified_diff(BINARY_NEW)
    assert [f.path for f in files] == ["blob.bin"]
    assert files[0].status == "added"
    assert files[0].added_lines == ()  # binary: no text lines, but still counted


def test_binary_out_of_scope_blocks() -> None:
    """A binary blob committed outside scope is an out-of-scope change, not a
    silent pass."""
    ev = policy.evaluate_diff(BINARY_NEW, ["src/**"])
    assert "blob.bin" in ev.out_of_scope


def test_binary_into_gate_surface_is_visible_to_tamper_scan() -> None:
    """A binary file dropped into .github/workflows/ must be catchable by the
    gate-tamper scan, which reads the raw parsed diff."""
    paths = {f.path for f in policy.parse_unified_diff(BINARY_INTO_WORKFLOWS)}
    assert ".github/workflows/evil.bin" in paths
    assert any(_glob_hit(".github/workflows/evil.bin", g) for g in GATE_TAMPER_GLOBS), (
        "a binary written into the workflows dir must hit a gate-tamper glob"
    )


def test_rename_checks_both_endpoints() -> None:
    files = policy.parse_unified_diff(RENAME)
    assert len(files) == 1
    f = files[0]
    assert f.status == "renamed"
    assert f.path == "vendor/moved.py"
    assert f.old_path == "src/keep.py"


def test_rename_new_path_out_of_scope_blocks() -> None:
    """Moving an in-scope file OUT to an out-of-scope path flags the destination."""
    ev = policy.evaluate_diff(RENAME, ["src/**"])
    assert "vendor/moved.py" in ev.out_of_scope
    assert "src/keep.py" not in ev.out_of_scope  # source stays in scope


def test_rename_old_path_out_of_scope_blocks() -> None:
    """Moving an out-of-scope file INTO scope flags the source it disturbed: a
    rename that deletes vendor/old.py must not be authorized by a vendor-blind
    contract just because the destination lands in src/."""
    diff = (
        "diff --git a/vendor/old.py b/src/new.py\n"
        "similarity index 100%\n"
        "rename from vendor/old.py\n"
        "rename to src/new.py\n"
    )
    ev = policy.evaluate_diff(diff, ["src/**"])
    assert "vendor/old.py" in ev.out_of_scope
    assert "src/new.py" not in ev.out_of_scope
