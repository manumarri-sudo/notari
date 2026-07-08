"""HookDecision.classified_by - the structured classification source.

The run_hook downshift guards (trust scope, promoted override, bypass mode)
must gate on this structured field, NOT on a substring of the human-readable
`reason`. A future reason-wording change must not be able to silently broaden
a guard (so a pattern-matched HIGH gets auto-allowed) or disable it. These
tests pin the field so that coupling can't regress. (audit #21)
"""

from __future__ import annotations

from nota.adapters.claude_code import _classification_source, decide
from nota.policy import Risk


def test_default_edit_is_classified_default() -> None:
    d = decide("Edit", {"file_path": "/x/main.py"})
    assert d.risk is Risk.HIGH
    assert d.classified_by == "default"


def test_default_write_is_classified_default() -> None:
    assert decide("Write", {"file_path": "/x/f.py", "content": "x = 1"}).classified_by == "default"


def test_bash_pattern_verdict_is_not_default() -> None:
    # A Bash verdict comes from classify_command's pattern set, never the
    # default table, so it must NOT be downshift-eligible.
    d = decide("Bash", {"command": "git push --force origin main"})
    assert d.classified_by == "pattern"
    assert d.classified_by != "default"


def test_secret_write_is_classified_secret_not_default() -> None:
    # Concatenated so this file is not itself a literal secret the gate blocks.
    secret = "ghp_" + "A" * 36
    d = decide("Write", {"file_path": "/x/config.py", "content": f"TOKEN = '{secret}'"})
    assert d.risk is Risk.CRITICAL
    assert d.classified_by == "secret"
    assert d.classified_by != "default"


def test_namespace_tool_is_classified_namespace() -> None:
    assert _classification_source("postgres.drop_table", "anything") == "namespace"


def test_source_helper_maps_each_case() -> None:
    assert _classification_source("Edit", "default risk for Edit") == "default"
    assert _classification_source("Bash", "matches rm -rf rule") == "pattern"
    assert _classification_source("Write", "secret detected: GitHub PAT") == "secret"
    # A non-default reason for a builtin tool is treated as pattern (fail-safe:
    # not downshift-eligible), never silently as default.
    assert _classification_source("Edit", "per-tool override: HIGH") == "pattern"
