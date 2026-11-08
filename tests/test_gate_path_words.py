"""Gate self-tamper by shell word (0.5.5).

Bash joins quoted fragments, resolves backslash escapes and expands braces
before a program sees its arguments, so a regex over the raw command text
missed `"$HOME"/".notari"/pause.json`, `~/"."notari/`, `~/.nota\\ri/` and
`~/.{notari,cache}/`. Two Codex reviews of 0.5.1 (2026-11-08) activated a
pause with each of these against the released gate. The policy module now
reads each word the way the shell does, in one linear pass, and both the
classifier and the adapter consult it. Every CRITICAL row below was LOW or
MEDIUM on 0.5.4 in at least one layer; the read-only rows guard against the
false positive that motivated the 0.5.1 work in the first place.
"""

from __future__ import annotations

import time

import pytest

from notari.adapters.claude_code import _writes_to_gate_state
from notari.policy import (
    Risk,
    classify_command,
    is_gate_path_word,
    normalize_shell_word,
    segment_writes_gate_path,
    shell_words,
)

# ---------------------------------------------------------------------------
# Word-level helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ('"$HOME"/".notari"/pause.json', "~/.notari/pause.json"),
        ('~/"."notari/pause.json', "~/.notari/pause.json"),
        ("~/.nota\\ri/pause.json", "~/.notari/pause.json"),
        ("~/.no\\\ntari/pause.json", "~/.notari/pause.json"),
        ("${HOME}/.notari/approvals.json", "~/.notari/approvals.json"),
        ("'/tmp/a;b'", "/tmp/a;b"),
        ('"a\\"b"', 'a"b'),
    ],
)
def test_normalize_shell_word_reads_like_bash(word: str, expected: str) -> None:
    assert normalize_shell_word(word) == expected


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ("~/.notari/pause.json", True),
        ('"$HOME"/".notari"', True),  # the directory itself, as a cp destination
        ("~/.{notari,cache}/pause.json", True),
        ("~/.notarize/pause.json", False),
        ("/tmp/notari/pause.json", False),
        ("~/.claude/settings.json", True),
        ("~/.cursor/hooks.json", True),
        ("~/.claude/settings.json.bak", False),
    ],
)
def test_is_gate_path_word(word: str, expected: bool) -> None:
    assert is_gate_path_word(word) is expected


def test_shell_words_keeps_quoted_separators_and_substitutions_inside_words() -> None:
    words = shell_words("tee '/tmp/a;b' \"$(printf '%s' \"$HOME/.notari/pause.json\")\" x")
    assert words == ["tee", "'/tmp/a;b'", '"$(printf \'%s\' "$HOME/.notari/pause.json")"', "x"]


@pytest.mark.parametrize(
    ("segment", "expected"),
    [
        ("cp /tmp/x ~/.notari/pause.json", True),
        ("sed -i 's/a/b/' ~/.notari/config.toml", True),
        ("sed -n '1p' ~/.notari/pause.json", False),  # a read
        ("dd if=/tmp/x of=~/.notari/pause.json", True),
        ("env FOO=1 command cp /tmp/x ~/.notari/pause.json", True),
        ("ls -la ~/.notari/", False),
        ("python3 -c 'print(1+1)'", False),
    ],
)
def test_segment_writes_gate_path(segment: str, expected: bool) -> None:
    assert segment_writes_gate_path(segment) is expected


# ---------------------------------------------------------------------------
# Both layers, end to end
# ---------------------------------------------------------------------------

READ_ONLY = [
    "ls -d ~/x 2>/dev/null; echo ---; ls -la ~/.notari/ 2>/dev/null; cat ~/.notari/config.toml",
    "echo hi > /tmp/out && cat ~/.notari/config.toml",
    "cp a b; cat ~/.notari/config.toml",
    "sed -n '1p' ~/.notari/pause.json",
    "wc -c ~/.notari/config.toml > /tmp/count",
    "cat ~/.notari/config.toml | tee /tmp/copy",
    "python3 -c 'print(open(\"README.md\").read())'",
    "echo x > ~/.notarize/pause.json",
]

WRITES = [
    # Quote splitting, escapes, continuations, braces (Codex round 1 and 2, finding 1 and 2).
    'echo x > "$HOME"/".notari"/pause.json',
    'echo x > ~/"."notari/pause.json',
    "echo x | tee ~/.{notari,cache}/pause.json",
    "echo x > ~/.nota\\ri/pause.json",
    "echo x > ~/.no\\\ntari/pause.json",
    "printf x > \\\n~/.notari/pause.json",
    'echo x > "$(printf \'%s\' "$HOME/.notari/pause.json")"',
    # Directory destinations without a trailing slash.
    'cp /tmp/pause.json "$HOME"/".notari"',
    'cp -t ~/"."notari /tmp/pause.json',
    'install -t ~/"."notari /tmp/pause.json',
    # Interpreter one-liners that write the file.
    'python -c \'open("/Users/m/." "notari/pause.json", "w").write("{}")\'',
    'ruby -e \'File.write(File.expand_path("~/.notari/pause.json"), "{}")\'',
    'node -e \'require("fs").writeFileSync("/Users/m/.notari/pause.json", "{}")\'',
    # Quoted separators before the path (round 1, finding 3).
    "echo '{}' | tee '/tmp/a;b' \"$HOME/.notari/pause.json\"",
    "cp '/tmp/a;b' \"$HOME/.notari/pause.json\"",
    "sed -i 's/a;b/c/' \"$HOME/.notari/pause.json\"",
    # Plain shapes that must keep working.
    "truncate -s 0 ~/.notari/approvals.json",
    "tee \\\n~/.notari/pause.json < /tmp/a",
    "env FOO=1 command cp /tmp/x ~/.notari/pause.json",
    "echo x >| ~/.notari/pause.json",
    "echo x >${HOME}/.notari/approvals.json",
    "dd if=/tmp/x of=~/.notari/pause.json",
]


@pytest.mark.parametrize("cmd", READ_ONLY)
def test_read_only_mentions_stay_below_critical_in_both_layers(cmd: str) -> None:
    assert classify_command(cmd).risk is not Risk.CRITICAL
    assert _writes_to_gate_state(cmd) is False


@pytest.mark.parametrize("cmd", WRITES)
def test_gate_state_writes_are_critical_in_both_layers(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL
    assert _writes_to_gate_state(cmd) is True


# ---------------------------------------------------------------------------
# Bounded time: the hook has a 10 s budget and a regex with overlapping quote
# alternatives took over 11 s on twenty adjacent fragments (0.5.1 branch).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "echo x > " + '"a"' * 20 + "/tmp/out",
        "tee " + ('"a"' * 200 + "/tmp/out ") * 50,
        "cp " + "a" * 5000 + " /tmp/out",
        "echo x > " + "\\a" * 2000 + "/tmp/out",
    ],
)
def test_classification_time_is_bounded(cmd: str) -> None:
    t0 = time.monotonic()
    classify_command(cmd)
    assert time.monotonic() - t0 < 0.5
