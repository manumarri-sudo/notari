"""Third Codex review of the 0.5.5 candidate (2026-11-08): wrappers and
reordered `sed -i`, reads paired with the write that must still be denied,
pre-existing shapes now covered by the shell-word parser, and the inputs
that were quadratic in the first candidate.

Every CRITICAL row here was LOW or MEDIUM in at least one layer on the
reviewed candidate 77c26b7 or on released 0.5.4; every read control is
paired with a write in the same program.
"""

from __future__ import annotations

import time

import pytest

from notari.adapters.claude_code import _writes_to_gate_state
from notari.policy import Risk, classify_command

WRITES = [
    # Finding 1: a reordered or quoted in-place flag behind a wrapper or in a subshell.
    "(sed -e 's/false/true/' -i '' ~/.notari/pause.json)",
    "nice -n 1 sed -e 's/false/true/' -i '' ~/.notari/pause.json",
    "env -i PATH=/usr/bin:/bin sed -e 's/false/true/' -i '' ~/.notari/pause.json",
    "printf x | xargs -I{} sed -e 's/false/true/' -i '' ~/.notari/pause.json",
    "sed -n -i.bak -e 's/before/after/p' ~/.notari/pause.json",
    "sed -i.bak -n -e 's/before/after/p' ~/.notari/pause.json",
    "sed '-n' '-i.bak' -e 's/before/after/p' ~/.notari/pause.json",
    # Finding 5: shapes that were out of reach for a regex.
    'find /tmp -maxdepth 0 -exec cp /tmp/x "$HOME"/".notari"/pause.json \\;',
    'sh -c "sh -c \'tee \\"\\$HOME\\"/\\".notari\\"/pause.json\'" < /tmp/x',
    'eval \'tee "$HOME"/".notari"/pause.json\' < /tmp/x',
    'sh -c \'tee "$HOME"/".notari"/pause.json\' < /tmp/x',
    "tee ~/{.,.cache}/.{nota,ca}ri/pause.json < /tmp/x",
    "tee ~/.{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,notari}/pause.json < /tmp/x",
    "tee ~/.{cache,{notari,other}}/pause.json < /tmp/x",
    "tee ~/.nota{r..r}i/pause.json < /tmp/x",
    "tee ~/.nota$'\\x72'i/pause.json < /tmp/x",
    'python3 -c \'import os; open(os.path.join(os.environ["HOME"], ".notari", "pause.json"), "w").write("{}")\'',
    'python3 -c \'from pathlib import Path; Path.home().joinpath(".notari", "pause.json").write_text("{}")\'',
    'awk \'BEGIN {print "{}" > (ENVIRON["HOME"] "/.notari/pause.json")}\'',
    'php -r \'file_put_contents(getenv("HOME")."/.notari/pause.json", "{}");\'',
    'node --eval \'require("fs").writeFileSync(process.env.HOME+"/.notari/pause.json", "{}")\'',
    'env -i HOME="$HOME" cp /tmp/x "$HOME"/".notari"/pause.json',
    'command -p cp /tmp/x "$HOME"/".notari"/pause.json',
    'nice -n 1 cp /tmp/x "$HOME"/".notari"/pause.json',
    "cp --target-directory=~/.notari /tmp/pause.json",
    "mv -t ~/.notari /tmp/pause.json",
    "mv ~/.notari/key /tmp/elsewhere",  # moving the gate's key away destroys state
    "ln -sf /tmp/x ~/.notari/pause.json",
    "echo x > ${HOME:-/x}/.notari/pause.json",
    # Finding 6 pairs: the write half of each read control below.
    'ruby -e \'File.write(File.expand_path("~/.notari/pause.json"), "{}")\'',
    'node -e \'require("fs").writeFileSync("/Users/m/.notari/pause.json", "{}")\'',
    'perl -e \'open(F, ">", "$ENV{HOME}/.notari/pause.json"); print F "{}"\'',
    'python3 -c \'open("/Users/m/.notari/pause.json", "w").write("{}")\'',
    "rsync /tmp/copy ~/.notari/config.toml",
    "cp /tmp/backup.toml ~/.notari/config.toml",
]

READS = [
    # Finding 1 control.
    "sed -n -e 's/before/after/p' ~/.notari/pause.json",
    # Finding 6: the operation and its destination decide, not the path alone.
    "ruby -e 'puts File.read(File.expand_path(\"~/.notari/pause.json\"))'",
    'node -e \'console.log(require("fs").readFileSync("/Users/m/.notari/pause.json", "utf8"))\'',
    'perl -e \'open(F, "<", "$ENV{HOME}/.notari/pause.json"); print <F>\'',
    "python3 -c 'print(open(\"/Users/m/.notari/pause.json\").read())'",
    "rsync ~/.notari/config.toml /tmp/copy",
    "cp ~/.notari/config.toml /tmp/backup.toml",
    "awk '{print}' ~/.notari/config.toml",
    'echo \'tee "$HOME"/".notari"/pause.json\'',  # a quoted mention is data
    "ls ~/.notari/pause.json >/tmp/list",
    "cp a b",
]


@pytest.mark.parametrize("cmd", WRITES)
def test_writes_are_critical_in_both_layers(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL
    assert _writes_to_gate_state(cmd) is True


@pytest.mark.parametrize("cmd", READS)
def test_reads_stay_below_critical_in_both_layers(cmd: str) -> None:
    assert classify_command(cmd).risk is not Risk.CRITICAL
    assert _writes_to_gate_state(cmd) is False


# ---------------------------------------------------------------------------
# Findings 2 and 5 (review 3), Manu's item 5: linear time. The first candidate
# took 11.8 s on 60,000 brace commas and 6.5 s on 300,000 assignment prefixes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "cmd"),
    [
        ("brace commas", "tee /tmp/{" + "," * 60000 + "x"),
        ("open braces", "tee /tmp/" + "{" * 30000 + "x"),
        ("quoted fragments", "echo x > " + '"a"' * 2000 + "/tmp/out"),
        ("nested substitutions", "echo " + "$(" * 5000),
        ("many words", "cp " + "a " * 100000 + "b"),
    ],
)
def test_adversarial_inputs_classify_quickly(label: str, cmd: str) -> None:
    t0 = time.monotonic()
    classify_command(cmd)
    assert time.monotonic() - t0 < 1.0, label


def test_assignment_prefixes_scale_linearly() -> None:
    def timed(n: int) -> float:
        cmd = "A=1 " * n + "true"
        t0 = time.monotonic()
        classify_command(cmd)
        return time.monotonic() - t0

    small, large = timed(100_000), timed(200_000)
    # Linear work doubles; the quadratic pop(0) loop quadrupled (0.63 s to 2.64 s).
    assert large < 3.0
    assert large < 3 * max(small, 0.05)
