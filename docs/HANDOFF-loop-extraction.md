# Handoff: extract the "loop" surface from notari

Paste everything below into a fresh Claude Code session started in `~/quill`.

---

## Your task

Notari is being narrowed to **one product: the Change Passport**. A human signs a
contract (task plus path scope), CI verifies the actual PR diff against it, and issues
a signed verdict a reviewer can re-check without trusting the repo it came from. The
local gate stays as a bundled on-ramp. Everything else goes.

Your job is the removal of the **"loop" surface**: the lessons, insights, learning,
decay, journal and saves machinery. **Plan first, get the plan approved, then execute.**

### Why, with the numbers that drove it

Measured on this codebase:

| surface | source | tests | commits (of 365) |
|---|---|---|---|
| plumbing (mostly `cli.py`) | 27.7% | 7.2% | - |
| gate (local guard) | 26.0% | 11.7% | 122 |
| **change control (the product)** | **14.9%** | **5.2%** | 112 |
| loop (what you are removing) | 14.5% | **18.6%** | 40 |
| receipt / audit | 5.6% | 9.2% | 33 |

The differentiated surface has the thinnest test coverage of anything named, while the
loop has more than three times its test investment. Competitive research found no
credible competitor for signed contract-versus-diff verification, while the local gate
is being commoditized by Microsoft's Agent Governance Toolkit, GitHub Copilot, Cursor
hooks and OpenAI Codex approval tiers. The loop competes with nothing and is asked for
by nobody.

### Exact scope

Remove these seven modules, **3,331 lines**, and their tests:

| module | lines | imported by |
|---|---|---|
| `learning.py` | 893 | `adapters/claude_code.py`, `adapters/cursor.py`, `cli.py`, `doctor.py`, `journal.py` |
| `learn.py` | 516 | `adapters/claude_code.py`, `cli.py`, `doctor.py`, `learning.py` |
| `saves.py` | 456 | `cli.py`, `insights.py` |
| `journal.py` | 435 | `cli.py` |
| `insights.py` | 364 | `cli.py` |
| `lessons.py` | 360 | `cli.py`, `teach.py` |
| `decay.py` | 307 | `adapters/claude_code.py`, `cli.py`, `doctor.py`, `learn.py` |

Also remove the hidden CLI commands they back: `learn`, `insights`, `saves`, `roster`,
`night`, and any `lessons` surface in `teach.py`.

**This is a refactor, not a file deletion.** Five of the seven reach into
`adapters/claude_code.py`, which was hardened hours ago against a critical gate bypass.
Regressing that file is the single worst outcome of this work.

### Out of scope

Do not touch `secrets.py`, `verify.py`, `contract.py`, `perimeter.py`, `passport.py`,
`attest.py`, `audit.py`, `provenance.py`, or `scripts/notari-passport.sh`. They were
adversarially reviewed across nine passes and are settled. If your change appears to
require editing them, stop and say so rather than proceeding.

---

## Ground state

- Repo `~/quill`, package `notari`, now **PRIVATE** on GitHub (`manumarri-sudo/notari`).
- Branch `notari-secfix-wave2-20260724`, 32 commits ahead of `main`, PR #10 open.
- Baseline: **1548 passed, 4 xfailed**. `ruff check`, `ruff format --check`, `mypy` clean.
- Notari now runs its own change control. There is a signed contract in `.notari/`
  scoped to `src/**`, `tests/**`, `docs/**`, `README.md`, `.github/**`, `action.yml`.
  Work outside that scope makes `notari verify` BLOCK, correctly.
- Python is `.venv/bin/python`. There is no `pytest` on PATH; use
  `.venv/bin/python -m pytest`.

---

## Rules that are not negotiable

These come from an eighteen-hour session in which nine adversarial review passes still
missed three of the four worst defects. Each rule below exists because ignoring it cost
real time or shipped a real bug.

**1. Green tests prove almost nothing.** Three separate tests were found passing for
reasons unrelated to their names, and one of them sat directly on top of a complete gate
bypass: `test_pause_json_is_in_adapter_gate_surface` asserted that one filename appeared
in one list, and passed happily while the two files that actually mattered were
unprotected. **Assert properties, never mechanisms.** After writing any test, ask what
would have to break for it to fail, and if the answer is "an implementation detail
changed", rewrite it.

**2. Prove every new or changed test can fail.** Stash the source, watch the test fail,
restore, watch it pass. Report the counts. A test never observed failing is a decoration.

**3. Run it, do not only read it.** One push to CI found a `TemplateValidationException`
that had made the GitHub Action fail on every single run for over two weeks, which no
amount of local testing had surfaced. For this task that means: after the refactor,
actually run `notari init`, `begin`, `verify`, `status`, `doctor`, and `explain` on a
throwaway repo and read the output, rather than trusting the suite.

**4. `ruff check` is not `ruff format --check`.** CI runs both. "ruff clean" was reported
all session from the linter alone while the formatter was failing on eight files. Run
both, every time, before claiming clean.

**5. Verify before you describe.** A regex-based dead-code analysis reported three live
modules as unreferenced, because it matched the module name after the word `import` and
missed `from notari.insights import ...`. Acting on it would have deleted working
features. Use AST for import analysis, and generally: read the source or run the command
before describing behaviour.

**6. Do not trust a subagent's report.** Reproduce every finding yourself before acting.
Two reviewers this session returned SHIP or LAUNCH on code containing gate-defeating
bugs, one reported a defect that did not reproduce, and one reported four items that
were already fixed in the working tree.

**7. The gate is ON and it will block you.** `notari claude-hook` runs on every tool
call. Expect it to refuse: `curl | bash`, writing credential-shaped strings into files
(build such strings by concatenation in tests), and any write into `.notari/`. Also
`python -c` touching a path under `.notari/` is denied by design, so use `cat` to read
those files. Do not try to work around the gate. If it blocks something legitimate,
that is a finding worth reporting.

**8. Delete tests only by replacing their coverage.** If a loop test also covers
behaviour the gate or change control depends on, that coverage must survive somewhere.

---

## Phase 1: plan, and stop

Produce a written plan before changing a single line. It must contain:

1. **A call-graph, produced with AST, not grep**, for each of the seven modules: every
   call site, in which file, at which line, and what each one does.
2. **A classification of every call site** into: pure loop functionality to delete,
   genuinely shared machinery that must be preserved and moved, or a seam where the
   caller needs a small replacement (for example a `pass`, a default value, or a removed
   branch).
3. **The ordering**, leaf modules first, and the reason for that order.
4. **The blast radius on `adapters/claude_code.py`**: exact lines you intend to touch,
   and how you will show afterwards that the self-tamper protections and the risk
   classification are unchanged. `tests/test_gate_self_tamper.py` and
   `tests/test_disable_auth.py` are the load-bearing suites there.
5. **The test inventory**: which test files go, which are rewritten, and what coverage
   would be lost.
6. **What you will NOT do**, and any point where the plan touches out-of-scope files.

Present the plan and wait for approval. Do not begin executing.

---

## Phase 2: execute

Work in small commits, one module or one seam per commit, running the full suite between
each. Do not batch the deletions into a single change, because a bisect has to be able to
find which removal broke something.

For every commit:

- full suite green, with the count stated
- `ruff check`, `ruff format --check`, `mypy src/notari` all clean
- a commit message saying what was removed, what it was replacing, and what now happens
  instead

After the last commit, run this and report the real output:

- fresh-repo smoke: `notari init`, commit exactly what init prints, `notari begin ... --scope 'src/api/**'`,
  make a change, `notari verify`. It must reach **PASS**. This flow was broken twice
  before, so it is the canary.
- `notari --help` and confirm no command references a removed module
- `notari doctor` and `notari status`
- `tests/test_gate_self_tamper.py` and `tests/test_disable_auth.py` explicitly green
- `notari verify` in `~/quill` itself, which must still PASS against the signed contract
- final line counts: source removed, tests removed, and the new per-surface percentages
  using `docs/` analysis if you want to reproduce the table above

---

## Definition of done

- The seven modules and their CLI commands are gone.
- `grep -ri "lesson\|insight\|decay\|journal\|saves" src/notari/` returns only unrelated
  matches, and you have read each remaining hit to confirm it.
- No dead imports, no orphaned config, no docstring or help text referring to removed
  features. `docs/SECURITY-MODEL.md` and `README.md` mention nothing that no longer exists.
- The full suite passes, the first-run flow reaches PASS, and the gate suites are green.
- You have stated plainly what you did not verify.

## One last thing

If at any point the honest answer is "this is riskier than it looked" or "removing this
would break the gate", say that and stop. Stopping with a clear explanation is a better
outcome than a clever workaround. The most valuable thing produced in the previous
session was not any individual fix, it was noticing that the tests were lying.
