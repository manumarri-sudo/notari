# Nota Lessons: local learning for AI coding agents

Nota does not train a model. It turns repeated local findings into compact,
human-approved instructions for the agents that work in *this* repo.

When `nota verify` returns BLOCK or NEEDS_REVIEW, Nota records a small
structured note about what went wrong. When the same kind of mistake repeats,
`nota lessons` surfaces it and suggests a one-line rule. A human promotes the
rules they agree with, and `nota teach` writes them into the agent instruction
files (`CLAUDE.md`, `AGENTS.md`, Cursor rules) that future agents read before
they start. That is the whole loop:

```
verify → explain → fix-prompt → lessons → promote → teach → agent-brief
```

## What it is, precisely

- **Local by default.** Mistake events live in `.nota/mistakes.jsonl` and
  promoted lessons in `.nota/lessons.json`, both inside your repo. Nothing is
  sent off-machine. There is no telemetry and no global learning in this
  release.
- **No raw content.** A mistake event stores a rule id, a finding type, a
  path *kind* (`ci_workflow`, `lockfile`, `auth`, …), a basename-redacted path,
  and a stable fingerprint. It never stores source code, diffs, prompts, secret
  values, or private file contents. (Secret findings store the pattern *name*,
  e.g. "AWS Access Key ID", never the value.)
- **Human-gated.** No lesson is ever auto-promoted or auto-written into an
  instruction file. `nota lessons promote <id>` is an explicit human action,
  and `nota teach` only writes lessons you already promoted.
- **Advisory, not policy.** A promoted lesson is guidance an agent reads; it
  does **not** change what Nota blocks. The signed perimeter and contract are
  the only things that decide a verdict, and a lesson can never widen or weaken
  them. If you want a lesson *enforced*, add the path to the signed perimeter
  (that is what a lesson's `policy_candidate` severity is hinting at).
- **Deterministic verdicts, unchanged.** The learning layer runs strictly
  *after* the verdict, in a best-effort try/except, so a learning failure can
  never fail the gate open or closed. Same diff + same contract → same verdict,
  always. No LLM is anywhere in the decision path.

## Commands

```bash
nota lessons                                 # repeated mistakes, ranked, with a suggested lesson + severity
nota lessons --json                          # machine-readable
nota lessons promote no-ci-edits-without-ci-scope   # accept one (idempotent)
nota teach --agents claude,codex,cursor      # write promoted lessons into agent instruction files
nota agent-brief                             # compact pre-work brief: task, scope, forbidden paths, lessons
```

`nota teach` edits only the block between the `<!-- nota-lessons:start -->`
and `<!-- nota-lessons:end -->` markers. Everything you wrote outside that block
is preserved byte-for-byte, and re-running is a no-op if nothing changed.

## Lesson severity

Each suggested lesson carries a level so the signal stays sharp:

| Severity | Meaning |
| --- | --- |
| `inform` | Just worth mentioning in the agent brief. |
| `warn` | Worth flagging before it happens again. |
| `block` | Nota already blocks this deterministically today. |
| `policy_candidate` | Consider adding the path to the signed perimeter so it's *enforced*, not just advised. |

## Working with a swarm of agents

The loop is safe when many agents work in the same repo at once:

- **Recording is concurrency-safe.** Each `nota verify` serializes its mistake
  records into a single atomic `O_APPEND` write, so parallel agents can't
  interleave or corrupt a line in `.nota/mistakes.jsonl`.
- **Duplicates can't inflate counts across re-runs.** Every event carries a
  fingerprint (`contract_id + head_commit + rule_id + finding_type + path_kind`),
  and re-recording the same failing commit is a no-op. A different commit with
  the same pattern still counts, which is what you want — that's the signal that
  a *pattern* is recurring across the swarm, not noise from one flaky re-run.
  (Under a tight simultaneous race the best-effort dedup may let one duplicate
  through; the fingerprint keeps that harmless and the file never corrupts.)
- **Teaching is a human, single-writer step.** `nota teach` is something an
  operator runs, not something each agent runs, so there is no write contention
  on `CLAUDE.md` / `AGENTS.md` in normal use. If you script it, run it once from
  a single place after promoting.
- **One boundary, many agents.** The contract and perimeter are per-repo and
  signed, so every agent in the swarm is measured against the *same* approved
  boundary. Hand each agent the output of `nota agent-brief` before it starts so
  the whole swarm shares the same scope, forbidden paths, and promoted lessons.

## What it is not

- Not model training or fine-tuning.
- Not telemetry — nothing leaves your machine by default.
- Not a global lesson network. Any future cross-repo sharing would be opt-in,
  redacted, aggregated, signed, inspectable, and reversible — never raw code,
  diffs, prompts, or secret values.
- Not a code reviewer. Nota checks whether a change was *authorized*, not
  whether it's *good*.
