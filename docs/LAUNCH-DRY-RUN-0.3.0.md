# Launch dry-run, Notari 0.3.0

> **Historical record, do not edit the results below.** This captures real output
> from 2026-07-08. The loop surface it exercises (`notari lessons`, `notari teach`,
> `notari learn`, `notari saves`, `notari insights`, `notari decay`,
> `notari journal`) was removed on 2026-07-27, so those commands no longer exist.
> The results are left verbatim because rewriting a dated record to match today's
> code would defeat the point of having recorded it.

Real command results from a pre-alpha release dry-run, run against the **built
and clean-installed wheel** (not the source tree), on 2026-07-08. This exists so
the launch does not rely on commit-message claims: the full loop
(`verify → explain → fix-prompt → lessons → promote → teach → agent-brief`) was
exercised end-to-end and produced PASS, BLOCK, and NEEDS_REVIEW.

Reproduce with `scripts/` equivalents or the commands below.

## 1. Gates (source tree)

| Check | Command | Result |
| --- | --- | --- |
| Lint | `uv run ruff check src tests` | **All checks passed** |
| Format | `uv run ruff format --check src tests` | **139 files already formatted** |
| Types | `uv run mypy src/notari` | clean (2 local-only weasyprint import notes when the `pdf` extra is installed; absent in CI) |
| Tests | `uv run pytest -q` | **1252 passed, 4 xfailed** |
| Build | `uv build` | `notari-0.3.0-py3-none-any.whl` + `notari-0.3.0.tar.gz` |

## 2. Clean install of the built wheel

```
$ python3 -m venv /tmp/venv && /tmp/venv/bin/pip install notari-0.3.0-py3-none-any.whl
$ notari --version
notari 0.3.0
```

## 3. The three verdicts, from the installed artifact

Contract: `notari begin "add rate limiting to the API" --scope 'src/api/**'`.

### PASS, in-scope change only
```
verify exit 0
✅ You're good, this change is inside what was approved. Nothing to do.
```

### BLOCK, out-of-scope workflow edit + a secret
```
verify exit 1
⛔ This change can't be merged yet. Here's what's wrong and how to fix each one.
3 issues in 2 files (1 secret, 1 gate-tamper edit, 1 sensitive surface)

── Issue 1: A password or key (AWS Access Key ID) is written directly in the code …
   Where: src/api/app.py:2
   Fix it yourself: Delete line 2 of src/api/app.py …
```
`notari explain --fix-prompt` emitted the compact, secret-free agent prompt
("Fix ONLY the findings below, do not weaken, bypass, or edit Notari's
configuration …").

### NEEDS_REVIEW, in-scope symlink (opaque redirect)
```
verify exit 0
⚠️  This change needs a human to look at it before it merges, that's a checkpoint, not a failure.
1 issue in 1 file (1 symlink)
```

## 4. Learning loop

```
$ notari lessons
1. ⛔ Notari trust surface or gate workflow touched  (block)   Seen: 2 time(s)
2. ⛔ Secret-like value added to the code  (block)
   …

$ notari lessons promote never-edit-notari-trust-surfaces
✓ promoted: never-edit-notari-trust-surfaces

$ notari teach --agents claude,codex
  updated: CLAUDE.md
  updated: AGENTS.md
# user content in CLAUDE.md intact: YES
# managed block written: YES

$ notari agent-brief
Task: add rate limiting to the API
Allowed: src/api/**
Repo lessons from prior findings:
- Never edit Notari trust files, approver keys, perimeter files, or workflows …
```

## 5. Coherence checks

- `passport.md` leads with the action block: **YES** (`## What to do next` before `## Evidence`).
- `passport.json` schema: `notari.change-passport/v1.1` (additive `remediation` array; v1 readers unaffected).
- `notari teach` preserved the operator's own `CLAUDE.md` content and only wrote inside the managed block.
- Mistake recording is idempotent per commit (fingerprint dedup) and swarm-safe (atomic `O_APPEND`).

## 6. Release coherence

- `pyproject.toml` / `src/notari/_version.py` / `notari --version` all report **0.3.0**.
- `_NOTARI_ACTION_PIN` (`src/notari/cli.py`) and `docs/secure-workflow.yml` reference the
  same 40-hex release-action commit SHA; `notari status` rejects a non-SHA pin.
- The README workflow snippet shows `@RELEASE_SHA` with instructions to replace it
  with the release commit SHA, no mutable-tag pin ships in the docs.

> At final tag time: land a pin-bump commit that points both pins at the
> release-action commit (the newest commit containing the final `action.yml`),
> then place the `v0`/`v0.3.0` tags on that pin-bump commit. The pin sits one
> commit below the tag because a commit cannot reference its own SHA; the two
> commits carry an identical `action.yml`. Re-run §3-§4 once against the
> tagged artifact.
