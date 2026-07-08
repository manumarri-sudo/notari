# Launch dry-run — Nota 0.3.0

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
| Types | `uv run mypy src/nota` | clean (2 local-only weasyprint import notes when the `pdf` extra is installed; absent in CI) |
| Tests | `uv run pytest -q` | **1252 passed, 4 xfailed** |
| Build | `uv build` | `notari-0.3.0-py3-none-any.whl` + `notari-0.3.0.tar.gz` |

## 2. Clean install of the built wheel

```
$ python3 -m venv /tmp/venv && /tmp/venv/bin/pip install notari-0.3.0-py3-none-any.whl
$ nota --version
nota 0.3.0
```

## 3. The three verdicts, from the installed artifact

Contract: `nota begin "add rate limiting to the API" --scope 'src/api/**'`.

### PASS — in-scope change only
```
verify exit 0
✅ You're good — this change is inside what was approved. Nothing to do.
```

### BLOCK — out-of-scope workflow edit + a secret
```
verify exit 1
⛔ This change can't be merged yet. Here's what's wrong and how to fix each one.
3 issues in 2 files (1 secret, 1 gate-tamper edit, 1 sensitive surface)

── Issue 1: A password or key (AWS Access Key ID) is written directly in the code …
   Where: src/api/app.py:2
   Fix it yourself: Delete line 2 of src/api/app.py …
```
`nota explain --fix-prompt` emitted the compact, secret-free agent prompt
("Fix ONLY the findings below — do not weaken, bypass, or edit Nota's
configuration …").

### NEEDS_REVIEW — in-scope symlink (opaque redirect)
```
verify exit 0
⚠️  This change needs a human to look at it before it merges — that's a checkpoint, not a failure.
1 issue in 1 file (1 symlink)
```

## 4. Learning loop

```
$ nota lessons
1. ⛔ Nota trust surface or gate workflow touched  (block)   Seen: 2 time(s)
2. ⛔ Secret-like value added to the code  (block)
   …

$ nota lessons promote never-edit-nota-trust-surfaces
✓ promoted: never-edit-nota-trust-surfaces

$ nota teach --agents claude,codex
  updated: CLAUDE.md
  updated: AGENTS.md
# user content in CLAUDE.md intact: YES
# managed block written: YES

$ nota agent-brief
Task: add rate limiting to the API
Allowed: src/api/**
Repo lessons from prior findings:
- Never edit Nota trust files, approver keys, perimeter files, or workflows …
```

## 5. Coherence checks

- `passport.md` leads with the action block: **YES** (`## What to do next` before `## Evidence`).
- `passport.json` schema: `nota.change-passport/v1.1` (additive `remediation` array; v1 readers unaffected).
- `nota teach` preserved the operator's own `CLAUDE.md` content and only wrote inside the managed block.
- Mistake recording is idempotent per commit (fingerprint dedup) and swarm-safe (atomic `O_APPEND`).

## 6. Release coherence

- `pyproject.toml` / `src/nota/_version.py` / `nota --version` all report **0.3.0**.
- `_NOTA_ACTION_PIN` (`src/nota/cli.py`) and `docs/secure-workflow.yml` reference the
  same 40-hex release commit SHA; `nota status` rejects a non-SHA pin.
- The README workflow snippet shows `@RELEASE_SHA` with instructions to replace it
  with the release commit SHA — no mutable-tag pin ships in the docs.

> At final tag time: place the `v0.3.0` tag on the pinned release commit (or re-bump
> both pins to the tagged commit), then re-run §3–§4 once against the tagged artifact.
