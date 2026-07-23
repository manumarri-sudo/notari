<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark-dark.svg">
  <img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark.svg" alt="" width="38">
</picture>

# notari

> **Notari** issues a signed **Change Passport** for every AI-authored pull
> request: a receipt any reviewer or auditor can re-verify from the signature
> alone, without re-running Notari or trusting a screenshot, recording which
> files a human approved the agent to touch and
> whether it stayed inside them. A human signs the boundary once; in CI, Notari
> checks each pull request against it and stamps the passport **PASS**,
> **NEEDS_REVIEW**, or **BLOCK**. There is no model in that verdict, so it cannot
> be prompt-injected. It does **not** judge whether the code is correct: it
> attests to *where* the change went and whether it leaked a secret, the part a
> human most often skims past on a large agent PR. And a repeated mistake becomes
> a short rule you promote into `CLAUDE.md` / `AGENTS.md`, so the agent stops
> making it. **Alpha**; treat
> [the security model](https://github.com/manumarri-sudo/notari/blob/main/docs/SECURITY-MODEL.md)
> as the source of truth over any one-line claim.

## Start here: one command

```bash
uvx notari init
```

Nothing to install first. In one command, inside any git repo, that generates an
approver keypair and a gate keypair, signs a secure-by-default perimeter, writes
the hardened GitHub workflow (`pull_request_target`, SHA-pinned, the pull request
checked out into a data-only directory), gitignores your private keys, and then
prints your honest posture plus the exact steps still missing. Measured from a
clean machine with no Python tooling configured, the CLI resolves and runs in
about a second and a half.

Prefer a persistent install? `pipx install notari` or `pip install notari`, then
`notari init`. Either way the next two commands are the whole daily loop:

```bash
notari begin "add rate limiting" --scope "src/auth/**"   # sign what the agent may touch
notari verify --strict                                    # in CI: PASS, NEEDS_REVIEW, or BLOCK
```

## What you actually get

Four surfaces, each stated at its real strength rather than its most flattering one:

**1. The gate, which is the provable boundary.** In CI, outside the agent's reach,
every changed path outside `.notari/` is measured against a signed scope and a signed
perimeter, each touched file is scanned for 26 vendor secret patterns, and renames
(both endpoints), mode-only changes, binaries, symlinks, submodules, and
`.gitattributes` diff-hiding are all in the inventory rather than blind spots. You name
the scope per task (`--scope`), so a narrow scope means "only these paths", and the
explicit `--scope '**'` means "anything the signed perimeter does not forbid", stated
plainly on the passport either way so a PASS is never ambiguous. Secret detection is a
finite pattern set, so it catches the common vendor-format leaks rather than proving no
secret exists. There is no model in the decision path, so there is nothing to
prompt-inject.

**2. The receipt, which outlives the run.** A Change Passport (`passport.json` plus a
PR-ready `passport.md`) whose Ed25519 signature anyone can re-check later with
`notari verify-passport`, months on, on a different machine, so a forged or tampered
verdict fails and you trust the signed receipt rather than a screenshot. This checks
that the gate genuinely issued this verdict, not that the code is correct, and it does
not re-run the gate. Behind it sits an HMAC-chained audit log that detects edits and
insertions cryptographically, and trailing truncation against a sealed high-water-mark
once `notari audit verify` has run; the passport's footer cites the exact chain entry
for its run.

**3. The loop, which stops the same mistake recurring.** `notari explain` turns a BLOCK
into a per-finding fix and a paste-ready agent prompt, `notari lessons` ranks what an
agent keeps getting wrong, and `notari teach` writes the lessons you promote into
`CLAUDE.md`, `AGENTS.md`, or Cursor rules, so the next session starts already knowing.
All local, all human-gated, no telemetry, and no raw code, diffs, or secret values ever
leave your machine.

**4. The guard on your laptop, which is defense-in-depth and not a hard boundary.** An
optional `PreToolUse` hook gates the agent's tool calls as they happen (`rm -rf`,
`git push --force`, `DROP TABLE`, `vercel --prod`, `.env` reads), critical calls need a
single-use ten-minute approval that on macOS is hardware-attested through Touch ID on
the Secure Enclave, and files the agent writes get an AST pass that flags
`shutil.rmtree` and `exec(b64decode(...))` before a later `python foo.py` can run them.

That fourth row is deliberately labelled: an application-layer gate can be routed
around by a determined adversary, and the limits are enumerated in
[the security model](https://github.com/manumarri-sudo/notari/blob/main/docs/SECURITY-MODEL.md)
rather than buried. The boundary that holds is the CI one.

**New here?** Start with the
[Quickstart](https://github.com/manumarri-sudo/notari/blob/main/docs/QUICKSTART.md)
(zero to a blocked bad PR in ~10 minutes). Then:
[Security & threat model](https://github.com/manumarri-sudo/notari/blob/main/docs/SECURITY-MODEL.md) ·
[Product & tiers](https://github.com/manumarri-sudo/notari/blob/main/docs/PRODUCT.md).

**Found a bypass, a confusing error, or a reason you'd never adopt this?** That is
exactly the feedback this alpha exists for:
[open an issue](https://github.com/manumarri-sudo/notari/issues).

**Want to attack it first?** `bash examples/bypass_probes.sh` runs twelve bypass
shapes against a freshly signed perimeter and prints the verdict for each:
rename into a forbidden path, mode-only change, case variant, a secret hidden
behind a `.gitattributes -diff` entry, an agent widening its own signed
contract, and more. Eleven BLOCK; the twelfth is the documented line-split
secret limit. A thirteenth shape that earns an undeserved PASS is the single
most useful thing you can send.

<!-- mcp-name: io.github.manumarri-sudo/notari -->

[![PyPI](https://img.shields.io/pypi/v/notari.svg)](https://pypi.org/project/notari/)
[![Python versions](https://img.shields.io/pypi/pyversions/notari.svg)](https://pypi.org/project/notari/)
[![CI](https://img.shields.io/github/actions/workflow/status/manumarri-sudo/notari/ci.yml?branch=main&label=ci)](https://github.com/manumarri-sudo/notari/actions/workflows/ci.yml)
[![Typed](https://img.shields.io/badge/typed-strict-blue.svg)](https://mypy.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An AI agent opens a pull request. Which files was it *not* approved to touch? On
a 40-file agent diff that is the question a human skims past, and it is the one
Notari answers, at the merge boundary in CI, with a signed Change Passport a
reviewer can re-verify instead of trusting a screenshot. The verdict is a
deterministic function of the diff, the signed contract, and the policy, so
there is no model in it to jailbreak. It records *where* the change went and
*whether* it leaked a secret; it does not prove the in-scope code is correct or
free of a backdoor. That is the honest scope.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-flow-dark.svg">
  <img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-flow-light.svg" alt="How Notari works: a human signs the task boundary, the AI agent writes the diff, CI verifies the change against the signed boundary and issues a PASS, NEEDS_REVIEW, or BLOCK verdict, recorded in a signed Change Passport any reviewer can re-check." width="920">
</picture>

The full loop, live, an agent edits in and out of scope, Notari verifies each
diff (PASS / NEEDS_REVIEW / BLOCK), and a repeated mistake becomes a lesson
taught back to the agent (from
[`examples/change_control_demo.sh`](https://github.com/manumarri-sudo/notari/blob/main/examples/change_control_demo.sh),
unedited):

<img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-demo.gif" alt="Terminal recording of the demo: setup, a PASS on an in-scope change, BLOCK verdicts on forbidden-path and secret-introducing changes, notari explain remediation, and the lessons loop writing a promoted rule into CLAUDE.md." width="920">

```bash
# 0. one-time: create a human approver key. Keep the PRIVATE half off the build
#    box; pin the PUBLIC half so a PR cannot edit the trust root (in CI this is a
#    repo/org secret or variable, NOT a path inside the checkout).
notari keygen --out approver.pem
export NOTARI_APPROVER_PUBKEYS="$(cat approver.pem.pub)"

# 1. sign the standing boundary ONCE: what agents may touch, what is off-limits.
notari guard --key approver.pem --allow "src/**" --forbid "migrations/**"

# 2. capture AND SIGN the approved task (a signed contract can't be forged by the agent).
notari begin "Add rate-limiting to the login endpoint" --scope "src/auth/**" --key approver.pem
#    commit .notari/{perimeter.json,perimeter.sig,contract.json,contract.sig} to the BASE branch.

# 3. the agent writes the diff and opens the PR.

# 4. CI verifies the PR against the signed boundary, in strict mode.
notari verify --strict        # PASS · NEEDS_REVIEW · BLOCK   (BLOCK fails the build)
#    add --sign-key gate.pem (or NOTARI_GATE_KEY in CI) to ALSO sign the verdict,
#    so a reviewer can re-check it with `notari verify-passport`.
```

That full sequence, pinned external approver key, signed perimeter, signed
contract, `--strict`, is the real adversarial boundary. Drop any of it (`notari
begin` / `notari verify` with no flags) and Notari still runs, but in *cooperative*
mode: honest review automation for a non-adversarial agent, not a boundary
against one trying to escape. Verdict signing is opt-in (it needs a gate key); it
is not on by default. See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for
the full deployment checklist.

`notari verify` reads `git diff <base>..HEAD`, checks every changed file against the
scope you approved, scans each touched file for hardcoded secrets and sensitive surfaces
(CI config, lockfiles, test deletions), evaluates any logged exceptions, and writes
a **Change Passport**: `passport.json` + a PR-ready `passport.md`, that cites the
HMAC-chained audit entry for the run, so a reviewer can trace the verdict back to a
tamper-evident record instead of trusting the markdown alone.

---

## Why this layer

The agents writing your code have shell access, file write, deploy permissions, and
your credentials, and the failures are already on the record: in July 2025 [Replit's
agent deleted a production database](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
during a vibe-coding session and fabricated data to cover it; that same month a
Cursor agent ran `rm -rf ~/` against a developer's home directory; in August an
autonomous agent committed a customer's GitHub token into a public commit. The
common thread is not that the model is evil, it is that nothing checked the change
against what was actually approved before it shipped.

Notari puts that check where it can be enforced and recorded: **in CI, on the pull
request**, where the gate runs outside the agent's own process and cannot be quietly
switched off by the thing it is reviewing. The verdict is a deterministic function of
the diff, the contract, and the policy, there is no LLM in the decision path, so the
gate itself cannot be prompt-injected.

## What Notari is, and what it is not

Calibration matters more than marketing.

- **Notari is a verification-and-evidence artifact, not a content classifier.** It
  does not predict whether a change is "good." It checks the diff against a recorded
  contract (scope, secrets, sensitive surfaces) and issues a signed verdict a human
  can review. There is no model in the gate.
- **The CI gate is the defensible boundary; the local gate is defense-in-depth.**
  Notari also ships an optional on-laptop runtime gate (below). That gate is a
  deterministic speed bump and recorder at the tool-dispatch layer, it raises the
  bar against careless agents and the common destructive/exfiltration shapes, but it
  is **not** a hard boundary against a determined adversary actively trying to escape
  it (write-then-run, flag reordering, inherited-env, ungated network egress are all
  documented limits). The full, honest threat model is in
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
- **Notari does not certify compliance.** The audit log is machine-verifiable evidence
  your auditor will want to review, not the artifact they will accept on its own.
- **Notari is not a hosted service.** It is a single Python package. The audit log and
  signing key live on your disk in mode `0o600`; you own the key, the log, and the
  verdict. No cloud round-trip on the verify path, no telemetry by default.
- **Notari spends no AI tokens.** There is no LLM inside it: the verdict, the secret
  scan, the plain-English `explain`, and the local gate are all deterministic code
  (regex, globs, AST, counting). No model, no API key, no per-check cost, nothing to
  meter. The only tokens in the picture are the ones your coding agent already spends
  writing the code, and, if you *choose* to paste a Notari fix-prompt back to it, the
  ones it spends on the fix. That is a deliberate design property, not a limitation:
  a gate with a model in it could be prompt-injected and would bill you per PR; this
  one cannot and does not.

## Change Control in detail

### 1. `notari begin`, capture the contract

```bash
notari begin "Add rate-limiting to the login endpoint" \
            --scope "src/auth/**" --scope "tests/auth/**" \
            --approved-by alice \
            --key approver.pem \
            --expires-in 7 --repo owner/repo
```

Writes `.notari/contract.json`: the approved task (text or a URL to a ticket), the
`allowed_paths` scope (globs, directory prefixes, or exact paths), the base commit
the change starts from, and a `contract_id`. `--key` signs it so `verify --strict`
can prove a human authored it (required in strict mode); `--expires-in` sets a lapse
deadline; `--repo` binds the approval to one repository so a signed contract can't be
replayed elsewhere. Commit the contract (and `.sig`) to the branch, it is the fixed
record the diff is later measured against, and the Change Passport cites it.

### 2. `notari verify`, gate the diff

```bash
notari verify --strict        # enforced mode: requires the signed perimeter + contract
notari verify                 # local/cooperative: advisory, forgeable by the agent
```

`verify` (`src/notari/verify.py`, on top of `policy.evaluate_diff`):

1. builds the authoritative changed-path inventory from
   `git diff --name-status -z --find-renames <base_commit>..<candidate>`, both
   rename endpoints, binary and mode-only changes included,
2. matches every changed path (both ends of a rename) against the contract scope,
3. scans each touched file for the 26 vendor-format secret patterns in
   [`src/notari/secrets.py`](src/notari/secrets.py), reading the whole file from the
   candidate commit (not just added lines) so a 100% rename or a UTF-16 file cannot
   hide a credential,
4. classifies sensitive surfaces (CI/workflow files, lockfiles, test deletions,
   git configuration like `.gitattributes` that controls diff visibility),
5. applies any logged exceptions in `.notari/exceptions.json` (ignored entirely in
   strict mode, an unsigned waiver file cannot weaken a strict verdict),
6. composes a verdict, **PASS**, **NEEDS_REVIEW**, or **BLOCK**: and chains a
   `verification.run` event into the audit log.

`BLOCK` exits non-zero (fails CI); `PASS` and `NEEDS_REVIEW` exit 0, so review is
surfaced without hard-stopping the pipeline. The whole thing is deterministic: given
the same inputs, the diff, the contract, the signed perimeter, the trusted approver
keys, the strict flag, and any (signed) exceptions, it returns the same verdict,
explainable line by line. There is no model in the decision path; the only clock
reference is contract-expiry enforcement (`--expires-in`), which is an explicit
human-set deadline, not a heuristic.

### 3. The Change Passport

`verify` writes `passport.json` (machine-readable, for downstream tooling and status
checks) and `passport.md` (PR-ready). The markdown footer cites the
`verification.run` audit MAC, so the passport traces back to the tamper-evident chain
rather than asking you to trust the document.

### 4. The GitHub Action

```yaml
# .github/workflows/notari-change-control.yml
on:
  pull_request_target:          # NOT pull_request, see "Why pull_request_target" below
    branches: [main]
jobs:
  change-control:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          path: _pr_checkout             # isolate candidate code from trusted runtime
          persist-credentials: false
      # Pin to the release commit SHA, not a mutable tag, `notari status`
      # rejects a non-SHA pin. `notari init` writes the current pin for you.
      - uses: manumarri-sudo/notari@7eec505486005e8b5c50197b97dd9b1e6a3f761a  # 0.4.1 release action
        with:
          head: ${{ github.event.pull_request.head.sha }}
          head-sha: ${{ github.event.pull_request.head.sha }}
          checkout-path: _pr_checkout
          strict: "true"
          block-on-review: "true"   # NEEDS_REVIEW fails the job too, so a review-class change can't merge unseen
          approver-pubkeys: ${{ secrets.NOTARI_APPROVER_PUBKEYS }}
          gate-key: ${{ secrets.NOTARI_GATE_KEY }}
          gate-pubkeys: ${{ vars.NOTARI_GATE_PUBKEYS }}
```

**Why `pull_request_target`:** the `pull_request` event runs the PR's version of the
workflow, so an AI agent can modify the workflow to remove the Notari step entirely,
and the gate never fires. `pull_request_target` runs from the base branch (main),
so only merged code controls the gate definition (the PR cannot edit the workflow
that judges it). Strict mode **refuses to run** under
`pull_request` to enforce this. **Why `path: _pr_checkout`:** isolates the candidate
checkout so no candidate-controlled Python module (pip.py, json.py) can shadow
trusted imports during Notari installation. A full secure template is at
[`docs/secure-workflow.yml`](docs/secure-workflow.yml).

The composite action ([`action.yml`](action.yml)) runs `notari verify --strict`,
publishes a commit Status Check, and fails the job on `BLOCK`. The approver public
key and gate signing key come from repo/org secrets a PR cannot read or edit, that is
what makes the trust root external. If a PR has no `.notari/contract.json`,
verification **errors and the job fails closed** (exit 2), rather than passing
silently, so deleting or omitting the contract cannot wave a change through.
Initialize Change Control on the base branch (`notari begin --key`) before requiring
the check.

## After a BLOCK: explain, fix, and teach future agents

A verdict is where most gates stop. Notari turns the block into the fix, and turns
repeated blocks into repo lessons future agents read before they drift again, all
local, no telemetry, deterministic (no model decides anything):

```bash
notari verify                                     # PASS · NEEDS_REVIEW · BLOCK + a passport
notari explain                                    # the passport in plain English + a fix per finding
notari explain --fix-prompt                       # a compact prompt to paste into your coding agent
notari lessons                                    # repeated local mistakes, ranked, with a suggested lesson
notari lessons promote no-ci-edits-without-ci-scope   # human-gated: accept a lesson
notari teach --agents claude,codex,cursor         # write promoted lessons into CLAUDE.md / AGENTS.md / Cursor rules
notari agent-brief                                # the compact pre-work brief to hand an agent before it starts
```

`notari explain` reads the passport and says, per finding, what's wrong in plain
language, the exact `git` command to undo it, and a paste-ready instruction for the
agent, plus *what Notari does not prove* (it checks the boundary, not code
correctness). `--fix-prompt` and `--agent-brief` emit the compact agent surfaces
without dumping the full passport into context. **Notari never uploads raw code,
diffs, prompts, or secret values; lessons are local and human-promoted.**

## Trust spine: sign the boundary once, the agent can't forge it

The point of running in CI is that the gate lives where the agent can't disable
it, but that only matters if the agent also can't *fake its approval* or *edit
its own judge*. Notari closes both with Ed25519 (verification uses a public key,
forging needs the private key, not the same secret, which is what the symmetric
HMAC chain could never give you):

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-trust-dark.svg">
  <img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-trust-light.svg" alt="Why the agent can't cheat: editing the CI workflow is defeated by base-branch control, planting an approver key is defeated by trust roots pinned outside the checkout, forging the verdict is defeated by the gate signature, and hiding changes behind symlinks or submodules surfaces as NEEDS_REVIEW." width="920">
</picture>

```bash
notari keygen --out approver.pem          # human's key; keep the private half OFF the box
notari guard --key approver.pem --forbid 'migrations/**' --forbid 'src/auth/**'
#   ^ signs .notari/perimeter.json once. From now on EVERY agent's PR is checked
#     against it automatically, you're paged only when one crosses the line.
```

- **A human signs the perimeter once; every PR is enforced with no per-change
  approval.** That is the answer to "I'm not going to sit and approve a hundred
  agents." Forbidden paths and gate-tamper edits BLOCK; secrets BLOCK by default
  (a signed perimeter can relax to review); in-bounds work PASSes silently.
- **The agent can't authorize itself (in strict mode, with an off-box trust
  root).** Editing the perimeter, the approver keys (`.notari/approvers/**`), or
  the workflow that runs the gate is itself a BLOCK (gate-tamper detection), and
  tampering with a signed perimeter or contract invalidates the signature.
  The contract is protected by its Ed25519 signature, not the gate-tamper glob
  set, in strict mode an unsigned or forged contract is a BLOCK because its
  provenance check fails. The committed
  `.notari/approvers/*.pub` set is a *convenience*, not a boundary: in strict mode
  only the externally-pinned `NOTARI_APPROVER_PUBKEYS` are trusted, because an
  agent could otherwise plant a key in the base commit and sign its own approval.
  Off-box keys + strict is what makes this a real claim rather than a hopeful one.
- **The verdict can't be forged.** With a gate key (`notari verify --strict
  --sign-key gate.pem`, or `NOTARI_GATE_KEY` in CI), the passport is signed;
  anyone re-checks it with `notari verify-passport passport.json` and a flipped
  verdict or untrusted signer fails.
- **Or use GitHub's own reviews.** `notari check-approval` requires a human who is
  not the PR author to have approved the current head commit, an agent can't
  approve its own PR, and the approval is dismissed when new code is pushed.

**What this requires to be a real boundary (not optional):** the trust root must
live where a PR can't edit it. Hold the approver/gate **private keys off the
build machine** (a repo/org secret: `NOTARI_GATE_KEY`, `NOTARI_APPROVER_PUBKEYS`),
**sign the contract** (`notari begin --key`) and require it in strict mode,
**pin the Action to the release commit SHA** (not a mutable tag, and not the PR's own
checkout; `notari status` rejects a non-SHA pin), and make the
**Status Check required** in branch protection. With those in place the bypasses
the security model enumerates are closed against the attacks the test suite
exercises (including the composite rogue-key-in-base attack, the Action-wrapper
fail-open, and binary/rename diff coverage, all closed with regression tests);
without them it is honest review automation for a cooperative agent. This has
**not yet had an external security audit**, so treat "closed" as "closed against
what we currently test," and treat
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md), which tracks the residual open
items, as authoritative over this README.

## The local runtime gate (optional, defense-in-depth)

Separately from CI, Notari can gate an agent's tool calls **as they happen** on your
laptop, via Claude Code's `PreToolUse` hook. This is the supporting surface, scoped
honestly as defense-in-depth, a deterministic speed bump and recorder, not a hard
boundary.

```bash
notari onboard      # detect agents, install the hook, pick a risk preset
```

From the next session, every `Bash` / `Edit` / `Write` / `NotebookEdit` passes
through the compiled-regex classifier in [`src/notari/policy.py`](src/notari/policy.py):
`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `.env`
reads, and the CVE-2025-59536 subcommand-chain bypass are critical-class by default.
Critical calls are refused with a plain-English reason and a single-use, 10-minute
`notari approve <token>`; on macOS the approval is hardware-attested through Touch ID
on the Secure Enclave. Files an agent writes are scanned with the same 26 secret
patterns and an AST pass ([`code_scan.py`](src/notari/code_scan.py)) that flags
destructive Python shapes (`shutil.rmtree`, `os.system`, `exec(b64decode(...))`)
before a later `python foo.py` can run them. Every decision lands in
`~/.notari/audit.log.jsonl`, HMAC-SHA256 chained for tamper evidence.

Supporting surfaces on the local gate, all derived from the same chain on read:
`notari receipts` (per-session did / changed / uncertain / to-verify), `notari trifecta`
(lethal-trifecta exposure: untrusted input + private data + exfil vector),
`notari pins` (tool-description pinning against MCP rug-pulls), `notari decay`
(permissions that erode without reinforcement), and `notari audit` (review and verify
the chain). `notari scan-secrets` runs the secret detectors standalone over files.

**Why this is defense-in-depth and not the headline:** an application-layer gate can
be routed around by a capable adversary (the limits above). The provable boundary is
the CI gate, which runs where the agent cannot disable it and produces a signed
record. The local gate is real and useful, but its honest claim is "raises the bar
and records everything," not "cannot be bypassed."

## The signed audit log

Both surfaces write to `$NOTARI_HOME/audit.log.jsonl`, mode `0o600`. Each entry's
`mac` is `HMAC-SHA256(prev_mac || canonical(payload))` under your installation's key
(auto-generated at first run, stored at `$NOTARI_HOME/key`, mode `0o600`). Writes take
`fcntl.flock(LOCK_EX)` and re-read the tail MAC inside the lock so concurrent writers
can't break the chain. A sealed `<log>.head` high-water-mark lets `verify` detect
trailing truncation, not just edits and insertions.

```bash
notari audit verify
# chain intact: 72739 entries verified.
```

That count is from 76 days of real dogfooding on the maintainer's machine
(2026-05-07 to 2026-07-22, re-measured at release); your own
log starts at one. The chain is locally tamper-evident (and optionally externally
anchored), see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for exactly what
that does and does not buy.

## Install

The one-command path is at the top of this README (`uvx notari init`). The rest:

```bash
uvx notari begin --help     # no install; run any subcommand once
pipx install notari         # or install the CLI persistently
pip install notari          # or into an existing venv
```

One name everywhere: the PyPI dist, CLI binary, import path, config dir
(`~/.notari/`), and env vars (`NOTARI_*`) are all `notari`.
For a development checkout: `git clone https://github.com/manumarri-sudo/notari && cd
notari && pip install -e .`.

## CLI surface

```
notari begin          capture the approved task into .notari/contract.json
notari verify         compare the diff to the contract, emit PASS / NEEDS_REVIEW / BLOCK
notari explain        turn the passport into plain-English remediation (--fix-prompt, --agent-brief, --format html)
notari fix-prompt     compact paste-ready fix prompt for the coding agent
notari lessons        aggregate repeated local mistakes; promote <id> to accept one
notari teach          write promoted lessons into CLAUDE.md / AGENTS.md / Cursor rules
notari agent-brief    compact pre-work brief to hand an agent before it starts
notari onboard        first-run setup for the local gate (detect agents, install hook)
notari audit          review what got blocked / allowed / asked; verify the chain
notari approve <tok>  confirm a pending one-shot approval (Touch ID on macOS)
notari approvals      list (hashed ids) / revoke pending approval tokens
notari receipts       per-session did / changed / uncertain / to-verify
notari trifecta       lethal-trifecta exposure tracking
notari pins           tool-description pins (anti-poisoning, anti-rug-pull)
notari decay          permissions that erode without reinforcement
notari scan-secrets   scan files for hardcoded credentials
notari scan-prompts   scan files for prompt-injection-shape patterns (signal only)
notari commit-hook-install   add a session-summary block to the commit message template
notari doctor         diagnose the install
notari version        print the version
```

Run `notari --help` for the full list (including `night`/`off` gate-weakening toggles,
read [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) before using them).

## What's shipping today vs. on the roadmap

**Shipping (0.3.0), with on-disk evidence:** the Change Control flow
(`begin`/`verify`/passport + GitHub Action), the HMAC-chained audit log (32k+ entries
dogfooded, truncation-detectable, `notari audit verify` clean), the local PreToolUse
gate with Touch ID approvals and 26-pattern secret detection, the write-then-run AST
scan, and the read-side surfaces (receipts, trifecta, pins, decay). The full test
suite (`uv run pytest` for the live count), `ruff`, `ruff format`, and
`mypy --strict` are green and enforced in CI.

**Roadmap (not shipping today, do not assume present):** PR-comment rendering of the
passport (the Action publishes a Status Check today), the lethal-trifecta enforcement
escalation as a CI signal, per-tool hook adapters for Cline / Aider / Continue /
Windsurf / Zed, WebAuthn for cross-platform hardware-attested approval, and a
`from notari import gate` BYO-agent library API. The MCP proxy, OS sandbox, desktop
dashboard, and out-of-band notification channels that earlier previews shipped were
**removed** in the Change Control pivot and are not coming back in this line.

## Security

`notari` is itself security-critical code. The threat model, the honest list of what
the gate stops well and where it can be bypassed, and the responsible-disclosure
address are in [SECURITY.md](SECURITY.md) and [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
When PyPI publishing is wired, releases will be signed via
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with PEP 740
attestations (planned, not yet in place).

## Contributing

Missed a dangerous-action class, a scope-bypass on the diff parser, or a false
positive? Open an issue with a repro. Adapters live under `src/notari/adapters/`.

## License

MIT. See [LICENSE](LICENSE). Vendored third-party code is attributed in
[NOTICE](NOTICE). Version history in [CHANGELOG.md](CHANGELOG.md). Repo:
[github.com/manumarri-sudo/notari](https://github.com/manumarri-sudo/notari).

---

Built with assistance from Claude (Anthropic).
