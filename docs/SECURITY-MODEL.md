# Notari security model and threat model

This document states plainly what Notari is, what it defends against well, and
where its limits are. It exists because a security tool that overstates its
guarantees is worse than one that is honest about them: an operator who
believes the walls are thicker than they are takes risks they would not
otherwise take.

The short version: **Notari is a deterministic, application-layer gate and
evidence recorder. It is a strong defense-in-depth layer and an excellent
audit trail. It is not a hard security boundary against a determined,
adversarial agent that is actively trying to escape it.** Both of those
sentences are true at the same time, and the rest of this document explains
why.

## Where Notari sits (the trust boundary)

Notari currently runs in two relevant places:

1. The **CI Change Control gate** (`notari verify`), which runs in CI, outside
   the agent's reach, and verifies a PR diff against a human-signed boundary.
   This is the provable boundary and the product's headline surface; the rest
   of this document's "hard boundary" honesty is about the *local* layer below.
2. An optional **PreToolUse hook** in the coding agent (Claude Code, Cursor)
   that fires before each built-in tool call (Bash, Edit, Write, NotebookEdit).
   This is **defense-in-depth** on the developer's machine, not a hard boundary.

> Earlier previews also included an **MCP proxy** between the agent and the MCP
> servers it calls. That proxy was **removed in the Change Control pivot** and
> is **not** part of the current launch surface. Mentions of "the proxy"
> elsewhere in older notes refer to that removed component.

The local hook is at the **application layer**. Notari sees the *tool calls the
agent chooses to make through the framework*. It classifies them with a
compiled regex/policy set (no LLM in the decision path) and returns allow /
ask / deny, writing every decision to an HMAC-chained audit log.

What Notari does **not** see, by construction:

- System calls (the actual `unlink`, `connect`, `execve` the kernel runs).
- Actions taken in-process by an interpreter it already allowed to start
  (what `python3 script.py` does once it is running).
- Writes that do not flow through a gated tool (a sandbox escape, or a
  framework bug that skips the hook).
- Network bytes leaving the machine.

Everything in the "what it does well" list below is *within* that boundary;
everything in the "known limits" list is a consequence of *where the boundary
is drawn*.

## What Notari defends against well

For the common case (a capable but non-adversarial agent, or a careless one,
or a single-shot prompt injection that is not specifically tuned to evade
Notari), the gate is genuinely effective:

- **Irreversible destructive commands** in their direct and common-obfuscated
  forms: `rm -rf`, `DROP TABLE`, `git push --force`, `vercel --prod`,
  `mkfs`, `dd`, fork bombs, and the documented bypass shapes
  (`bash -c "$(curl | sh)"`, base64-decode-to-shell, interpreter heredocs,
  `python -c "...rmtree..."`, `$(which rm) -rf`, variable-assembled
  `$a$b -rf`). See `src/notari/policy.py` and `tests/test_kill_test_2026_06.py`.
- **Credential reads and the exfiltration shape**: `cat ~/.aws/credentials |
  curl ...`, `env`/`printenv` dumps, reads of `~/.ssh`, `~/.npmrc`, and
  friends, and the lethal-trifecta third edge (untrusted input + private
  data + exfil path in one session).
- **Gate self-tamper through a gated tool**: an Edit/Write or shell
  redirection aimed at `~/.claude/settings.json`, `~/.cursor/hooks.json`, or
  `~/.notari/config.toml` is classified CRITICAL, so an agent cannot quietly
  rewrite the gate's own config to disable it *through the tools Notari gates*.
- **Tool-description poisoning / rug-pulls** at the MCP layer (invisible
  Unicode, injection-shaped phrases, schema drift after first trust).
- **A complete, tamper-evident record** of everything attempted, allowed, and
  refused, including everything allowed while the gate was paused
  (`gate_paused` markers) so even an off-window is on the record.

The gate's classifier has no LLM in it, so the gate itself **cannot be
prompt-injected or jailbroken**. That is true and worth stating. It is *not*
the same claim as "cannot be bypassed" (see below).

## Known limits (read this before you trust it with your life)

These are the second-review critique's points, restated honestly. They are
real. We do not close them with more regex.

1. **Semantic shell obfuscation is unbounded.** Regex enumerates the common
   evasions; it cannot enumerate all of them. The Tier-1 and Tier-2 audits
   (2026-06-12) closed the cheapest named shapes - single-variable
   reconstruction (`x=rm; $x -rf`), `printf`-assembled strings piped to a
   shell, `${IFS}` whitespace games, ANSI-C escape reconstruction
   (`$'\x72\x6d'`, decoded before matching), command-substitution binary
   resolution (`$(echo rm) -rf`), and `eval` of a destructive literal are now
   caught (see `tests/test_audit_fixes_tier1.py` and `_tier2.py`) - but the
   *class* remains open: glob-expanded binary paths (`/bin/[r]m -rf`), deeper
   string-splitting, novel encodings, and importance-unknown truncation
   (`: > important.db`) still evade, and are kept on the record as xfail-marked
   residual tests. Catching "what a command *does*" rather than "what it
   *looks like*" needs a shell AST parser or a syscall-level view, not a
   pattern list.

2. **Application-layer hooks can be bypassed by the layer below them.** Notari
   relies on the agent framework to call the hook. If the framework has a bug
   (for example, a subagent dispatched with bypass-permissions that skips
   PreToolUse hooks), or if an attacker writes to the hook config *without
   going through a gated tool*, Notari never fires. The gate self-tamper
   detection above only covers tampering that flows through a gated tool.
   Relatedly, `NOTARI_BYPASS_MODE` / `CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS` in the
   *inherited* environment downshift HIGH verdicts to a silent allow (the
   operator opted out of HIGH prompts); the CRITICAL class never softens. An
   agent that *sets* those vars through a gated tool is classified self-tamper
   and denied, but one that inherits them already-exported (from the operator's
   shell or a parent process) is not caught, because there is no gated tool call
   to intercept. Treat a pre-exported bypass var as equivalent to running
   without the gate for the HIGH class.

3. **The write-then-run loophole.** An agent can use the (allowed) Write tool
   to create `deploy.py`, put `DROP TABLE` or a `requests.post` exfiltration
   inside it, and then run `python3 deploy.py`, which looks like a MEDIUM
   command. The destructive action happens inside the interpreter, invisible
   to a command classifier. Scanning file *writes* for destructive payloads
   is a partial mitigation (Notari already scans writes for secrets); it does
   not close the loophole.

4. **Network egress is not gated.** Blocking `curl` does nothing against a
   Python `requests.post`. The Tier-2 audit (2026-06-12) added classification
   for the common *credential-exfil shapes* - `scp`/`curl -F @cred`/
   `nc < cred`/`openssl < cred`, wget request-body posts, and interpreter
   one-liners that read a file/env and POST it - so the cheap exfil patterns
   are now caught at the command layer. This is a partial mitigation, not
   egress gating: a novel script, an already-running interpreter, or any
   channel the classifier does not enumerate still exfiltrates freely. Notari
   tracks the lethal trifecta heuristically but does not inspect or block the
   outbound connection itself; only a network-egress proxy (roadmap) closes
   this.

5. **Local key + local log.** The audit log is tamper-*evident*, not
   tamper-*proof*. A fully compromised machine can rewrite both the log and
   the HMAC key. The right framing is "locally tamper-evident, optionally
   externally anchored," not "immutable."

6. **Trailing truncation is not detected by the chain alone.** Deleting the
   last N lines of the log leaves a shorter but *valid* chain - each remaining
   entry still links to its predecessor - so a bare chain walk passes on a
   truncated log. This is a weaker prerequisite than the limit-5 case: it needs
   only write access to the log file, not the HMAC key. Mitigation, now wired
   into the CLI: a clean `notari audit verify` seals a high-water-mark (entry
   count + last mac) to a `<log>.head` sidecar, and every subsequent
   `notari audit verify` both reports BROKEN when the log is shorter than the
   sealed count AND checks that the entry at the sealed position still carries
   the sealed mac, so a same-length rewrite of the sealed prefix is caught too.
   The residuals are stated plainly, because a partial mitigation described as a
   full one is worse than none:
   - **Rolling window after each seal.** Events appended *after* the last seal
     and then deleted back to exactly the sealed count are NOT detected: the
     entry at the sealed position is unchanged, so both the count and the mac
     still match. Only per-write sealing closes this, and it is deferred (see
     below), so between two verifies the tail is unprotected.
   - Truncation *before* the first seal, or deletion of the unsigned sidecar on
     a compromised host, stays undetected.
   - An attacker who can read the HMAC key can re-chain and re-seal at will.
   Per-write detection (a head pointer updated under the emit flock) would close
   the rolling window but is deferred rather than risk the audited tamper-evidence
   write path; it is the roadmap item that makes "detects trailing truncation"
   unconditional.

## What the limits mean for the claims

- The audit log is **auditor-reviewable evidence**, not a guarantee of
  prevention and not "the artifact your auditor will accept" on its own.
  Auditor acceptance depends on scope, sampling, key custody, and retention,
  none of which a tool can decide for you. A cryptographically signed log of
  the gate failing to stop an attack is a high-quality *record of a breach*,
  not a mitigating control. Notari maps to evidence requests (SOC 2 CC6/CC7/CC8,
  EU AI Act Article 12-shaped logging, ISO/IEC 42001 A.6.2.8); it does not
  certify compliance by itself.
- "The gate cannot be jailbroken" (true: no LLM in it) is **not** "the gate
  cannot be bypassed" (false: see limits 1-4). Keep the two separate in any
  copy.

### Claims we do and do not make

A launch-gate for any README or marketing copy. If a claim is not at least
"partial" below, it does not ship.

| Claim | Status | Honest form |
|---|---|---|
| Deterministic gate | **Supported** | Same tool call -> same allow/ask/deny; no model in the decision path. Scope it to the *verdict*, never to record-and-replay. |
| Tamper-evident audit log | **Supported** | HMAC-chained, locally tamper-evident (limits 5-6), optionally externally anchored. Not "immutable". |
| Blocks the irreversible class | **Supported** | rm -rf / DROP TABLE / force-push / npm publish / .env reads etc. are default-critical via inspectable regex. |
| Prevents prompt injection | **Partial / reframe** | It cannot be prompt-injected (no LLM) and refuses some injection *consequences* (lethal-trifecta deny); it does not *prevent* injection. Say "refuses the consequence, not detects the cause." |
| Secure by default | **Partial** | The local hook fails closed, but `off`/`--no-biometric` exist and the app layer is bypassable (limits 1-4). Say "defense-in-depth by default." The provable boundary is the CI gate (next row), not the local hook. |
| CI gate runs outside the agent | **Supported, deployment-gated** | `notari verify` runs in CI where the agent can't disable it, enforces a **human-signed perimeter** (Ed25519: forging needs the approver's private key, which lives off the box), BLOCKs any edit to its own trust surfaces (perimeter, approver keys, workflow), and emits a **gate-signed passport** anyone re-verifies with `notari verify-passport`. The agent cannot forge approval (no private key), bootstrap trust (editing `.notari/approvers/**` is a gate-tamper BLOCK), or forge the verdict (asymmetric). This is a real boundary **iff** the trust root is deployed off the PR's reach, see the deployment checklist below. Absent that (no signed perimeter, keys committed in-repo, action run from the PR's own checkout), it degrades to honest review automation for a cooperative agent, and `--strict` BLOCKs rather than pretending. |

### Deployment checklist (what makes the CI gate a real boundary)

All four are required; any one missing drops it back to cooperative-only:

1. **Keys off the build machine.** The approver/gate **private** keys never live
   in the repo. Publish the approver **public** key as `NOTARI_APPROVER_PUBKEYS`
   (INLINE PEM, not a path inside the checkout, strict mode rejects an in-repo
   key path) and the gate signing key as `NOTARI_GATE_KEY`, repo/org **secrets** a
   PR cannot read or edit. (A committed `.notari/approvers/*.pub` set is a
   convenience layer used only in cooperative mode; strict ignores it entirely.)
2. **Pin the Action to the release commit SHA**
   (`uses: manumarri-sudo/notari@<40-hex release SHA>`, `notari init` writes the
   current pin, and `notari status` rejects a mutable-tag pin), not the PR's own
   checkout (`uses: ./` + `install-from-source`), so a PR can't ship a modified
   gate that judges itself.
3. **Make the Status Check required** in branch protection, with admin-bypass and
   force-push disabled, otherwise a `BLOCK` is merely advisory.
4. **Sign the contract** with the approver key (`notari begin --key`). The contract
   supplies the base commit and allowed scope, so an unsigned one is forgeable by
   the agent (it could move the base to hide commits, or widen scope). In strict
   mode an unsigned/forged contract is a BLOCK.

### CI gate: known limits and the external-review status

An independent skeptical security review (2026-06-23) found, and we fixed, two
complete bypasses: an unsigned per-PR contract whose base commit could be moved
to hide malicious commits (P0-1, now requires a signed contract in strict mode),
and an unsigned wildcard exceptions file that could waive whole finding classes
(P0-2, strict mode no longer honors branch-authored exceptions). Both are covered
by adversarial tests in `tests/test_trust_spine.py`.

A second review pass (same date) drove three more to closure, each with a
regression test:

- **Composite rogue-key-in-base attack (closed).** An attacker who plants a
  public key in the base commit (where the gate-tamper scan can't see it, since
  the diff starts *after* it) and signs their own perimeter + contract with it.
  Strict mode now trusts **only** externally-pinned `NOTARI_APPROVER_PUBKEYS`, so
  a committed key is never a trust root (`test_p0_1_composite_rogue_key_plus_base_move_blocks`).
- **Action-wrapper fail-open (closed).** `scripts/notari-passport.sh` now runs the
  verifier into a fresh `mktemp` dir and reads the verdict only from there (a
  committed/stale passport can't be read), fails closed on any non-`0/1` exit or
  unrecognised verdict, and re-verifies the passport's gate signature when a gate
  pubkey is configured (`tests/test_action_wrapper.py`).
- **Binary / rename diff coverage (closed).** The unified-diff parser now seeds
  each file from the `diff --git` header and parses `Binary files … differ`
  stanzas, so a binary blob is inventoried against scope and the gate-tamper
  surfaces; `evaluate_diff` checks both ends of a rename
  (`tests/test_diff_binary_rename.py`).

A third pass, an adversarial red-team of `verify --strict`, plus differential
fuzzing of the diff parser against real git, drove two more to closure:

- **Case-fold / homoglyph escape of the forbid + gate-tamper surfaces (closed).**
  On a case-insensitive filesystem (macOS/Windows runners, many deploy targets)
  `src/Auth/login.py` IS `src/auth/login.py`, but matching was case-sensitive, so
  a capital-letter variant escaped a forbid of `src/auth/**` while the wildcard
  scope `src/**` still covered it, `verify --strict` returned PASS on an auth
  backdoor, and a `.github/Workflows/ci.yml` variant escaped gate-tamper. The
  deny side now folds case + NFKC compatibility forms and maps common homoglyphs
  to ASCII (`deny_hit`), while the allow side stays strict so a variant that
  isn't caught falls out of scope instead. Reproduced end-to-end and pinned in
  `tests/test_perimeter_casefold.py`.
- **git C-quoted path decoding (closed).** A path with a byte ≥ 0x80 is emitted
  by git as `"a/caf\303\251.env"`; the parser left the escapes literal, so an
  exact forbidden/gate path with a non-ASCII byte slipped past. Decoded at the
  single path chokepoint (`tests/test_diff_quoted_paths.py`).

A fourth pass (2026-06-24, source + targeted exploit suite, scored 5.0/10) drove
the remaining inventory and evidence bugs to closure:

- **Rename OUT of a gate or forbidden surface (Critical, closed).** Gate-tamper
  and forbidden checks looked only at a rename's DESTINATION, so renaming the
  workflow (or protected code) out of its path escaped the BLOCK. `verify` now
  builds the inventory from `git diff --name-status -z --find-renames` and
  applies every path rule to BOTH endpoints (`tests/test_rename_and_inventory.py`).
- **Quoted mode-only change disappears (High, closed).** A chmod on a C-quoted
  unicode path produced an empty textual-parse and vanished from every check; the
  authoritative name-status inventory now reports it.
- **Candidate identity mismatch (High, closed).** The diff was taken against a
  symbolic ref while the passport recorded repo HEAD. The candidate is now
  resolved to one SHA used for the diff, the inventory, and the recorded head.
- **Wrapper rc/verdict inconsistency (High, closed).** The wrapper now requires
  process rc, passport verdict, and exit_code to agree, failing closed otherwise
  (`tests/test_action_wrapper.py`).
- **Trust-root path indirection (High, closed).** Strict mode rejects a
  `NOTARI_APPROVER_PUBKEYS` file path that resolves inside the checkout, so the
  "external" trust root can't be redirected to a PR-controlled file
  (`tests/test_trust_root_path.py`).
- **block_secrets honored (closed).** The signed perimeter's block_secrets now
  composes the verdict (default BLOCK; a signed false downgrades to review).

A fifth pass closed the remaining context-binding gaps from earlier reviews and
added `.gitattributes` surface detection:

- **Contract context-binding: repo, expiry, candidate SHA (closed).** The signed
  contract now binds the repository (`notari begin --repo`, strict BLOCKs on
  mismatch), an expiry deadline (`--expires-in`, strict BLOCKs on expired or
  malformed), and the candidate SHA is resolved once and used for the diff,
  the inventory, and the recorded head. These close the cross-repo replay,
  stale-approval, and candidate-identity-mismatch vectors. Regression tests
  in `tests/test_contract_expiry.py`.
- **`.gitattributes` as a sensitive surface (closed).** A `.gitattributes` change
  can suppress diff visibility in tools that don't use `--text` (H-2 residual);
  it is now classified as a `gitconfig` sensitive surface, triggering
  NEEDS_REVIEW so a human sees it.
- **"No clock in the decision path" claim corrected.** Contract expiry
  enforcement uses `datetime.now()`; the README now states this honestly
  (an explicit human-set deadline, not a heuristic).

A sixth pass (2026-06-25, deployment-path review, scored 4.5/10) exposed gaps
between the source code and what a user can actually deploy:

- **Base-commit option injection (H-1, closed).** An untrusted
  `contract.base_commit` like `--output=/path` was passed to git where it could
  be interpreted as an option. `verify()` now validates it as a hex SHA before
  any git call; strict BLOCKs, cooperative falls back to no base.
  `tests/test_security_regressions.py::TestH1BaseCommitOptionInjection`.
- **Renamed-file secret evasion (H-4, closed).** A 100% rename produces no
  added lines in the diff, so secrets in renamed files escaped the added-line
  scanner. The verifier now reads the destination blob directly and runs the
  secret patterns over it.
  `tests/test_security_regressions.py::TestH4RenameSecretDetection`.
- **Glob matcher stack overflow (M-2, closed).** The recursive segment-aware
  glob matcher hit `RecursionError` on paths with 1600+ segments. Rewritten as
  iterative bottom-up DP with O(n*m) worst case.
  `tests/test_security_regressions.py::TestM2DeepPathGlob`.
- **Wrapper strict head_commit binding (H-3, closed).** In strict mode the
  wrapper now requires the passport to contain a `head_commit` SHA, so an
  empty value can't bypass the candidate-binding check.
- **Dogfood workflow fail-open (C-2, closed).** The skip-on-missing-contract
  step (which was fail-open: GitHub reports skipped jobs as success) and
  `continue-on-error` were removed; the Action fails closed on missing contract.
- **Action version pinned (C-2, closed in source).** `action.yml` now defaults
  to `==0.3.0` (exact pin). Version bumped to 0.3.0.
- **Contract provenance checked early (M-1, closed).** Strict mode now verifies
  contract signature, repo binding, and expiry BEFORE consuming contract fields
  in expensive git operations. A forged contract is rejected immediately.
- **UTF-16 secret detection (R6-H1, closed).** Blob scanner now detects
  UTF-16LE/BE (with and without BOM) and decodes before applying secret
  patterns. Files that can't be decoded as UTF-8 fall back to latin-1.
- **Candidate blob scanning (R6-H2, closed).** The secret scanner reads file
  content from the candidate commit's git objects (`git cat-file blob`), not the
  worktree. A divergence between the checkout and the evaluated commit can no
  longer cause the scanner to miss a secret or scan the wrong version.

A seventh pre-flight pass (2026-06-26, self-review before round-7 external) closed:

- **Candidate SHA validation (R7-H1, closed).** `candidate_sha` is now validated
  as a hex SHA after `_resolve_sha()`; a ref that doesn't resolve (e.g.
  `--output=/tmp/evil`) is blocked rather than passed through to git commands.
- **Wrapper status-SHA binding (R7-H2, closed).** The wrapper now always
  compares the passport's `head_commit` against the SHA used for the Status
  Check, regardless of whether `NOTARI_HEAD_SHA` was explicitly set. Eliminates
  the window where two independent `git rev-parse HEAD` calls could diverge.
- **Wrapper REASONS sanitization (R7-H3, closed).** `REASONS` from the passport
  is sanitized (CR/LF stripped, leading `::` removed) before echoing, preventing
  Actions workflow-command injection from attacker-controlled passport data.
- **UTF-8 BOM handling (R7-M1, closed).** `_decode_blob` now strips the UTF-8
  BOM (EF BB BF) and handles truncated BOM-prefixed files gracefully.
- **_waived_secret crash guard (R7-M2, closed).** Non-numeric `line` values in
  `.notari/exceptions.json` no longer crash the gate with ValueError.
- **NOTARI_HEAD_SHA validation (R7-M3, closed).** The wrapper validates
  `NOTARI_HEAD_SHA` against `^[0-9a-fA-F]{40}$` to prevent option injection.
- **python → python3 (R7-L1, closed).** Wrapper uses `python3` throughout.

A round-8 hardening pass added:

- **Base-commit ancestry check (R8-H1, closed).** `verify()` now checks that
  `base_commit` is a git ancestor of the candidate via `git merge-base
  --is-ancestor`. A base that equals the candidate (empty diff, every check
  trivially passes) is the canonical false-positive PASS, strict mode blocks it
  outright. A base that is not an ancestor (stale or forged) also blocks in
  strict. Shallow clones where the merge base is unreachable produce a warning,
  not a block, to avoid false negatives.
- **Status-check fingerprint (R8-M1, closed).** The wrapper embeds the passport's
  audit MAC (first 12 hex chars) in the Status Check description as `[mac:...]`.
  A spoofed status posted by an attacker-injected workflow cannot reproduce a MAC
  it never computed, so fake checks are detectable post-hoc. A
  `status-fingerprint` file records `sha/mac/context/state` for `notari
  verify-passport` cross-checks. Full closure requires a GitHub App as the check
  source; the fingerprint is defense-in-depth.
- **NEEDS_REVIEW blocking (R8-M2, closed).** `block-on-review` input / env
  `NOTARI_BLOCK_ON_REVIEW=true` promotes NEEDS_REVIEW to failure state + exit 1.
- **Supply-chain SHA pinning (R8-L1, closed).** `actions/setup-python` and
  `actions/checkout` pinned to commit SHAs in `action.yml` and
  `docs/secure-workflow.yml`.
- **Empty-diff staleness warning (R8-L2, closed).** When the diff is empty but
  the contract scopes specific paths (not `["**"]`), a warning surfaces that the
  contract may be stale or the work was never committed.

Genuinely still open, do not rely on the CI gate against a determined adversary
until these land:

- **Caller workflow impersonation (round-6 C-1: MITIGATED).** The GitHub Action
  runs inside a caller workflow that lives in the candidate repository. Under the
  `pull_request` event, a PR can modify that workflow to remove Notari entirely.
  **Mitigation (shipped):** strict mode now **refuses to run** under the
  `pull_request` event (exit 2) unless explicitly opted out with
  `NOTARI_ALLOW_PULL_REQUEST_TRIGGER=true`. The secure setup uses
  `pull_request_target`, which runs the workflow from the base branch, immune
  to PR modifications. A secure workflow template is shipped at
  `docs/secure-workflow.yml`. The opt-out exists only for the dogfood repo
  (which uses `install-from-source` and intentionally runs from the PR branch).
  **Residual risk:** `pull_request_target` + `actions/checkout@v4` with
  `ref: PR-head` checks out untrusted code, but Notari does not execute it, it
  only reads the git tree for `git diff`. The remaining escalation paths are:
  1. A GitHub App as the status check source (strongest, eliminates even the
     `statuses: write` fake-check vector).
  2. An org/enterprise ruleset-required workflow in a trusted repo.
- **Contract replay / one-use nonce.** The contract now binds repo, scope, base,
  and expiry, but NOT a one-use nonce or protected branch, so a valid contract
  is replayable within the same repo until it expires. For tenants that share an
  approver key across repos, the repo binding closes cross-repo replay; within a
  single repo, expiry is the time-bound.
- **NEEDS_REVIEW blocking (MITIGATED).** The `block-on-review` input (env
  `NOTARI_BLOCK_ON_REVIEW=true`) promotes NEEDS_REVIEW to a blocking state: the
  Status Check reports `failure` and the job exits 1, the same as BLOCK. The
  passport verdict itself stays `NEEDS_REVIEW` for the audit trail; only the gate
  behavior changes. Operators that need a hard stop on sensitive surfaces set this
  rather than wiring up a separate approval gate. Without it, NEEDS_REVIEW still
  exits 0 (soft signal) and depends on branch protection.
- **Action supply chain (MITIGATED).** `actions/setup-python` is SHA-pinned in
  `action.yml`, `actions/checkout` and `manumarri-sudo/notari` are SHA-pinned in
  `docs/secure-workflow.yml`. All `pip install` commands use `python -I`
  (isolated mode) and `PYTHONSAFEPATH=1` to prevent candidate-controlled Python
  modules (pip.py, json.py, sitecustomize.py) from shadowing trusted imports.
  The secure template checks out the PR into an isolated subdirectory
  (`_pr_checkout`) with `persist-credentials: false`. The **release** job
  (`release.yml`), which holds OIDC publish rights, pins `pip`, `build`, and
  `twine` to exact versions instead of `--upgrade`, and the build backend
  (`hatchling`) is pinned exactly in `[build-system]`, so the privileged job no
  longer resolves whatever `latest` is at publish time. PyPI versions are
  immutable, so an exact pin cannot be swapped for a compromised re-upload.
  **Residual:** the CI gate job still installs Notari's own transitive
  dependencies version-ranged, not hash-locked, so a compromised transitive
  dependency could execute in the gate process; and the release pins are exact
  versions, not hashes. A fully hermetic build adds `--require-hashes` against a
  committed lock. Use `--require-hashes` in hardened deployments today.

- **Off-box evidence anchoring.** The Merkle transparency tree head is built but
  not yet anchored off the runner, so a CI passport's MAC is not independently
  resolvable. There has been **no external security audit** of the full
  end-to-end construction; treat the CI gate as alpha.
- **Perimeter allow-list as outer bound.** The signed perimeter's `allowed_paths`
  now caps a contract's scope (a contract can narrow but not widen past it), but
  `contract_id` still does not cryptographically bind the *specific* scope a
  human saw at approval time; a re-signed contract with a different scope under
  the same id is not detected beyond the signature itself.
- **Exotic homoglyph confusables.** `deny_hit` folds case + the common
  Cyrillic/Greek look-alikes an attacker actually reaches for, but Unicode has
  thousands of confusables and the table is not exhaustive; a path using an
  obscure look-alike of a forbidden segment could still read as that segment to a
  human while being a distinct codepoint. The strict allow-list mitigates it (an
  unrecognised variant falls out of scope), and the homoglyph only bites if the
  protected code actually lives under the look-alike path.
- **Non-trust `.notari/` files in a PR.** `verify` strips `.notari/` from the
  scope/secret evaluation (so committing the contract it describes is not
  self-flagged), and gate-tamper covers `.notari/perimeter.*` and
  `.notari/approvers/**`. A *different* `.notari/` file in a PR (e.g. a local-hook
  config) does not change the CI verdict, but could alter the optional local
  runtime hook's behavior on a machine that re-reads it; treat `.notari/` as
  trusted only to the extent its trust-bearing files are signed.

| Claim | Status | Honest form |
|---|---|---|
| Auditor evidence pack | **Partial** | Maps to evidence requests (SOC 2, EU AI Act Art 12-shaped, ISO 42001 A.6.2.8); does not certify compliance by itself. |
| Enterprise-grade / production-safe | **Not yet** | Alpha, squatted dist name, no external audit. Do not claim. |
| Cannot be bypassed / agent-proof | **Dangerous** | False - see limits 1-4. Never claim. |

## Roadmap to close the gaps (in honesty order)

The fixes for the limits above are architectural, not pattern additions:

- **Shell AST / intent classification** for limit 1 (keep it local and fast;
  a lightweight intent classifier or a real bash parser, not an LLM in the
  hot path).
- **Move the enforced boundary into CI, not the kernel.** An earlier preview
  shipped an opt-in macOS Seatbelt floor (`notari shell`); it was **removed** in
  the Change Control pivot because a local kernel floor still runs on the
  machine the agent controls. The chosen direction is the opposite: enforce in
  CI, where `notari verify` gates the diff in a process the agent cannot reach.
  A kernel-layer local control (eBPF / Landlock / Endpoint Security) remains a
  possible future addition for the local-gate surface, but it is not what makes
  Notari a boundary today, the CI gate is.
- **Network-egress proxy** for limits 3 and 4: catch unauthorized outbound
  connections regardless of the language or script that opened them.
- **Config-file integrity monitoring** for limit 2: detect changes to the
  hook config even when they do not flow through a gated tool.

Until those land, position Notari honestly: the gate that refuses the
irreversible thing and records what was attempted, on the developer-laptop
tool-dispatch layer, as one layer of defense-in-depth. Pair it with
model-level guardrails and (for real adversaries) a kernel-layer control.
Never substitute it for either.

## Control plane vs. data plane (the CI gate's core invariant)

The `pull_request_target` gate runs with the base repo's secrets and a write
token, against **untrusted** PR code. The one non-negotiable rule is that PR
("candidate") code is **data, never control**: no trusted process ever runs with
the candidate checkout as its working directory or on its import path.

How the shipped Action enforces this:

- **Data-only checkout.** The secure workflow checks the PR out into a
  subdirectory (`path: _pr_checkout`) with `persist-credentials: false`, so the
  write token is never written into the tree a candidate controls. The Action is
  told where the candidate lives via `checkout-path`; it reads it only through
  `git` subcommands.
- **Isolated interpreter.** Notari is **installed** with `python -I` (isolated: the
  current directory and user site are off `sys.path`). At **verify** time the
  wrapper `cd`s into the candidate checkout so `git` finds the repo, which makes
  cwd candidate-controlled, so every trusted Python process it starts is isolated:
  the installed `notari` console script does not place cwd on `sys.path`, and the
  wrapper's inline `python3 -I` reads use isolated mode (available since Python 3.4,
  so this does **not** depend on the interpreter version), with `PYTHONSAFEPATH=1`
  (Python 3.11+) exported as defense-in-depth. A candidate `pip.py`,
  `sitecustomize.py`, `usercustomize.py`, or a shadow stdlib module (`json.py`,
  `pathlib.py`) therefore cannot execute at interpreter startup or shadow a trusted
  import. This is proven by a live reproduction in
  `tests/test_secure_workflow_isolation.py`: the shadow fires *without* isolation
  and does **not** fire with it.
- **Minimal network in the privileged job.** The secret-bearing job installs a
  pinned Notari and does **not** run `pip install --upgrade pip`. Remaining
  supply-chain limitation: the pinned Notari's dependency tree is resolved from
  PyPI without `--require-hashes`; a fully hermetic gate installs from a
  hash-locked lockfile or a prebuilt container.

## Round-10 controls (this pass)

- **Strict repo binding, closed both ways.** Strict BLOCKs when the contract is
  bound to a different repo, when the contract has no binding but the environment
  identifies the repo, **and**: the newly closed hole, when *both* the contract
  binding and the current repo identity are absent, so a signed contract can never
  be replayed against an arbitrary repo.
- **Resource ceilings + scan dispositions.** `NOTARI_MAX_DIFF_BYTES`,
  `NOTARI_MAX_FILES`, and `NOTARI_GIT_TIMEOUT` bound what the gate reads; a capped
  streaming git reader keeps memory bounded on a candidate-crafted giant diff.
  Incomplete scan coverage is recorded as a disposition and **BLOCKs in strict /
  NEEDS_REVIEW in cooperative, never a silent PASS.**
- **Submodule opacity evidence.** A gitlink (mode `160000`) pointer move is
  NEEDS_REVIEW and the passport records the old/new nested commit IDs, so a
  reviewer can audit exactly which opaque commit was pulled in.
- **init / status parity.** `notari init` emits a SHA-pinned Action (not a mutable
  tag) that `notari status` accepts, and the secure-workflow template passes
  `checkout-path` so the wrapper finds the candidate repo instead of failing
  closed at the workspace root.

### What this still does NOT do

- It does not make a bare commit **status** unspoofable: any workflow with
  `statuses: write` can POST the `notari/change-control` context. The passport
  fingerprint MAC makes a spoofed success *detectable* post-hoc, but binding the
  *source* of the check requires a GitHub App check-run (a paid/roadmap item).
- It does not hash-lock Notari's transitive dependencies (see above).
- It does not read GitHub branch protection; `notari status` reports what it can
  observe locally and says when required-check enforcement is UNKNOWN rather than
  claiming it.
