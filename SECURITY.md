# Security policy

`notari` is security-critical code: a CI/CD change-control gate (`notari verify`)
plus an optional local tool-dispatch gate installed as agent hooks (Claude Code,
Cursor, git hooks). A buggy gate is worse than no gate, because it manufactures
false confidence. This document describes what the project protects against, what
it does not, and how to report a vulnerability. The calibrated threat model — what
the gate stops well and exactly where it can be bypassed — lives in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md); read it alongside this file, and
treat it as the source of truth wherever the two differ.

## Reporting a vulnerability

Please use [GitHub Security Advisories](https://github.com/manumarri-sudo/notari/security/advisories/new).
For the most sensitive reports, open a draft advisory before any public discussion.

We aim to respond within 48 hours and to ship a fix within 7 days for
high-severity issues. Found a bypass? That is exactly the feedback this alpha
exists for — a working bypass with a repro is a high-severity report, not an
embarrassment to soften.

## Threat model

### What an attacker (usually the agent itself, or a prompt-injected agent) would try

In rough priority order:

1. **Bypass the CI gate.** Merge an out-of-scope or forbidden change without a
   BLOCK: smuggle paths past the scope check (symlinks, submodules, renames,
   case tricks), edit the workflow that runs the gate, or run the gate against
   the PR's own modified copy of Notari instead of the pinned release.
2. **Forge authorization.** Fabricate or alter the signed contract/perimeter,
   plant a different approver public key inside the checkout, or forge the
   gate's verdict signature on a Change Passport.
3. **Disable the local gate.** Get the gated agent to run `notari off`/`pause`,
   rewrite `~/.notari/` config/policy files, unset the hook, or re-point the
   hook binary — from inside its own gated session.
4. **Forge or hide audit log entries.** Make a blocked or unapproved action look
   approved, or remove it from the log entirely.
5. **Exfiltrate secrets.** Steal the HMAC signing key (`~/.notari/key`) or an
   approver private key mistakenly stored on the build box, or exfiltrate
   secret values that the scanner should have redacted from logs and passports.

### Most relevant CWEs

- CWE-78 OS command injection (hook/CI subprocess with attacker-influenced args)
- CWE-22 path traversal (scope checks, config paths, log paths)
- CWE-59 link following (symlinks that point in-scope paths at forbidden targets)
- CWE-347 improper verification of cryptographic signature (contract, perimeter, passport)
- CWE-345 insufficient verification of audit log authenticity
- CWE-367 TOCTOU on file existence/permission checks
- CWE-200 information exposure (logs or passports leaking secret values)
- CWE-732 incorrect file permissions on log/key
- CWE-502 deserialization of untrusted data (config files, hook payloads, diffs)

## What we protect against

- **Out-of-scope and forbidden-path changes at the merge boundary.** Deterministic
  path/scope verification in CI against a human-signed contract and perimeter.
  No AI in the decision path; nothing to jailbreak.
- **The agent editing its own judge.** The deployment model pins the Action to a
  release commit SHA and runs the gate from the base branch's trust roots
  (`pull_request_target` + keys outside the checkout), so a PR cannot modify the
  gate that judges it. `notari status` rejects non-SHA pins.
- **Verdict forgery.** When a gate key is configured (`gate-key` +
  `gate-pubkeys`), Change Passports carry a gate signature and reviewers can
  re-verify a passport rather than trusting CI output text; without one, the
  passport labels itself unsigned, report-grade evidence.
- **Symlink and submodule smuggling.** Any in-scope symlink addition/change and
  any submodule pointer move surfaces as NEEDS_REVIEW with the target recorded,
  wherever it points, instead of passing silently.
- **Secret leakage in the diff.** Secret scanning fails the build before merge,
  and recorded evidence redacts values.
- **Gate self-disable from inside a gated session (local gate).** `notari off`,
  `notari pause`, edits to `~/.notari/` policy files, and edits to the agent's
  hook config classify as CRITICAL and are denied even under bypass mode; a
  human disabling the gate in their own terminal is deliberately not subject to
  this (Touch ID / TTY challenge on the human path).
- **Tampering with the audit log.** Every entry includes an HMAC of the previous
  entry's MAC. A modification or insertion breaks the chain at the next
  `notari audit verify`.
- **World-readable secrets.** The audit log and HMAC key are created `0o600`;
  `notari doctor` warns if their permissions have since broadened.

## What we do NOT protect against

- **Semantic badness inside an authorized scope.** A backdoor written entirely
  within the allowed paths PASSes. Notari checks *where* the change went and
  whether secrets leaked, not whether the code is correct or honest. Pair with
  human review of in-scope code.
- **Compromise of a user with code execution.** If an attacker has shell as the
  user running the local gate, they can read the HMAC key and forge entries.
  Userspace Python cannot fully defend against this; see hardening below.
- **A repo without the deployment checklist.** Without branch protection, the
  required check, a SHA-pinned action, trust roots outside the checkout, and a
  gate key for signed verdicts, the CI gate is advisory, not adversarial. The checklist in
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) is what makes it a boundary.
- **Model-side evasion of the local gate.** If the model is tricked into not
  calling a tool at all (e.g. it simulates output instead), the tool-dispatch
  gate has nothing to gate. The CI gate exists precisely because the merge
  boundary is harder to evade than the tool boundary.
- **The unbounded shell-grammar tail.** The local command classifier is regex
  over an unbounded grammar; documented residual escapes live in
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) ("known limits") and in
  xfailed tests rather than being quietly ignored.
- **Memory hygiene of secrets in Python.** We keep secrets out of logs and
  reprs, but we make no claims that secrets are unrecoverable from process
  memory. Operators who need that assurance should run under a dedicated user
  account with restricted swap.

## Hardening recommendations

- Keep approver private keys off the build box; pin approver public keys in a
  repo/org secret or variable, never a path inside the checkout.
- Pin the Action to the release commit SHA (`notari init` writes the current
  pin); make the gate a required status check; protect the base branch.
- Generate a fresh HMAC key per machine; rotate periodically (document the old
  chain head, generate the new key, write a `chain.rotate` boundary event).
- Anchor the chain head externally (e.g. an hourly copy to a backup location)
  so on-disk tampering is detectable even if the local copy is rewritten.
- Run with `umask 0077` so temporary files inherit safe permissions.
- On Linux, consider running the local gate under `bubblewrap`/`firejail`; on
  macOS, `sandbox-exec`.

## Supply chain

Current, verifiable:

- The lockfile (`uv.lock`) is committed and tested in CI.
- `pip-audit --strict` runs on every PR as a **blocking** gate (a dependency CVE
  fails the build).
- Releases publish to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
  (OIDC from `release.yml`; no API token lives in repo secrets), and GitHub
  build-provenance attestations are generated for release artifacts.
- Third-party actions in the workflows are SHA-pinned.

Planned, not yet in place (do not assume present):

- An OSSF Scorecard report (target 8+).
- An SBOM (CycloneDX) attached to every GitHub release.

## Audit history

| Date | Auditor | Scope | Report |
|---|---|---|---|
| _none yet_ | _scheduled post-1.0_ | | |

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes (current alpha line) |

After 1.0, we will support the latest minor and the previous one with security fixes.
