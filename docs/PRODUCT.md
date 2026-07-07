# Quill — Product & Tiers

Quill is open-source change control for AI coding agents. The core security
primitive — a human-signed boundary that deterministically gates agent-authored
diffs — is free and open source **forever**. Paid tiers add the things a *team*
needs once the primitive works: shared policy, history, monitoring, and the
governance/compliance surface that only makes sense across many repos and people.

The dividing line is deliberate: **we never paywall the ability to enforce a
boundary.** You can run the full gate, in strict mode, on unlimited repos, for
free. You pay when you want to operate it as a team at scale.

---

## Free / OSS (MIT) — shipped today

Everything below exists in this repository and is covered by tests.

| Capability | Command / surface |
|---|---|
| Signed perimeter (paths agents may / may never touch) | `quill init`, `quill guard` |
| Signed, scoped, expiring, repo-bound task contracts | `quill begin` |
| Deterministic verdict (PASS / NEEDS_REVIEW / BLOCK) | `quill verify` |
| Change Passport (JSON + Markdown evidence) | `quill verify`, passport artifact |
| Gate-signed passports + independent re-verification | `quill verify-passport` |
| Honest posture (🔴/🟡/🟢, exact next steps) | `quill status` |
| Environment / key / workflow / chain diagnostics | `quill doctor` |
| Secure GitHub Action + `pull_request_target` template | `action.yml`, `quill init` |
| Tamper-evident local audit log (hash-chained) | `quill audit …` |
| Secret scanning on added lines (incl. UTF-16, `-diff`) | inside `quill verify` |
| Submodule / gitlink opacity evidence | inside `quill verify` |
| Resource ceilings + scan dispositions (no silent PASS) | inside `quill verify` |

**Design guarantees (all backed by code + tests in this repo):**

- No candidate-controlled Python module executes before verification — the Action
  installs and runs in isolated mode (`python -I`, `PYTHONSAFEPATH=1`) and the PR
  is checked out into a data-only directory. (`tests/test_secure_workflow_isolation.py`)
- Strict mode requires a signed perimeter **and** a signed, repo-bound contract; an
  unbound contract cannot silently pass. (`tests/test_trust_spine.py`,
  `tests/test_contract_expiry.py`)
- A contract cannot widen past the perimeter; forbidden-path and gate-tamper edits
  BLOCK. (`tests/test_trust_spine.py`, `tests/test_security_regressions.py`)
- Oversized / unscannable content is BLOCKed (strict) or flagged (cooperative),
  never reported as fully scanned. (`tests/test_resource_limits.py`)

## What stays open source, forever

The **enforcement core** is permanently OSI-licensed and will never move behind a
paywall or a source-available license:

- the CLI (`init`, `guard`, `begin`, `verify`, `verify-passport`, `status`, `doctor`)
- the GitHub Action and the secure workflow template
- the Ed25519 signing/verification of perimeter, contract, and passport
- the deterministic policy engine (scope, forbidden paths, secrets, submodules)
- the local audit log and the Change Passport format

This is a commitment, not a footnote: teams adopt a security tool only if they
trust it won't be rug-pulled. Enforcement is never paywalled.

---

## Pro Team — planned (hosted)

> Status: **roadmap.** Design targets, not shipped features. The free gate works
> without any of this.

Team operation of the same gate, without each repo being an island:

- Hosted dashboard: posture across every repo in one view.
- Centralized, versioned policy templates pushed to many repos.
- **GitHub App check-source**: post the verdict as a Checks-API *check run* from a
  known App identity, so branch protection can require *Quill specifically* — a bare
  commit status can be spoofed by anyone with `statuses: write`.
- Signed evidence retention (searchable passport history).
- Slack / email alerts on BLOCK and on policy drift.
- Policy drift detection (a repo whose workflow or perimeter fell out of policy).
- Branch-protection verification (confirm the check is actually *required*).
- Multi-repo inventory and posture rollups.

## Business / Enterprise — planned

> Status: **roadmap.**

The governance and compliance surface for regulated / large orgs:

- SSO / SAML / SCIM (SSO is **not** priced as a tax).
- Centralized approver + gate key management; KMS / HSM integration.
- Audit exports and compliance evidence packs (map passports to controls).
- Multi-org governance, advanced reporting, configurable data retention.
- SIEM integration, custom policy packs.
- Support, onboarding, and a VPC / self-hosted option.

---

## Why teams upgrade (the pain, not the feature)

1. **Activation (free):** the moment a fake bad PR gets BLOCKed with a passport
   that names the exact violation. That is when Quill stops being abstract.
2. **Willingness-to-pay signal:** number of repos with the gate enabled, and BLOCK
   volume. A team gating five-plus repos and catching real BLOCKs weekly has
   crossed from "trying it" to "depending on it."
3. **The paid trigger:** "I can't see our posture across 30 repos," "I need the
   verdict to come from an identity a PR can't spoof," and "the auditor wants
   evidence" — none of which a single-repo CLI can answer, and all of which are
   about *scale and governance*, not about re-enabling security you already had.
