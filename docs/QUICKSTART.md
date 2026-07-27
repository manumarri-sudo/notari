# Notari Quickstart

Get from zero to a blocked bad PR in about ten minutes. Everything here is free
and open source, runs locally, and needs no account.

## What Notari does in one sentence

Notari checks every AI-authored change against a **human-signed boundary** (the
paths agents may and may never touch) and issues a **Change Passport**: a
deterministic PASS / NEEDS_REVIEW / BLOCK verdict with the evidence behind it, so
an autonomous coding agent cannot quietly edit your workflows, your migrations, or
leak a secret without a human seeing it.

## Install

```bash
pipx install notari      # installs the `notari` command
notari --version
```

## 1. Set up the boundary (about 2 minutes)

```bash
cd your-repo
notari init
```

`notari init` generates an approver keypair and a gate keypair, signs a
secure-by-default perimeter, writes the **secure** GitHub workflow
(`pull_request_target`, SHA-pinned, PR checked out into a data-only directory),
and gitignores your private keys. It finishes by printing your posture and the
exact steps left to make the boundary real.

## 2. Declare what agents may never touch

```bash
notari guard \
  --key .notari/keys/approver.pem \
  --forbid ".github/workflows/**" \
  --forbid "migrations/**" \
  --forbid ".notari/keys/**"
```

Forbidden paths **BLOCK** unconditionally, even a signed contract cannot widen
past them. This is your outer perimeter. (`--key` is the approver private key
`notari init` generated; it re-signs the perimeter so the change is trusted.)

## 3. Commit the boundary, THEN sign a scoped task (about 1 minute)

Order matters here, once: `notari begin` freezes the current HEAD as the
contract's *base*, and `notari verify` later judges everything after that
point. Any setup file still uncommitted when you run `begin` (the perimeter,
the `.gitignore` entries the key commands wrote) rides inside the task's diff
and muddies your first verdict, so land the boundary first (`begin` warns you
if you forget):

```bash
git add .notari .gitignore && git commit -m "notari: signed boundary"

notari begin "add rate limiting to the API" \
  --scope "src/api/**" \
  --key .notari/keys/approver.pem \
  --expires-in 7 \
  --repo owner/name

git add .notari && git commit -m "notari: open task contract"
```

`--repo` binds the contract to one repository so it cannot be replayed elsewhere, and
it is required for `--strict` to accept the contract, so include it now even though the
local demo below runs in cooperative mode. In CI the repo is filled in automatically
from `$GITHUB_REPOSITORY`.

Pass `--key` so the contract is **signed**: an unsigned contract cannot establish
provenance under `notari verify --strict` (the CI default), so the boundary wouldn't
actually enforce. `--expires-in` takes a number of days; after it lapses,
`notari verify --strict` BLOCKs so a stale approval can't authorize work forever. In
CI the repo is bound automatically from `$GITHUB_REPOSITORY`; locally pass `--repo
owner/name`. (The contract commit itself lands after the base by design; verify
exempts it because its integrity is protected by the approver signature, which
the agent cannot forge.)

## 4. Watch a good change PASS

```bash
echo "rate_limit = 100" >> src/api/limits.py
git add -A && git commit -m "in-scope change"
notari verify
```

You get a green **PASS**: "diff is within the approved boundary: in scope, no
secrets, nothing forbidden," signed by your approver key. That is the everyday
happy path; now break it.

> **Local vs. CI, one honest distinction:** the `notari verify` you just ran is
> *cooperative* mode, which is advisory because the trust root sits on this machine
> where the agent could reach it. The enforced boundary is `notari verify --strict`
> running in CI, where the approver public key lives as a repository secret
> (`NOTARI_APPROVER_PUBKEYS`) that a pull request cannot edit. Strict mode ignores the
> committed `.notari/approvers/*.pub` for exactly that reason, so run strict in CI, not
> from the checkout you are demonstrating in.

## 5. Watch a bad change get blocked

```bash
# An agent edits a workflow it was never scoped to touch, in a NEW commit
# on top of the base the contract recorded:
echo "# tampered" >> .github/workflows/ci.yml
git add -A && git commit -m "sneaky workflow edit"

notari verify
```

You get a **BLOCK** with a Change Passport that names the exact forbidden surface.
(If instead you see a PASS with a warning that "the diff is empty," the bad change
landed in the same commit as the contract base, make it a separate commit on top,
as above, so there is a diff to check.)
Try the same with an out-of-scope file, or a line like `AWS_SECRET_ACCESS_KEY=...`,
and you will see the scope and secret findings respectively.

## 6. Explain the failure and fix it with your agent

```bash
notari explain
notari explain --fix-prompt
```

`notari explain` turns the passport into plain English: per finding, what's wrong,
the exact `git` command to undo it, and what Notari does *not* prove (it checks the
boundary, not whether the code is correct). `--fix-prompt` emits a compact prompt
you paste into Claude Code, Codex, Cursor, or another coding agent, it tells the
agent exactly what to revert, split, or ask approval for, without dumping the full
passport into context. (`--format html` writes a click-to-copy page for a
non-technical reviewer.)

## 7. Brief the next agent before it starts

```bash
notari agent-brief
```

`notari agent-brief` renders the approved task, the allowed scope, the forbidden
paths, and the surfaces that trigger human review, compact enough to paste at the
top of an agent session. Handing it over before work starts is cheaper than
explaining a BLOCK afterwards. **This is local by default, no code, diffs,
prompts, or secret values ever leave your machine.**

## 8. Ask what is still missing for a *real* boundary

```bash
notari status
```

Notari is honest here. A key sitting on the same laptop the agent runs on is **not**
a boundary, the agent runs as you and can read it. `notari status` reports:

- 🔴 **unconfigured**: no signed perimeter yet
- 🟡 **cooperative**: honest review automation, but the trust root is still
  reachable by the agent (a local/committed key)
- 🟢 **enforced**: the approver trust root is off-box (a CI secret or hardware
  key), the gate runs pinned trusted code, and a required status check gates merge

To reach 🟢 you move three things off the machine (Notari prints the commands):

```bash
gh secret set NOTARI_GATE_KEY < .notari/keys/gate.pem
gh secret set NOTARI_APPROVER_PUBKEYS < .notari/keys/approver.pub
# then delete the local private keys, and make the `notari/change-control`
# status check REQUIRED in branch protection on main.
```

## 9. Confirm your environment

```bash
notari doctor
```

Checks Python, the installed Notari version, keys, the workflow, dependencies, the
Action wiring, and the audit chain, and tells you what to fix.

---

**Next:** read [`SECURITY-MODEL.md`](SECURITY-MODEL.md) for the threat model and the
control/data separation, and [`PRODUCT.md`](PRODUCT.md) for what stays free forever
versus what the paid team tiers add.
