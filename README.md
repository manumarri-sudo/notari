<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark-dark.svg">
  <img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark.svg" alt="" width="38">
</picture>

# Notari

Notari is an open-source alpha for reviewing committed Git changes. It is
a policy gate with a signed evidence trail, not a security control against a
hostile pull request author: it catches careless agent changes, and a PR
author who is trying to evade it can (see [Known limitations](#known-limitations)).

Its scan flags workflow edits, checks added lines against
26 vendor-format secret patterns, and flags test, CI, lockfile, git-config and
agent-instruction changes for review. Other governance files (CODEOWNERS, dependabot config,
`requirements.txt`, Makefile, Dockerfile) are not flagged. An optional signed
boundary checks the changed paths against the paths a human signed for a task.

[![PyPI](https://img.shields.io/pypi/v/notari.svg)](https://pypi.org/project/notari/)
[![CI](https://github.com/manumarri-sudo/notari/actions/workflows/ci.yml/badge.svg)](https://github.com/manumarri-sudo/notari/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Try the scan

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) on macOS
or Linux. Run this from a Git branch with a committed change and substitute the
branch it targets if that branch is named something other than `main`.

```bash
uvx notari scan --base main --no-passport
```

| Result | What it means | Exit |
| --- | --- | --- |
| PASS | The scan found no matching checks to flag. | 0 |
| NEEDS_REVIEW | A change needs inspection, such as a lockfile, test, or low-confidence credential pattern. | 0 |
| BLOCK | The scan found a blocking change or could not complete its coverage. | 1 |
| Error | The command could not produce a verdict. | 2 |

The scan compares commits. Commit the changes you want included. Omit
`--no-passport` to save the unsigned JSON and Markdown evidence in `.notari/`.
Run `notari explain` to see the findings and suggested fixes.

## Add it to GitHub

Copy the [scan workflow](docs/scan-workflow.yml) into
`.github/workflows/notari-scan.yml` on your default branch. It fetches the
candidate commit for inspection and posts `notari/scan` to the PR head.
Follow the [GitHub setup in the quickstart](docs/QUICKSTART.md#github-actions)
to verify the status and set it as required. Repositories with GitHub Actions
event restrictions may need a workflow-specific policy.

## Signed change control

Run `notari init` to generate keys, sign an initial perimeter, and write a
workflow. Use `notari guard` to set the standing boundaries, `notari begin`
to sign a task and its allowed paths, and `notari verify --strict` with the
trusted approver key to check a change. A configured gate signing key signs the
resulting Change Passport. A reviewer can use `notari verify-passport` with
the trusted gate public key and `--head-sha` set to the expected PR head to
verify that evidence. Without `--head-sha`, a valid passport for any commit
verifies. Strict mode requires the contract to expire within 30 days and, in
CI, rejects a contract older than the one on the target branch.
The [signed quickstart](docs/QUICKSTART.md#install) walks through this setup.

## Local hooks and audit

The optional Claude Code and Cursor hooks inspect supported tool requests
before execution. They can ask for approval or block a request and record the
decision. They are advisory: quoting, aliases, SQL clients (`psql -c "DROP
TABLE ..."`) and downloads onto the hook's own settings file are not caught.
Use `notari doctor` to check your setup, `notari audit show` to inspect
recorded decisions, and `notari audit verify` to check the local audit chain.
The chain key lives in `~/.notari/key`, readable by the user the agent runs
as, so the log is not evidence against that agent. The CLI sends no telemetry
by default.

The [security model](docs/SECURITY-MODEL.md) describes the rule coverage, key
placement and local-hook limits. A scan PASS describes the checks applied to
the Git change. Human review remains necessary for the behavior of the code.
Keep private keys separate from an agent's working environment.

## Known limitations

These were confirmed by an external audit (2026-11-10) and are not fixed:

- A commit status can be posted by any workflow with `statuses: write`, so a
  same-repository workflow can overwrite `notari/scan` or
  `notari/change-control`. Require the workflow through an org ruleset.
- A signed contract can be reused by a different PR in the same repository
  until it expires (at most 30 days in strict mode), unless the contract on
  the target branch is newer.
- `notari init` writes the approver private key into `.notari/keys/` in the
  working tree, where an agent running as the same user can read it and sign
  its own contract. Move it off the machine as `notari init` instructs.
- The scan matches 26 regexes. It has no pattern for GitLab, npm or PyPI
  tokens (in a `name = value` line they are rated NEEDS_REVIEW at most), and
  it does not decode split, base64, hex or compressed secrets, or BOM-less
  UTF-16 files.
- The gate job installs Notari's dependencies by version range, not by hash,
  while it holds the gate signing key.
- Test files are not a review surface in the default perimeter, so a weakened
  test passes strict mode when it is in scope.

## Releases and security

The package is available on [PyPI](https://pypi.org/project/notari/) through
Trusted Publishing. GitHub builds publish provenance attestations. The
[security policy](SECURITY.md) explains how to report a vulnerability privately,
and the [changelog](CHANGELOG.md) records fixes and limitations.

See [contributing](CONTRIBUTING.md) for development and [testing](docs/TESTING.md)
for verification. The code is available under the [MIT license](LICENSE).
