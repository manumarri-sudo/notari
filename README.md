<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark-dark.svg">
  <img src="https://raw.githubusercontent.com/manumarri-sudo/notari/main/docs/assets/notari-mark.svg" alt="" width="38">
</picture>

# Notari

Notari is an open-source alpha for reviewing committed Git changes. Its scan
flags workflow edits, checks for 26 vendor-format secret patterns, and calls out
files that deserve a closer look. An optional signed boundary checks which paths
a human approved for a task.

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
the trusted gate public key and the expected PR head to verify that evidence.
The [signed quickstart](docs/QUICKSTART.md#install) walks through this setup.

## Local hooks and audit

The optional Claude Code and Cursor hooks inspect supported tool requests
before execution. They can ask for approval or block a request and record the
decision. Use `notari doctor` to check your setup, `notari audit` to inspect
recorded decisions, and `notari audit verify` to check the local audit chain.
The CLI sends no telemetry by default.

The [security model](docs/SECURITY-MODEL.md) describes the rule coverage, key
placement and local-hook limits. A scan PASS describes the checks applied to
the Git change. Human review remains necessary for the behavior of the code.
Keep private keys separate from an agent's working environment.

## Releases and security

The package is available on [PyPI](https://pypi.org/project/notari/) through
Trusted Publishing. GitHub builds publish provenance attestations. The
[security policy](SECURITY.md) explains how to report a vulnerability privately,
and the [changelog](CHANGELOG.md) records fixes and limitations.

See [contributing](CONTRIBUTING.md) for development and [testing](docs/TESTING.md)
for verification. The code is available under the [MIT license](LICENSE).
