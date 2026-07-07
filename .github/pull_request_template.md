<!--
Thanks for opening a PR.

Before submitting, please run:
  pytest --no-cov
  ruff check src tests
  ruff format --check src tests

If the change touches the gate (policy.py, classify_command, secrets.py,
adapters/), add a test that exercises the new behavior. The audit-log
chain is the deliverable; if your change can break the chain shape,
mention it explicitly here.
-->

## What this changes

A short description of what's different after this PR. The "why" matters
more than the "what"; the diff shows the what.

## How it was tested

- [ ] `pytest --no-cov` passes locally
- [ ] `ruff check src tests` passes
- [ ] If you added a new tool-call risk pattern: a unit test in `test_classify_command.py` or `test_secrets.py` exercises it
- [ ] If you changed the audit-log event taxonomy: a test in `test_audit.py` exercises chain integrity across the new event type

## Anything reviewers should know

Edge cases, dependencies on other in-flight PRs, things you're explicitly
not addressing in this PR but plan to follow up on.

## Checklist

- [ ] Tests pass locally
- [ ] CHANGELOG.md `[Unreleased]` section updated if the change is user-facing
- [ ] README.md updated if the change adds a new CLI command or changes an existing one
- [ ] No em dashes in user-facing text
