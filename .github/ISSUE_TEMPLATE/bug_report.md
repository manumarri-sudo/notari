---
name: Bug report
about: Something Quill should do but doesn't, or shouldn't do but does
title: "bug: "
labels: ["bug"]
---

<!--
Before filing: please confirm the bug reproduces on the latest released
version. `quill version` to check.
-->

## What happened

A clear description of the bug. Include the exact command or tool call
that triggered it.

## What you expected

A description of what Quill should have done instead.

## Steps to reproduce

1.
2.
3.

## Environment

- OS: <!-- macOS / Linux / Windows + version -->
- Quill version: <!-- output of `quill version` -->
- Python version: <!-- output of `python --version` -->
- Coding agent: <!-- Claude Code / Cursor / Cline / etc. and version -->

## Relevant audit log entries

If the bug involves a gate decision, paste the relevant `~/.quill/audit.log.jsonl`
lines. Strip any sensitive args before pasting; Quill's redaction normally
keeps these out but verify.

```json

```

## `quill doctor` output

```

```

## Anything else
