---
name: Missed dangerous action
about: An agent ran a command Nota should have refused
title: "missed-action: "
labels: ["missed-dangerous-action", "policy"]
---

<!--
This is the highest-signal issue type for Nota. Every accepted issue
ships as a new pattern in src/nota/policy.py or src/nota/secrets.py
in the next release. Reproducibility matters more than narrative.
-->

## The action Nota let through

Exact command, tool name, and args (redact secrets):

```

```

## Why this is dangerous

One or two sentences. If it's a well-known CVE class, link the CVE.

## What Nota should have done

`Risk.CRITICAL` (block + type-to-confirm) / `Risk.HIGH` (ask y/N) / other?

## Synthetic reproduction

A safe test command that exercises the same pattern Nota should match
against. Doesn't have to actually be destructive; the regex must catch it.

```

```

## Relevant policy section

If you've already located the regex set that should have fired, link
the relevant constant in [`src/nota/policy.py`](../../src/nota/policy.py).

## Environment

- Nota version:
- Coding agent + version:
- OS:

## Anything else
