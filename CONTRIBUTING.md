# Contributing to nota

Thanks for thinking about it.

Nota is a security-critical proxy. Buggy security tooling is worse than no security tooling. We bias toward fewer features, well-tested defaults, and changes that come with a regression test.

## Setup

```bash
git clone https://github.com/manumarri-sudo/nota
cd nota
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Python 3.11+ required.

## What we welcome

- **Missed dangerous-action patterns.** Open an issue with a real-world incident and the shell command (or tool name) that should have been classified `critical` or `high`. Bonus points for a published red-team trace.
- **Adapter PRs** under `src/nota/adapters/`. Cursor, Cline, Continue, Aider, OpenAI Agents SDK, LangGraph, AutoGen, CrewAI - every host has a different tool-call protocol; one adapter per host.
- **Documentation that makes the first-run faster.** If something tripped you up on install, that's a doc bug.
- **Threat-model holes.** Read [SECURITY.md](SECURITY.md) and tell us what we missed. Critical issues go through GitHub Security Advisories, not public issues.

## What we'll push back on

- Features that require putting an LLM in the gate. Nota's value is *deterministic* checks; an LLM judge is jailbreakable and slow.
- Features that send tool args, intent text, file paths, or audit-log contents off the user's machine without explicit opt-in. The privacy positioning is the product.
- Heavy new dependencies. Nota ships with six runtime deps; we mean to keep it that way.
- "Make it more general." Nota is opinionated on purpose.

## How we work

- Commits are small and reviewable. If the diff is over ~300 lines, it probably should be two PRs.
- Every change to the gate or the audit log lands with a test in `tests/`.
- `mypy --strict` and `pyright` both pass on `src/nota/`. New code in that path follows the same rule.
- Lint with `ruff check src tests`. Format with `ruff format src tests`.
- Public-API additions get an entry in `CHANGELOG.md` under `[Unreleased]`.

## Filing issues

For features, please include:
- What you were trying to do
- What you expected to happen
- What happened instead
- Your `nota --version`, MCP client, and OS

For dangerous-action misses, please include:
- The exact tool name or shell command
- What the default classification was
- What it should have been, and why

For security issues, please use [GitHub Security Advisories](https://github.com/manumarri-sudo/nota/security/advisories/new) instead of a public issue.

## License

By contributing, you agree your contribution is licensed under the MIT License (same as the repo).
