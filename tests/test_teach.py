"""Tests for the compact agent-facing surfaces: fix_prompt and agent_brief.

These moved out of test_lessons.py when the lessons and managed-block halves of
teach.py were removed. They cover Change Passport surface, not loop surface:
`notari fix-prompt` renders what to fix after a BLOCK, and `notari agent-brief`
renders the approved scope before an agent starts work.

Non-negotiables under test: no secret VALUE ever reaches either output, neither
surface ever instructs an agent to defeat the gate, and both stay compact
(token discipline, since agents read these on every task).
"""

from __future__ import annotations

from notari.teach import agent_brief, fix_prompt

SECRET_VALUE = "AKIA" + "X" * 16  # a value that must never leak into outputs


def _passport(verdict: str = "BLOCK", **evidence) -> dict:
    ev = {
        "changed_files": [],
        "out_of_scope": [],
        "forbidden_hits": [],
        "gate_tamper_hits": [],
        "secret_findings": [],
        "sensitive_surfaces": {},
        "submodule_changes": [],
        "symlink_changes": [],
        "scan_dispositions": [],
    }
    ev.update(evidence)
    return {
        "schema": "notari.change-passport/v1.1",
        "verdict": verdict,
        "contract": {
            "id": "abc123",
            "task": "add rate limiting to login endpoint",
            "allowed_paths": ["src/auth/**", "tests/auth/**"],
        },
        "evidence": ev,
    }


# Phrases that would turn the fix prompt into a BYPASS prompt. A fix prompt that
# ever told an agent to defeat the gate would be self-defeating; guard hard.
_BYPASS_PHRASES = [
    "disable notari",
    "weaken notari",
    "turn off strict",
    "remove the notari",
    "delete the workflow",
    "delete approver",
    "change the perimeter",
    "edit .notari",
    "ignore notari",
    "skip notari",
    "bypass the gate",
]


def test_fix_prompt_is_compact_and_leaks_nothing():
    p = _passport(
        out_of_scope=[".github/workflows/deploy.yml"],
        secret_findings=[{"path": "a.py", "line": 3, "pattern": "AWS Access Key ID"}],
    )
    prompt = fix_prompt(p)
    assert "add rate limiting to login endpoint" in prompt
    assert "src/auth/**" in prompt
    assert "do not weaken" in prompt.lower()
    assert "git diff --name-only" in prompt
    assert SECRET_VALUE not in prompt
    assert "verification_run_mac" not in prompt and "provenance" not in prompt
    assert len(prompt) < 3200  # ~800 tokens


def test_fix_prompt_never_instructs_bypass():
    # Exercise every finding kind so all rendered guidance is covered.
    p = _passport(
        out_of_scope=["ops.cfg"],
        forbidden_hits=["src/pay.py"],
        gate_tamper_hits=[".notari/perimeter.json"],
        secret_findings=[{"path": "a.py", "line": 1, "pattern": "JWT"}],
        sensitive_surfaces={"ci": ["ci.yml"]},
        symlink_changes=[{"path": "l", "status": "A", "target": "../x"}],
        submodule_changes=[{"path": "vendor", "status": "M"}],
    )
    low = fix_prompt(p).lower()
    for phrase in _BYPASS_PHRASES:
        assert phrase not in low, f"fix prompt contains bypass phrase: {phrase!r}"
    # It must positively tell the agent NOT to weaken the gate.
    assert "do not weaken, bypass, or edit notari" in low


def test_fix_prompt_caps_findings():
    p = _passport(out_of_scope=[f"f{i}.py" for i in range(12)])
    prompt = fix_prompt(p)
    assert "and 7 more" in prompt
    assert len(prompt) < 3200


def test_agent_brief_never_instructs_bypass():
    brief = agent_brief(
        task="t",
        allowed_paths=["src/**"],
        forbidden_paths=[".github/workflows/**"],
        review_surfaces=["ci"],
    ).lower()
    for phrase in _BYPASS_PHRASES:
        assert phrase not in brief, f"agent brief contains bypass phrase: {phrase!r}"


def test_agent_brief_is_compact():
    brief = agent_brief(
        task="add rate limiting to login endpoint",
        allowed_paths=["src/auth/**", "tests/auth/**"],
        forbidden_paths=[".github/workflows/**", "migrations/**", ".notari/**"],
        review_surfaces=["ci", "lockfiles"],
    )
    assert brief.startswith("Task: add rate limiting")
    assert "Never touch: .github/workflows/**" in brief
    assert "git diff --name-only" in brief
    assert len(brief) < 1200  # ~300 tokens


def test_agent_brief_carries_every_boundary_the_contract_declares():
    """The brief is the only thing some agents ever read about the contract, so
    each of the three boundary kinds has to survive into the text. Asserted as
    presence of the paths themselves rather than of any particular sentence,
    so rewording the brief does not silently drop a boundary.
    """
    brief = agent_brief(
        task="t",
        allowed_paths=["src/auth/**"],
        forbidden_paths=["migrations/**"],
        review_surfaces=["ci"],
    )
    assert "src/auth/**" in brief, "allowed scope missing from the brief"
    assert "migrations/**" in brief, "forbidden path missing from the brief"
    assert "ci" in brief, "review surface missing from the brief"


def test_agent_brief_says_anywhere_when_scope_is_unrestricted():
    """An empty allowed_paths must not render as an empty 'Allowed:' line that
    an agent could read as 'nothing is allowed'."""
    brief = agent_brief(task="t", allowed_paths=[], forbidden_paths=[], review_surfaces=[])
    assert "anywhere not forbidden" in brief
