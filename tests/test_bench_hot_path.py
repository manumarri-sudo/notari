"""Benchmarks for the gate hot path. Pinned to a perf budget.

Run only when explicitly requested:

    pytest tests/test_bench_hot_path.py -m bench --benchmark-only \
        --benchmark-min-rounds=200 --no-cov

Budgets (from README):
    classify_command (allow path):  P50 < 50us, P99 < 250us
    audit emit (single, no fsync):  P50 < 250us, P99 < 1ms
    full hook decide() path:        P50 < 500us, P99 < 2ms

Numbers are P50/P99 wall-clock per call on Apple Silicon. CI will pin a
"don't get worse than this" multiplier (1.5x baseline) so a regression
fails loudly without requiring a hardware-class spec.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

# Skip the entire bench file if pytest-benchmark isn't installed. Default
# `pytest` runs collect this file but only run it when the user opts in via
# `-m bench` (see pyproject [tool.pytest.ini_options].markers).
pytest.importorskip("pytest_benchmark")

from quill.adapters.claude_code import decide, run_hook
from quill.audit import AuditLog
from quill.policy import Risk, classify, classify_command

pytestmark = pytest.mark.bench


# -- 1. policy.classify_command (the regex-iter that dominates Bash gating) ---


@pytest.mark.benchmark(group="policy")
def test_bench_classify_command_critical(benchmark):
    cmd = "rm -rf node_modules"
    result = benchmark(classify_command, cmd)
    assert result.risk is Risk.CRITICAL


@pytest.mark.benchmark(group="policy")
def test_bench_classify_command_high(benchmark):
    cmd = "git push origin main"
    result = benchmark(classify_command, cmd)
    assert result.risk is Risk.HIGH


@pytest.mark.benchmark(group="policy")
def test_bench_classify_command_low(benchmark):
    # The fast-path: read-only command, classifier hits LOW pattern.
    cmd = "ls -la /tmp"
    result = benchmark(classify_command, cmd)
    assert result.risk is Risk.LOW


@pytest.mark.benchmark(group="policy")
def test_bench_classify_command_medium_uncategorized(benchmark):
    # The slowest classifier path: walks every CRITICAL + HIGH + LOW pattern,
    # falls through to MEDIUM. Worst case for the regex iter.
    cmd = "some-novel-binary --flag value"
    result = benchmark(classify_command, cmd)
    assert result.risk is Risk.MEDIUM


@pytest.mark.benchmark(group="policy")
def test_bench_classify_namespace(benchmark):
    # Namespace classifier - the hot path for MCP-routed tool names.
    out = benchmark(classify, "filesystem.read_file")
    assert out is Risk.LOW


# -- 2. AuditLog.emit (flock + HMAC + write + maybe-fsync) -------------------


@pytest.fixture
def fresh_audit(tmp_path: Path):
    p = tmp_path / "audit.log.jsonl"
    key = secrets.token_bytes(32)
    log = AuditLog(path=p, hmac_key=key)
    yield log
    log.close()


@pytest.mark.benchmark(group="audit")
def test_bench_audit_emit_low_risk_no_fsync(benchmark, fresh_audit):
    # The common path: low-risk tool.attempted. fsync is batched, so this
    # measures HMAC + write + flock cost without the per-call disk sync.
    payload = {"tool_name": "filesystem.read_file", "arg_keys": ["path"], "arg_count": 1}

    def do():
        fresh_audit.emit(
            event_type="tool.attempted",
            session_id="bench-session",
            agent_id="root",
            risk="low",
            payload=payload,
            force_fsync=False,
        )

    benchmark(do)


@pytest.mark.benchmark(group="audit")
def test_bench_audit_emit_critical_force_fsync(benchmark, fresh_audit):
    # The slow path: every CRITICAL emit force-fsyncs. Pins the upper bound.
    payload = {"tool_name": "fs.delete_file", "reason": "rm -rf"}

    def do():
        fresh_audit.emit(
            event_type="verdict.blocked",
            session_id="bench-session",
            agent_id="root",
            risk="critical",
            payload=payload,
            force_fsync=True,
        )

    benchmark(do)


# -- 3. Full Claude-hook decide() (no audit, no notify, no taint) ------------


@pytest.mark.benchmark(group="hook")
def test_bench_hook_decide_bash_low(benchmark):
    out = benchmark(decide, "Bash", {"command": "ls -la"})
    assert out.permission == "allow"


@pytest.mark.benchmark(group="hook")
def test_bench_hook_decide_bash_critical(benchmark):
    out = benchmark(decide, "Bash", {"command": "rm -rf /"})
    assert out.permission == "deny"


@pytest.mark.benchmark(group="hook")
def test_bench_hook_decide_edit(benchmark):
    out = benchmark(
        decide, "Edit", {"file_path": "/tmp/x.py", "old_string": "a", "new_string": "b"}
    )
    # Edit is HIGH by default → "ask".
    assert out.permission == "ask"


# -- 4. End-to-end run_hook (decide + audit emit + JSON parse) ----------------


@pytest.mark.benchmark(group="e2e")
def test_bench_run_hook_e2e_allow(benchmark, fresh_audit):
    """Full hook path: parse → decide → emit attempt + verdict to audit.

    Excludes: notification dispatch, taint state, session-index disk I/O.
    These are the bytes that actually matter on the gate-allow hot path.
    """
    stdin_text = json.dumps(
        {
            "session_id": "bench-sid",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
    )

    def do():
        run_hook(stdin_text, audit=fresh_audit)

    benchmark(do)


@pytest.mark.benchmark(group="e2e")
def test_bench_run_hook_e2e_block(benchmark, fresh_audit):
    """Full hook path with a CRITICAL command (force_fsync per emit)."""
    stdin_text = json.dumps(
        {
            "session_id": "bench-sid-crit",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf node_modules"},
            "cwd": "/tmp",
        }
    )

    def do():
        run_hook(stdin_text, audit=fresh_audit)

    benchmark(do)
