"""Step 4 tests: startup self-test for the classifier invariants.

Four invariants under test:

  1. The self-test passes against the default classifier (the known-bad
     payload DENYs, the known-good payload ALLOWs).
  2. The self-test fails LOUD (returns ok=False with a real reason)
     when the classifier is misconfigured to fail-open on the
     known-bad payload.
  3. The self-test fails LOUD when the classifier is misconfigured to
     deny everything (including the known-good payload).
  4. Self-test is fast: < 10 ms per invocation across 100 calls,
     and the cache flag means subsequent calls are essentially free.

The self-test is the fix for the silent-failure class that hid the
journal parser bug for ~3 weeks. A broken gate that fails-open is
worse than no gate; the test must surface the problem at startup
rather than at first-tool-call.
"""

from __future__ import annotations

import time


def _reset_self_test_cache(monkeypatch) -> None:
    """Each test starts with a fresh cache flag."""
    import quill.adapters.claude_code as cc

    monkeypatch.setattr(cc, "_SELF_TEST_DONE", False, raising=False)


# ---------------------------------------------------------------------------
# Test 1: Self-test passes under the default classifier.


def test_self_test_passes_default_classifier(monkeypatch) -> None:
    _reset_self_test_cache(monkeypatch)
    # Make sure the test isn't sandbagged by env flags.
    monkeypatch.delenv("QUILL_NO_SELF_TEST", raising=False)
    from quill.adapters.claude_code import self_test

    ok, reason = self_test()
    assert ok, f"default classifier should pass self-test; got: {reason}"
    assert reason == "ok"

    # Second call hits the cache.
    ok2, reason2 = self_test()
    assert ok2 is True
    assert reason2 == "cached"


# ---------------------------------------------------------------------------
# Test 2: When the critical-payload classifier fails-open, self-test
# detects + reports it.


def test_self_test_detects_misconfigured_classifier_that_fails_open(
    monkeypatch,
) -> None:
    _reset_self_test_cache(monkeypatch)
    monkeypatch.delenv("QUILL_NO_SELF_TEST", raising=False)
    # Stub `decide` so the known-CRITICAL payload returns 'allow'
    # (simulating a corrupted policy table).
    import quill.adapters.claude_code as cc
    from quill.adapters.claude_code import HookDecision
    from quill.policy import Risk

    def broken_decide(tool_name, tool_input):
        return HookDecision(
            permission="allow",
            reason="STUB",
            risk=Risk.LOW,
            audit_event_type="verdict.allowed",
        )

    monkeypatch.setattr(cc, "decide", broken_decide)
    ok, reason = cc.self_test()
    assert not ok, "broken classifier must NOT pass self-test"
    assert "DROP TABLE" in reason or "critical" in reason.lower()
    assert "permission=allow" in reason


# ---------------------------------------------------------------------------
# Test 3: When the low-payload classifier fails-closed (denies
# everything), self-test detects + reports it.


def test_self_test_detects_classifier_that_denies_everything(
    monkeypatch,
) -> None:
    _reset_self_test_cache(monkeypatch)
    monkeypatch.delenv("QUILL_NO_SELF_TEST", raising=False)
    import quill.adapters.claude_code as cc
    from quill.adapters.claude_code import HookDecision
    from quill.policy import Risk

    def deny_everything(tool_name, tool_input):
        return HookDecision(
            permission="deny",
            reason="STUB-DENY",
            risk=Risk.CRITICAL,
            audit_event_type="verdict.blocked",
        )

    monkeypatch.setattr(cc, "decide", deny_everything)
    ok, reason = cc.self_test()
    assert not ok
    assert "ls -la" in reason or "low" in reason.lower()
    assert "permission=deny" in reason


# ---------------------------------------------------------------------------
# Test 4: Self-test is fast + cached.


def test_self_test_is_fast_and_cached(monkeypatch) -> None:
    _reset_self_test_cache(monkeypatch)
    monkeypatch.delenv("QUILL_NO_SELF_TEST", raising=False)
    from quill.adapters.claude_code import self_test

    # First call: real work. < 10 ms even on slow CI.
    t0 = time.perf_counter()
    ok, _ = self_test()
    t1 = time.perf_counter()
    assert ok
    first_call_ms = (t1 - t0) * 1000
    assert first_call_ms < 10.0, (
        f"first self-test took {first_call_ms:.2f}ms (budget 10ms). "
        f"The classifier may have become expensive."
    )

    # 100 cached calls should be essentially free.
    t0 = time.perf_counter()
    for _ in range(100):
        self_test()
    t1 = time.perf_counter()
    total_ms = (t1 - t0) * 1000
    assert total_ms < 5.0, (
        f"100 cached self-tests took {total_ms:.2f}ms; expected <5ms. Cache hit path is too slow."
    )

    # QUILL_NO_SELF_TEST env override returns the skip reason without
    # running the checks.
    _reset_self_test_cache(monkeypatch)
    monkeypatch.setenv("QUILL_NO_SELF_TEST", "1")
    ok, reason = self_test()
    assert ok
    assert "skipped" in reason.lower()
