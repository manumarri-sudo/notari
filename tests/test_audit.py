"""Audit-log foundation tests.

Covers: append-only writes, chain integrity, tamper detection, file mode.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from nota.audit import AuditLog, read_head, seal_head, verify_chain
from nota.errors import AuditError


def test_emits_signed_event(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(
            event_type="session.start",
            session_id="ses_1",
            payload={"intent": "test"},
        )
    assert p.exists()
    with p.open() as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == 1
    assert lines[0]["type"] == "session.start"
    assert "mac" in lines[0]
    assert "prev_mac" in lines[0]


def test_chain_intact_across_many_events(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        for i in range(50):
            log.emit(
                event_type="tool.attempted",
                session_id="ses_1",
                risk="low" if i % 2 == 0 else "high",
                payload={"tool_name": f"fs.read_file_{i}"},
            )
    total, failures = verify_chain(p, key)
    assert total == 50
    assert failures == []


def test_chain_detects_modified_entry(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={"k": 1})
        log.emit(event_type="b", session_id="s", payload={"k": 2})
        log.emit(event_type="c", session_id="s", payload={"k": 3})

    raw = p.read_text().splitlines()
    # Tamper: change the second entry's payload
    obj = json.loads(raw[1])
    obj["payload"]["k"] = 999
    raw[1] = json.dumps(obj, separators=(",", ":"))
    p.write_text("\n".join(raw) + "\n")

    total, failures = verify_chain(p, key)
    assert total == 3
    assert 2 in failures


def test_chain_detects_inserted_entry(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={"k": 1})
        log.emit(event_type="b", session_id="s", payload={"k": 2})

    # Inject a forged entry by copying the second line and modifying it
    raw = p.read_text().splitlines()
    forged = json.loads(raw[1])
    forged["type"] = "INJECTED"
    raw.insert(1, json.dumps(forged, separators=(",", ":")))
    p.write_text("\n".join(raw) + "\n")

    total, failures = verify_chain(p, key)
    assert total == 3
    assert failures  # something must fail


def test_chain_continues_across_reopens(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={})
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="b", session_id="s", payload={})

    total, failures = verify_chain(p, key)
    assert total == 2
    assert failures == []


def test_chain_resumes_after_event_larger_than_4kb(tmp_path: Path) -> None:
    """Regression: `_tail_mac` previously read the last 4 KB only and
    called `splitlines()`. Any event whose serialised line exceeded 4 KB
    returned a fragment, `json.loads` raised, and the chain anchor
    crashed on every reopen. Long bash commands routinely cross 4 KB
    once chain bookkeeping (prev_mac, mac, ts, ids) is added.
    """
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    # Make the first event huge enough that its serialised line is well
    # over 4 KB on its own.
    huge_payload = {"command": "x" * 6000, "description": "big"}
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="bash.huge", session_id="s", payload=huge_payload)
    # Reopen - this triggers _tail_mac on a file whose last line is >4 KB.
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="bash.next", session_id="s", payload={})

    total, failures = verify_chain(p, key)
    assert total == 2
    assert failures == []


def test_chain_resumes_when_log_has_only_one_huge_event(tmp_path: Path) -> None:
    """Edge case: an audit log containing a single >4 KB event with no
    preceding entries. Walk-backwards must not loop forever and must
    correctly return that event's mac as the chain anchor.
    """
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="bash.only", session_id="s", payload={"command": "y" * 8000})
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="bash.after", session_id="s", payload={})
    total, failures = verify_chain(p, key)
    assert total == 2
    assert failures == []


def test_audit_log_file_mode_is_0o600(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={})
    mode = stat.S_IMODE(p.stat().st_mode)
    # Owner read+write only; group/other should have no access.
    assert mode & 0o077 == 0, f"audit log is too permissive: {oct(mode)}"


def test_force_fsync_on_high_risk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """High-risk entries must be force-fsynced at emit time; low-risk batch up.

    A single high-risk entry sits well below FSYNC_BATCH_SIZE, so the ONLY
    reason it must hit the platter during emit() is the risk-based force. We
    spy on os.fsync to observe the durability barrier the instant the event is
    written, before any close() runs its batch flush. This kills the mutant
    that drops the ``risk in ("high","critical")`` clause from the predicate:
    without it a lone high-risk emit would defer to the batch and never fsync.
    """
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32

    fsync_fds: list[int] = []
    real_fsync = os.fsync

    def spy_fsync(fd: int) -> None:
        fsync_fds.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy_fsync)

    log = AuditLog(path=p, hmac_key=key)
    try:
        # A single low-risk emit must NOT fsync: it batches up.
        log.emit(event_type="low", session_id="s", risk="low", payload={})
        assert fsync_fds == [], "a lone low-risk emit must batch, not fsync"

        # A single high-risk emit MUST fsync during emit(), before close().
        log.emit(event_type="high", session_id="s", risk="high", payload={})
        assert fsync_fds, "high-risk emit must force-fsync at emit time, before close"
    finally:
        log.close()

    # And the durability barrier does not corrupt the chain.
    total, failures = verify_chain(p, key)
    assert total == 2
    assert failures == []


def test_chain_intact_under_concurrent_multiprocess_writers(tmp_path: Path) -> None:
    """The Claude Code hook spawns one subprocess per tool call. Parallel
    tool calls => concurrent emits to the same log from separate processes.

    Without fcntl.flock around the read-tail+write sequence, two processes
    each read the same prev_mac and append with that same prev_mac, breaking
    the chain at every collision. This regression test forks N workers that
    all emit M entries each and verifies the chain at the end.
    """
    import multiprocessing as mp

    p = tmp_path / "audit.jsonl"
    key = b"k" * 32

    def worker(path_str: str, key_bytes: bytes, worker_id: int, n: int) -> None:
        log = AuditLog(path=Path(path_str), hmac_key=key_bytes)
        try:
            for i in range(n):
                log.emit(
                    event_type="tool.attempted",
                    session_id=f"ses_{worker_id}",
                    risk="low",
                    payload={"i": i, "worker": worker_id},
                )
        finally:
            log.close()

    workers = 4
    per_worker = 25
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=worker, args=(str(p), key, w, per_worker)) for w in range(workers)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=10)
        assert proc.exitcode == 0, f"worker exited {proc.exitcode}"

    total, failures = verify_chain(p, key)
    assert total == workers * per_worker
    assert failures == [], (
        f"chain broke under concurrent writers: {len(failures)} of {total} "
        f"failures at lines {failures[:10]}"
    )


# ---------------------------------------------------------------------------
# Trailing-truncation detection (#4/#16). The chain alone CANNOT see that the
# last N lines were deleted - a shorter valid chain verifies clean. seal_head
# records a high-water-mark so a later verify against it flags the shortfall.
# ---------------------------------------------------------------------------


def _emit_n(p: Path, key: bytes, n: int) -> None:
    with AuditLog(path=p, hmac_key=key) as log:
        for i in range(n):
            log.emit(event_type="t", session_id="s", payload={"i": i})


def test_truncation_passes_verify_without_a_sealed_head(tmp_path: Path) -> None:
    # Documents the residual limit: with no high-water-mark, a shortened log
    # still verifies clean.
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    _emit_n(p, key, 10)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:6]) + "\n")  # drop the last 4 entries
    total, failures = verify_chain(p, key)
    assert total == 6
    assert failures == []  # invisible to the bare chain


def test_seal_head_then_shorten_is_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    _emit_n(p, key, 10)

    head = seal_head(p, key)
    assert head["count"] == 10
    assert read_head(p)["count"] == 10

    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:6]) + "\n")  # drop the last 4 entries

    sealed = read_head(p)["count"]
    total, failures = verify_chain(p, key, expected_count=sealed)
    assert total == 6
    assert 0 in failures, "a shortfall past the sealed count must be flagged"


def test_seal_head_refuses_a_broken_chain(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    _emit_n(p, key, 3)
    # Corrupt a middle line so the chain no longer verifies.
    lines = p.read_text().splitlines()
    obj = json.loads(lines[1])
    obj["payload"] = {"i": 999}
    lines[1] = json.dumps(obj, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError):
        seal_head(p, key)


def test_read_head_absent_returns_none(tmp_path: Path) -> None:
    assert read_head(tmp_path / "nope.jsonl") is None
