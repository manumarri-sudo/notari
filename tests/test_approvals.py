"""One-shot approval token tests.

Covers: digest stability, issue → consume → exhausted, expiry, revocation,
mismatch by tool name, mismatch by args, persistence across reload.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nota.approvals import (
    DEFAULT_TTL_SECONDS,
    Approval,
    ApprovalStore,
    args_digest,
)


def _mk_approval(
    token: str, mins_ago: int, *, approved: bool = False, expired: bool = False
) -> Approval:
    now = datetime.now(UTC)
    issued = now - timedelta(minutes=mins_ago)
    exp = (issued - timedelta(minutes=20)) if expired else (now + timedelta(minutes=10))
    return Approval(
        token=token,
        tool_name="Bash",
        args_digest="d",
        expires_at=exp.isoformat(),
        issued_at=issued.isoformat(),
        approved_at=now.isoformat() if approved else "",
    )


def test_latest_pending_picks_newest_unapproved(tmp_path: Path) -> None:
    """`nota approve --latest` resolves to the most recent block still
    awaiting approval - skipping already-approved and expired ones even if
    they are newer."""
    store = ApprovalStore(path=tmp_path / "approvals.json")
    store.approvals = {
        "old": _mk_approval("old", 5),
        "newest": _mk_approval("newest", 1),
        "approved_but_newer": _mk_approval("approved_but_newer", 0, approved=True),
        "expired": _mk_approval("expired", 2, expired=True),
    }
    chosen = store.latest_pending()
    assert chosen is not None
    assert chosen.token == "newest"


def test_latest_pending_none_when_nothing_pending(tmp_path: Path) -> None:
    store = ApprovalStore(path=tmp_path / "approvals.json")
    assert store.latest_pending() is None
    store.approvals = {"a": _mk_approval("a", 1, approved=True)}
    assert store.latest_pending() is None  # only an already-approved token remains


def test_approve_refuses_when_touchid_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The self-approval fix: when Touch ID can't fire (the agent's own process,
    SSH, no hardware), `nota approve` REFUSES by default instead of silently
    approving via the typed-token fallback. Otherwise an agent reads its own
    token from `nota approvals list` and releases its own blocked call."""
    from typer.testing import CliRunner

    import nota.touchid as touchid
    from nota.cli import app

    monkeypatch.setenv("NOTA_HOME", str(tmp_path))
    monkeypatch.setattr(touchid, "is_available", lambda: False)

    store = ApprovalStore.load()
    ap = store.issue("Bash", {"command": "git push --force origin main"})

    result = CliRunner().invoke(app, ["approve", ap.token])
    assert result.exit_code != 0, "must refuse approval when Touch ID unavailable"

    reloaded = ApprovalStore.load()
    assert ap.token not in reloaded.approvals or not reloaded.approvals[ap.token].approved_at, (
        "the token must NOT be left approved after a refusal"
    )


def test_approve_no_biometric_is_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--no-biometric stays the explicit, operator-chosen escape hatch for
    genuine headless use, and still approves when Touch ID is unavailable."""
    from typer.testing import CliRunner

    import nota.touchid as touchid
    from nota.cli import app

    monkeypatch.setenv("NOTA_HOME", str(tmp_path))
    monkeypatch.setattr(touchid, "is_available", lambda: False)

    store = ApprovalStore.load()
    ap = store.issue("Bash", {"command": "echo hi"})

    result = CliRunner().invoke(app, ["approve", ap.token, "--no-biometric"])
    assert result.exit_code == 0, "explicit --no-biometric opt-in should approve"

    reloaded = ApprovalStore.load()
    assert reloaded.approvals[ap.token].approved_at, "token should be approved"


def test_issued_token_never_starts_with_dash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leading-dash token is unpassable as a CLI argument (parsed as an
    option flag), so issue() must re-draw past base64url's '-' prefix."""
    import nota.approvals as approvals_mod

    monkeypatch.setenv("NOTA_HOME", str(tmp_path))
    draws = iter(["-dashfirst", "-alsodash", "cleantoken"])
    monkeypatch.setattr(approvals_mod.secrets, "token_urlsafe", lambda n: next(draws))

    store = ApprovalStore.load()
    ap = store.issue("Bash", {"command": "echo hi"})
    assert ap.token == "cleantoken"


def test_args_digest_stable_across_orderings() -> None:
    a = {"path": "/x", "encoding": "utf-8"}
    b = {"encoding": "utf-8", "path": "/x"}
    assert args_digest(a) == args_digest(b)


def test_args_digest_changes_on_value_diff() -> None:
    assert args_digest({"path": "/x"}) != args_digest({"path": "/y"})


def test_issue_then_approve_then_consume_flips_state(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "rm -rf node_modules"})
    store.approve(ap.token)
    consumed = store.consume("Bash", {"command": "rm -rf node_modules"})
    assert consumed is not None
    assert consumed.consumed_at != ""
    # second consume of the same call returns None - single-shot.
    again = store.consume("Bash", {"command": "rm -rf node_modules"})
    assert again is None


def test_issue_without_approve_is_not_consumable(tmp_path: Path) -> None:
    """SECURITY: the gate auto-issues a token on every block so the
    notification can offer `nota approve`. That token MUST NOT release the
    call on its own - otherwise a denied command auto-allows its own retry,
    defeating the gate against any agent that simply tries again.

    Regression for the issuance==approval bug found 2026-06-10.
    """
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    store.issue("Bash", {"command": "rm -rf /"})
    # No approve() step - the operator never confirmed.
    assert store.consume("Bash", {"command": "rm -rf /"}) is None
    # Still listable as pending (awaiting approval), just not consumable.
    assert len(store.active()) == 1
    assert not store.active()[0].is_consumable


def test_consume_rejects_different_args(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "rm -rf node_modules"})
    store.approve(ap.token)
    # Same tool, different command - must NOT match.
    consumed = store.consume("Bash", {"command": "rm -rf /"})
    assert consumed is None


def test_consume_rejects_different_tool(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "x"})
    store.approve(ap.token)
    consumed = store.consume("Edit", {"command": "x"})
    assert consumed is None


def test_expired_approval_is_inactive(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "ls"}, ttl_seconds=1)
    # force expiry
    ap.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    store.save()
    consumed = store.consume("Bash", {"command": "ls"})
    assert consumed is None
    # Active list excludes expired.
    assert store.active() == []


def test_revoke_drops_token(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "ls"})
    store.approve(ap.token)  # approved → would be consumable but for revoke
    assert store.revoke(ap.token) is True
    assert store.consume("Bash", {"command": "ls"}) is None


def test_persistence_across_reload(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    s1 = ApprovalStore(path=p)
    ap = s1.issue("Bash", {"command": "rm -rf x"})
    s1.approve(ap.token)  # approval must persist across reload
    s2 = ApprovalStore.load(path=p)
    consumed = s2.consume("Bash", {"command": "rm -rf x"})
    assert consumed is not None


def test_default_ttl_is_ten_minutes(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "x"})
    delta = datetime.fromisoformat(ap.expires_at) - datetime.fromisoformat(ap.issued_at)
    assert abs(delta.total_seconds() - DEFAULT_TTL_SECONDS) < 5  # ±5s tolerance


def test_approve_returns_active_token(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "x"})
    confirmed = store.approve(ap.token)
    assert confirmed is not None
    assert confirmed.token == ap.token


def test_approve_returns_none_for_unknown_token(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    assert store.approve("does-not-exist") is None


def test_active_excludes_consumed(tmp_path: Path) -> None:
    p = tmp_path / "approvals.json"
    store = ApprovalStore(path=p)
    ap = store.issue("Bash", {"command": "x"})
    store.approve(ap.token)
    store.consume("Bash", {"command": "x"})
    assert store.active() == []
