"""Tests for GitHub PR-review provenance (pure decision, no network)."""

from __future__ import annotations

from typing import Any

from quill import github_review as gh

HEAD = "deadbeef" * 5  # 40-char sha


def _review(user: str, state: str, commit: str = HEAD) -> dict[str, Any]:
    return {"user": {"login": user}, "state": state, "commit_id": commit}


def test_human_approval_on_head_passes() -> None:
    r = gh.evaluate_approval([_review("alice", "APPROVED")], head_sha=HEAD, pr_author="agent-bot")
    assert r.approved is True
    assert r.approver == "alice"


def test_self_approval_does_not_count() -> None:
    """The author (an agent) approving its own PR is ignored."""
    r = gh.evaluate_approval(
        [_review("agent-bot", "APPROVED")], head_sha=HEAD, pr_author="agent-bot"
    )
    assert r.approved is False


def test_stale_approval_before_new_push_does_not_count() -> None:
    """Approval on an old commit must not authorize newly pushed code."""
    r = gh.evaluate_approval(
        [_review("alice", "APPROVED", commit="0" * 40)], head_sha=HEAD, pr_author="agent-bot"
    )
    assert r.approved is False
    assert "stale" in r.detail


def test_latest_review_wins_changes_requested_after_approval() -> None:
    reviews = [
        _review("alice", "APPROVED"),
        _review("alice", "CHANGES_REQUESTED"),  # later -> overrides
    ]
    r = gh.evaluate_approval(reviews, head_sha=HEAD, pr_author="agent-bot")
    assert r.approved is False


def test_latest_review_wins_approval_after_changes() -> None:
    reviews = [
        _review("alice", "CHANGES_REQUESTED"),
        _review("alice", "APPROVED"),  # later -> approval stands
    ]
    r = gh.evaluate_approval(reviews, head_sha=HEAD, pr_author="agent-bot")
    assert r.approved is True


def test_allowed_reviewers_enforced() -> None:
    reviews = [_review("random-person", "APPROVED")]
    r = gh.evaluate_approval(
        reviews, head_sha=HEAD, pr_author="agent-bot", allowed_reviewers=["alice", "bob"]
    )
    assert r.approved is False


def test_allowed_reviewer_in_set_passes() -> None:
    reviews = [_review("Bob", "APPROVED")]
    r = gh.evaluate_approval(
        reviews, head_sha=HEAD, pr_author="agent-bot", allowed_reviewers=["alice", "bob"]
    )
    assert r.approved is True


def test_no_reviews() -> None:
    r = gh.evaluate_approval([], head_sha=HEAD, pr_author="agent-bot")
    assert r.approved is False
    assert "no reviews" in r.detail


def test_check_pr_approval_with_injected_fetch() -> None:
    def fake_fetch(owner: str, repo: str, pr: int, token: str) -> list[dict[str, Any]]:
        assert (owner, repo, pr, token) == ("o", "r", 7, "tok")
        return [_review("alice", "APPROVED")]

    r = gh.check_pr_approval(
        owner="o",
        repo="r",
        pr_number=7,
        head_sha=HEAD,
        pr_author="agent-bot",
        token="tok",
        fetch=fake_fetch,
    )
    assert r.approved is True
