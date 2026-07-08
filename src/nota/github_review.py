"""GitHub PR-review provenance: the human clicks Approve, the agent can't.

The signed perimeter (``perimeter`` + ``provenance``) is one root of trust. This
is the other, for teams who'd rather use GitHub's own review system than manage
keys: require that a *human who is not the PR author* has submitted an APPROVED
review **on the current head commit**. An agent opening a PR with its own token
cannot approve its own PR, and an approval is dismissed the moment a new commit
is pushed - so this can't be replayed against code the human never saw.

The decision is a pure function over the reviews list (``evaluate_approval``),
so it is fully testable without the network. ``fetch_reviews`` is the only part
that talks to GitHub, via the stdlib (no new dependency), and is injected so
tests never hit the wire. This lives OUTSIDE ``verify`` on purpose: ``verify``
is deterministic and network-free, and the Action calls this check alongside it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from nota.errors import NotaError

API_ROOT = "https://api.github.com"
APPROVED = "APPROVED"


class GitHubReviewError(NotaError):
    """Raised when the reviews API cannot be reached or parsed."""


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    approver: str | None  # the human whose approval counted
    detail: str


def evaluate_approval(
    reviews: Sequence[dict[str, Any]],
    *,
    head_sha: str,
    pr_author: str,
    allowed_reviewers: Sequence[str] | None = None,
) -> ApprovalResult:
    """Pure decision: is there a fresh, human, non-author APPROVED review?

    Rules (each closes a bypass):
      * Only the *latest* review per user counts (GitHub keeps history; an old
        APPROVED followed by a later CHANGES_REQUESTED must not pass).
      * The approver must not be the PR author (no self-approval).
      * The approval must be on ``head_sha`` (a stale approval from before the
        agent pushed new commits does not count - the human never saw this code).
      * If ``allowed_reviewers`` is given, the approver must be in it.
    """
    latest: dict[str, dict[str, Any]] = {}
    for r in reviews:
        user = (r.get("user") or {}).get("login")
        if not user:
            continue
        # reviews arrive oldest-first; later entries overwrite earlier ones.
        latest[user] = r

    allow = {u.lower() for u in allowed_reviewers} if allowed_reviewers else None
    for user, r in latest.items():
        if r.get("state") != APPROVED:
            continue
        if user.lower() == pr_author.lower():
            continue
        if allow is not None and user.lower() not in allow:
            continue
        if r.get("commit_id") != head_sha:
            continue
        return ApprovalResult(True, user, f"approved by {user} on {head_sha[:12]}")

    if not latest:
        return ApprovalResult(False, None, "no reviews on this pull request")
    stale = any(
        r.get("state") == APPROVED
        and (r.get("user") or {}).get("login", "").lower() != pr_author.lower()
        for r in latest.values()
    )
    if stale:
        return ApprovalResult(
            False, None, "an approval exists but not on the current head commit (stale)"
        )
    return ApprovalResult(False, None, "no human (non-author) approval on the current head commit")


def fetch_reviews(
    owner: str, repo: str, pr_number: int, token: str, *, api_root: str = API_ROOT
) -> list[dict[str, Any]]:
    """GET the reviews for a PR via the GitHub REST API (stdlib only)."""
    url = f"{api_root}/repos/{owner}/{repo}/pulls/{pr_number}/reviews?per_page=100"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        msg = f"cannot fetch PR reviews: {e}"
        raise GitHubReviewError(msg) from e
    if not isinstance(data, list):
        msg = f"unexpected reviews payload: {type(data).__name__}"
        raise GitHubReviewError(msg)
    return data


def check_pr_approval(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    pr_author: str,
    token: str,
    allowed_reviewers: Sequence[str] | None = None,
    fetch: Callable[..., list[dict[str, Any]]] = fetch_reviews,
) -> ApprovalResult:
    """Fetch reviews and evaluate them. `fetch` is injectable for tests."""
    reviews = fetch(owner, repo, pr_number, token)
    return evaluate_approval(
        reviews, head_sha=head_sha, pr_author=pr_author, allowed_reviewers=allowed_reviewers
    )
