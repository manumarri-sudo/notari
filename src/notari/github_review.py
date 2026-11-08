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

from notari.errors import NotariError

API_ROOT = "https://api.github.com"
APPROVED = "APPROVED"
REVIEWS_PER_PAGE = 100
MAX_REVIEW_PAGES = 100


class GitHubReviewError(NotariError):
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
    """Fetch complete oldest-first review history, or fail without authorizing.

    Later pages can revoke an earlier approval. Build each page URL from the
    configured API root instead of forwarding the token to a response's Link URL.
    A full final page at the finite request limit leaves completeness unknown,
    so it must fail closed rather than return a potentially stale approval.
    """
    endpoint = f"{api_root.rstrip('/')}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    reviews: list[dict[str, Any]] = []
    for page in range(1, MAX_REVIEW_PAGES + 1):
        req = urllib.request.Request(f"{endpoint}?per_page={REVIEWS_PER_PAGE}&page={page}")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as e:
            msg = f"cannot fetch PR reviews page {page}: {e}"
            raise GitHubReviewError(msg) from e
        if not isinstance(data, list) or any(not isinstance(review, dict) for review in data):
            msg = f"unexpected reviews payload on page {page}: expected a list of review objects"
            raise GitHubReviewError(msg)
        reviews.extend(data)
        if len(data) < REVIEWS_PER_PAGE:
            return reviews
    msg = f"PR review history exceeds {MAX_REVIEW_PAGES} pages; refusing incomplete history"
    raise GitHubReviewError(msg)


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
