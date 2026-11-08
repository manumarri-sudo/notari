"""A superseding review on page two must participate in authorization."""

import json
import urllib.error

import pytest

from notari import github_review as gh


class Response:
    def __init__(self, data):
        self.data = data
        self.headers = {"Link": '<https://untrusted.invalid/reviews?page=2>; rel="next"'}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.data).encode()


def test_later_page_revocation_overrides_old_approval(monkeypatch) -> None:
    head = "a" * 40
    first = [{"user": {"login": "alice"}, "state": "APPROVED", "commit_id": head}]
    first.extend(
        {"user": {"login": "commenter"}, "state": "COMMENTED", "commit_id": head} for _ in range(99)
    )
    second = [{"user": {"login": "alice"}, "state": "CHANGES_REQUESTED", "commit_id": head}]
    requested = []

    def urlopen(request, **_):
        requested.append(request.full_url)
        return Response(second if "page=2" in request.full_url else first)

    monkeypatch.setattr(gh.urllib.request, "urlopen", urlopen)
    reviews = gh.fetch_reviews("owner", "repo", 1, "test-token")
    result = gh.evaluate_approval(
        reviews, head_sha=head, pr_author="agent", allowed_reviewers=["alice"]
    )
    assert len(requested) == 2
    assert not result.approved, "an earlier approval survived a later-page revocation"


def test_pagination_stays_on_configured_api_root(monkeypatch) -> None:
    requested = []

    def urlopen(request, **_):
        requested.append(request.full_url)
        assert request.get_header("Authorization") == "Bearer test-token"
        return Response([{}] * 100 if len(requested) == 1 else [])

    monkeypatch.setattr(gh.urllib.request, "urlopen", urlopen)
    gh.fetch_reviews(
        "owner", "repo", 1, "test-token", api_root="https://enterprise.invalid/api/v3/"
    )
    assert requested == [
        "https://enterprise.invalid/api/v3/repos/owner/repo/pulls/1/reviews?per_page=100&page=1",
        "https://enterprise.invalid/api/v3/repos/owner/repo/pulls/1/reviews?per_page=100&page=2",
    ]


@pytest.mark.parametrize("failure", ["network", "invalid-json", "invalid-shape"])
def test_later_page_failure_never_returns_partial_approval(monkeypatch, failure) -> None:
    requested = []

    def urlopen(request, **_):
        requested.append(request.full_url)
        if len(requested) == 1:
            return Response(
                [{"user": {"login": "alice"}, "state": "APPROVED", "commit_id": "a" * 40}]
                + [{}] * 99
            )
        if failure == "network":
            raise urllib.error.URLError("later page unavailable")
        if failure == "invalid-shape":
            return Response({"message": "not a review page"})
        response = Response([])
        response.read = lambda: b"not json"
        return response

    monkeypatch.setattr(gh.urllib.request, "urlopen", urlopen)
    with pytest.raises(gh.GitHubReviewError, match="page 2"):
        gh.check_pr_approval(
            owner="owner",
            repo="repo",
            pr_number=1,
            head_sha="a" * 40,
            pr_author="agent",
            token="test-token",
            allowed_reviewers=["alice"],
        )
    assert len(requested) == 2


def test_full_page_at_request_cap_fails_closed(monkeypatch) -> None:
    requested = []

    def urlopen(request, **_):
        requested.append(request.full_url)
        return Response([{}] * 100)

    monkeypatch.setattr(gh, "MAX_REVIEW_PAGES", 2)
    monkeypatch.setattr(gh.urllib.request, "urlopen", urlopen)
    with pytest.raises(gh.GitHubReviewError, match="refusing incomplete history"):
        gh.fetch_reviews("owner", "repo", 1, "test-token")
    assert len(requested) == 2
