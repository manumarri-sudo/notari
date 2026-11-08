#!/usr/bin/env bash
# Release through two CI-checked pull requests. The workflow pin points to the
# release merge commit, so the pin update follows the first merge.
set -euo pipefail

VERSION="${1:?usage: release.sh <version> <branch>}"
BRANCH="${2:?usage: release.sh <version> <branch>}"
REPO="manumarri-sudo/notari"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ -z "$(git status --porcelain)" ]]
gh auth status >/dev/null 2>&1
git switch "$BRANCH"
grep -Fxq "version = \"$VERSION\"" pyproject.toml

wait_for_ci() {
  local sha=$1 event=$2 run attempt
  for attempt in {1..30}; do
    run=$(gh run list --repo "$REPO" --workflow ci.yml --event "$event" --commit "$sha" \
      --limit 1 --json databaseId --jq '.[0].databaseId // empty')
    if [[ -n "$run" ]]; then
      gh run watch --repo "$REPO" --exit-status "$run" >&2
      return
    fi
    sleep 5
  done
  echo "No ci run for $sha ($event)." >&2
  return 1
}

merge_checked_pr() {
  local pr=$1 sha=$2
  wait_for_ci "$sha" pull_request
  gh pr merge "$pr" --repo "$REPO" --merge --match-head-commit "$sha" >&2
  gh pr view "$pr" --repo "$REPO" --json mergeCommit --jq .mergeCommit.oid
}

notes=$(mktemp)
trap 'rm -f "$notes"' EXIT
awk -v version="$VERSION" '
  index($0, "## [" version "]") == 1 { found=1; next }
  /^## \[/ && found { exit }
  found { print }
' CHANGELOG.md > "$notes"
test -s "$notes"

git push -u origin "HEAD:refs/heads/$BRANCH"
release_sha=$(git rev-parse HEAD)
release_pr=$(gh pr create --repo "$REPO" --base main --head "$BRANCH" \
  --title "Release Notari $VERSION" --body-file "$notes")
merge_sha=$(merge_checked_pr "$release_pr" "$release_sha")
git fetch --no-tags origin main
test "$(git rev-parse FETCH_HEAD)" = "$merge_sha"

pin_branch="release/pin-$VERSION"
git switch -c "$pin_branch" "$merge_sha"
python3 scripts/bump_action_pin.py "$merge_sha" "$VERSION"
git add docs/scan-workflow.yml docs/secure-workflow.yml src/notari/cli.py
git commit -m "Pin workflow templates to Notari $VERSION"
git push -u origin "$pin_branch"
pin_pr=$(gh pr create --repo "$REPO" --base main --head "$pin_branch" \
  --title "Pin workflow templates to Notari $VERSION" \
  --body "Pin the shipped Action to the reviewed release merge commit.")
tag_commit=$(merge_checked_pr "$pin_pr" "$(git rev-parse HEAD)")
git fetch --no-tags origin main
test "$(git rev-parse FETCH_HEAD)" = "$tag_commit"
wait_for_ci "$tag_commit" push

git tag -a "v$VERSION" "$tag_commit" -m "Notari $VERSION"
git push origin "refs/tags/v$VERSION"
gh release create "v$VERSION" --repo "$REPO" --title "Notari $VERSION" \
  --verify-tag --notes-file "$notes"
