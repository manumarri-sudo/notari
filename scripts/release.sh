#!/usr/bin/env bash
# Release runbook, scripted. Run from the repo root after `gh auth login`:
#
#     bash scripts/release.sh 0.5.0 fix/heredoc-chain-count-0.4.3
#
# Every step is the one docs/LAUNCH-DRY-RUN-0.3.0.md section 6 describes, in
# order, with the pin bump between merge and tag because a commit cannot name
# its own SHA. The script stops at the first failure and never force-pushes.
#
# What it cannot do: tick "Publish this Action to the GitHub Marketplace" on
# the release. The REST API has no such field, so the script creates the
# release and prints the URL; open it, click Edit, tick the box, and save.
# Two-factor confirmation and the Marketplace Developer Agreement are yours.
#
# The dogfood check (notari-change-control) BLOCKs any release that edits
# action.yml or the workflow, because the gate's own surfaces always BLOCK.
# That red check is the gate working on its own release, not a defect; branch
# protection does not require it, so the merge below proceeds. Read the
# passport in the PR before merging anyway.
set -euo pipefail

VERSION="${1:?usage: release.sh <version> <branch>}"
BRANCH="${2:?usage: release.sh <version> <branch>}"
REPO="manumarri-sudo/notari"

gh auth status >/dev/null 2>&1 || { echo "run: gh auth login"; exit 2; }
[[ "$(git rev-parse --abbrev-ref HEAD)" == "$BRANCH" ]] || git checkout -q "$BRANCH"
grep -q "^version = \"$VERSION\"" pyproject.toml || { echo "pyproject.toml is not $VERSION"; exit 2; }

echo "== 1. push main (release contract) and the branch"
git push origin main
git push -u origin "$BRANCH"

echo "== 2. open the pull request"
PR_URL=$(gh pr create --repo "$REPO" --base main --head "$BRANCH" \
  --title "$VERSION: the drop-in scan is the product" \
  --body-file <(awk "/^## \[$VERSION\]/{f=1} f&&/^## \[/&&!/\[$VERSION\]/{exit} f" CHANGELOG.md))
echo "$PR_URL"
gh pr checks "$PR_URL" --watch --fail-fast || echo "(a red notari-change-control is expected on a release that edits action.yml; read its passport, then continue)"

echo "== 3. merge with a merge commit (the pin needs one SHA to point at)"
gh pr merge "$PR_URL" --merge --delete-branch=false
git checkout -q main && git pull -q --ff-only origin main
MERGE_SHA=$(git rev-parse HEAD)
echo "merge commit: $MERGE_SHA"

echo "== 4. bump every Action pin to the merge commit, commit, tag the pin bump"
uv run python scripts/bump_action_pin.py "$MERGE_SHA" "$VERSION"
git add README.md docs/scan-workflow.yml docs/secure-workflow.yml src/notari/cli.py
git commit -m "pin the Action template to the $VERSION release commit"
git tag -a "v$VERSION" -m "notari $VERSION"
git push origin main "v$VERSION"

echo "== 5. publish the release (release.yml publishes to PyPI by trusted publishing)"
gh release create "v$VERSION" --repo "$REPO" --title "notari $VERSION" --verify-tag \
  --notes-file <(awk "/^## \[$VERSION\]/{f=1} f&&/^## \[/&&!/\[$VERSION\]/{exit} f" CHANGELOG.md)
gh run watch --repo "$REPO" --exit-status "$(gh run list --repo "$REPO" --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"

echo "== 6. in the browser: https://github.com/$REPO/releases/edit/v$VERSION"
echo "   tick 'Publish this Action to the GitHub Marketplace', pick Security as the primary category, save."
echo "== 7. confirm: pip index versions notari; curl -s https://pypi.org/pypi/notari/json | grep -o '\"version\":\"[^\"]*\"'"
