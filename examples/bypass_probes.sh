#!/usr/bin/env bash
#
# Adversarial probe suite: twelve ways to try to sneak a change past the gate.
#
# Each probe builds a throwaway repository, signs a real perimeter and contract
# with a freshly generated approver key, commits a candidate change, and prints
# the verdict `notari verify --strict` returns. Nothing here is mocked: these are
# the same code paths CI runs.
#
#   bash examples/bypass_probes.sh            # verdict table
#   VERBOSE=1 bash examples/bypass_probes.sh  # full verifier output per probe
#
# Expected result as of 0.4.0: eleven BLOCK, and probe 10 PASSes because secret
# detection is line-based and a credential split across two lines is a
# documented limit (docs/SECURITY-MODEL.md). If you find a thirteenth shape that
# gets an undeserved PASS, that is the most useful bug report this project can
# receive: https://github.com/manumarri-sudo/notari/issues
#
# Test credentials are assembled from fragments at runtime so no literal key
# sits in the file (Notari's own gate blocks writing one, which is the point).
set -uo pipefail

NOTARI="${NOTARI:-notari}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/notari-probe.XXXXXX")"
KEYDIR="$WORK/keys"
mkdir -p "$KEYDIR"

"$NOTARI" keygen --out "$KEYDIR/approver.pem" >/dev/null 2>&1
NOTARI_APPROVER_PUBKEYS="$(cat "$KEYDIR/approver.pem.pub")"
export NOTARI_APPROVER_PUBKEYS
export NOTARI_REPO_ID="probe/repo"
export GITHUB_REPOSITORY="probe/repo"

# AWS's own documentation example key, in fragments.
FAKE_ID="AKIA""IOSFODNN7""EXAMPLE"
FAKE_SECRET="wJalrXUtnFEMI/""K7MDENG/bPxRfiCY""EXAMPLEKEY"

# Build a repo whose BASE commit already carries the signed perimeter, which is
# how a real deployment looks: the boundary is established before the work
# starts, so it is not part of the diff under review.
new_repo() {
  local name="$1" scope="$2" r="$WORK/$1"
  mkdir -p "$r/src/auth" "$r/migrations"
  cd "$r" || exit 1
  git init -q .
  git config user.email probe@example.com
  git config user.name probe
  echo "ok" > src/auth/login.py
  echo "base" > migrations/0001.sql
  echo "readme" > README.md
  git add -A >/dev/null; git commit -qm base >/dev/null
  "$NOTARI" guard --key "$KEYDIR/approver.pem" --allow "src/**" --forbid "migrations/**" >/dev/null 2>&1
  git add -A >/dev/null; git commit -qm "signed perimeter" >/dev/null
  if [[ -n "$scope" ]]; then
    "$NOTARI" begin "probe task" --scope "$scope" --repo probe/repo --key "$KEYDIR/approver.pem" >/dev/null 2>&1
  else
    "$NOTARI" begin "probe task" --repo probe/repo --key "$KEYDIR/approver.pem" >/dev/null 2>&1
  fi
  git add -A >/dev/null; git commit -qm "signed contract" >/dev/null
}

run_verify() {
  local label="$1" out rc verdict
  out="$("$NOTARI" verify --strict --passport-dir "$PWD/.probe-out" 2>&1)"
  rc=$?
  verdict="$(grep -oE 'PASS|NEEDS_REVIEW|BLOCK' <<<"$out" | head -1)"
  printf '%-46s => %-13s (exit %s)\n' "$label" "${verdict:-NO-VERDICT}" "$rc"
  [[ "${VERBOSE:-0}" == "1" ]] && printf '%s\n---\n' "$out"
  return 0
}

new_repo p1 "src/auth/**"
echo "tampered" >> migrations/0001.sql
git add -A >/dev/null; git commit -qm change >/dev/null
run_verify "1. edit a forbidden path"

new_repo p2 "src/auth/**"
git mv src/auth/login.py migrations/login.py >/dev/null
git add -A >/dev/null; git commit -qm rename >/dev/null
run_verify "2. rename in-scope file into forbidden path"

new_repo p3 "src/auth/**"
chmod +x migrations/0001.sql
git add -A >/dev/null; git commit -qm chmod >/dev/null
run_verify "3. mode-only change, no content diff"

new_repo p4 "src/**"
ln -s ../../migrations src/auth/link
git add -A >/dev/null; git commit -qm symlink >/dev/null
run_verify "4. symlink from scope into forbidden dir"

new_repo p5 "src/**"
printf 'src/auth/creds.py -diff\n' > .gitattributes
printf 'AWS="%s"\nk="%s"\n' "$FAKE_ID" "$FAKE_SECRET" > src/auth/creds.py
git add -A >/dev/null; git commit -qm secret >/dev/null
run_verify "5. secret hidden behind .gitattributes -diff"

new_repo p6 ""
echo "x" >> README.md
git add -A >/dev/null; git commit -qm readme >/dev/null
run_verify "6. contract with NO scope, edits outside perimeter"

new_repo p7 ""
echo "x" >> migrations/0001.sql
git add -A >/dev/null; git commit -qm mig >/dev/null
run_verify "7. contract with NO scope, edits forbidden path"

new_repo p8 "src/**"
mkdir -p MIGRATIONS && echo "x" > MIGRATIONS/evil.sql
git add -A >/dev/null; git commit -qm case >/dev/null
run_verify "8. case variant of a forbidden directory"

new_repo p9 "src/**"
mkdir -p .github/workflows && echo "on: push" > .github/workflows/ci.yml
git add -A >/dev/null; git commit -qm wf >/dev/null
run_verify "9. edit the workflow that runs the gate"

new_repo p10 "src/**"
printf 'a="AKIA"\nb="IOSFODNN7EXAMPLE"\n' > src/auth/split.py
git add -A >/dev/null; git commit -qm split >/dev/null
run_verify "10. secret split across two lines (known limit)"

new_repo p11 "src/**"
printf '[submodule "x"]\n\tpath = src/x\n\turl = https://example.com/x.git\n' > .gitmodules
git add -A >/dev/null; git commit -qm sub >/dev/null
run_verify "11. add a submodule pointer"

new_repo p12 "src/auth/**"
python3 -I "$HERE/_widen_contract.py" "$PWD/.notari/contract.json"
echo "tampered" >> migrations/0001.sql
git add -A >/dev/null; git commit -qm widen >/dev/null
run_verify "12. agent widens its own signed contract"

echo
echo "probe repos left at: $WORK"
