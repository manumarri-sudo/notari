#!/usr/bin/env bash
#
# Notari Change Control - GitHub Action wrapper.
#
# Runs `notari verify`, turns the Change Passport into a PR-visible summary +
# commit Status Check, exposes the verdict as a step output, and exits 0 for
# PASS / NEEDS_REVIEW or 1 for BLOCK so the job gates the merge.
#
# Fail-closed design (security re-review P0-3): the verdict is read ONLY from a
# passport this run wrote into a fresh temp dir, never from the repo working
# tree, so a passport committed into the PR (or left over from a prior step)
# can never be mistaken for a real verdict. Any unexpected verifier exit, a
# missing/malformed passport, an unrecognised verdict, or (when a gate public
# key is configured) a passport whose signature does not verify, all fail the
# job rather than letting the merge through.
#
# Inputs (environment):
#   NOTARI_HEAD          ref to verify against the contract base (default HEAD)
#   NOTARI_PASSPORT_DIR  where the published passport.{json,md} are copied
#                       (default .notari); the verdict is NOT trusted from here
#   NOTARI_STRICT        "true" (default) requires a signed perimeter + contract
#   NOTARI_FAIL_ON_BLOCK "true" to exit 1 on BLOCK (default true)
#   NOTARI_BLOCK_ON_REVIEW "true" treats NEEDS_REVIEW as BLOCK for the Status
#                       Check state + job exit (default false). The passport
#                       verdict itself is left unchanged.
#   NOTARI_GATE_PUBKEYS  trusted gate PUBLIC key(s) (PEM/paths). When set, the
#                       passport signature MUST verify or the job fails closed.
#   NOTARI_HEAD_SHA      commit SHA to attach the Status Check to (default: git HEAD)
#   GITHUB_TOKEN        token for the Status Check + PR comment (optional)
#   GITHUB_REPOSITORY   owner/repo (provided by Actions)
#   GITHUB_OUTPUT       step-output file (provided by Actions)
#   GITHUB_STEP_SUMMARY job-summary file (provided by Actions)
#
set -euo pipefail

# Prevent candidate-controlled Python modules (pip.py, json.py, etc.) in the
# checkout from shadowing trusted imports. This wrapper runs with cwd inside the
# candidate checkout, so the inline `python3 -I -c` calls below use isolated mode
# (available since Python 3.4) to drop cwd from sys.path, this does NOT depend on
# the interpreter version. PYTHONSAFEPATH (Python 3.11+) is exported too as
# defense-in-depth, but -I is the load-bearing control on older runners.
export PYTHONSAFEPATH=1

PUBLISH_DIR="${NOTARI_PASSPORT_DIR:-.notari}"
FAIL_ON_BLOCK="${NOTARI_FAIL_ON_BLOCK:-true}"
STATUS_CONTEXT="notari/change-control"

# Evaluate the SAME commit the Status Check reports against, so the evaluated
# candidate, the passport, and the published status all describe one SHA
# (security review H-6: evaluated ref and status SHA could diverge). Prefer the
# explicit candidate SHA; fall back to NOTARI_HEAD, then HEAD.
# Validate explicit SHA inputs against hex pattern to prevent option injection.
if [[ -n "${NOTARI_HEAD_SHA:-}" ]] && ! [[ "$NOTARI_HEAD_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "::error::NOTARI_HEAD_SHA is not a valid 40-hex SHA: '${NOTARI_HEAD_SHA}'"
  exit 2
fi
EVAL_REF="${NOTARI_HEAD_SHA:-${NOTARI_HEAD:-HEAD}}"

# --strict (default on) requires a signed perimeter AND signed contract from a
# trusted approver, so an unsigned / tampered / absent boundary BLOCKs rather
# than silently passing.
STRICT_FLAG=""
if [[ "${NOTARI_STRICT:-true}" == "true" ]]; then
  STRICT_FLAG="--strict"
fi

# Strict mode must not expose switches that silently degrade it to cooperative
# behavior. fail-on-block=false would let a literal BLOCK return success, which
# is incompatible with an enforced boundary (security review M-3).
if [[ -n "$STRICT_FLAG" && "$FAIL_ON_BLOCK" != "true" ]]; then
  echo "::error::strict mode cannot run with fail-on-block=false (a BLOCK must fail the job)."
  exit 2
fi

# Workflow impersonation guard (C-1). Under the 'pull_request' event GitHub runs
# the PR's version of the workflow, so a PR can remove or replace this step and
# the gate never fires. 'pull_request_target' runs from the base branch and is
# immune. In strict mode this is a hard error unless explicitly opted out,
# because the entire trust spine is bypassed if the workflow is candidate-controlled.
if [[ -n "$STRICT_FLAG" && "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  if [[ "${NOTARI_ALLOW_PULL_REQUEST_TRIGGER:-false}" != "true" ]]; then
    echo "::error::strict mode requires pull_request_target (not pull_request). The pull_request event runs the PR's workflow, so a PR can remove Notari entirely. See docs/SECURITY-MODEL.md for the secure template. Set NOTARI_ALLOW_PULL_REQUEST_TRIGGER=true to override (NOT recommended)."
    exit 2
  else
    echo "::warning::running under pull_request with NOTARI_ALLOW_PULL_REQUEST_TRIGGER=true, the caller workflow is candidate-controlled. A PR can remove this step."
  fi
fi

# A private temp dir we own: the verifier writes here, and the verdict is read
# back ONLY from here. Nothing in the repo tree can influence the decision.
#
# WORK is declared and the trap is installed BEFORE mktemp runs. Creating the temp
# dir first left a window where a failure (an unwritable TMPDIR, for instance)
# aborted with exit 1 and NO trap coverage: no "::error::", no fallback summary,
# and an exit code indistinguishable from a BLOCK verdict.
WORK=""
cleanup() { [[ -n "$WORK" ]] && rm -rf "$WORK"; return 0; }

# Evidence-emission state, read by the EXIT trap. `set -e` aborts with the
# failing command's status, which is normally 1, and 1 is exactly what this
# script uses to mean "the gate says BLOCK", so without normalising, a crash is
# indistinguishable from a refusal. Every deliberate fail-closed path here
# already exits 2, so the trap maps any OTHER nonzero abort onto 2 as well and
# says so, rather than letting a broken gate impersonate a reviewed decision.
EVIDENCE_EMITTED=0
VERDICT_EXIT=0

on_exit() {
  local rc=$? # capture FIRST; every command below clobbers $?
  cleanup
  if [[ "$rc" -ne 0 && "$rc" -ne 2 && "$VERDICT_EXIT" != "1" ]]; then
    echo "::error::notari wrapper aborted before publishing a verdict (rc=$rc); failing closed"
    if [[ "$EVIDENCE_EMITTED" != "1" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      printf '## Notari: the gate did not complete\n\nThe wrapper aborted (rc=%s) before it could publish a verdict. This is a tooling failure, not a review decision, so do not read the missing check as approval.\n' \
        "$rc" >>"$GITHUB_STEP_SUMMARY" 2>/dev/null || true
    fi
    exit 2
  fi
  exit "$rc"
}
# INT / TERM / HUP as well as EXIT: an unhandled signal bypasses an EXIT trap
# entirely, so a cancelled or timed-out job produced no explanation at all. A
# candidate cannot usually signal the runner, so this is about runner-side
# cancellation rather than a forgeable verdict, but the trap's whole purpose is
# that an incomplete run says so.
trap on_exit EXIT INT TERM HUP

if ! WORK="$(mktemp -d "${TMPDIR:-/tmp}/notari.XXXXXX")"; then
  echo "::error::could not create a private temp dir (TMPDIR=${TMPDIR:-/tmp}); failing closed"
  exit 2
fi

# 1. Run the verifier into the temp dir. It exits 1 on BLOCK and 0 on
#    PASS/NEEDS_REVIEW; any OTHER exit is a crash / bad invocation. Capture the
#    real exit code without aborting so we can tell BLOCK apart from failure.
set +e
notari verify $STRICT_FLAG --head "$EVAL_REF" --passport-dir "$WORK" \
  >"$WORK/stdout" 2>"$WORK/stderr"
NOTARI_RC=$?
set -e

PASSPORT_JSON="$WORK/passport.json"
PASSPORT_MD="$WORK/passport.md"

# 2. Fail closed on any non-verdict exit. BLOCK is rc=1 WITH a passport; rc 0/1
#    are the only sanctioned codes. Anything else (or a missing passport) is an
#    error, never a pass.
if [[ "$NOTARI_RC" != "0" && "$NOTARI_RC" != "1" ]] || [[ ! -f "$PASSPORT_JSON" ]]; then
  echo "::error::notari verify failed to produce a verdict (rc=$NOTARI_RC)"
  cat "$WORK/stderr" 2>/dev/null || true
  exit 2
fi

# 3. Read the verdict + reasons from THIS run's passport only.
read_field() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$PASSPORT_JSON" "$1"
}
VERDICT="$(read_field verdict)"
EXIT_CODE="$(read_field exit_code)"
REASONS="$(python3 -I -c 'import json,sys; print("; ".join(json.load(open(sys.argv[1]))["reasons"]))' "$PASSPORT_JSON")"

# 3a. The verdict must be one Notari actually emits. A malformed / truncated /
#     hand-crafted passport that decodes to anything else fails closed.
case "$VERDICT" in
  PASS | NEEDS_REVIEW | BLOCK) ;;
  *)
    echo "::error::unrecognised verdict '$VERDICT' in passport; failing closed"
    exit 2
    ;;
esac

# 3a-bis. Process rc, passport verdict, and passport exit_code MUST agree. A
#     buggy, replaced, or supply-chain-substituted verifier could otherwise emit
#     contradictory evidence (e.g. process rc=1 but a PASS passport) and have the
#     wrapper select the favorable side. Bind the three together and fail closed
#     on any disagreement (security review: evidence-integrity inconsistency).
case "$VERDICT" in
  BLOCK) WANT_RC=1; WANT_EXIT=1 ;;
  *)     WANT_RC=0; WANT_EXIT=0 ;;
esac
if [[ "$NOTARI_RC" != "$WANT_RC" || "$EXIT_CODE" != "$WANT_EXIT" ]]; then
  echo "::error::inconsistent verdict evidence (process rc=$NOTARI_RC, verdict=$VERDICT, exit_code=$EXIT_CODE); failing closed"
  exit 2
fi

# 3b. If a gate public key is configured, the passport's signature MUST verify.
#     This binds the verdict to the off-box gate identity: a passport whose body
#     was edited (e.g. a flipped verdict) or signed by an untrusted key fails the
#     job. Without a configured pubkey we cannot check a signature, so we do not
#     pretend to - the deployment checklist calls for setting it in CI.
if [[ -n "${NOTARI_GATE_PUBKEYS:-}" ]]; then
  if ! notari verify-passport "$PASSPORT_JSON" >/dev/null 2>"$WORK/sig.err"; then
    echo "::error::passport signature did not verify against the trusted gate key"
    cat "$WORK/sig.err" 2>/dev/null || true
    exit 2
  fi
elif [[ -n "$STRICT_FLAG" ]]; then
  # Strict authenticates the contract/perimeter; an unsigned passport cannot be
  # re-verified independently of this repo, so strict-grade EVIDENCE requires a
  # gate key. This is mandatory by default (no silent downgrade); an operator who
  # wants report-grade evidence must opt out EXPLICITLY and visibly (security
  # review M-4 + "strict must not expose silent degrade switches").
  if [[ "${NOTARI_ALLOW_UNSIGNED_EVIDENCE:-false}" == "true" ]]; then
    echo "::warning::strict mode with NOTARI_ALLOW_UNSIGNED_EVIDENCE=true, the passport is UNSIGNED and cannot be independently re-verified."
  else
    echo "::error::strict mode requires a gate-signed passport. Set gate-key + gate-pubkeys, or set NOTARI_ALLOW_UNSIGNED_EVIDENCE=true to accept report-grade unsigned evidence."
    exit 2
  fi
fi

# 3c. Candidate binding: the passport must describe the SAME commit the Status
#     Check reports against, so evidence can't identify a different candidate
#     than the one being gated (security review H-6). In strict mode the passport
#     MUST contain a valid head_commit; an empty one bypasses the binding check.
HEAD_COMMIT="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("head_commit") or "")' "$PASSPORT_JSON")"
if [[ -n "$STRICT_FLAG" && -z "$HEAD_COMMIT" ]]; then
  echo "::error::strict mode requires the passport to contain a head_commit SHA; failing closed."
  exit 2
fi
# The passport head_commit must match the SHA used for the Status Check,
# regardless of whether NOTARI_HEAD_SHA was explicitly set. Resolve HEAD now
# so the binding is always checked (wrapper-scanner HIGH-1).
STATUS_SHA="${NOTARI_HEAD_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"
if [[ -n "$HEAD_COMMIT" && -n "$STATUS_SHA" && "$HEAD_COMMIT" != "$STATUS_SHA" ]]; then
  echo "::error::candidate mismatch: passport head_commit=$HEAD_COMMIT but status SHA=$STATUS_SHA; failing closed."
  exit 2
fi

# Passport fingerprint: the audit MAC binds the status check to THIS passport.
# A real Notari status carries it in the description; a spoofed "success" posted
# by an attacker-injected workflow cannot reproduce a MAC it never computed, so
# fake checks are detectable post-hoc (defense-in-depth against status-check
# spoofing, an evil PR workflow can still POST to the context, but it can't
# forge the fingerprint). Sanitize to hex-only so it can't carry an injection.
MAC="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("audit",{}).get("verification_run_mac",""))' "$PASSPORT_JSON")"
SAFE_MAC="$(printf '%s' "$MAC" | tr -cd '0-9a-fA-F')"

# Sanitize REASONS before echoing: strip CR/LF and leading :: to prevent
# Actions workflow-command injection from attacker-controlled passport data.
SAFE_REASONS="$(printf '%s' "$REASONS" | tr -d '\r\n' | sed 's/^:://')"
echo "Notari verdict: $VERDICT ($SAFE_REASONS)"

# 4. Publish the verified passport to the repo-visible dir for humans/tooling.
#    This is a copy of the artifact we already trusted, not the source of truth.
#
#    SECURITY (red-team 2026-07-22, finding 1): PUBLISH_DIR is inside the
#    candidate checkout (_pr_checkout/.notari), and .notari is excluded from
#    scope and symlink scanning, so a PR can commit a symlink here that a naive
#    `cp` / `>` would FOLLOW to overwrite a runner file OUTSIDE the checkout. We
#    refuse a symlinked publish dir, and replace any symlink AT each target with
#    a real file before writing, so the write lands in the intended directory
#    and can never be redirected out of it.
TREE_ROOT="$(pwd -P)"

# The publish is done by a small `python3 -I` helper rather than shell, because
# the shell version could not close the attack safely (security re-review
# 2026-07-23): a bare `[[ -L ]]` inspected only the leaf; `mkdir -p` followed a
# symlinked INTERMEDIATE component before any check; `mv -f` FOLLOWS a
# destination symlink-to-directory (moving our file outside the checkout instead
# of replacing the link, GNU needs `-T`); a check-then-write by pathname left a
# TOCTOU window; and `$(set +o)` captured `errexit` OFF (bash clears it in the
# command-substitution subshell), so restoring it silently disabled fail-fast.
#
# The helper walks the publish dir one component at a time using openat on held
# directory fds with O_NOFOLLOW|O_DIRECTORY, so a symlink at ANY component (leaf
# or ancestor) fails closed and no symlink is ever traversed, which also confines
# every write to the checkout without a separate containment check. It rejects
# absolute paths and `..`, writes to a temp file created O_EXCL|O_NOFOLLOW in the
# final dir fd, then renameat's it onto the destination, replacing any symlink
# there without following it. Race-free (all operations are relative to fds we
# hold, never re-resolved by pathname) and atomic. Only POSIX separators are
# treated as separators, so a directory legitimately named `a\b\c` is ONE
# component rather than three (runners here are Linux).
#
# `-I` is isolated mode: it drops cwd from sys.path and ignores PYTHONPATH and
# user site-packages. Note what it does NOT do: a hostile `os.py` in the checkout
# could not shadow `os` for this invocation either way, because CPython has
# already imported `os` into sys.modules before the `-c` body runs. The isolation
# earns its keep on PYTHONPATH and user site-packages, so keep it, but do not
# credit it with preventing a shadow it was never the barrier against.
NOTARI_SAFE_WRITE_PY='
import os, sys
tree_root, pub, name = sys.argv[1], sys.argv[2], sys.argv[3]
data = sys.stdin.buffer.read()
parts = [p for p in pub.split("/") if p not in ("", ".")]
if os.path.isabs(pub) or any(p == ".." for p in parts):
    sys.exit("notari: refusing unsafe publish dir %r" % pub)
if "/" in name or name in ("", ".", ".."):
    sys.exit("notari: refusing unsafe dest name %r" % name)
try:
    root_fd = os.open(tree_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as e:
    sys.exit("notari: cannot open tree root %r: %s" % (tree_root, e))
fds = [root_fd]
try:
    for comp in parts:
        try:
            os.mkdir(comp, 0o755, dir_fd=fds[-1])
        except FileExistsError:
            pass
        try:
            fds.append(os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        except OSError as e:
            sys.exit("notari: refusing to publish, %r is a symlink or not a directory (%s)" % (comp, e))
    ddfd = fds[-1]
    # Unguessable temp name, and no pre-unlink. The old name was the pid, so a
    # candidate who guessed it could pre-create `.notari.tmp.<pid>` as a
    # DIRECTORY: the pre-unlink caught only FileNotFoundError, so the resulting
    # error escaped and aborted the wrapper. O_EXCL (not name secrecy) is what
    # makes the create safe; randomness just removes the collision a candidate
    # could arrange.
    tmpname = ".notari.tmp.%s" % os.urandom(8).hex()
    try:
        wfd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=ddfd)
    except OSError as e:
        sys.exit("notari: cannot create a temp file in the publish dir (%s)" % e)
    try:
        with os.fdopen(wfd, "wb") as fh:
            fh.write(data)
        os.rename(tmpname, name, src_dir_fd=ddfd, dst_dir_fd=ddfd)
    except BaseException as e:
        try:
            os.unlink(tmpname, dir_fd=ddfd)
        except OSError:
            pass
        # A candidate-planted DIRECTORY at the destination makes rename raise
        # EISDIR. Report it as a refusal, not as an unhandled traceback: the
        # caller degrades this to a warning, and a traceback in the log reads as
        # broken tooling rather than as a hostile repo, which is what invites a
        # maintainer to override the gate.
        if isinstance(e, OSError):
            sys.exit("notari: cannot publish %r (%s)" % (name, e))
        raise
finally:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
'
notari_safe_put() { # $1=dest-basename; file CONTENT arrives on stdin
  python3 -I -c "$NOTARI_SAFE_WRITE_PY" "$TREE_ROOT" "$PUBLISH_DIR" "$1"
}
# Publishing is a convenience copy of an artifact we ALREADY trusted (the verdict
# was read from $WORK and validated in steps 2 to 3c), so a failure here must not
# abort the run: the candidate controls this directory, and a directory planted at
# the destination used to crash the helper under `set -e`, skipping every evidence
# channel below and leaving a real BLOCK visible to nobody but a traceback. Same
# `... || echo "::warning::"` idiom the Status Check POST already uses; `set -e` is
# suspended inside a `||` list, and the ecosystem convention (Trivy publishing its
# SARIF from an `if: always()` step) is this same separation of verdict from
# publication.
notari_safe_put passport.json <"$PASSPORT_JSON" ||
  echo "::warning::could not publish passport.json into $PUBLISH_DIR (verdict unaffected)"
# An `if` rather than a bare `[[ ... ]] && cmd` AND-list. This is legibility, not
# a bug fix: bash exempts every command of an AND-OR list except the last from
# `set -e`, and when the condition fails the list just yields 1 without exiting
# (verified: `set -e; [[ -f /nonexistent ]] && echo hi; echo SURVIVED` reaches
# SURVIVED). The `if` makes the guard explicit and leaves room for the `||`
# warning below.
if [[ -f "$PASSPORT_MD" ]]; then
  notari_safe_put passport.md <"$PASSPORT_MD" ||
    echo "::warning::could not publish passport.md into $PUBLISH_DIR (verdict unaffected)"
fi

# 5. Step output (so later steps / the job can branch on the verdict). From here
#    on the verdict HAS reached a durable channel, so the EXIT trap no longer
#    needs to emit its fallback summary. GITHUB_OUTPUT and GITHUB_STEP_SUMMARY
#    are runner-owned append files outside the checkout, so a later abort cannot
#    unwrite what was already appended.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "verdict=$VERDICT"
    echo "exit_code=$EXIT_CODE"
  } >>"$GITHUB_OUTPUT"
  EVIDENCE_EMITTED=1
fi

# 6. Job summary: the full markdown passport, visible on the PR's Checks tab.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$PASSPORT_MD" ]]; then
  cat "$PASSPORT_MD" >>"$GITHUB_STEP_SUMMARY"
fi

# 6a. Inline annotations: drop each finding onto the exact file/line of the PR
#     diff, so a reviewer sees "what's wrong" right where it happened without
#     opening the summary. Rendered (and escaped) by Notari from the SAME passport
#     we just validated; best-effort, never affects the verdict.
if [[ "$VERDICT" != "PASS" ]]; then
  notari explain --passport "$PASSPORT_JSON" --format github 2>/dev/null || true
fi

# NEEDS_REVIEW blocking: when enabled, NEEDS_REVIEW is treated as BLOCK for the
# Status Check state and the job exit, so the job fails on any finding (not just
# hard violations). The passport verdict itself is left unchanged, this only
# affects how the wrapper reports/gates.
BLOCK_FOR_EXIT="false"
[[ "$VERDICT" == "BLOCK" ]] && BLOCK_FOR_EXIT="true"
if [[ "${NOTARI_BLOCK_ON_REVIEW:-false}" == "true" && "$VERDICT" == "NEEDS_REVIEW" ]]; then
  echo "::warning::NEEDS_REVIEW treated as BLOCK (block-on-review=true)"
  BLOCK_FOR_EXIT="true"
fi

# 7. Commit Status Check. PASS / NEEDS_REVIEW -> success (NEEDS_REVIEW is a soft
#    signal); BLOCK -> failure. With block-on-review, NEEDS_REVIEW -> failure too.
#    Best-effort: a missing token just skips it.
if [[ "$BLOCK_FOR_EXIT" == "true" ]]; then
  STATE="failure"
else
  STATE="success"
fi
if [[ -n "${GITHUB_TOKEN:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "$STATUS_SHA" ]]; then
  if [[ -n "$SAFE_MAC" ]]; then
    DESC="$VERDICT: ${SAFE_REASONS:0:100} [mac:${SAFE_MAC:0:12}]"
  else
    DESC="$VERDICT: ${SAFE_REASONS:0:130}"
  fi
  python3 -I - "$STATE" "$DESC" "$STATUS_SHA" <<'PY' || echo "::warning::could not publish Status Check"
import json, os, sys, urllib.request
state, desc, sha = sys.argv[1], sys.argv[2], sys.argv[3]
repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GITHUB_TOKEN"]
body = json.dumps({
    "state": state,
    "description": desc,
    "context": "notari/change-control",
}).encode()
req = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/statuses/{sha}",
    data=body,
    method="POST",
    headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    },
)
urllib.request.urlopen(req, timeout=15).read()
print("published Status Check:", state)
PY

  # Record the SHA + MAC we just posted so `notari verify-passport` can
  # cross-check that the status check on this commit was the one Notari wrote,
  # not a spoof posted by an injected workflow on the same context. Written
  # through the same O_NOFOLLOW helper, so a symlink planted at the target is
  # replaced, never followed.
  printf 'sha=%s\nmac=%s\ncontext=%s\nstate=%s\n' \
    "$STATUS_SHA" "$SAFE_MAC" "$STATUS_CONTEXT" "$STATE" \
    | notari_safe_put status-fingerprint ||
    echo "::warning::could not record the status fingerprint; the Status Check was already posted with its MAC, so this only costs verify-passport's cross-check for this run"
fi

# 8. Exit code: fail the job on BLOCK (when fail-on-block is on), and on
#    NEEDS_REVIEW when block-on-review promoted it to a blocking state above.
if [[ "$BLOCK_FOR_EXIT" == "true" && "$FAIL_ON_BLOCK" == "true" ]]; then
  # Mark this as the DELIBERATE verdict exit so the EXIT trap passes 1 through
  # instead of normalising it to 2 as it does for an abnormal abort.
  VERDICT_EXIT=1
  exit 1
fi
exit 0
