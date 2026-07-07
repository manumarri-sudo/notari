#!/usr/bin/env bash
#
# Quill Change Control - GitHub Action wrapper.
#
# Runs `quill verify`, turns the Change Passport into a PR-visible summary +
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
#   QUILL_HEAD          ref to verify against the contract base (default HEAD)
#   QUILL_PASSPORT_DIR  where the published passport.{json,md} are copied
#                       (default .quill); the verdict is NOT trusted from here
#   QUILL_STRICT        "true" (default) requires a signed perimeter + contract
#   QUILL_FAIL_ON_BLOCK "true" to exit 1 on BLOCK (default true)
#   QUILL_BLOCK_ON_REVIEW "true" treats NEEDS_REVIEW as BLOCK for the Status
#                       Check state + job exit (default false). The passport
#                       verdict itself is left unchanged.
#   QUILL_GATE_PUBKEYS  trusted gate PUBLIC key(s) (PEM/paths). When set, the
#                       passport signature MUST verify or the job fails closed.
#   QUILL_HEAD_SHA      commit SHA to attach the Status Check to (default: git HEAD)
#   GITHUB_TOKEN        token for the Status Check + PR comment (optional)
#   GITHUB_REPOSITORY   owner/repo (provided by Actions)
#   GITHUB_OUTPUT       step-output file (provided by Actions)
#   GITHUB_STEP_SUMMARY job-summary file (provided by Actions)
#
set -euo pipefail

# Prevent candidate-controlled Python modules (pip.py, json.py, etc.) in the
# checkout from shadowing trusted imports. This wrapper runs with cwd inside the
# candidate checkout, so the inline `python3 -I -c` calls below use isolated mode
# (available since Python 3.4) to drop cwd from sys.path — this does NOT depend on
# the interpreter version. PYTHONSAFEPATH (Python 3.11+) is exported too as
# defense-in-depth, but -I is the load-bearing control on older runners.
export PYTHONSAFEPATH=1

PUBLISH_DIR="${QUILL_PASSPORT_DIR:-.quill}"
FAIL_ON_BLOCK="${QUILL_FAIL_ON_BLOCK:-true}"
STATUS_CONTEXT="quill/change-control"

# Evaluate the SAME commit the Status Check reports against, so the evaluated
# candidate, the passport, and the published status all describe one SHA
# (security review H-6: evaluated ref and status SHA could diverge). Prefer the
# explicit candidate SHA; fall back to QUILL_HEAD, then HEAD.
# Validate explicit SHA inputs against hex pattern to prevent option injection.
if [[ -n "${QUILL_HEAD_SHA:-}" ]] && ! [[ "$QUILL_HEAD_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "::error::QUILL_HEAD_SHA is not a valid 40-hex SHA: '${QUILL_HEAD_SHA}'"
  exit 2
fi
EVAL_REF="${QUILL_HEAD_SHA:-${QUILL_HEAD:-HEAD}}"

# --strict (default on) requires a signed perimeter AND signed contract from a
# trusted approver, so an unsigned / tampered / absent boundary BLOCKs rather
# than silently passing.
STRICT_FLAG=""
if [[ "${QUILL_STRICT:-true}" == "true" ]]; then
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
  if [[ "${QUILL_ALLOW_PULL_REQUEST_TRIGGER:-false}" != "true" ]]; then
    echo "::error::strict mode requires pull_request_target (not pull_request). The pull_request event runs the PR's workflow, so a PR can remove Quill entirely. See docs/SECURITY-MODEL.md for the secure template. Set QUILL_ALLOW_PULL_REQUEST_TRIGGER=true to override (NOT recommended)."
    exit 2
  else
    echo "::warning::running under pull_request with QUILL_ALLOW_PULL_REQUEST_TRIGGER=true — the caller workflow is candidate-controlled. A PR can remove this step."
  fi
fi

# A private temp dir we own: the verifier writes here, and the verdict is read
# back ONLY from here. Nothing in the repo tree can influence the decision.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/quill.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# 1. Run the verifier into the temp dir. It exits 1 on BLOCK and 0 on
#    PASS/NEEDS_REVIEW; any OTHER exit is a crash / bad invocation. Capture the
#    real exit code without aborting so we can tell BLOCK apart from failure.
set +e
quill verify $STRICT_FLAG --head "$EVAL_REF" --passport-dir "$WORK" \
  >"$WORK/stdout" 2>"$WORK/stderr"
QUILL_RC=$?
set -e

PASSPORT_JSON="$WORK/passport.json"
PASSPORT_MD="$WORK/passport.md"

# 2. Fail closed on any non-verdict exit. BLOCK is rc=1 WITH a passport; rc 0/1
#    are the only sanctioned codes. Anything else (or a missing passport) is an
#    error, never a pass.
if [[ "$QUILL_RC" != "0" && "$QUILL_RC" != "1" ]] || [[ ! -f "$PASSPORT_JSON" ]]; then
  echo "::error::quill verify failed to produce a verdict (rc=$QUILL_RC)"
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

# 3a. The verdict must be one Quill actually emits. A malformed / truncated /
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
if [[ "$QUILL_RC" != "$WANT_RC" || "$EXIT_CODE" != "$WANT_EXIT" ]]; then
  echo "::error::inconsistent verdict evidence (process rc=$QUILL_RC, verdict=$VERDICT, exit_code=$EXIT_CODE); failing closed"
  exit 2
fi

# 3b. If a gate public key is configured, the passport's signature MUST verify.
#     This binds the verdict to the off-box gate identity: a passport whose body
#     was edited (e.g. a flipped verdict) or signed by an untrusted key fails the
#     job. Without a configured pubkey we cannot check a signature, so we do not
#     pretend to - the deployment checklist calls for setting it in CI.
if [[ -n "${QUILL_GATE_PUBKEYS:-}" ]]; then
  if ! quill verify-passport "$PASSPORT_JSON" >/dev/null 2>"$WORK/sig.err"; then
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
  if [[ "${QUILL_ALLOW_UNSIGNED_EVIDENCE:-false}" == "true" ]]; then
    echo "::warning::strict mode with QUILL_ALLOW_UNSIGNED_EVIDENCE=true — the passport is UNSIGNED and cannot be independently re-verified."
  else
    echo "::error::strict mode requires a gate-signed passport. Set gate-key + gate-pubkeys, or set QUILL_ALLOW_UNSIGNED_EVIDENCE=true to accept report-grade unsigned evidence."
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
# regardless of whether QUILL_HEAD_SHA was explicitly set. Resolve HEAD now
# so the binding is always checked (wrapper-scanner HIGH-1).
STATUS_SHA="${QUILL_HEAD_SHA:-$(git rev-parse HEAD 2>/dev/null || true)}"
if [[ -n "$HEAD_COMMIT" && -n "$STATUS_SHA" && "$HEAD_COMMIT" != "$STATUS_SHA" ]]; then
  echo "::error::candidate mismatch: passport head_commit=$HEAD_COMMIT but status SHA=$STATUS_SHA; failing closed."
  exit 2
fi

# Passport fingerprint: the audit MAC binds the status check to THIS passport.
# A real Quill status carries it in the description; a spoofed "success" posted
# by an attacker-injected workflow cannot reproduce a MAC it never computed, so
# fake checks are detectable post-hoc (defense-in-depth against status-check
# spoofing — an evil PR workflow can still POST to the context, but it can't
# forge the fingerprint). Sanitize to hex-only so it can't carry an injection.
MAC="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("audit",{}).get("verification_run_mac",""))' "$PASSPORT_JSON")"
SAFE_MAC="$(printf '%s' "$MAC" | tr -cd '0-9a-fA-F')"

# Sanitize REASONS before echoing: strip CR/LF and leading :: to prevent
# Actions workflow-command injection from attacker-controlled passport data.
SAFE_REASONS="$(printf '%s' "$REASONS" | tr -d '\r\n' | sed 's/^:://')"
echo "Quill verdict: $VERDICT ($SAFE_REASONS)"

# 4. Publish the verified passport to the repo-visible dir for humans/tooling.
#    This is a copy of the artifact we already trusted, not the source of truth.
mkdir -p "$PUBLISH_DIR"
cp "$PASSPORT_JSON" "$PUBLISH_DIR/passport.json"
[[ -f "$PASSPORT_MD" ]] && cp "$PASSPORT_MD" "$PUBLISH_DIR/passport.md"

# 5. Step output (so later steps / the job can branch on the verdict).
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "verdict=$VERDICT"
    echo "exit_code=$EXIT_CODE"
  } >>"$GITHUB_OUTPUT"
fi

# 6. Job summary: the full markdown passport, visible on the PR's Checks tab.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$PASSPORT_MD" ]]; then
  cat "$PASSPORT_MD" >>"$GITHUB_STEP_SUMMARY"
fi

# NEEDS_REVIEW blocking: when enabled, NEEDS_REVIEW is treated as BLOCK for the
# Status Check state and the job exit, so the job fails on any finding (not just
# hard violations). The passport verdict itself is left unchanged — this only
# affects how the wrapper reports/gates.
BLOCK_FOR_EXIT="false"
[[ "$VERDICT" == "BLOCK" ]] && BLOCK_FOR_EXIT="true"
if [[ "${QUILL_BLOCK_ON_REVIEW:-false}" == "true" && "$VERDICT" == "NEEDS_REVIEW" ]]; then
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
    "context": "quill/change-control",
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

  # Record the SHA + MAC we just posted so `quill verify-passport` can
  # cross-check that the status check on this commit was the one Quill wrote,
  # not a spoof posted by an injected workflow on the same context.
  printf 'sha=%s\nmac=%s\ncontext=%s\nstate=%s\n' \
    "$STATUS_SHA" "$SAFE_MAC" "$STATUS_CONTEXT" "$STATE" \
    >"$PUBLISH_DIR/status-fingerprint"
fi

# 8. Exit code: fail the job on BLOCK (when fail-on-block is on), and on
#    NEEDS_REVIEW when block-on-review promoted it to a blocking state above.
if [[ "$BLOCK_FOR_EXIT" == "true" && "$FAIL_ON_BLOCK" == "true" ]]; then
  exit 1
fi
exit 0
