"""`nota verify`: compare the diff to the contract and render a verdict.

This is the heart of Change Control. Given a contract (the human-approved task
+ scope + base commit), verify:

  1. generates ``git diff <base_commit> HEAD``,
  2. runs the deterministic policy evaluation over it
     (out-of-scope paths, secret hits on added lines, sensitive surfaces),
  3. subtracts any human exceptions logged in ``.nota/exceptions.json``,
  4. composes a verdict: PASS, NEEDS_REVIEW, or BLOCK,
  5. audit-chains a ``verification.run`` event.

No AI anywhere on this path - every step is a string, glob, or regex operation,
so the verdict is reproducible and explainable line by line.
"""

from __future__ import annotations

import enum
import json
import logging
import os
import re
import select
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nota import events as ev
from nota import perimeter as perimeter_mod
from nota import policy
from nota import provenance as provenance_mod
from nota.contract import Contract, repo_root
from nota.errors import NotaError
from nota.perimeter import GATE_TAMPER_GLOBS, Perimeter, deny_hit
from nota.provenance import ProvenanceResult

if TYPE_CHECKING:
    from nota.audit import AuditLog
    from nota.policy import DiffEvaluation

_log = logging.getLogger(__name__)


class VerifyError(NotaError):
    """Raised when the diff cannot be generated."""


class Verdict(str, enum.Enum):
    PASS = "PASS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    BLOCK = "BLOCK"

    @property
    def exit_code(self) -> int:
        """BLOCK fails CI (1); PASS / NEEDS_REVIEW succeed (0). NEEDS_REVIEW is
        a soft signal: it surfaces evidence for a human without failing the
        build, matching the architecture's exit-code contract."""
        return 1 if self is Verdict.BLOCK else 0


def exceptions_path(root: Path) -> Path:
    return root / ".nota" / "exceptions.json"


def load_exceptions(root: Path) -> list[dict[str, Any]]:
    """Read logged human exceptions. Tolerant: a missing or malformed file
    yields no exceptions (fail safe - an unreadable waiver file must never
    silently waive findings)."""
    p = exceptions_path(root)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("exceptions", [])
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict)]


# Resource ceilings. A candidate can craft an enormous diff or a huge added
# blob to exhaust runner memory / CPU, or to push a real finding past a
# truncation point so the scan looks clean. We bound what we read and record a
# DISPOSITION, so an incomplete scan is never reported as a clean PASS (strict
# BLOCKs; cooperative surfaces a NEEDS_REVIEW warning). All limits are
# env-overridable for large monorepos.
DEFAULT_MAX_DIFF_BYTES = 50 * 1024 * 1024  # 50 MiB of unified diff text
DEFAULT_MAX_FILES = 20_000  # changed-path endpoints
DEFAULT_GIT_TIMEOUT = 300  # seconds per git subprocess


@dataclass(frozen=True)
class ScanLimits:
    """Configurable ceilings on how much candidate content the gate will scan."""

    max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES
    max_files: int = DEFAULT_MAX_FILES
    git_timeout: int = DEFAULT_GIT_TIMEOUT

    @classmethod
    def from_env(cls, env: dict[str, str]) -> ScanLimits:
        def _pos_int(name: str, default: int) -> int:
            raw = (env.get(name) or "").strip()
            if not raw:
                return default
            try:
                val = int(raw)
            except ValueError:
                return default
            return val if val > 0 else default

        return cls(
            max_diff_bytes=_pos_int("NOTA_MAX_DIFF_BYTES", DEFAULT_MAX_DIFF_BYTES),
            max_files=_pos_int("NOTA_MAX_FILES", DEFAULT_MAX_FILES),
            git_timeout=_pos_int("NOTA_GIT_TIMEOUT", DEFAULT_GIT_TIMEOUT),
        )


_STDERR_CAP = 8192  # keep only enough stderr to explain a failure


def _git_capture(args: list[str], root: Path, *, timeout: int, max_bytes: int) -> tuple[str, bool]:
    """Run a git command, reading AT MOST ``max_bytes`` of stdout.

    Returns ``(text, truncated)``. Unlike ``subprocess.run(capture_output=True)``
    this streams and stops at the cap, so a candidate-crafted multi-gigabyte diff
    cannot buffer the whole output into memory and OOM the runner.

    The wall-clock ``timeout`` is enforced on every read via ``select`` on the raw
    pipe fds, so it bounds a git process that hangs *between* bytes as well as one
    that streams forever — a blocking ``BufferedReader.read(n)`` would only re-check
    the deadline after a full chunk arrived, and a stalled git never delivers one.
    stdout and stderr are drained together so neither pipe buffer can wedge the
    other. POSIX-only (Actions runners are Linux); ``select`` on pipe fds is the
    supported path there.
    """
    try:
        proc = subprocess.Popen(
            args,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        msg = "git not found on PATH"
        raise VerifyError(msg) from e

    assert proc.stdout is not None and proc.stderr is not None
    out_fd = proc.stdout.fileno()
    err_fd = proc.stderr.fileno()
    chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    err_total = 0
    total = 0
    truncated = False
    deadline = time.monotonic() + timeout
    open_fds = {out_fd, err_fd}
    try:
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                msg = f"git timed out ({timeout}s ceiling)"
                raise VerifyError(msg)
            ready, _, _ = select.select(list(open_fds), [], [], remaining)
            if not ready:  # select itself hit the deadline
                proc.kill()
                msg = f"git timed out ({timeout}s ceiling)"
                raise VerifyError(msg)
            for fd in ready:
                data = os.read(fd, 65536)
                if not data:  # EOF on this pipe
                    open_fds.discard(fd)
                    continue
                if fd == out_fd:
                    if total < max_bytes:
                        chunks.append(data[: max_bytes - total])
                    total += len(data)
                    if total > max_bytes:
                        truncated = True
                        open_fds.discard(out_fd)  # got enough; stop reading stdout
                elif err_total < _STDERR_CAP:
                    err_chunks.append(data[: _STDERR_CAP - err_total])
                    err_total += len(data)
            if truncated and out_fd not in open_fds:
                proc.kill()  # don't wait on the rest of a huge stream
                break
    finally:
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    # A real failure (bad ref, not a repo) must not be mistaken for an empty diff.
    # Deliberate truncation kills the process (rc != 0) on purpose, so only raise
    # when we did NOT truncate.
    if rc not in (0, None) and not truncated:
        detail = b"".join(err_chunks).decode("utf-8", errors="replace").strip()
        msg = f"git command failed (rc={rc}): {detail or args}"
        raise VerifyError(msg)
    return b"".join(chunks).decode("utf-8", errors="replace"), truncated


def git_diff(
    base_commit: str | None,
    root: Path,
    *,
    head: str = "HEAD",
    text: bool = False,
    limits: ScanLimits | None = None,
) -> tuple[str, bool]:
    """Return ``(diff_text, truncated)`` for ``git diff <base_commit> <head>``.

    When no base commit is recorded (a contract created before the first
    commit), diff the empty tree against HEAD so the whole history shows up as
    additions rather than silently producing an empty - and falsely passing -
    diff.

    ``text=True`` adds ``--text``, forcing a textual diff even for files git would
    treat as binary. The secret scan uses this so a ``.gitattributes`` entry like
    ``secret.txt -diff`` (which makes git render the file as ``Binary files …
    differ`` and hide its added lines) cannot suppress secret detection (security
    review H-2).
    """
    lim = limits or ScanLimits()
    flags = ["--text"] if text else []
    if base_commit:
        args = ["git", "diff", *flags, base_commit, head]
    else:
        # 4b825dc... is git's well-known empty-tree object; diffing against it
        # surfaces every line as an addition.
        args = ["git", "diff", *flags, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", head]
    # errors="replace" (inside _git_capture): real repos contain binary blobs
    # (images, compiled fixtures) whose diff stanzas are not valid UTF-8. Strict
    # decoding would crash the gate on an innocuous binary change; replacement
    # keeps the text hunks intact and turns undecodable bytes into U+FFFD, which
    # the line-oriented parser simply ignores.
    return _git_capture(args, root, timeout=lim.git_timeout, max_bytes=lim.max_diff_bytes)


_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _resolve_sha(root: Path, ref: str) -> str:
    """Resolve `ref` to a concrete commit SHA once, so the diff, the passport,
    the audit event, and any Status Check all describe the SAME candidate. The
    diff was previously taken against a symbolic ref while the passport recorded
    repository HEAD, which could differ (security review: candidate identity
    mismatch). Falls back to the raw ref string if resolution fails."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ref
    return out.stdout.strip() or ref


def _is_ancestor(root: Path, base: str, head: str) -> bool:
    """Return True iff `base` is an ancestor of `head` (or base == head).

    Uses ``git merge-base --is-ancestor`` (exit 0 = ancestor, exit 1 = not).
    Any other failure - notably a shallow clone where the merge base is beyond
    the fetched history - raises CalledProcessError, which the caller treats as
    "can't prove non-ancestry" and warns rather than blocking."""
    proc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, head],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    raise subprocess.CalledProcessError(
        proc.returncode, proc.args, output=proc.stdout, stderr=proc.stderr
    )


def git_name_status(
    base_commit: str | None,
    root: Path,
    *,
    head: str = "HEAD",
    limits: ScanLimits | None = None,
) -> tuple[list[Any], bool]:
    """Authoritative changed-path inventory via ``git diff --name-status -z``.

    This is the SECURITY source of truth for which paths a candidate touches:
    unlike the textual diff it is NUL-delimited (no C-quoting), and it reports
    binary files, mode-only changes, and BOTH ends of a rename - the exact cases
    a textual-patch parser can drop. Returns ``(records, truncated)``; the same
    byte ceiling + streaming reader that bounds the textual diff bounds this too,
    so an adversarial name-status stream cannot buffer unbounded into memory. A
    truncated record tail is dropped by the tolerant parser; the caller surfaces
    truncation as an incomplete-coverage disposition."""
    lim = limits or ScanLimits()
    base = base_commit or _EMPTY_TREE
    args = ["git", "diff", "--name-status", "-z", "--find-renames", base, head]
    text, truncated = _git_capture(
        args, root, timeout=lim.git_timeout, max_bytes=lim.max_diff_bytes
    )
    return policy.parse_name_status(text), truncated


def _glob_match(value: str, pattern: str | None) -> bool:
    """A None/empty pattern matches anything; otherwise reuse the policy path
    matcher so exception globs behave exactly like scope globs."""
    if not pattern:
        return True
    return policy._path_matches(value, pattern)


def _waived_scope(path: str, exceptions: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") == "scope" and _glob_match(path, e.get("path")):
            return e
    return None


def _waived_secret(
    finding: policy.SecretFinding, exceptions: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") != "secret":
            continue
        if not _glob_match(finding.path, e.get("path")):
            continue
        line = e.get("line")
        if line is not None:
            try:
                if int(line) != finding.line:
                    continue
            except (ValueError, TypeError):
                continue
        return e
    return None


def _waived_surface(
    category: str, path: str, exceptions: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") != "surface":
            continue
        cat = e.get("category")
        if cat and cat != category:
            continue
        if not _glob_match(path, e.get("path")):
            continue
        return e
    return None


@dataclass(frozen=True)
class VerifyResult:
    verdict: Verdict
    contract: Contract
    evaluation: DiffEvaluation
    base_commit: str | None
    head_commit: str | None
    out_of_scope: tuple[str, ...]  # unwaived
    secret_findings: tuple[policy.SecretFinding, ...]  # unwaived
    sensitive_surfaces: dict[str, tuple[str, ...]]  # unwaived
    exceptions_applied: tuple[dict[str, Any], ...]
    reasons: tuple[str, ...]
    audit_mac: str | None = None
    # Trust spine (all optional so the contract-only path is unchanged):
    provenance: ProvenanceResult | None = None  # was the perimeter signed by a human?
    contract_provenance: ProvenanceResult | None = None  # was the contract signed by a human?
    forbidden_hits: tuple[str, ...] = ()  # paths the perimeter forbids outright
    gate_tamper_hits: tuple[str, ...] = ()  # edits to the gate's own trust surfaces
    perimeter_id: str | None = None
    strict: bool = False
    # Authoritative changed-path inventory from `git diff --name-status -z` (both
    # rename endpoints, binary + mode-only included). The passport/audit evidence
    # uses THIS, not the weaker textual parser, so evidence can't under-report a
    # change the enforcement layer acted on (security review M-1).
    inventory_paths: tuple[str, ...] = ()
    # Submodule (gitlink) pointer moves with old/new commit IDs — opaque content
    # that scope/secret scanning cannot reach inside (submodule opacity evidence).
    submodule_changes: tuple[dict[str, str], ...] = ()
    # Symlink (mode 120000) additions/changes with the recorded target: an
    # in-scope link can redirect at a forbidden path while scanners see only
    # the target string. Drives NEEDS_REVIEW, so the passport must carry it
    # (evidence may never under-report what the verdict acted on).
    symlink_changes: tuple[dict[str, str], ...] = ()
    # Scan-coverage dispositions (e.g. oversized-diff, too-many-files). Non-empty
    # means the scanners did not see the whole candidate; strict treats this as a
    # BLOCK, cooperative as NEEDS_REVIEW. Never a silent PASS.
    scan_dispositions: tuple[str, ...] = ()

    @property
    def changed_paths(self) -> tuple[str, ...]:
        # Prefer the authoritative inventory; fall back to the textual evaluation
        # only when no inventory was supplied (direct DiffEvaluation callers).
        return self.inventory_paths or self.evaluation.changed_paths


_HEX_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")


def _is_hex_sha(ref: str) -> bool:
    return bool(_HEX_SHA_RE.match(ref))


_UTF16_LE_BOM = b"\xff\xfe"
_UTF16_BE_BOM = b"\xfe\xff"
_UTF8_BOM = b"\xef\xbb\xbf"


def _decode_blob(raw: bytes) -> str:
    """Decode a git blob to text, handling UTF-16 and UTF-8 (with and without BOM).

    Returns the decoded string so ASCII-oriented secret patterns can match.
    Falls back to latin-1 (lossless for arbitrary bytes) so we never silently
    skip content."""
    if raw.startswith(_UTF16_LE_BOM):
        try:
            return raw[2:].decode("utf-16-le")
        except (UnicodeDecodeError, ValueError):
            pass
    if raw.startswith(_UTF16_BE_BOM):
        try:
            return raw[2:].decode("utf-16-be")
        except (UnicodeDecodeError, ValueError):
            pass
    if raw.startswith(_UTF8_BOM):
        try:
            return raw[3:].decode("utf-8")
        except UnicodeDecodeError:
            pass
    if b"\x00" in raw[:512]:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                decoded = raw.decode(enc)
                if "�" not in decoded[:256]:
                    return decoded
            except (UnicodeDecodeError, ValueError):
                continue
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _read_candidate_blob(root: Path, candidate_sha: str, path: str) -> str | None:
    """Read a file from the candidate commit's tree, not the worktree.

    Returns decoded text (handling UTF-16/UTF-8), or None if the blob doesn't
    exist at that commit. Logs a warning on unexpected git failures so silent
    scan skips are visible."""
    try:
        proc = subprocess.run(
            ["git", "cat-file", "blob", f"{candidate_sha}:{path}"],
            cwd=root,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        _log.warning("blob read failed for %s:%s — %s", candidate_sha[:12], path, e)
        return None
    return _decode_blob(proc.stdout)


def _block_result(
    contract: Contract,
    reason: str,
    *,
    strict: bool = False,
    root: Path | None = None,
    head: str = "HEAD",
) -> VerifyResult:
    """Produce a minimal BLOCK result for early-exit validation failures.

    Resolves head_commit from the repo so the wrapper's candidate-binding check
    doesn't reject the passport with a misleading 'missing head_commit' error."""
    head_commit = _resolve_sha(root, head) if root is not None else None
    empty_eval = policy.DiffEvaluation(
        files=(),
        out_of_scope=(),
        secret_findings=(),
        sensitive_surfaces={},
        allowed_paths=tuple(contract.allowed_paths),
    )
    return VerifyResult(
        verdict=Verdict.BLOCK,
        contract=contract,
        evaluation=empty_eval,
        base_commit=contract.base_commit,
        head_commit=head_commit,
        out_of_scope=(),
        secret_findings=(),
        sensitive_surfaces={},
        exceptions_applied=(),
        reasons=(reason,),
        strict=strict,
    )


def verify(
    *,
    contract: Contract,
    root: Path | None = None,
    head: str = "HEAD",
    audit: AuditLog | None = None,
    session_id: str = "nota-change-control",
    perimeter: Perimeter | None = None,
    strict: bool = False,
    env: dict[str, str] | None = None,
) -> VerifyResult:
    """Run the full verification and return a VerifyResult.

    Generates the diff, evaluates it against the contract scope, subtracts
    logged exceptions, composes the verdict, and (when an audit log is given)
    chains a ``verification.run`` event whose mac is attached to the result so a
    passport can cite the tamper-evident record.

    When a signed ``perimeter`` is supplied this also enforces the standing
    boundary (forbidden paths -> BLOCK, perimeter-chosen review surfaces) and,
    in ``strict`` mode, requires the perimeter's provenance to be a valid
    signature from a trusted approver - otherwise the boundary is unestablished
    and the verdict is BLOCK. Gate-tamper edits (the workflow, the approver keys,
    the perimeter itself) are always a BLOCK, perimeter or not.
    """
    root = repo_root(root)

    # Validate base_commit before passing it to git. The contract is untrusted
    # until its provenance is checked (below), and a crafted base_commit like
    # "--output=/path" could be interpreted as a git option. Resolve to a full
    # hex SHA first; reject anything that doesn't look like one.
    base = contract.base_commit
    if base is not None:
        base = base.strip()
        if not _is_hex_sha(base):
            base = _resolve_sha(root, base)
            if not _is_hex_sha(base):
                if strict:
                    return _block_result(
                        contract,
                        f"contract base_commit {contract.base_commit!r} is not a valid commit SHA",
                        strict=strict,
                        root=root,
                        head=head,
                    )
                _log.warning(
                    "contract base_commit %r did not resolve to a valid SHA; "
                    "falling back to empty-tree diff (entire repo history as additions)",
                    contract.base_commit,
                )
                base = None

    # Early-exit checks: verify contract provenance, repo binding, and expiry
    # BEFORE consuming any contract-controlled fields (base_commit, scope) in
    # expensive git operations. A forged contract should not force git work
    # (security review round 6, M-1).
    _env = env if env is not None else dict(os.environ)
    contract_prov = provenance_mod.verify_artifact(
        contract.to_dict(), root / ".nota" / "contract.sig", root, _env, strict=strict
    )
    if strict and not contract_prov.status.is_trustworthy:
        return _block_result(
            contract,
            f"contract provenance not established: {contract_prov.detail}",
            strict=strict,
            root=root,
            head=head,
        )

    expected_repo = (_env.get("NOTA_REPO_ID") or _env.get("GITHUB_REPOSITORY") or "").strip()
    if strict and contract.repo and contract.repo != expected_repo:
        repo_msg = (
            f"contract is bound to repo {contract.repo!r}, but this is {expected_repo!r}"
            if expected_repo
            else f"contract is bound to repo {contract.repo!r}, but the current repo is unknown (set NOTA_REPO_ID)"
        )
        return _block_result(contract, repo_msg, strict=strict, root=root, head=head)
    if strict and not contract.repo:
        # Strict must never accept an unbound contract. Two cases both BLOCK:
        #  - env knows the repo but the contract didn't pin it (--repo missing);
        #  - NEITHER side has an identity, so the contract could be replayed
        #    against any repo. The previous code only blocked the first case,
        #    letting the double-missing case proceed unbound (security review:
        #    strict repo binding).
        repo_msg = (
            f"contract has no repository binding; strict requires --repo (expected {expected_repo!r})"
            if expected_repo
            else "contract has no repository binding and the current repo identity is "
            "unknown; strict requires --repo on the contract and NOTA_REPO_ID / "
            "GITHUB_REPOSITORY in the environment so the contract can't be replayed elsewhere"
        )
        return _block_result(contract, repo_msg, strict=strict, root=root, head=head)

    contract_expired = contract.is_expired()
    contract_expiry_malformed = contract.expiry_is_malformed()
    if strict and contract_expiry_malformed:
        return _block_result(
            contract,
            f"contract expiry is malformed ({contract.expires_at!r}); refusing to treat it as unlimited authorization",
            strict=strict,
            root=root,
            head=head,
        )
    if strict and contract_expired:
        return _block_result(
            contract,
            f"contract expired at {contract.expires_at}; re-approve to authorize",
            strict=strict,
            root=root,
            head=head,
        )

    # Resolve the candidate to ONE concrete SHA and use it for the diff, the
    # inventory, and the recorded head, so evaluated == recorded (security review:
    # candidate identity mismatch).
    candidate_sha = _resolve_sha(root, head)
    if not _is_hex_sha(candidate_sha):
        return _block_result(
            contract,
            f"candidate ref {head!r} did not resolve to a valid commit SHA",
            strict=strict,
            root=root,
            head=head,
        )

    # Defense-in-depth (base ancestry): a human-signed contract whose base_commit
    # equals HEAD (or otherwise sits off the candidate's history) yields an EMPTY
    # diff, so every policy check trivially passes — a false-positive PASS. Even
    # though the contract is signed, a human can make this mistake, so verify the
    # base is actually an ancestor of the candidate, and reject the degenerate
    # base == candidate case outright. We only run this when base is a real commit
    # (not None, not the empty tree), since those legitimately have no ancestry
    # relationship to HEAD.
    base_not_ancestor = False
    reasons_ancestry: tuple[str, ...] = ()
    if base is not None and base != _EMPTY_TREE and base == candidate_sha:
        # base == candidate is the canonical empty-diff trap: nothing to compare,
        # so nothing can be out of scope. Block in strict; warn in cooperative.
        base_not_ancestor = True
        if strict:
            return _block_result(
                contract,
                f"contract base_commit {base[:12]} is not an ancestor of "
                f"candidate {candidate_sha[:12]} (base equals the candidate, so "
                "the diff is empty and every check trivially passes)",
                strict=strict,
                root=root,
                head=head,
            )
        reasons_ancestry = (
            f"warning: base_commit {base[:12]} equals the candidate; the diff is "
            "empty so nothing was actually verified (not enforced; cooperative mode)",
        )
    elif base is not None and base != _EMPTY_TREE:
        try:
            base_not_ancestor = not _is_ancestor(root, base, candidate_sha)
        except subprocess.CalledProcessError as exc:
            # Shallow clone or unreachable merge base: can't prove non-ancestry.
            # Warn (cooperative) but never crash or block on inconclusive data.
            _log.warning(
                "base ancestry check inconclusive for %s..%s — %s",
                base[:12],
                candidate_sha[:12],
                exc,
            )
            reasons_ancestry = (
                f"warning: could not verify base_commit {base[:12]} is an ancestor "
                f"of {candidate_sha[:12]} (shallow clone?)",
            )
        else:
            if base_not_ancestor:
                if strict:
                    return _block_result(
                        contract,
                        f"contract base_commit {base[:12]} is not an ancestor of "
                        f"candidate {candidate_sha[:12]}; the diff does not describe "
                        "work built on the approved base (possible stale or forged base)",
                        strict=strict,
                        root=root,
                        head=head,
                    )
                reasons_ancestry = (
                    f"warning: base_commit {base[:12]} is not an ancestor of "
                    f"candidate {candidate_sha[:12]} (not enforced; cooperative mode)",
                )

    # --text forces a textual diff even for files git would call binary, so a
    # `.gitattributes` `-diff` entry cannot hide a secret-bearing file's added
    # lines from the scanner (security review H-2). Real binaries become text
    # hunks here; the authoritative inventory below, not this diff, drives path
    # policy, so that is only a secret-scan input.
    limits = ScanLimits.from_env(_env)
    scan_dispositions: list[str] = []
    diff_text, diff_truncated = git_diff(base, root, head=candidate_sha, text=True, limits=limits)
    if diff_truncated:
        # The diff exceeded the byte ceiling and was cut off, so the secret scan
        # below did NOT see the whole change. Record it as evidence; the verdict
        # logic downstream refuses to call an incompletely-scanned diff a PASS.
        scan_dispositions.append(
            f"oversized-diff: diff exceeded {limits.max_diff_bytes} bytes and was "
            "truncated; secret scanning did not cover the whole change"
        )
    # INVARIANT: the secret scan inside evaluate_diff runs over this --text diff,
    # not the authoritative inventory. Dropping --text would silently regress secret
    # detection on files marked `-diff` in .gitattributes (test_gitattributes_secret).
    evaluation = policy.evaluate_diff(diff_text, contract.allowed_paths)

    # Authoritative changed-path inventory (NUL-delimited, both rename endpoints,
    # binary + mode-only included). This is the source of truth for every path
    # rule; the textual diff above is kept only for added-line secret scanning.
    # We police the UNION of the two so a path either parser sees is never lost.
    inventory, inventory_truncated = git_name_status(base, root, head=candidate_sha, limits=limits)
    if inventory_truncated:
        scan_dispositions.append(
            f"oversized-inventory: the changed-path list exceeded {limits.max_diff_bytes} "
            "bytes and was truncated; path policy did not see every changed file"
        )
    if len(inventory) > limits.max_files:
        scan_dispositions.append(
            f"too-many-files: {len(inventory)} changed paths exceed the "
            f"{limits.max_files}-file ceiling; path policy may be incomplete"
        )
    raw_changed: set[str] = set()  # every touched path, both ends, incl. .nota/
    policed_changed: set[str] = set()  # scope/surface set: .nota/ excluded
    for cp in inventory:
        for p in cp.endpoints:
            raw_changed.add(p)
            if not p.startswith(".nota/"):
                policed_changed.add(p)
    # Detect submodule (gitlink) changes: mode 160000 entries are opaque — the
    # candidate scanner can't read their content (they're commit objects, not
    # blobs), so secret scanning and scope enforcement don't reach inside them.
    # We record the OLD/NEW commit IDs the pointer moved between so a reviewer
    # can audit exactly which nested commit was pulled in (submodule opacity
    # evidence). ``git diff --raw -z`` lists only changed entries with both SHAs,
    # NUL-delimited so a path with a tab/newline can't be mis-parsed. The read goes
    # through the same capped reader as the diff, so a candidate with millions of
    # tiny changed paths can't buffer the whole --raw output into the (secret-bearing)
    # job's memory; a truncated or failed scan surfaces as an incomplete-coverage
    # disposition rather than silently dropping the submodule flag (fail closed).
    _ZERO_SHA = "0" * 40
    submodule_paths: list[str] = []
    submodule_changes: list[dict[str, str]] = []
    # Symlink (mode 120000) additions/changes: git stores a symlink as a blob
    # whose CONTENT is the target path, so an in-scope symlink can point AT a
    # forbidden path (e.g. src/checkout/x → ../auth/secret) while the diff only
    # shows an in-scope file with innocuous "content". Scope and secret scanning
    # both see the harmless target string and miss the boundary crossing. We
    # surface every symlink for review (opaque-redirect evidence), mirroring the
    # submodule-opacity treatment; a symlink whose own path is forbidden already
    # BLOCKs via the forbidden-surface check.
    symlink_paths: list[str] = []
    symlink_changes: list[dict[str, str]] = []
    try:
        raw_text, raw_truncated = _git_capture(
            ["git", "diff", "--raw", "--no-abbrev", "-z", base or _EMPTY_TREE, candidate_sha],
            root,
            timeout=limits.git_timeout,
            max_bytes=limits.max_diff_bytes,
        )
    except VerifyError:
        scan_dispositions.append(
            "submodule-scan-inconclusive: could not read the raw diff to detect "
            "gitlink (submodule) pointer changes"
        )
    else:
        if raw_truncated:
            scan_dispositions.append(
                "submodule-scan-truncated: the raw diff exceeded the byte ceiling; "
                "a gitlink change in the truncated tail may be undetected"
            )
        # -z records are NUL-delimited `meta \0 path` pairs (no rename detection is
        # requested, so there is exactly one path per record).
        parts = raw_text.split("\0")
        for i in range(0, len(parts) - 1, 2):
            meta, path = parts[i], parts[i + 1]
            if not meta.startswith(":"):
                continue
            cols = meta[1:].split()
            if len(cols) < 5:
                continue
            oldmode, newmode, oldsha, newsha, status = cols[:5]
            if not path or path.startswith(".nota/"):
                continue
            # Symlink addition/modification: newmode 120000. Record the target
            # (the blob content) so a reviewer sees where the link points.
            if newmode == "120000":
                target = ""
                if newsha != _ZERO_SHA:
                    try:
                        target, _ = _git_capture(
                            ["git", "cat-file", "blob", newsha],
                            root,
                            timeout=limits.git_timeout,
                            max_bytes=limits.max_diff_bytes,
                        )
                    except VerifyError:
                        target = ""
                symlink_changes.append({"path": path, "status": status, "target": target.strip()})
            if "160000" not in (oldmode, newmode):
                continue
            submodule_changes.append(
                {
                    "path": path,
                    "status": status,
                    "old_commit": "" if oldsha == _ZERO_SHA else oldsha,
                    "new_commit": "" if newsha == _ZERO_SHA else newsha,
                }
            )
        submodule_paths = sorted({c["path"] for c in submodule_changes})
        symlink_paths = sorted({c["path"] for c in symlink_changes})

    # Authoritative changed-file list for the evidence layer (both endpoints).
    inventory_paths = tuple(sorted({p for cp in inventory for p in cp.endpoints}))

    # Empty-diff staleness signal: if the base IS a valid ancestor but the diff
    # is empty while the contract claims a non-trivial scope (anything narrower
    # than the catch-all ["**"]), the contract probably describes work that was
    # never produced — a stale base or an accidental no-op. Surface it as a
    # warning so a reviewer notices the PASS isn't backed by any change. A ["**"]
    # scope is intentionally broad and an empty diff under it is unremarkable.
    nontrivial_scope = tuple(contract.allowed_paths) not in ((), ("**",))
    empty_diff_warning: tuple[str, ...] = ()
    if not base_not_ancestor and not inventory_paths and nontrivial_scope:
        empty_diff_warning = (
            "warning: diff is empty but the contract scopes specific paths "
            f"({', '.join(contract.allowed_paths)}); the contract may be stale "
            "or the change was never committed",
        )
    for df in policy.parse_unified_diff(diff_text):
        for p in (df.path, df.old_path):
            if p and p != "/dev/null":  # /dev/null is the add/delete sentinel
                raw_changed.add(p)
                if not p.startswith(".nota/"):
                    policed_changed.add(p)

    # Blob-level secret scan: read each touched file from the CANDIDATE COMMIT
    # (not the worktree) and run secret patterns over the decoded content. This
    # catches secrets that the diff-based scanner misses:
    #   - 100% renames (no added lines in the diff) — H-4
    #   - UTF-16/UTF-16BE files (diff --text garbles NUL bytes) — round-6 H-1
    #   - worktree != candidate divergence — round-6 H-2
    # Covers A (added), M (modified), R (renamed), C (copied). D (deleted) is
    # skipped since the file no longer exists in the candidate.
    from nota import secrets as _secrets

    blob_secret_findings: list[policy.SecretFinding] = []
    for cp in inventory:
        if cp.status == "D":
            continue
        dest = cp.path
        if dest.startswith(".nota/"):
            continue
        content = _read_candidate_blob(root, candidate_sha, dest)
        if content is None:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            for hit in _secrets.scan(line):
                blob_secret_findings.append(
                    policy.SecretFinding(path=dest, line=lineno, pattern_name=hit.pattern_name)
                )

    # Strict mode does NOT honor branch-authored exceptions (security review
    # P0-2): an unsigned .nota/exceptions.json could waive whole classes of
    # findings with an empty path. Cooperative mode still applies them.
    exceptions = [] if strict else load_exceptions(root)

    applied: list[dict[str, Any]] = []

    # Scope violations from the authoritative inventory too, so a path the textual
    # parser dropped (e.g. a quoted mode-only change) is still measured against the
    # contract scope. Preserve the parser's order, then append the extras.
    out_of_scope_all: list[str] = list(evaluation.out_of_scope)
    for p in sorted(policed_changed):
        if not policy.path_in_scope(p, contract.allowed_paths) and p not in out_of_scope_all:
            out_of_scope_all.append(p)

    unwaived_scope: list[str] = []
    for p in out_of_scope_all:
        e = _waived_scope(p, exceptions)
        if e is None:
            unwaived_scope.append(p)
        else:
            applied.append(e)

    # Merge diff-based and blob-based secret findings, dedup by (path, line, pattern).
    all_secret_findings = list(evaluation.secret_findings)
    seen_secrets: set[tuple[str, int, str]] = {
        (f.path, f.line, f.pattern_name) for f in all_secret_findings
    }
    for f in blob_secret_findings:
        key = (f.path, f.line, f.pattern_name)
        if key not in seen_secrets:
            all_secret_findings.append(f)
            seen_secrets.add(key)

    unwaived_secrets: list[policy.SecretFinding] = []
    for f in all_secret_findings:
        e = _waived_secret(f, exceptions)
        if e is None:
            unwaived_secrets.append(f)
        else:
            applied.append(e)

    # Combine parser-found surfaces with any from the authoritative inventory the
    # parser missed (e.g. a quoted mode-only edit to a CI file).
    surfaces_all: dict[str, list[str]] = {
        k: list(v) for k, v in evaluation.sensitive_surfaces.items()
    }
    for p in sorted(policed_changed):
        cat = policy.classify_sensitive_surface(p)
        if cat is not None and p not in surfaces_all.setdefault(cat, []):
            surfaces_all[cat].append(p)

    unwaived_surfaces: dict[str, list[str]] = {
        "tests": [],
        "ci": [],
        "lockfiles": [],
        "gitconfig": [],
    }
    for category, paths in surfaces_all.items():
        for p in paths:
            e = _waived_surface(category, p, exceptions)
            if e is None:
                unwaived_surfaces.setdefault(category, []).append(p)
            else:
                applied.append(e)

    # Gate-tamper over EVERY touched path (both rename endpoints, incl. .nota/),
    # so a PR cannot move its own judge out of a protected path to escape the
    # check (security review: rename-out of a gate surface).
    gate_tamper = tuple(
        sorted(p for p in raw_changed if any(deny_hit(p, g) for g in GATE_TAMPER_GLOBS))
    )

    forbidden_hits: tuple[str, ...] = ()
    provenance: ProvenanceResult | None = None
    perimeter_id: str | None = None
    review_categories: set[str] | None = None  # None = report every surface (legacy)
    if perimeter is not None:
        perimeter_id = perimeter.perimeter_id
        # Forbidden over every touched path, both endpoints: a rename OUT of a
        # forbidden namespace touches the forbidden source and must BLOCK
        # (security review: rename-out of a forbidden path).
        forbidden_hits = tuple(sorted(p for p in raw_changed if perimeter.forbids(p)))
        review_categories = set(perimeter.review_surfaces)
        provenance = provenance_mod.verify_artifact(
            perimeter.to_dict(), perimeter_mod.signature_path(root), root, env, strict=strict
        )
        # Enforce the signed perimeter's allow-list (security re-review): the
        # standing perimeter is the OUTER bound. A path is in effective scope only
        # if it is allowed by BOTH the contract and the perimeter, so a contract
        # cannot widen past the boundary a human signed. Empty perimeter allow-list
        # means "anywhere not forbidden". Both rename endpoints are checked. These
        # join the scope violations.
        if perimeter.allowed_paths:
            for p in sorted(policed_changed):
                if not policy.path_in_scope(p, perimeter.allowed_paths) and p not in unwaived_scope:
                    unwaived_scope.append(p)

    # contract_prov was already computed and strict failures early-exited above.
    # The variable is in scope for cooperative-mode warnings and the verdict.

    # Honor the signed perimeter's block_secrets setting: it BLOCKs by default
    # (and always, with no perimeter), but a human who signed block_secrets=false
    # downgrades a secret hit to a review signal rather than a hard fail. The
    # config is signed, so this can only be relaxed by the approver, never the PR.
    secrets_block = bool(unwaived_secrets) and (perimeter is None or perimeter.block_secrets)
    secrets_review = bool(unwaived_secrets) and not secrets_block

    reasons: list[str] = []
    reasons.extend(reasons_ancestry)
    reasons.extend(empty_diff_warning)
    if unwaived_secrets:
        tail = "" if secrets_block else " (perimeter block_secrets=false: review, not block)"
        reasons.append(f"{len(unwaived_secrets)} secret(s) detected on added lines{tail}")
    if unwaived_scope:
        reasons.append(f"{len(unwaived_scope)} path(s) changed outside the approved scope")
    if forbidden_hits:
        reasons.append(f"{len(forbidden_hits)} path(s) touch a forbidden perimeter surface")
    if gate_tamper:
        reasons.append(
            f"{len(gate_tamper)} edit(s) to Nota's own trust surfaces "
            "(workflow / approver keys / perimeter)"
        )

    if submodule_paths:
        detail = "; ".join(
            f"{c['path']} {c['old_commit'][:12] or '(new)'}→{c['new_commit'][:12] or '(removed)'}"
            for c in submodule_changes
        )
        reasons.append(
            f"{len(submodule_paths)} submodule pointer(s) changed — nested content is opaque "
            f"to scope/secret scanning [{detail}]"
        )

    if symlink_paths:
        detail = "; ".join(
            f"{c['path']} → {c['target'] or '(unreadable)'}" for c in symlink_changes
        )
        reasons.append(
            f"{len(symlink_paths)} symlink(s) added/changed — a link can redirect an "
            f"in-scope path at a forbidden target; scope/secret scanning sees only the "
            f"link text [{detail}]"
        )

    # Incomplete scan coverage: an oversized diff or an over-ceiling file count
    # means the scanners did NOT see the whole candidate. Strict refuses to bless
    # a change it could not fully read (fail closed); cooperative surfaces it for
    # review. Either way it can never be reported as a clean PASS.
    scan_incomplete = bool(scan_dispositions)
    if scan_incomplete:
        for d in scan_dispositions:
            reasons.append(
                f"incomplete scan coverage — {d}"
                + ("" if strict else " (not enforced; cooperative mode)")
            )

    surface_hits = {k: v for k, v in unwaived_surfaces.items() if v}
    # These surfaces are intrinsically dangerous regardless of the perimeter's
    # configured review list: agent-instruction files (CLAUDE.md, AGENTS.md,
    # Cursor rules) poison the next agent, and Nota's own learning state is
    # advisory-not-proof. They ALWAYS surface for review so an agent can't slip
    # an instruction-poisoning edit through under a perimeter that forgot them.
    _ALWAYS_REVIEW = {"agent_instructions", "nota_learning_state"}
    if review_categories is not None:
        review_hits = {
            k: v for k, v in surface_hits.items() if k in review_categories or k in _ALWAYS_REVIEW
        }
    else:
        review_hits = surface_hits
    if review_hits:
        reasons.append(
            "sensitive surfaces touched: "
            + ", ".join(f"{k} ({len(v)})" for k, v in review_hits.items())
        )

    provenance_blocks = bool(
        strict
        and perimeter is not None
        and provenance is not None
        and not provenance.status.is_trustworthy
    )
    strict_no_perimeter = bool(strict and perimeter is None)
    # Strict contract provenance/repo/expiry already early-exited above. These
    # blocks handle cooperative-mode warnings (strict cases can't reach here).
    contract_provenance_blocks = False  # strict already exited
    repo_mismatch = bool(contract.repo and contract.repo != expected_repo)
    repo_blocks = False  # strict already exited
    if repo_mismatch:
        reasons.append(
            f"warning: contract repo {contract.repo!r} != {expected_repo or 'unknown'} (not enforced; cooperative mode)"
        )

    contract_expired = contract.is_expired()
    contract_expiry_malformed = contract.expiry_is_malformed()
    contract_expiry_blocks = False  # strict already exited
    if contract_expired:
        reasons.append(
            f"warning: contract expired at {contract.expires_at} (not enforced; cooperative mode)"
        )
    elif contract_expiry_malformed:
        reasons.append(
            f"warning: contract expiry is malformed ({contract.expires_at!r}); "
            "ignored in cooperative mode"
        )
    if provenance_blocks and provenance is not None:
        reasons.append(f"perimeter provenance not established: {provenance.detail}")
    elif perimeter is not None and provenance is not None and not provenance.status.is_trustworthy:
        # Non-strict: surface the gap as a warning without failing the build.
        reasons.append(f"warning: perimeter provenance unverified ({provenance.detail})")
    if strict_no_perimeter:
        reasons.append("strict mode requires a signed perimeter, but none is configured")
    if not contract_prov.status.is_trustworthy:
        reasons.append(f"warning: contract provenance unverified ({contract_prov.detail})")

    # Strict fails closed on incomplete scan coverage; cooperative degrades it to
    # NEEDS_REVIEW (handled in the elif below), never a silent PASS.
    scan_blocks = bool(strict and scan_incomplete)
    block = bool(
        secrets_block
        or unwaived_scope
        or forbidden_hits
        or gate_tamper
        or provenance_blocks
        or strict_no_perimeter
        or contract_provenance_blocks
        or contract_expiry_blocks
        or repo_blocks
        or scan_blocks
    )
    if block:
        verdict = Verdict.BLOCK
    elif review_hits or secrets_review or submodule_paths or symlink_paths or scan_incomplete:
        verdict = Verdict.NEEDS_REVIEW
    else:
        verdict = Verdict.PASS
        reasons.append(
            "diff is within the approved boundary: in scope, no secrets, nothing forbidden"
        )
        if provenance is not None and provenance.status.is_trustworthy:
            reasons.append(provenance.detail)

    head_commit = candidate_sha

    audit_mac: str | None = None
    if audit is not None:
        audit_mac = audit.emit(
            event_type=ev.VERIFICATION_RUN,
            session_id=session_id,
            risk="high" if verdict is Verdict.BLOCK else "low",
            payload={
                "contract_id": contract.contract_id,
                "verdict": verdict.value,
                "base_commit": contract.base_commit or "",
                "head_commit": head_commit or "",
                "changed_files": len(inventory_paths),
                "out_of_scope": list(unwaived_scope),
                "secret_findings": [
                    {"path": f.path, "line": f.line, "pattern": f.pattern_name}
                    for f in unwaived_secrets
                ],
                "sensitive_surfaces": {k: list(v) for k, v in surface_hits.items()},
                "forbidden_hits": list(forbidden_hits),
                "gate_tamper_hits": list(gate_tamper),
                "perimeter_id": perimeter_id or "",
                "provenance": provenance.status.value if provenance is not None else "n/a",
                "provenance_key_id": provenance.key_id if provenance is not None else "",
                "contract_provenance": contract_prov.status.value,
                "contract_signer_key_id": contract_prov.key_id or "",
                "strict": strict,
                "exceptions_applied": len(applied),
            },
        )

    return VerifyResult(
        verdict=verdict,
        contract=contract,
        evaluation=evaluation,
        base_commit=contract.base_commit,
        head_commit=head_commit,
        out_of_scope=tuple(unwaived_scope),
        secret_findings=tuple(unwaived_secrets),
        sensitive_surfaces={k: tuple(v) for k, v in unwaived_surfaces.items()},
        exceptions_applied=tuple(applied),
        reasons=tuple(reasons),
        audit_mac=audit_mac,
        provenance=provenance,
        contract_provenance=contract_prov,
        forbidden_hits=forbidden_hits,
        gate_tamper_hits=gate_tamper,
        perimeter_id=perimeter_id,
        strict=strict,
        inventory_paths=inventory_paths,
        submodule_changes=tuple(submodule_changes),
        symlink_changes=tuple(symlink_changes),
        scan_dispositions=tuple(scan_dispositions),
    )
