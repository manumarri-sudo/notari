"""The GitHub Action wrapper must fail closed (security re-review P0-3).

These tests drive ``scripts/notari-passport.sh`` as a black box through a real
git repo, proving the two properties that matter:

  1. a passport committed into the PR (or left over from a prior step) can never
     be mistaken for this run's verdict - the wrapper reads the verdict only from
     a passport it wrote into a private temp dir;
  2. the published passport reflects the *real* verdict, overwriting any stale one.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parent.parent / "scripts" / "notari-passport.sh"


def _run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True, capture_output=True, text=True)


def _git_env(home: Path) -> dict[str, str]:
    """A git/notari env with the venv's bin on PATH so the `notari` console script
    and `git` resolve, and a throwaway HOME so we never touch the real one."""
    venv_bin = str(Path(sys.executable).parent)
    env = dict(os.environ)
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    env["HOME"] = str(home)
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@e",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@e",
    )
    return env


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "repo"
    root.mkdir()
    env = _git_env(tmp_path / "home")
    _run(["git", "init", "-q", "-b", "main"], root, env)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('hi')\n")
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "base"], root, env)
    return root, env


def test_committed_passport_cannot_fake_a_pass(repo: tuple[Path, dict[str, str]]) -> None:
    """An attacker commits a PASS passport into the PR, then makes an out-of-scope
    change whose real verdict is BLOCK. The wrapper must fail the job (exit 1) and
    publish the REAL BLOCK passport, not the planted one."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo

    # Contract: only src/** is in scope (cooperative mode keeps this test focused
    # on the wrapper's fail-closed logic, not on signing).
    _run(["notari", "begin", "task: tidy src", "--scope", "src/**"], root, env)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "contract"], root, env)

    # The PR makes an out-of-scope change -> real verify() yields BLOCK...
    (root / "PAYLOAD.txt").write_text("exfiltrate\n")
    # ...and plants a forged PASS passport in the repo-visible passport dir.
    notari_dir = root / ".notari"
    notari_dir.mkdir(exist_ok=True)
    (notari_dir / "passport.json").write_text(
        json.dumps({"verdict": "PASS", "exit_code": 0, "reasons": ["forged"]})
    )
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "pr"], root, env)

    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={**env, "NOTARI_STRICT": "false", "NOTARI_PASSPORT_DIR": ".notari"},
        capture_output=True,
        text=True,
    )

    # The job fails on the real BLOCK, and the published passport is the real one.
    assert proc.returncode == 1, f"expected BLOCK exit 1, got {proc.returncode}: {proc.stderr}"
    published = json.loads((notari_dir / "passport.json").read_text())
    assert published["verdict"] == "BLOCK"
    assert "PAYLOAD.txt" in published["evidence"]["out_of_scope"]


def _install_fake_notari(
    bin_dir: Path,
    *,
    rc: int,
    verdict: str,
    exit_code: int,
    head_commit: str = "",
) -> None:
    """A stand-in `notari` that writes a passport with the given verdict/exit_code
    into --passport-dir and exits with `rc`, to drive the wrapper's evidence-
    consistency check without depending on the real verifier's behavior."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / "notari"
    hc_field = f',"head_commit":"{head_commit}"' if head_commit else ""
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'dir="."; prev=""\n'
        'for a in "$@"; do [[ "$prev" == "--passport-dir" ]] && dir="$a"; prev="$a"; done\n'
        'mkdir -p "$dir"\n'
        f'printf \'{{"verdict":"{verdict}","exit_code":{exit_code},"reasons":["fake"]{hc_field}}}\' '
        '> "$dir/passport.json"\n'
        'printf "# passport\\n" > "$dir/passport.md"\n'
        f"exit {rc}\n"
    )
    fake.chmod(0o755)


def test_wrapper_fails_closed_on_rc_verdict_mismatch(
    repo: tuple[Path, dict[str, str]],
) -> None:
    """A verifier that exits rc=1 but writes a PASS passport is contradictory
    evidence; the wrapper must fail closed (exit 2), not pick the favorable side."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    bin_dir = root.parent / "fakebin"
    _install_fake_notari(bin_dir, rc=1, verdict="PASS", exit_code=0)
    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={
            **env,
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],  # fake notari wins
            "NOTARI_STRICT": "false",
            "NOTARI_PASSPORT_DIR": ".notari",
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, (
        f"expected fail-closed exit 2, got {proc.returncode}: {proc.stderr}"
    )
    assert "inconsistent verdict evidence" in (proc.stdout + proc.stderr)


def _wrapper(
    root: Path, env: dict[str, str], extra: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={**env, "NOTARI_PASSPORT_DIR": ".notari", **extra},
        capture_output=True,
        text=True,
    )


def test_strict_rejects_fail_on_block_false(repo: tuple[Path, dict[str, str]]) -> None:
    """Strict mode must not let fail-on-block=false neuter a BLOCK (review M-3)."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    proc = _wrapper(root, env, {"NOTARI_STRICT": "true", "NOTARI_FAIL_ON_BLOCK": "false"})
    assert proc.returncode == 2
    assert "fail-on-block=false" in (proc.stdout + proc.stderr)


def _repo_head(root: Path, env: dict[str, str]) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_strict_requires_gate_signature_by_default(repo: tuple[Path, dict[str, str]]) -> None:
    """A real PASS but no gate key -> strict refuses unsigned evidence (review M-4)."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    head_sha = _repo_head(root, env)
    bin_dir = root.parent / "fakebin_pass"
    _install_fake_notari(bin_dir, rc=0, verdict="PASS", exit_code=0, head_commit=head_sha)
    proc = _wrapper(
        root,
        env,
        {"PATH": str(bin_dir) + os.pathsep + env["PATH"], "NOTARI_STRICT": "true"},
    )
    assert proc.returncode == 2
    assert "requires a gate-signed passport" in (proc.stdout + proc.stderr)


def test_strict_unsigned_evidence_opt_out_is_explicit(repo: tuple[Path, dict[str, str]]) -> None:
    """With the explicit opt-out, the same PASS is accepted (visible downgrade)."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    head_sha = _repo_head(root, env)
    bin_dir = root.parent / "fakebin_pass2"
    _install_fake_notari(bin_dir, rc=0, verdict="PASS", exit_code=0, head_commit=head_sha)
    proc = _wrapper(
        root,
        env,
        {
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            "NOTARI_STRICT": "true",
            "NOTARI_ALLOW_UNSIGNED_EVIDENCE": "true",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_strict_rejects_pull_request_trigger(repo: tuple[Path, dict[str, str]]) -> None:
    """Strict mode must refuse to run under the 'pull_request' event because
    the PR controls the workflow and can remove Notari entirely (C-1)."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    head_sha = _repo_head(root, env)
    bin_dir = root.parent / "fakebin_pr"
    _install_fake_notari(bin_dir, rc=0, verdict="PASS", exit_code=0, head_commit=head_sha)
    proc = _wrapper(
        root,
        env,
        {
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            "NOTARI_STRICT": "true",
            "NOTARI_ALLOW_UNSIGNED_EVIDENCE": "true",
            "GITHUB_EVENT_NAME": "pull_request",
        },
    )
    assert proc.returncode == 2
    assert "pull_request_target" in (proc.stdout + proc.stderr)


def test_strict_allows_pull_request_target_trigger(repo: tuple[Path, dict[str, str]]) -> None:
    """pull_request_target is the secure trigger and must be accepted."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    head_sha = _repo_head(root, env)
    bin_dir = root.parent / "fakebin_prt"
    _install_fake_notari(bin_dir, rc=0, verdict="PASS", exit_code=0, head_commit=head_sha)
    proc = _wrapper(
        root,
        env,
        {
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            "NOTARI_STRICT": "true",
            "NOTARI_ALLOW_UNSIGNED_EVIDENCE": "true",
            "GITHUB_EVENT_NAME": "pull_request_target",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_strict_pull_request_with_opt_in(repo: tuple[Path, dict[str, str]]) -> None:
    """The explicit opt-in allows pull_request for dogfood repos."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo
    head_sha = _repo_head(root, env)
    bin_dir = root.parent / "fakebin_opt"
    _install_fake_notari(bin_dir, rc=0, verdict="PASS", exit_code=0, head_commit=head_sha)
    proc = _wrapper(
        root,
        env,
        {
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            "NOTARI_STRICT": "true",
            "NOTARI_ALLOW_UNSIGNED_EVIDENCE": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "NOTARI_ALLOW_PULL_REQUEST_TRIGGER": "true",
        },
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "candidate-controlled" in (proc.stdout + proc.stderr)


def test_symlinked_passport_target_is_not_followed_outside_checkout(
    repo: tuple[Path, dict[str, str]], tmp_path: Path
) -> None:
    """Red-team finding 1: a PR commits .notari/passport.json as a symlink to a
    file OUTSIDE the checkout. The wrapper must not follow it (which would let a
    PR overwrite a runner file from the trusted job); it replaces the symlink
    with a real file in place and leaves the victim untouched."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo

    victim = tmp_path / "victim.txt"
    victim.write_text("DO NOT OVERWRITE")

    _run(["notari", "begin", "task: tidy src", "--scope", "src/**"], root, env)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "contract"], root, env)

    # Out-of-scope change so verify produces a real (BLOCK) passport to publish.
    (root / "PAYLOAD.txt").write_text("x\n")
    notari_dir = root / ".notari"
    notari_dir.mkdir(exist_ok=True)
    # The attack: passport.json is a symlink pointing at the outside victim.
    link = notari_dir / "passport.json"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(victim)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "pr"], root, env)

    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={**env, "NOTARI_STRICT": "false", "NOTARI_PASSPORT_DIR": ".notari"},
        capture_output=True,
        text=True,
    )
    # The victim outside the checkout is untouched...
    assert victim.read_text() == "DO NOT OVERWRITE", proc.stderr
    # ...and the published passport is a REAL file inside .notari, not the symlink.
    published = notari_dir / "passport.json"
    assert not published.is_symlink(), "symlink must be replaced by a real file"
    assert json.loads(published.read_text())["verdict"] == "BLOCK"


def test_symlinked_publish_dir_is_refused(
    repo: tuple[Path, dict[str, str]], tmp_path: Path
) -> None:
    """A PR makes .notari itself a symlink to an outside dir. The wrapper must
    refuse to publish rather than write through it."""
    if not WRAPPER.exists():
        pytest.skip("wrapper script not present")
    root, env = repo

    outside = tmp_path / "outside_dir"
    outside.mkdir()

    _run(["notari", "begin", "task: tidy src", "--scope", "src/**"], root, env)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "contract"], root, env)

    (root / "PAYLOAD.txt").write_text("x\n")
    # The publish dir (separate from the real .notari contract dir) is a symlink
    # to a dir outside the checkout.
    (root / "pubout").symlink_to(outside)
    _run(["git", "add", "-A"], root, env)
    _run(["git", "commit", "-qm", "pr"], root, env)

    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=root,
        env={**env, "NOTARI_STRICT": "false", "NOTARI_PASSPORT_DIR": "pubout"},
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "symlink" in (proc.stdout + proc.stderr).lower()
    # Nothing was written into the outside dir.
    assert not (outside / "passport.json").exists()
