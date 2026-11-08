"""Check the real wrapper's request body without a GitHub token or network."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from test_action_wrapper import _git_env, _repo_head, _run, _wrapper

_CAPTURE = """\
import json
import os
import sys
import urllib.request
from pathlib import Path

def capture(request, timeout):
    Path(os.environ["CAPTURE_PATH"]).write_text(json.dumps(json.loads(request.data)))
    if os.environ["POST_FAILS"] == "1":
        raise OSError("transport unavailable")
    return type("Response", (), {"read": lambda self: b""})()

urllib.request.urlopen = capture
exec(compile(sys.stdin.read(), "<status publisher>", "exec"))
"""


@pytest.mark.parametrize(
    ("mode", "context", "post_fails"),
    [
        ("scan", "notari/scan", False),
        ("boundary", "notari/change-control", False),
        ("scan", "notari/scan", True),
    ],
)
def test_wrapper_posts_the_mode_status(
    tmp_path: Path, mode: str, context: str, post_fails: bool
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    env = _git_env(tmp_path / "home")
    _run(["git", "init", "-qb", "main"], root, env)
    _run(["git", "commit", "--allow-empty", "-qm", "base"], root, env)
    base = _repo_head(root, env)
    if mode == "boundary":
        _run(["notari", "begin", "test", "--scope", "src/**"], root, env)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("answer = 42\n")
    _run(["git", "add", "."], root, env)
    _run(["git", "commit", "-qm", "candidate"], root, env)
    bindir = tmp_path / "shim"
    bindir.mkdir()
    (bindir / "capture.py").write_text(_CAPTURE)
    python = bindir / "python3"
    python.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = \'-I\' ] && [ "$2" = \'-\' ] && [ "$#" -ge 5 ]; then\n'
        '  exec "$REAL_PYTHON" -I "$CAPTURE_SCRIPT" "$3" "$4" "$5" "${6:-}"\n'
        "fi\n"
        'exec "$REAL_PYTHON" "$@"\n'
    )
    python.chmod(0o755)
    capture = tmp_path / "request.json"
    result = _wrapper(
        root,
        env,
        {
            "PATH": f"{bindir}:{env['PATH']}",
            "REAL_PYTHON": sys.executable,
            "CAPTURE_SCRIPT": str(bindir / "capture.py"),
            "CAPTURE_PATH": str(capture),
            "POST_FAILS": str(int(post_fails)),
            "GITHUB_TOKEN": "test-only",
            "GITHUB_REPOSITORY": "fixture/repo",
            "NOTARI_MODE": mode,
            "NOTARI_BASE_SHA": base,
            "NOTARI_STRICT": "false",
        },
    )
    body = json.loads(capture.read_text())
    assert body["context"] == context
    assert body["state"] == "success"
    assert result.returncode == (2 if post_fails else 0), result.stdout + result.stderr
    fingerprint = root / ".notari" / "status-fingerprint"
    assert fingerprint.exists() is not post_fails
