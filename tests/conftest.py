"""Test isolation - make sure tests don't share global state under ~/.quill/.

Many of Quill's modules persist state to `$QUILL_HOME/<file>` - approvals,
pin store, decay store, taint state, sessions index, etc. Without isolation,
test A leaves an approval in `~/.quill/approvals.json` that test B then
consumes (different test, different intent), producing flaky verdicts.

This autouse fixture points QUILL_HOME at a per-test tmp directory so
every test gets a fresh, empty state dir. Tests that explicitly need to
touch the user's real `~/.quill/` should bypass this fixture by reading
the original env vars they want.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_quill_home(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Each test runs with a fresh QUILL_HOME under tmp/. Auto-applied."""
    home = tmp_path_factory.mktemp("quill_home")
    monkeypatch.setenv("QUILL_HOME", str(home))
    # Belt-and-suspenders: also clear per-file overrides so nothing the
    # parent shell set leaks into this test.
    for var in (
        "QUILL_CONFIG",
        "QUILL_LOG",
        "QUILL_KEY",
        "QUILL_DECAY_FILE",
        "QUILL_TELEMETRY_PATH",
        "QUILL_WATCH_PID",
        "QUILL_SESSIONS",
        "QUILL_TAINT_FILE",
        "QUILL_PINS_FILE",
        "QUILL_APPROVALS_FILE",
        "QUILL_OVERNIGHT_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield home
