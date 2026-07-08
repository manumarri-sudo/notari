"""Test isolation - make sure tests don't share global state under ~/.nota/.

Many of Nota's modules persist state to `$NOTA_HOME/<file>` - approvals,
pin store, decay store, taint state, sessions index, etc. Without isolation,
test A leaves an approval in `~/.nota/approvals.json` that test B then
consumes (different test, different intent), producing flaky verdicts.

This autouse fixture points NOTA_HOME at a per-test tmp directory so
every test gets a fresh, empty state dir. Tests that explicitly need to
touch the user's real `~/.nota/` should bypass this fixture by reading
the original env vars they want.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_nota_home(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Each test runs with a fresh NOTA_HOME under tmp/. Auto-applied."""
    home = tmp_path_factory.mktemp("nota_home")
    monkeypatch.setenv("NOTA_HOME", str(home))
    # Belt-and-suspenders: also clear per-file overrides so nothing the
    # parent shell set leaks into this test.
    for var in (
        "NOTA_CONFIG",
        "NOTA_LOG",
        "NOTA_KEY",
        "NOTA_DECAY_FILE",
        "NOTA_TELEMETRY_PATH",
        "NOTA_WATCH_PID",
        "NOTA_SESSIONS",
        "NOTA_TAINT_FILE",
        "NOTA_PINS_FILE",
        "NOTA_APPROVALS_FILE",
        "NOTA_OVERNIGHT_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield home
