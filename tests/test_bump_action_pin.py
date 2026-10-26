"""scripts/bump_action_pin.py moves every Action pin together, or refuses."""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bump_action_pin.py"


def _load():
    spec = importlib.util.spec_from_file_location("bump_action_pin", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    mod = _load()
    for rel in mod.SITES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return tmp_path


def test_every_site_in_the_repo_carries_exactly_one_pin_value() -> None:
    """The live tree's pins agree with each other (one release, one SHA)."""
    mod = _load()
    shas = set()
    for rel in mod.SITES:
        found = re.findall(r"manumarri-sudo/notari@([0-9a-f]{40})", (ROOT / rel).read_text())
        assert found, rel
        shas.update(found)
    assert len(shas) == 1, shas


def test_bump_rewrites_all_sites_to_the_new_sha(tree: Path) -> None:
    mod = _load()
    new = "f" * 40
    counts = mod.bump(tree, new, "9.9.9")
    assert set(counts) == set(mod.SITES)
    for rel in mod.SITES:
        text = (tree / rel).read_text()
        assert f"manumarri-sudo/notari@{new}" in text
        assert not re.search(r"manumarri-sudo/notari@(?![f]{40})[0-9a-f]{40}", text), rel
    assert "9.9.9 release action" in (tree / "src/notari/cli.py").read_text()


@pytest.mark.parametrize("bad", ["v0.5.0", "abc123", "F" * 40, "a" * 39])
def test_bump_refuses_anything_but_a_full_sha(tree: Path, bad: str) -> None:
    mod = _load()
    before = {rel: (tree / rel).read_text() for rel in mod.SITES}
    with pytest.raises(ValueError, match="40-hex"):
        mod.bump(tree, bad, "0.5.0")
    assert before == {rel: (tree / rel).read_text() for rel in mod.SITES}


def test_bump_refuses_when_a_site_lost_its_pin(tree: Path) -> None:
    mod = _load()
    (tree / "docs/scan-workflow.yml").write_text("name: x\n")
    with pytest.raises(ValueError, match="no pin found"):
        mod.bump(tree, "e" * 40, "0.5.0")
