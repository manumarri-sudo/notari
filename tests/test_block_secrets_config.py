"""The signed perimeter's block_secrets setting composes the verdict (review 3.13).

By default (and with no perimeter) a secret on an added line is a BLOCK. A human
who signs a perimeter with block_secrets=false downgrades it to a review signal -
the config is signed, so only the approver can relax it, never the PR.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

import pytest

from quill import contract as contract_mod
from quill import perimeter as perimeter_mod
from quill import verify as verify_mod
from quill.verify import Verdict

# Built at runtime so this source file never contains the contiguous key shape.
_SECRET_VALUE = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_SECRET_LINE = f'aws_key = "{_SECRET_VALUE}"\n'


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@e")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "app.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


def _add_secret_and_contract(repo: Path) -> contract_mod.Contract:
    contract, _ = contract_mod.begin("task", allowed_paths=["src/**"], root=repo)
    (repo / "src" / "app.py").write_text("x = 1\n" + _SECRET_LINE)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add secret in scope")
    return contract


def test_secret_blocks_by_default(repo: Path) -> None:
    contract = _add_secret_and_contract(repo)
    perim = perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="h")
    assert perim.block_secrets is True
    result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
    assert result.verdict is Verdict.BLOCK
    assert result.secret_findings


def test_signed_block_secrets_false_downgrades_to_review(repo: Path) -> None:
    contract = _add_secret_and_contract(repo)
    perim = dataclasses.replace(
        perimeter_mod.default_perimeter(allowed_paths=("src/**",), approved_by="h"),
        block_secrets=False,
    )
    result = verify_mod.verify(contract=contract, root=repo, perimeter=perim)
    # Surfaced for a human, but not a hard fail - the approver signed for that.
    assert result.verdict is Verdict.NEEDS_REVIEW
    assert result.secret_findings
