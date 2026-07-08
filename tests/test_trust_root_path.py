"""Strict trust root must come from OUTSIDE the checkout (security review 3.6).

`NOTA_APPROVER_PUBKEYS` accepts inline PEM or a file path. In strict mode a path
that resolves inside the repo is a PR-controlled file, so honoring it would
redirect the "external" trust root back into the checkout an attacker controls.
Strict loading must ignore such a path (and then fail closed for lack of trust),
while inline PEM and a genuinely external path still work.
"""

from __future__ import annotations

from pathlib import Path

from nota import attest
from nota import provenance as provenance_mod


def test_strict_rejects_approver_key_path_inside_checkout(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".nota" / "approvers").mkdir(parents=True)
    rogue = root / ".nota" / "approvers" / "human.pub"
    _, pub = attest.generate_keypair()
    rogue.write_text(pub)
    env = {provenance_mod.APPROVER_ENV: str(rogue)}  # path INSIDE the checkout
    trusted = provenance_mod.load_trusted_approvers(root, env, strict=True)
    assert trusted == {}, "a PR-controlled key path must not become a strict trust root"


def test_strict_accepts_inline_pem(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _, pub = attest.generate_keypair()
    env = {provenance_mod.APPROVER_ENV: pub}  # inline PEM, not a path
    trusted = provenance_mod.load_trusted_approvers(root, env, strict=True)
    assert len(trusted) == 1


def test_strict_accepts_external_key_path(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "outside" / "human.pub"  # outside the checkout
    external.parent.mkdir(parents=True)
    _, pub = attest.generate_keypair()
    external.write_text(pub)
    env = {provenance_mod.APPROVER_ENV: str(external)}
    trusted = provenance_mod.load_trusted_approvers(root, env, strict=True)
    assert len(trusted) == 1
