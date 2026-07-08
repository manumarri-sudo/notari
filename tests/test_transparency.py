"""Tests for the Merkle transparency log.

The property under test: once a signed tree head is anchored, any later rewrite
or deletion of recorded history is *detectable*, and a fresh "clean" head cannot
be forged without the off-box signing key.
"""

from __future__ import annotations

from nota import attest
from nota import transparency as tl


def _leaves(n: int) -> list[bytes]:
    return [f"passport-{i}".encode() for i in range(n)]


def test_root_is_deterministic_and_single_leaf_matches() -> None:
    assert tl.merkle_root([b"x"]) == tl._leaf_hash(b"x")
    assert tl.merkle_root(_leaves(5)) == tl.merkle_root(_leaves(5))


def test_inclusion_proof_verifies_every_index() -> None:
    for n in range(1, 12):
        leaves = _leaves(n)
        root = tl.merkle_root(leaves)
        for m in range(n):
            proof = tl.inclusion_proof(leaves, m)
            assert tl.verify_inclusion(leaves[m], m, n, proof, root) is True


def test_tampered_leaf_breaks_inclusion() -> None:
    leaves = _leaves(6)
    root = tl.merkle_root(leaves)
    proof = tl.inclusion_proof(leaves, 3)
    assert tl.verify_inclusion(b"forged", 3, 6, proof, root) is False


def test_signed_head_verifies_and_forgery_rejected() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    log = tl.MerkleLog(_leaves(4))
    head = log.head(sign_key_pem=priv_pem)
    pub = attest.load_public_key(pub_pem)
    keys = {attest.key_id(pub): pub}
    assert tl.verify_head_signature(head, keys) == attest.key_id(pub)

    # a different (untrusted) gate key cannot validate it
    _, other_pub = attest.generate_keypair()
    op = attest.load_public_key(other_pub)
    assert tl.verify_head_signature(head, {attest.key_id(op): op}) is None


def test_anchor_detects_rewrite_of_history() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    pub = attest.load_public_key(pub_pem)
    keys = {attest.key_id(pub): pub}

    log = tl.MerkleLog(_leaves(5))
    anchored = log.head(sign_key_pem=priv_pem)  # published off-box at size 5
    assert tl.check_against_anchor(log, anchored, keys).intact is True

    # agent rewrites an already-anchored leaf
    tampered = tl.MerkleLog([*_leaves(2), b"backdoor", *_leaves(5)[3:]])
    res = tl.check_against_anchor(tampered, anchored, keys)
    assert res.intact is False
    assert "rewritten" in res.detail


def test_anchor_detects_deletion() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    pub = attest.load_public_key(pub_pem)
    keys = {attest.key_id(pub): pub}

    anchored = tl.MerkleLog(_leaves(5)).head(sign_key_pem=priv_pem)
    shrunk = tl.MerkleLog(_leaves(3))  # agent deleted the last two entries
    res = tl.check_against_anchor(shrunk, anchored, keys)
    assert res.intact is False
    assert "deleted" in res.detail


def test_anchor_allows_honest_append() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    pub = attest.load_public_key(pub_pem)
    keys = {attest.key_id(pub): pub}

    anchored = tl.MerkleLog(_leaves(5)).head(sign_key_pem=priv_pem)
    grown = tl.MerkleLog(_leaves(8))  # first 5 unchanged, 3 appended
    assert tl.check_against_anchor(grown, anchored, keys).intact is True


def test_unsigned_or_untrusted_anchor_is_rejected() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    pub = attest.load_public_key(pub_pem)
    keys = {attest.key_id(pub): pub}

    log = tl.MerkleLog(_leaves(5))
    unsigned = log.head()  # no signature
    assert tl.check_against_anchor(log, unsigned, keys).intact is False


def test_persistence_roundtrip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "tlog"
    log = tl.MerkleLog()
    log.append(b"a")
    log.append(b"b")
    log.save(p)
    again = tl.MerkleLog.load(p)
    assert again.root() == log.root()
    assert len(again) == 2
