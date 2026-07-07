"""Merkle transparency log: make tampering and deletion *provable*, not just blocked.

The gap the signed passport alone leaves open: an agent on a machine it controls
can delete its local evidence and pretend nothing happened. You cannot stop
deletion of a file on the attacker's own box - but you can make it so that any
deletion or rewrite of *already-recorded* history is detectable by anyone,
forever, from a single tiny anchor.

That is what a Merkle transparency log does (the same structure behind
Certificate Transparency and Sigstore's Rekor). Every passport becomes a leaf.
The log has a 32-byte root that changes if *any* leaf changes. Periodically the
gate signs the current ``(size, root)`` - a **signed tree head** - and that 32
bytes gets anchored somewhere off the agent's reach (a GitHub Status, an
evidence branch, a public log). From then on:

  * Rewrite any already-anchored leaf  -> the recomputed root no longer matches
    the anchored, signed root.          (tamper is provable)
  * Delete leaves below the anchored size -> same: the prefix no longer hashes
    to the anchored root.               (deletion is provable)
  * Forge a fresh "clean" root          -> impossible without the off-box signing
                                          key (asymmetric, not on the box).

You still cannot prevent the agent from deleting its *local copy*; you make that
act leave an un-erasable, third-party-verifiable hole. Implements RFC 6962 leaf/
node hashing and inclusion proofs; consistency is verified by re-deriving each
anchored prefix root (sound; Rekor's compact consistency proofs are the
light-client optimization, noted in the roadmap).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from quill import attest

# RFC 6962 domain separation: leaves are prefixed 0x00, internal nodes 0x01, so
# a leaf can never be reinterpreted as an internal node (second-preimage guard).
_LEAF = b"\x00"
_NODE = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def _k(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over `leaves` (each is raw leaf data)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _k(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """Audit path proving leaf m is in the tree of `leaves` (ordered leaf->root)."""
    n = len(leaves)
    if not 0 <= m < n:
        msg = f"index {m} out of range for {n} leaves"
        raise IndexError(msg)
    if n == 1:
        return []
    k = _k(n)
    if m < k:
        return [*inclusion_proof(leaves[:k], m), merkle_root(leaves[k:])]
    return [*inclusion_proof(leaves[k:], m - k), merkle_root(leaves[:k])]


def _root_from_proof(leaf_data: bytes, m: int, n: int, proof: list[bytes]) -> bytes:
    """Reconstruct the root from a leaf + its inclusion proof (mirrors the prover)."""
    if n == 1:
        if proof:
            raise ValueError("non-empty proof for single-leaf tree")
        return _leaf_hash(leaf_data)
    sibling = proof[-1]
    inner = proof[:-1]
    k = _k(n)
    if m < k:
        return _node_hash(_root_from_proof(leaf_data, m, k, inner), sibling)
    return _node_hash(sibling, _root_from_proof(leaf_data, m - k, n - k, inner))


def verify_inclusion(leaf_data: bytes, m: int, n: int, proof: list[bytes], root: bytes) -> bool:
    """True iff `proof` proves `leaf_data` sits at index m of a size-n tree with `root`."""
    if not 0 <= m < n:
        return False
    try:
        return _root_from_proof(leaf_data, m, n, list(proof)) == root
    except (ValueError, IndexError):
        return False


# --------------------------------------------------------------------------- #
# Signed tree head — the 32 bytes you anchor off-box                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SignedTreeHead:
    size: int
    root_hex: str
    signature: dict[str, str] | None  # attest.Signature.to_dict(), or None if unsigned

    def body(self) -> dict[str, Any]:
        return {"size": self.size, "root": self.root_hex}

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        if self.signature is not None:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedTreeHead:
        return cls(
            size=int(data["size"]),
            root_hex=str(data["root"]),
            signature=data.get("signature"),
        )


# --------------------------------------------------------------------------- #
# The log                                                                     #
# --------------------------------------------------------------------------- #


class MerkleLog:
    """An append-only log of leaf data, persisted one hex line per leaf.

    The file lives on disk (and is therefore deletable by whoever owns the box -
    that is unavoidable); its integrity is protected by anchoring signed tree
    heads off-box, not by the file's own permissions.
    """

    def __init__(self, leaves: list[bytes] | None = None) -> None:
        self._leaves: list[bytes] = list(leaves or [])

    @classmethod
    def load(cls, path: Path) -> MerkleLog:
        if not path.exists():
            return cls([])
        leaves = [bytes.fromhex(ln) for ln in path.read_text().split() if ln.strip()]
        return cls(leaves)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(leaf.hex() + "\n" for leaf in self._leaves))

    def __len__(self) -> int:
        return len(self._leaves)

    def append(self, data: bytes) -> int:
        """Append leaf data (e.g. a passport digest); return its index."""
        self._leaves.append(data)
        return len(self._leaves) - 1

    def root(self) -> bytes:
        return merkle_root(self._leaves)

    def inclusion_proof(self, m: int) -> list[bytes]:
        return inclusion_proof(self._leaves, m)

    def head(self, sign_key_pem: str | None = None) -> SignedTreeHead:
        """Current ``(size, root)``, signed by the gate key when one is given."""
        size = len(self._leaves)
        root_hex = self.root().hex()
        sig = None
        if sign_key_pem:
            priv = attest.load_private_key(sign_key_pem)
            sig = attest.sign_payload({"size": size, "root": root_hex}, priv).to_dict()
        return SignedTreeHead(size=size, root_hex=root_hex, signature=sig)

    def prefix_root(self, size: int) -> bytes:
        """Root over the first `size` leaves — used to re-derive an anchored head."""
        return merkle_root(self._leaves[:size])


def verify_head_signature(
    head: SignedTreeHead, gate_keys: dict[str, Ed25519PublicKey]
) -> str | None:
    """Return the trusted gate key_id that signed `head`, or None."""
    if head.signature is None:
        return None
    try:
        sig = attest.Signature.from_dict(head.signature)
    except attest.AttestError:
        return None
    return attest.verify_against_any(head.body(), sig, gate_keys)


@dataclass(frozen=True)
class TamperCheck:
    intact: bool
    detail: str


def check_against_anchor(
    log: MerkleLog,
    anchored: SignedTreeHead,
    gate_keys: dict[str, Ed25519PublicKey],
) -> TamperCheck:
    """Detect any rewrite or deletion of history below a previously-anchored head.

    `anchored` is a signed tree head you trust because it was published off-box.
    This (1) verifies the anchor's signature, (2) checks the log still has at
    least `anchored.size` leaves (else trailing deletion), and (3) re-derives the
    root over the first `anchored.size` leaves and compares it to the anchored
    root. Any tamper to already-recorded history fails (3); deletion fails (2);
    a forged anchor fails (1).
    """
    if verify_head_signature(anchored, gate_keys) is None:
        return TamperCheck(False, "anchored tree head is unsigned or from an untrusted key")
    if len(log) < anchored.size:
        return TamperCheck(
            False,
            f"log has {len(log)} leaves but {anchored.size} were anchored — "
            "trailing entries were deleted",
        )
    if log.prefix_root(anchored.size).hex() != anchored.root_hex:
        return TamperCheck(
            False,
            "the first "
            f"{anchored.size} leaves no longer match the anchored root — history was rewritten",
        )
    return TamperCheck(
        True, f"intact: {anchored.size} anchored leaves verified against the signed root"
    )
