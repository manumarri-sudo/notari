"""Asymmetric attestation: the off-box root of trust for Change Control.

The HMAC audit chain (``audit.py``) is *tamper-evident* but not *tamper-proof*:
its key is symmetric, so whoever can verify the chain can also forge it, and on
a compromised host that key is readable. That is fine for a local recorder, but
it cannot answer the question Change Control actually has to answer - *can the
agent that wrote the diff also forge its own approval and its own verdict?*

This module answers "no" with Ed25519:

  * **Contracts are signed by a human approver.** The private approver key never
    lives in the repo or on the build machine. ``quill verify`` checks the
    contract signature against a set of *trusted approver public keys*. An agent
    can edit ``contract.json`` all it likes - without the approver's private key
    it cannot produce a valid signature, so a forged or widened contract fails
    provenance. Verification is public (the pubkey), forging is private (the
    privkey); the two are not the same key, which is exactly what HMAC could not
    give us.

  * **Passports are signed by the gate identity.** The verdict is signed with a
    key that, in CI, is an OIDC/secret identity the PR cannot read. Anyone can
    re-verify a passport with ``quill verify-passport`` against the gate's public
    key; nobody without the private key can mint a new "PASS".

No key material is generated implicitly. Keys are created explicitly with
``quill keygen`` and held by the human / the CI identity, off the agent's box.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from quill.errors import QuillError

ALG = "ed25519"


class AttestError(QuillError):
    """Raised when a key is malformed or a signing/verification step fails."""


# --------------------------------------------------------------------------- #
# Canonicalization                                                            #
# --------------------------------------------------------------------------- #


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used as the signed payload.

    Sorted keys, no insignificant whitespace, UTF-8. The same object always
    yields the same bytes regardless of dict insertion order, so a signature is
    stable across processes and re-serializations.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# --------------------------------------------------------------------------- #
# Keys                                                                        #
# --------------------------------------------------------------------------- #


def key_id(pub: Ed25519PublicKey) -> str:
    """Short stable identifier for a public key: sha256 of its raw bytes."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 keypair."""
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as e:
        msg = f"not a valid PEM private key: {e}"
        raise AttestError(msg) from e
    if not isinstance(key, Ed25519PrivateKey):
        msg = "private key is not Ed25519"
        raise AttestError(msg)
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError) as e:
        msg = f"not a valid PEM public key: {e}"
        raise AttestError(msg) from e
    if not isinstance(key, Ed25519PublicKey):
        msg = "public key is not Ed25519"
        raise AttestError(msg)
    return key


# --------------------------------------------------------------------------- #
# Sign / verify                                                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Signature:
    """A detached signature plus the id of the key that produced it."""

    alg: str
    key_id: str
    signature_b64: str

    def to_dict(self) -> dict[str, str]:
        return {"alg": self.alg, "key_id": self.key_id, "signature": self.signature_b64}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Signature:
        try:
            return cls(
                alg=str(data["alg"]),
                key_id=str(data["key_id"]),
                signature_b64=str(data["signature"]),
            )
        except (KeyError, TypeError) as e:
            msg = f"malformed signature object: {e}"
            raise AttestError(msg) from e


def sign_payload(payload: Any, priv: Ed25519PrivateKey) -> Signature:
    """Sign the canonical encoding of `payload` with `priv`."""
    raw_sig = priv.sign(canonical_bytes(payload))
    return Signature(
        alg=ALG,
        key_id=key_id(priv.public_key()),
        signature_b64=base64.b64encode(raw_sig).decode(),
    )


def verify_payload(payload: Any, sig: Signature, pub: Ed25519PublicKey) -> bool:
    """True iff `sig` is a valid signature over `payload` under `pub`.

    Fail-closed: any malformed signature, algorithm mismatch, or key-id mismatch
    returns False rather than raising, so a verifier loop can simply treat the
    key as "did not sign this".
    """
    if sig.alg != ALG:
        return False
    if sig.key_id != key_id(pub):
        return False
    try:
        raw_sig = base64.b64decode(sig.signature_b64, validate=True)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return False
    try:
        pub.verify(raw_sig, canonical_bytes(payload))
    except InvalidSignature:
        return False
    return True


def verify_against_any(
    payload: Any, sig: Signature, trusted: dict[str, Ed25519PublicKey]
) -> str | None:
    """Return the trusted key_id that validates `sig` over `payload`, or None.

    `trusted` maps key_id -> public key. This is the multi-approver / multi-gate
    case: a payload is authentic if *any* trusted key signed it.
    """
    pub = trusted.get(sig.key_id)
    if pub is None:
        return None
    return sig.key_id if verify_payload(payload, sig, pub) else None
