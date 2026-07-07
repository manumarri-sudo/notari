"""Tests for the Ed25519 attestation primitives.

The security property under test is the one HMAC could not give us: a party who
can *verify* (holds the public key) cannot *forge* (needs the private key), and
any tampering with the signed payload invalidates the signature.
"""

from __future__ import annotations

import pytest

from quill import attest


def test_roundtrip_sign_verify() -> None:
    priv_pem, pub_pem = attest.generate_keypair()
    priv = attest.load_private_key(priv_pem)
    pub = attest.load_public_key(pub_pem)
    payload = {"task": "add rate limit", "scope": ["src/auth/**"]}
    sig = attest.sign_payload(payload, priv)
    assert attest.verify_payload(payload, sig, pub) is True


def test_canonical_is_order_independent() -> None:
    a = attest.canonical_bytes({"b": 1, "a": 2})
    b = attest.canonical_bytes({"a": 2, "b": 1})
    assert a == b


def test_tampered_payload_fails() -> None:
    """The dangerous twin: change one field after signing -> signature invalid."""
    priv_pem, pub_pem = attest.generate_keypair()
    priv = attest.load_private_key(priv_pem)
    pub = attest.load_public_key(pub_pem)
    payload = {"verdict": "PASS", "scope": ["src/auth/**"]}
    sig = attest.sign_payload(payload, priv)

    forged = {"verdict": "PASS", "scope": ["**"]}  # agent widens scope post-sign
    assert attest.verify_payload(forged, sig, pub) is False


def test_wrong_key_cannot_forge() -> None:
    """A different keypair (an agent's own key) cannot produce a valid sig."""
    approver_priv = attest.load_private_key(attest.generate_keypair()[0])
    _, approver_pub_pem = attest.generate_keypair()  # unrelated approver pubkey
    approver_pub = attest.load_public_key(approver_pub_pem)
    payload = {"task": "x"}
    sig = attest.sign_payload(payload, approver_priv)  # signed by the wrong key
    # key_id mismatch alone makes this False, before any crypto check.
    assert attest.verify_payload(payload, sig, approver_pub) is False


def test_verify_against_any_picks_the_signer() -> None:
    p1, pub1 = attest.generate_keypair()
    p2, pub2 = attest.generate_keypair()
    priv1 = attest.load_private_key(p1)
    trusted = {
        attest.key_id(attest.load_public_key(pub1)): attest.load_public_key(pub1),
        attest.key_id(attest.load_public_key(pub2)): attest.load_public_key(pub2),
    }
    payload = {"task": "x"}
    sig = attest.sign_payload(payload, priv1)
    matched = attest.verify_against_any(payload, sig, trusted)
    assert matched == attest.key_id(priv1.public_key())


def test_verify_against_any_rejects_untrusted_signer() -> None:
    """An agent signs with its own key; that key is not in the trusted set."""
    rogue = attest.load_private_key(attest.generate_keypair()[0])
    _, trusted_pub = attest.generate_keypair()
    trusted = {
        attest.key_id(attest.load_public_key(trusted_pub)): attest.load_public_key(trusted_pub)
    }
    payload = {"task": "x"}
    sig = attest.sign_payload(payload, rogue)
    assert attest.verify_against_any(payload, sig, trusted) is None


def test_signature_serialization_roundtrip() -> None:
    priv = attest.load_private_key(attest.generate_keypair()[0])
    sig = attest.sign_payload({"a": 1}, priv)
    again = attest.Signature.from_dict(sig.to_dict())
    assert again == sig


def test_malformed_signature_b64_is_false_not_raise() -> None:
    _, pub_pem = attest.generate_keypair()
    pub = attest.load_public_key(pub_pem)
    bad = attest.Signature(alg="ed25519", key_id=attest.key_id(pub), signature_b64="!!notb64!!")
    assert attest.verify_payload({"a": 1}, bad, pub) is False


def test_load_garbage_key_raises() -> None:
    with pytest.raises(attest.AttestError):
        attest.load_private_key("not a pem")
    with pytest.raises(attest.AttestError):
        attest.load_public_key("not a pem")
