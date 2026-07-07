"""Provenance: prove a *human* signed this governance artifact, not the agent.

`quill verify` trusts on-disk JSON (a contract, or a standing perimeter) to say
what was approved. On its own that file is forgeable: the same agent that writes
the diff can write the file. Provenance closes the hole by requiring the artifact
to carry an Ed25519 signature from a *trusted approver* whose private key lives
off the agent's box.

This module is artifact-agnostic - it signs and verifies any payload dict and
stores a detached ``.sig`` beside it - so both the per-task **contract** and the
sign-once standing **perimeter** use the same trust root. The perimeter is the
answer to "I don't want to approve every change": a human signs the boundary
*once*, and every PR from every agent is checked against it autonomously, with a
human paged only on a violation.

Where the trust root lives (escalating adversarial strength):

  1. ``.quill/approvers/*.pub`` - committed public keys. Convenient for a
     cooperative team, but an agent could add its own pubkey here, so this
     directory is a gate-tamper surface (editing it BLOCKs) and is only the
     convenience layer.
  2. ``QUILL_APPROVER_PUBKEYS`` env - newline-separated PEM blocks or file paths,
     supplied as a CI secret / org variable the PR cannot edit. The
     adversarially-safe pin.
"""

from __future__ import annotations

import enum
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from quill import attest

APPROVER_ENV = "QUILL_APPROVER_PUBKEYS"


def approvers_dir(root: Path) -> Path:
    return root / ".quill" / "approvers"


class ProvenanceStatus(str, enum.Enum):
    OK = "signed-trusted"  # valid signature from a trusted approver
    UNSIGNED = "unsigned"  # no signature file present
    BAD_SIGNATURE = "bad-signature"  # present but invalid / untrusted signer / artifact edited
    NO_APPROVERS = "no-approvers"  # no trusted approver keys configured at all

    @property
    def is_trustworthy(self) -> bool:
        return self is ProvenanceStatus.OK


@dataclass(frozen=True)
class ProvenanceResult:
    status: ProvenanceStatus
    key_id: str | None  # the trusted approver key that signed, when OK
    detail: str
    approver_count: int


# --------------------------------------------------------------------------- #
# Trusted approver keys                                                       #
# --------------------------------------------------------------------------- #


def _split_pem_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        current.append(line)
        if "END PUBLIC KEY" in line:
            blocks.append("\n".join(current))
            current = []
    return [b for b in blocks if "BEGIN PUBLIC KEY" in b]


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def _load_pubkeys_from_env(
    env: dict[str, str] | None = None,
    *,
    root: Path | None = None,
    strict: bool = False,
) -> dict[str, Ed25519PublicKey]:
    raw = (env or os.environ).get(APPROVER_ENV, "").strip()
    if not raw:
        return {}
    # Entries: PEM blocks inline, or paths to .pub files, separated by commas or
    # blank lines. Resolve paths first, then split the combined text on PEM
    # boundaries so multi-line blocks survive.
    pieces: list[str] = []
    for raw_chunk in raw.replace(",", "\n\n").split("\n\n"):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        p = Path(chunk).expanduser()
        if "BEGIN" not in chunk and p.is_file():
            # Strict trust must come from OUTSIDE the checkout (an off-box CI
            # secret), so reject a path that resolves inside the repo: otherwise
            # `QUILL_APPROVER_PUBKEYS=.quill/approvers/human.pub` would redirect
            # the "external" trust root back into a PR-controlled file (security
            # review: trust-root path indirection). Inline PEM is always allowed.
            if strict and root is not None and _is_inside(p, root):
                continue
            pieces.append(p.read_text())
        else:
            pieces.append(chunk)
    out: dict[str, Ed25519PublicKey] = {}
    for pem in _split_pem_blocks("\n".join(pieces)):
        try:
            pub = attest.load_public_key(pem)
        except attest.AttestError:
            continue
        out[attest.key_id(pub)] = pub
    return out


def _load_pubkeys_from_dir(root: Path) -> dict[str, Ed25519PublicKey]:
    d = approvers_dir(root)
    if not d.is_dir():
        return {}
    out: dict[str, Ed25519PublicKey] = {}
    for f in sorted(d.glob("*.pub")):
        try:
            pub = attest.load_public_key(f.read_text())
        except (OSError, attest.AttestError):
            continue
        out[attest.key_id(pub)] = pub
    return out


def load_trusted_approvers(
    root: Path, env: dict[str, str] | None = None, *, strict: bool = False
) -> dict[str, Ed25519PublicKey]:
    """Trusted approver public keys.

    In **strict** mode only the env-pinned keys (a CI secret a PR can't edit) are
    trusted; the committed ``.quill/approvers/*.pub`` set is IGNORED. This closes
    the composite bypass (security re-review): an attacker can plant a rogue key
    in the base commit where gate-tamper can't see it (the diff starts after it),
    then sign its own perimeter and contract with it. Trusting only the external
    pin means a planted key is never a trust root. In cooperative mode the
    committed set is a convenience and the env pin merges over it.
    """
    if strict:
        return _load_pubkeys_from_env(env, root=root, strict=True)
    keys = _load_pubkeys_from_dir(root)
    keys.update(_load_pubkeys_from_env(env))
    return keys


# --------------------------------------------------------------------------- #
# Sign / verify any artifact                                                  #
# --------------------------------------------------------------------------- #


def load_signature(sig_path: Path) -> attest.Signature | None:
    if not sig_path.exists():
        return None
    try:
        return attest.Signature.from_dict(json.loads(sig_path.read_text()))
    except (OSError, json.JSONDecodeError, attest.AttestError):
        return None


def write_signature(sig_path: Path, sig: attest.Signature) -> Path:
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_text(json.dumps(sig.to_dict(), indent=2) + "\n")
    return sig_path


def sign_artifact(payload: Any, private_pem: str, sig_path: Path) -> attest.Signature:
    """Sign `payload` (canonical JSON) with an approver private key; persist the sig."""
    priv = attest.load_private_key(private_pem)
    sig = attest.sign_payload(payload, priv)
    write_signature(sig_path, sig)
    return sig


def verify_artifact(
    payload: Any,
    sig_path: Path,
    root: Path,
    env: dict[str, str] | None = None,
    *,
    strict: bool = False,
) -> ProvenanceResult:
    """Check whether `payload` carries a valid signature from a trusted approver.

    The signature is verified over the *exact* payload, so any tamper (scope
    widened, a forbidden path removed) breaks it, and only the approver's private
    key can re-sign. In strict mode only externally-pinned keys are trusted (see
    ``load_trusted_approvers``), so a key committed to the PR is never a trust root.
    """
    trusted = load_trusted_approvers(root, env, strict=strict)
    sig = load_signature(sig_path)

    if not trusted:
        return ProvenanceResult(
            ProvenanceStatus.NO_APPROVERS,
            None,
            (
                f"no externally-pinned approver keys (set {APPROVER_ENV})"
                if strict
                else f"no trusted approver keys (add .quill/approvers/*.pub or set {APPROVER_ENV})"
            ),
            0,
        )
    if sig is None:
        return ProvenanceResult(
            ProvenanceStatus.UNSIGNED,
            None,
            "artifact is not signed; run `quill guard --key <approver.pem>` or `quill begin --key <approver.pem>`",
            len(trusted),
        )
    matched = attest.verify_against_any(payload, sig, trusted)
    if matched is None:
        return ProvenanceResult(
            ProvenanceStatus.BAD_SIGNATURE,
            None,
            "signature is invalid or from an untrusted key (was the artifact edited after approval?)",
            len(trusted),
        )
    return ProvenanceResult(
        ProvenanceStatus.OK, matched, f"signed by trusted approver {matched}", len(trusted)
    )
