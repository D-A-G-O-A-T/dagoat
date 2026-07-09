"""
Post-quantum signature interface (PROTOCOL layer — device-agnostic).

The protocol is written against the algorithm-agnostic `Signer` / `verify` interface.
Production uses ML-DSA-65 (FIPS 204) via the proper Rust crate; the wire format
length-prefixes signatures and public keys so the exact algorithm and its byte sizes
are irrelevant to serialization.

Reference note: no ML-DSA library is available in this environment, so the reference
`ReferenceSigner` is backed by Ed25519 (via `cryptography`) purely to exercise GENUINE
asymmetric sign/verify semantics (round-trip + tamper detection) in tests. It is a
stand-in ONLY — it is NOT post-quantum. `AlgId.ML_DSA_65` and the size constants below
model the production algorithm so bandwidth math stays faithful.
"""
from abc import ABC, abstractmethod
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class AlgId(Enum):
    REFERENCE_ED25519 = 0     # reference stand-in only (NOT post-quantum)
    ML_DSA_65 = 1             # production target (FIPS 204)


# Production ML-DSA-65 sizes (bytes) — for bandwidth documentation; the wire format is
# length-prefixed, so real signatures (much larger than the reference) drop in unchanged.
ML_DSA_65_PUBKEY_BYTES = 1952
ML_DSA_65_SIG_BYTES = 3309


class Signer(ABC):
    @property
    @abstractmethod
    def alg_id(self) -> AlgId: ...

    @abstractmethod
    def public_key(self) -> bytes: ...

    @abstractmethod
    def sign(self, msg: bytes) -> bytes: ...


def verify(alg_id: AlgId, pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """Algorithm-dispatched verification using ONLY the public key."""
    if alg_id == AlgId.REFERENCE_ED25519:
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
    if alg_id == AlgId.ML_DSA_65:
        raise NotImplementedError(
            "ML-DSA-65 verify requires the production PQC crate; not available in the "
            "reference environment. Swap in the real backend behind this same function."
        )
    raise ValueError(f"unknown alg_id {alg_id}")


class ReferenceSigner(Signer):
    """Ed25519-backed stand-in for ML-DSA-65 (NOT post-quantum). Reference/testing only."""

    def __init__(self, sk: Ed25519PrivateKey = None):
        self._sk = sk or Ed25519PrivateKey.generate()

    @property
    def alg_id(self) -> AlgId:
        return AlgId.REFERENCE_ED25519

    def public_key(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


def new_reference_keypair() -> ReferenceSigner:
    return ReferenceSigner()
