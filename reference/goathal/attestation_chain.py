"""
Hash-chain and rolling re-attestation rules (PROTOCOL layer — device-agnostic).
Spec A.3.

The chain is append-only and tamper-evident: each record's `prev_record` commits to the
exact prior signed record bytes, so altering any past record breaks every later link.
"""
from dataclasses import dataclass
from typing import List, Optional

from .capability import CapabilityRecord, record_hash, verify_record_signature, ZERO32


class ChainError(Exception):
    pass


class RecordChain:
    """Per-node append-only capability history."""

    def __init__(self, pubkey: bytes):
        self._pubkey = pubkey
        self._records: List[CapabilityRecord] = []

    @property
    def head_hash(self) -> bytes:
        return record_hash(self._records[-1]) if self._records else ZERO32

    @property
    def length(self) -> int:
        return len(self._records)

    def append(self, r: CapabilityRecord) -> None:
        if not verify_record_signature(r, self._pubkey):
            raise ChainError("signature/node_id invalid")
        if r.prev_record != self.head_hash:
            raise ChainError(
                f"prev_record {r.prev_record.hex()[:8]} != head {self.head_hash.hex()[:8]}")
        if self._records and r.epoch <= self._records[-1].epoch:
            raise ChainError("epoch must strictly increase")
        self._records.append(r)

    def verify_integrity(self) -> bool:
        """Recompute the whole chain: every link must hold and every signature verify."""
        prev = ZERO32
        for r in self._records:
            if not verify_record_signature(r, self._pubkey):
                return False
            if r.prev_record != prev:
                return False
            prev = record_hash(r)
        return True


# ---- rolling re-attestation rules (Spec A.3) ----
DEFAULT_MAX_BENCH_AGE_EPOCHS = 30 * 24     # ~30 days at hourly attestation epochs


def staleness_weight(record_epoch: int, current_epoch: int,
                     declared_cadence_epochs: int) -> float:
    """A node may declare a longer attestation cadence for bandwidth reasons. Within its
    declared cadence it is full-weight; beyond it, capability is treated as lower-
    confidence and weighted down (NEVER penalized — just less work). Returns (0, 1]."""
    age = max(current_epoch - record_epoch, 0)
    if age <= declared_cadence_epochs:
        return 1.0
    return max(0.1, declared_cadence_epochs / age)


def needs_rebenchmark(last_bench_epoch: int, current_epoch: int,
                      fingerprint_changed: bool, profile_version_changed: bool,
                      max_age_epochs: int = DEFAULT_MAX_BENCH_AGE_EPOCHS) -> bool:
    """Re-benchmark on driver/hardware change (fingerprint drift), registry profile bump,
    or age. A refresh outside tolerance re-probates that device only (handled upstream)."""
    return (fingerprint_changed
            or profile_version_changed
            or (current_epoch - last_bench_epoch) >= max_age_epochs)
