"""
CapabilityRecord / DeviceCapability wire format, hash-chain, density signal (F6), and
validity predicate (PROTOCOL layer — device-agnostic).

Spec A (design note 10), with two corrections found in implementation:
  * `observed_gpu_equiv` is renamed `observed_compute_equiv` (reference-device-
    equivalents). The original name embeds a device type and violates the standing
    invariant. Density is measured in reference-device-equivalents, not any one device.
  * The commitment / signed record carries NO device-type interpretation: `class_id`
    is an opaque registry string the protocol never parses.

Serialization is canonical (field-ordered, length-prefixed TLV) so a record signs and
hashes identically on any node — the precondition for signature verification and the
hash-chain.
"""
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .types import TaskClassCap
from .pqsign import AlgId, Signer, verify

ZERO32 = b"\x00" * 32
RESIDENTIAL_DENSITY_PLAUSIBLE = 5     # a residential last-mile credibly hosts ~1-5 units


class NetworkClass(Enum):
    UNKNOWN = 0
    RESIDENTIAL = 1
    DATACENTER = 2


class DensitySignal(Enum):
    OK = 0
    DEGRADE_QNETWORK = 1     # F4: high density degrades the network score
    COHORT_MERGE = 2         # F6: residential IP + high density -> concentrated cohort


# ---- record structures (Spec A.1) ----
@dataclass(frozen=True)
class Availability:
    window_bitmap: int          # 168-bit (24h x 7d), 1 bit/hour
    expected_idle_h: int
    preempt_p50_ms: int
    preempt_p95_ms: int


@dataclass(frozen=True)
class Envelope:
    max_power_w: int
    thermal_policy_class: int


@dataclass(frozen=True)
class DensityWitness:
    endpoint_id_commit: bytes            # 32-byte commitment to the network endpoint
    observed_compute_equiv: int          # reference-device-equivalents on this endpoint


@dataclass(frozen=True)
class AttestationRefs:
    idle_score_epoch: int
    network_class: NetworkClass
    tee: bool


@dataclass(frozen=True)
class DeviceCapability:
    class_id: str
    fingerprint_commit: bytes
    task_classes: Tuple[TaskClassCap, ...]
    determinism_ref: Tuple[str, int]     # (class_id, profile_version)
    availability: Availability
    envelope: Envelope
    density_witness: DensityWitness
    attestation_refs: AttestationRefs


@dataclass(frozen=True)
class CapabilityRecord:
    version: int
    node_id: bytes                       # SHA3-256(pubkey)
    operator_binding: bytes              # commitment to staked operator identity
    epoch: int
    nonce: bytes                         # from on-chain beacon (anti-replay)
    devices: Tuple[DeviceCapability, ...]
    prev_record: bytes                   # hash-chain to previous record
    alg_id: AlgId = AlgId.REFERENCE_ED25519
    signature: bytes = b""


# ---- canonical serialization ----
def _u16(n): return int(n).to_bytes(2, "big")
def _u32(n): return int(n).to_bytes(4, "big")
def _u64(n): return int(n).to_bytes(8, "big")
def _blob(b): return _u32(len(b)) + bytes(b)
def _str(s): return _blob(s.encode("utf-8"))


def _ser_task_class(tc: TaskClassCap) -> bytes:
    out = bytearray()
    out += _u32(tc.task_class_id)
    # fixed-point gcu_rate (6 decimals) -> deterministic integer, no float in the wire
    out += _u64(round(tc.measured_gcu_rate * 1_000_000))
    out += _u32(tc.mem_capacity_mb)
    out += _u16(tc.batch_limit)
    out += _u64(tc.last_bench_epoch)
    return bytes(out)


def _ser_device(d: DeviceCapability) -> bytes:
    out = bytearray()
    out += _str(d.class_id)
    out += _blob(d.fingerprint_commit)
    out += _u32(len(d.task_classes))
    for tc in d.task_classes:
        out += _blob(_ser_task_class(tc))
    out += _str(d.determinism_ref[0]) + _u32(d.determinism_ref[1])
    a = d.availability
    out += _blob(a.window_bitmap.to_bytes(21, "big")) + _u32(a.expected_idle_h)
    out += _u32(a.preempt_p50_ms) + _u32(a.preempt_p95_ms)
    out += _u32(d.envelope.max_power_w) + _u16(d.envelope.thermal_policy_class)
    out += _blob(d.density_witness.endpoint_id_commit)
    out += _u32(d.density_witness.observed_compute_equiv)
    ar = d.attestation_refs
    out += _u64(ar.idle_score_epoch) + _u16(ar.network_class.value) + _u16(1 if ar.tee else 0)
    return bytes(out)


def serialize_unsigned(r: CapabilityRecord) -> bytes:
    out = bytearray()
    out += b"GCAP\x01"
    out += _u16(r.version)
    out += _blob(r.node_id)
    out += _blob(r.operator_binding)
    out += _u64(r.epoch)
    out += _blob(r.nonce)
    out += _u32(len(r.devices))
    for d in r.devices:
        out += _blob(_ser_device(d))
    out += _blob(r.prev_record)
    out += _u16(r.alg_id.value)
    return bytes(out)


def serialize_signed(r: CapabilityRecord) -> bytes:
    return serialize_unsigned(r) + _blob(r.signature)


def record_hash(r: CapabilityRecord) -> bytes:
    """Hash over the full SIGNED record — the hash-chain commits to exact prior bytes."""
    return hashlib.sha3_256(serialize_signed(r)).digest()


def node_id_from_pubkey(pubkey: bytes) -> bytes:
    return hashlib.sha3_256(pubkey).digest()


# ---- signing ----
def sign_record(r: CapabilityRecord, signer: Signer) -> CapabilityRecord:
    """Return a copy with node_id/alg_id/signature filled from `signer`."""
    from dataclasses import replace
    nid = node_id_from_pubkey(signer.public_key())
    base = replace(r, node_id=nid, alg_id=signer.alg_id, signature=b"")
    sig = signer.sign(serialize_unsigned(base))
    return replace(base, signature=sig)


def verify_record_signature(r: CapabilityRecord, pubkey: bytes) -> bool:
    if r.node_id != node_id_from_pubkey(pubkey):
        return False
    from dataclasses import replace
    unsigned = serialize_unsigned(replace(r, signature=b""))
    return verify(r.alg_id, pubkey, unsigned, r.signature)


# ---- F6 density signal ----
def q_network_factor(observed_compute_equiv: int) -> float:
    """F4 curve: residential score degrades sharply past the plausible device count."""
    d = max(observed_compute_equiv, 1)
    if d <= RESIDENTIAL_DENSITY_PLAUSIBLE:
        return 0.85
    return max(0.10, 0.85 * (RESIDENTIAL_DENSITY_PLAUSIBLE / d) ** 1.5)


def evaluate_density(dev: DeviceCapability) -> DensitySignal:
    """F6: on a RESIDENTIAL endpoint, density above the plausible count is evidence of a
    concentrated cohort behind residential IPs -> mark for cohort merge (clustering, item 3).
    DATACENTER endpoints are already handled by ordinary clustering; no residential-merge."""
    d = dev.density_witness.observed_compute_equiv
    nc = dev.attestation_refs.network_class
    if nc == NetworkClass.RESIDENTIAL and d > RESIDENTIAL_DENSITY_PLAUSIBLE:
        return DensitySignal.COHORT_MERGE
    return DensitySignal.OK


# ---- validity predicate (Spec A.2) ----
@dataclass
class ValidationContext:
    registered_pubkey: bytes
    expected_nonce: bytes
    last_record_hash: Optional[bytes]                  # None for the first record
    tolerance_bands: Dict[int, Tuple[float, float]]    # task_class_id -> (lo, hi) gcu/h
    prior_fingerprints: Dict[str, bytes] = field(default_factory=dict)  # class_id -> commit
    probe_observed_equiv: Dict[bytes, int] = field(default_factory=dict)  # endpoint -> count
    density_underclaim_slack: int = 1


@dataclass
class ValidationResult:
    ok: bool
    checks: Dict[str, bool]
    reasons: List[str]
    density_signals: Dict[str, DensitySignal]          # per device class_id


def validate_record(r: CapabilityRecord, ctx: ValidationContext) -> ValidationResult:
    checks: Dict[str, bool] = {}
    reasons: List[str] = []

    checks["signature"] = verify_record_signature(r, ctx.registered_pubkey)
    if not checks["signature"]:
        reasons.append("signature/node_id mismatch")

    checks["nonce"] = (r.nonce == ctx.expected_nonce)
    if not checks["nonce"]:
        reasons.append("nonce does not match epoch beacon (possible replay)")

    expected_prev = ctx.last_record_hash if ctx.last_record_hash is not None else ZERO32
    checks["chain"] = (r.prev_record == expected_prev)
    if not checks["chain"]:
        reasons.append("prev_record does not chain to last accepted record")

    gcu_ok, fp_ok, density_ok = True, True, True
    signals: Dict[str, DensitySignal] = {}
    for d in r.devices:
        for tc in d.task_classes:
            band = ctx.tolerance_bands.get(tc.task_class_id)
            if band is not None and not (band[0] <= tc.measured_gcu_rate <= band[1]):
                gcu_ok = False
                reasons.append(f"{d.class_id} tc{tc.task_class_id} rate {tc.measured_gcu_rate} "
                               f"outside registry band {band}")
        prior = ctx.prior_fingerprints.get(d.class_id)
        if prior is not None and prior != d.fingerprint_commit:
            fp_ok = False
            reasons.append(f"{d.class_id} fingerprint drift (triggers re-benchmark)")
        # F6 cross-check: node must not under-declare density vs. probe observation
        probe = ctx.probe_observed_equiv.get(d.density_witness.endpoint_id_commit)
        if probe is not None and d.density_witness.observed_compute_equiv < probe - ctx.density_underclaim_slack:
            density_ok = False
            reasons.append(f"{d.class_id} density under-declared "
                           f"(claimed {d.density_witness.observed_compute_equiv} vs probe {probe})")
        # evaluate on the probe-observed value when available (defeats under-declaration)
        eff = DeviceCapability(
            d.class_id, d.fingerprint_commit, d.task_classes, d.determinism_ref,
            d.availability, d.envelope,
            DensityWitness(d.density_witness.endpoint_id_commit,
                           probe if probe is not None else d.density_witness.observed_compute_equiv),
            d.attestation_refs)
        signals[d.class_id] = evaluate_density(eff)

    checks["gcu_tolerance"] = gcu_ok
    checks["fingerprint_stable"] = fp_ok
    checks["density_consistent"] = density_ok

    # Hard checks gate acceptance. Fingerprint drift is a SOFT signal (Spec A.3: single
    # mismatch triggers re-benchmark; sustained mismatch flags the node) and is reported
    # but does not by itself reject the record.
    hard = ["signature", "nonce", "chain", "gcu_tolerance", "density_consistent"]
    ok = all(checks[k] for k in hard)
    return ValidationResult(ok=ok, checks=checks, reasons=reasons, density_signals=signals)
