"""
Item-2 demo: a node builds a signed CapabilityRecord with two devices (one plausible
residential density, one over-dense residential endpoint), an orchestrator validates it,
the F6 density signal fires on the over-dense device, and finally a tampered record and a
broken chain link are rejected.

Run from `reference/`:  python demo_item2.py
"""
from dataclasses import replace

from goathal.pqsign import ReferenceSigner, ML_DSA_65_SIG_BYTES, ML_DSA_65_PUBKEY_BYTES
from goathal.capability import (
    record_hash, verify_record_signature, validate_record, ValidationContext,
    evaluate_density, DensitySignal, NetworkClass, ZERO32,
)
from goathal.attestation_chain import RecordChain, ChainError
from tests._capfixtures import make_device, make_signed_record


def main():
    signer = ReferenceSigner()
    nonce = b"beacon-epoch-1".ljust(32, b"\x00")

    dev_ok = make_device(class_id="cls.a.v1", gcu_rate=1.0, endpoint=b"home-1".ljust(32, b"\x00"),
                         density=2, netclass=NetworkClass.RESIDENTIAL)
    dev_dense = make_device(class_id="cls.b.v1", gcu_rate=0.15, endpoint=b"warehouse".ljust(32, b"\x00"),
                            density=40, netclass=NetworkClass.RESIDENTIAL)

    rec = make_signed_record(signer, [dev_ok, dev_dense], epoch=1, nonce=nonce, prev=ZERO32)
    print("=== node produced a CapabilityRecord ===")
    print(f"  node_id      {rec.node_id.hex()[:16]}...")
    print(f"  alg_id       {rec.alg_id.name}  (production: ML-DSA-65, "
          f"pubkey {ML_DSA_65_PUBKEY_BYTES}B / sig {ML_DSA_65_SIG_BYTES}B)")
    print(f"  signature    {len(rec.signature)}B (reference)  verifies={verify_record_signature(rec, signer.public_key())}")
    print(f"  devices      {[d.class_id for d in rec.devices]}")

    ctx = ValidationContext(
        registered_pubkey=signer.public_key(), expected_nonce=nonce,
        last_record_hash=None, tolerance_bands={10: (0.1, 1.2)})
    res = validate_record(rec, ctx)
    print("\n=== orchestrator validation ===")
    for k, v in res.checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"  overall ok = {res.ok}")

    print("\n=== F6 density signals ===")
    for d in rec.devices:
        sig = evaluate_density(d)
        note = "-> mark for cohort merge (concentrated cohort behind a residential IP)" \
            if sig == DensitySignal.COHORT_MERGE else ""
        print(f"  {d.class_id}: density={d.density_witness.observed_compute_equiv} "
              f"net={d.attestation_refs.network_class.name} -> {sig.name} {note}")

    print("\n=== tamper & chain integrity ===")
    tampered = replace(rec, epoch=999)
    print(f"  tampered record verifies = {verify_record_signature(tampered, signer.public_key())} (expect False)")

    chain = RecordChain(signer.public_key())
    chain.append(rec)
    r2 = make_signed_record(signer, [dev_ok], epoch=2, nonce=nonce, prev=chain.head_hash)
    chain.append(r2)
    print(f"  chain length = {chain.length}, integrity = {chain.verify_integrity()}")
    bad = make_signed_record(signer, [dev_ok], epoch=3, nonce=nonce, prev=b"\x99" * 32)
    try:
        chain.append(bad)
        print("  BUG: broken link accepted")
    except ChainError as e:
        print(f"  broken chain link rejected: {e}")


if __name__ == "__main__":
    main()
