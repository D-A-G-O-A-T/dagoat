"""Shared builders for Item-2 tests/demo (test helper, not protocol code)."""
from goathal.types import TaskClassCap
from goathal.capability import (
    CapabilityRecord, DeviceCapability, Availability, Envelope, DensityWitness,
    AttestationRefs, NetworkClass, sign_record, ZERO32,
)
from goathal.pqsign import ReferenceSigner


def make_device(class_id="cls.a.v1", gcu_rate=1.0, endpoint=b"E" * 32,
                density=1, netclass=NetworkClass.RESIDENTIAL, fp=b"\xab" * 32,
                task_class_id=10):
    return DeviceCapability(
        class_id=class_id,
        fingerprint_commit=fp,
        task_classes=(TaskClassCap(task_class_id, gcu_rate, 24000, 32, 0),),
        determinism_ref=(class_id, 1),
        availability=Availability(window_bitmap=(1 << 100), expected_idle_h=8,
                                  preempt_p50_ms=10, preempt_p95_ms=40),
        envelope=Envelope(max_power_w=200, thermal_policy_class=1),
        density_witness=DensityWitness(endpoint_id_commit=endpoint,
                                       observed_compute_equiv=density),
        attestation_refs=AttestationRefs(idle_score_epoch=0, network_class=netclass, tee=False),
    )


def make_signed_record(signer: ReferenceSigner, devices, epoch=1,
                       nonce=b"N" * 32, prev=ZERO32, operator=b"O" * 32, version=1):
    rec = CapabilityRecord(
        version=version, node_id=b"", operator_binding=operator,
        epoch=epoch, nonce=nonce, devices=tuple(devices), prev_record=prev,
    )
    return sign_record(rec, signer)
