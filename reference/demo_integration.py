"""
GoatCoin (GOAT) - Phase 3 integration demo: the full loop across Items 1–4.

  Act 1  Conformance: two device classes pass the D.1 suite (Item 1)
  Act 2  Capability: signed CapabilityRecords + hash-chain + F6 density (Item 2)
  Act 3  Maturity: new class PROBATION -> RELAX -> MATURE (Item 3)
  Act 4  Cross-class task verified under the widened-tolerance rule (Item 4)
  Act 5  Divergence -> escalation -> slash -> attribution -> accumulators;
         one isolated fault is absorbed, a cheating PATTERN snaps the class up
  Act 6  Edge cases: strict task pins same-class; C-agrees-both -> no attribution
  Act 7  Neutrality audit over every protocol module

Self-contained; run from `reference/`:  python demo_integration.py
"""
from dataclasses import replace

from goathal.conformance import run_conformance
from goathal.neutrality import audit_protocol_layer
from goathal.types import Task, ExecPolicy, DeterminismProfile, DetKind
from goathal.pqsign import ReferenceSigner
from goathal.capability import (
    CapabilityRecord, DeviceCapability, Availability, Envelope, DensityWitness,
    AttestationRefs, NetworkClass, DensitySignal, sign_record, validate_record,
    ValidationContext, evaluate_density, ZERO32,
)
from goathal.attestation_chain import RecordChain
from goathal.maturity import (
    MaturityController, GateThresholds, RegistrationSet, Receipt, Stage,
    fold_receipts, cheat_ev_margin, P_FLOOR,
)
from goathal.verification import (
    ExecutorRef, Submission, Status, VerificationHarness, effective_profile,
)
from goathal.backends.reference_a import ReferenceBackendA, CLASS_ID as A_ID
from goathal.backends.reference_b import ReferenceBackendB, CLASS_ID as B_ID

TH = GateThresholds(v_min=100, epsilon=0.01, phi=50.0, x_clusters=25, x_asns=10)
TASK = Task(task_class_id=10, engine_build_id="build-1", payload=b"integration-corpus",
            seed=7, determinism_bound=10.0)
NONCE = b"beacon-epoch".ljust(32, b"\x00")
EXACT = DeterminismProfile(DetKind.EXACT, "l_inf", 0.0)
TOL8 = DeterminismProfile(DetKind.TOLERANCE, "l_inf", 8.0)


def banner(n, title):
    print(f"\n{'=' * 74}\nAct {n} - {title}\n{'=' * 74}")


def runner(backend):
    dev = backend.enumerate_devices()[0]
    def run(t):
        return backend.execute(backend.load(dev, t.engine_build_id), t,
                               ExecPolicy(power_cap_w=10_000))
    return run


def build_record(signer, backend, endpoint, density, epoch, prev):
    dev = backend.enumerate_devices()[0]
    rep = backend.benchmark(dev)
    prof = backend.determinism_profile(dev, 10)
    cap = DeviceCapability(
        class_id=dev.class_id, fingerprint_commit=rep.fingerprint,
        task_classes=rep.task_class_caps,
        determinism_ref=(dev.class_id, prof.profile_version),
        availability=Availability(window_bitmap=(1 << 100), expected_idle_h=8,
                                  preempt_p50_ms=10, preempt_p95_ms=backend.preempt_p95_ms),
        envelope=Envelope(max_power_w=200, thermal_policy_class=1),
        density_witness=DensityWitness(endpoint, density),
        attestation_refs=AttestationRefs(epoch, NetworkClass.RESIDENTIAL, False))
    rec = CapabilityRecord(version=1, node_id=b"", operator_binding=b"op".ljust(32, b"\x00"),
                           epoch=epoch, nonce=NONCE, devices=(cap,), prev_record=prev)
    return sign_record(rec, signer)


def good_receipts(class_id, window, n=200, clusters=30, asns=12):
    return [Receipt(class_id, 10, window, f"c{i % clusters}", f"a{i % asns}", False, False)
            for i in range(n)]


def main():
    backend_a, backend_b = ReferenceBackendA(0), ReferenceBackendB(0)
    run_a, run_b = runner(backend_a), runner(backend_b)

    # ---------------------------------------------------------------- Act 1
    banner(1, "Item 1 - both device classes pass the D.1 conformance suite")
    for label, cid, fac in ((A_ID, A_ID, lambda s: ReferenceBackendA(s)),
                            (B_ID, B_ID, lambda s: ReferenceBackendB(s))):
        rep = run_conformance(fac)
        print(f"  {cid:<12} -> {'ALL 8 CRITERIA PASS' if rep.all_passed else 'FAIL'}")

    # ---------------------------------------------------------------- Act 2
    banner(2, "Item 2 - capability registration, hash-chain, F6 density")
    signer_a, signer_b = ReferenceSigner(), ReferenceSigner()
    ctx_bands = {10: (0.1, 1.2), 11: (0.05, 1.2)}

    rec_a = build_record(signer_a, backend_a, b"home-desktop".ljust(32, b"\x00"), 1, 1, ZERO32)
    rec_b = build_record(signer_b, backend_b, b"home-laptop".ljust(32, b"\x00"), 3, 1, ZERO32)
    for name, rec, signer in (("node-A", rec_a, signer_a), ("node-B", rec_b, signer_b)):
        res = validate_record(rec, ValidationContext(
            registered_pubkey=signer.public_key(), expected_nonce=NONCE,
            last_record_hash=None, tolerance_bands=ctx_bands))
        d = rec.devices[0]
        print(f"  {name} ({d.class_id}, density={d.density_witness.observed_compute_equiv}): "
              f"valid={res.ok}  density={res.density_signals[d.class_id].name}")

    chain_a = RecordChain(signer_a.public_key())
    chain_a.append(rec_a)
    chain_a.append(build_record(signer_a, backend_a, b"home-desktop".ljust(32, b"\x00"),
                                1, 2, chain_a.head_hash))
    print(f"  node-A hash-chain: length={chain_a.length} integrity={chain_a.verify_integrity()}")

    signer_w = ReferenceSigner()
    ep_w = b"warehouse".ljust(32, b"\x00")
    rec_w = build_record(signer_w, backend_b, ep_w, 2, 1, ZERO32)   # claims density 2...
    res_w = validate_record(rec_w, ValidationContext(
        registered_pubkey=signer_w.public_key(), expected_nonce=NONCE,
        last_record_hash=None, tolerance_bands=ctx_bands,
        probe_observed_equiv={ep_w: 40}))                            # ...probe observed 40
    print(f"  'warehouse' node claims density 2, probe observed 40: valid={res_w.ok} "
          f"-> {res_w.density_signals[B_ID].name} (F6: merged for clustering)")

    # ---------------------------------------------------------------- Act 3
    banner(3, "Item 3 - new class maturity: PROBATION -> RELAX -> MATURE")
    ctrl = MaturityController(TH, tol_ref=8.0)
    ctrl.register_class(B_ID, RegistrationSet(60, 30, 12, 6), tol_width=TOL8.bound, window=0)
    st = ctrl.states[B_ID]
    print(f"  Stage-1 registration (60 nodes/30 clusters/12 ASNs/6 regions) -> "
          f"{st.stage.name} p={st.p_class}  slash={st.slash_mult:.0f}x")
    for w in range(1, 5):
        tr, _ = ctrl.process_window(B_ID, good_receipts(B_ID, w), window=w)
        print(f"  window {w}: {tr.from_stage.name}/{tr.from_p:.2f} -> "
              f"{tr.to_stage.name}/{tr.to_p:.2f} ({tr.kind})")
    print(f"  cheat-EV margin at MATURE sampling: slash {st.slash_mult:.0f}x x p_floor "
          f"{P_FLOOR} = {cheat_ev_margin(st.slash_mult, P_FLOOR):.2f}x (>1 -> cheating is -EV)")

    # ---------------------------------------------------------------- Act 4
    banner(4, "Item 4 - cross-class task verified under the widened tolerance")
    h = VerificationHarness(tol_ref=8.0)
    A = ExecutorRef("node-A", A_ID, "clu-1", "asn-1", EXACT)
    B = ExecutorRef("node-B", B_ID, "clu-2", "asn-2", TOL8)
    C = ExecutorRef("node-C", A_ID, "clu-3", "asn-3", EXACT)
    prof = effective_profile(EXACT, TOL8, False, TASK.determinism_bound)
    print(f"  pair profile: widened max(0, 8) = band {prof.bound}, capped by task bound "
          f"{TASK.determinism_bound}")
    out = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B, run_b(TASK)), window=5)
    print(f"  A(cls.a) executes, B(cls.b) verifies -> {out.status.name} ({out.detail})")

    # ---------------------------------------------------------------- Act 5
    banner(5, "divergence -> escalation -> slash -> attribution -> maturity")
    def cheat_run(t):
        r = run_b(t)
        return replace(r, vector=tuple(v + 50 for v in r.vector))

    print("  window 5: ONE isolated fault among 200 good tasks")
    out5 = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B, cheat_run(TASK)),
                    escalation_pool=[(C, run_a)], window=5)
    print(f"    escalation -> {out5.status.name}: winner={out5.winner} "
          f"slashed={out5.slashed} at {out5.slash_mult:.0f}x")
    w5 = good_receipts(B_ID, 5) + [r for r in out5.receipts if r.class_id == B_ID]
    acc5 = fold_receipts(w5)[(B_ID, 5)]
    tr5, _ = ctrl.process_window(B_ID, w5, window=5)
    print(f"    accumulator: V_c={acc5.V_c} D_num={acc5.D_num} "
          f"(rate {acc5.divergence_rate:.3%} < eps {TH.epsilon:.0%})")
    print(f"    -> {tr5.from_stage.name}/{tr5.from_p:.2f} stays {tr5.to_stage.name}/"
          f"{tr5.to_p:.2f} ({tr5.kind}): one fault absorbed, no hair-trigger")

    print("  window 6: cheating becomes a PATTERN (5 faults)")
    w6 = good_receipts(B_ID, 6)
    for _ in range(5):
        o = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B, cheat_run(TASK)),
                     escalation_pool=[(C, run_a)], window=6)
        w6 += [r for r in o.receipts if r.class_id == B_ID]
    acc6 = fold_receipts(w6)[(B_ID, 6)]
    tr6, _ = ctrl.process_window(B_ID, w6, window=6)
    print(f"    accumulator: V_c={acc6.V_c} D_num={acc6.D_num} "
          f"(rate {acc6.divergence_rate:.3%} >= eps {TH.epsilon:.0%})")
    print(f"    -> SNAP: {tr6.from_stage.name}/{tr6.from_p:.2f} -> "
          f"{tr6.to_stage.name}/{tr6.to_p:.2f} ({tr6.kind}, breached={tr6.reasons})")
    print("    each of the 5 faults was individually slashed at 20x task value")

    # ---------------------------------------------------------------- Act 6
    banner(6, "edge cases")
    strict = replace(TASK, determinism_bound=2.0)
    o1 = h.verify(strict, Submission(A, run_a(strict)), Submission(B, run_b(strict)))
    A2 = ExecutorRef("node-A2", A_ID, "clu-4", "asn-4", EXACT)
    o2 = h.verify(strict, Submission(A, run_a(strict)), Submission(A2, run_a(strict)))
    print(f"  strict task (bound 2.0): cross-class -> {o1.status.name}; "
          f"same-class -> {o2.status.name}")

    def plus(run, d):
        return lambda t: (lambda r: replace(r, vector=tuple(v + d for v in r.vector)))(run(t))
    B14 = ExecutorRef("node-B14", B_ID, "clu-2", "asn-2", TOL8)
    Cb = ExecutorRef("node-Cb", B_ID, "clu-3", "asn-3", TOL8)
    o3 = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B14, plus(run_a, 14)(TASK)),
                  escalation_pool=[(Cb, plus(run_a, 7))])
    print(f"  C-agrees-both (A vs A+14, C=A+7, band 8): -> {o3.status.name}, "
          f"slashed={o3.slashed}, profile_remeasure={o3.profile_remeasure}")

    # ---------------------------------------------------------------- Act 7
    banner(7, "neutrality - every protocol module, no device types, no content logic")
    import os
    pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "goathal")
    findings = audit_protocol_layer(pkg)
    print(f"  audit over 9 protocol modules: "
          f"{'CLEAN' if not findings else f'{len(findings)} FINDINGS'}")
    for f in findings:
        print(f"    {f.module}:{f.line_no} '{f.term}'")

    print("\nAll seven acts complete: Items 1-4 exercised end to end in one flow.")


if __name__ == "__main__":
    main()
