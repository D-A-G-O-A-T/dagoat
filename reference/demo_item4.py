"""
Item-4 demo: two different device classes cross-verify each other's output; a cheater
triggers escalation to a disjoint third executor and is slashed with divergence
attributed to its class; a strict task pins to same-class; a 3-way split quarantines.

Run from `reference/`:  python demo_item4.py
"""
from dataclasses import replace

from goathal.types import DeterminismProfile, DetKind, Task, ExecPolicy
from goathal.backends.reference_a import ReferenceBackendA, CLASS_ID as A_ID
from goathal.backends.reference_b import ReferenceBackendB, CLASS_ID as B_ID
from goathal.maturity import fold_receipts
from goathal.verification import (
    ExecutorRef, Submission, Status, VerificationHarness, effective_profile,
)

TASK = Task(task_class_id=10, engine_build_id="build-1", payload=b"demo-corpus",
            seed=7, determinism_bound=10.0)
EXACT = DeterminismProfile(DetKind.EXACT, "l_inf", 0.0)
TOL8 = DeterminismProfile(DetKind.TOLERANCE, "l_inf", 8.0)


def runner(backend):
    dev = backend.enumerate_devices()[0]
    def run(t):
        return backend.execute(backend.load(dev, t.engine_build_id), t,
                               ExecPolicy(power_cap_w=10_000))
    return run


def main():
    h = VerificationHarness(tol_ref=8.0)
    run_a, run_b = runner(ReferenceBackendA(0)), runner(ReferenceBackendB(0))
    A = ExecutorRef("nodeA", A_ID, "clu-1", "asn-1", EXACT)
    B = ExecutorRef("nodeB", B_ID, "clu-2", "asn-2", TOL8)
    C = ExecutorRef("nodeC", A_ID, "clu-3", "asn-3", EXACT)

    print("=== 1) cross-class verification: two classes check each other ===")
    prof = effective_profile(EXACT, TOL8, False, TASK.determinism_bound)
    print(f"  effective profile: {prof.kind.name} band={prof.bound} "
          f"(widened max(0, 8), capped by task bound {TASK.determinism_bound})")
    out = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B, run_b(TASK)))
    print(f"  -> {out.status.name}: {out.detail}; receipts={len(out.receipts)} clean")

    print("\n=== 2) cheater -> escalation to disjoint C -> slash + D_num attribution ===")
    rb = run_b(TASK)
    cheat = replace(rb, vector=tuple(v + 50 for v in rb.vector))
    out = h.verify(TASK, Submission(A, run_a(TASK)), Submission(B, cheat),
                   escalation_pool=[(C, run_a)], window=5)
    print(f"  -> {out.status.name}: {out.detail}")
    print(f"     winner={out.winner}  slashed={out.slashed} at {out.slash_mult:.0f}x task value")
    accs = fold_receipts(list(out.receipts))
    for (cid, w), acc in sorted(accs.items()):
        print(f"     accumulator[{cid}]: V_c={acc.V_c} D_num={acc.D_num} F_num={acc.F_num}")

    print("\n=== 3) strict task (bound 2.0) -> cross-class ineligible, pins same-class ===")
    strict = replace(TASK, determinism_bound=2.0)
    out = h.verify(strict, Submission(A, run_a(strict)), Submission(B, run_b(strict)))
    print(f"  cross-class attempt -> {out.status.name}")
    A2 = ExecutorRef("nodeA2", A_ID, "clu-4", "asn-4", EXACT)
    out = h.verify(strict, Submission(A, run_a(strict)), Submission(A2, run_a(strict)))
    print(f"  same-class pairing  -> {out.status.name} ({out.detail})")

    print("\n=== 4) 3-way split -> quarantine, no slash, profile re-measurement ===")
    ra = run_a(TASK)
    bad_b = replace(run_b(TASK), vector=tuple(v + 50 for v in run_b(TASK).vector))
    def bad_c(t):
        r = run_a(t)
        return replace(r, vector=tuple(v - 50 for v in r.vector))
    Cb = ExecutorRef("nodeCb", B_ID, "clu-3", "asn-3", TOL8)
    out = h.verify(TASK, Submission(A, ra), Submission(B, bad_b),
                   escalation_pool=[(Cb, bad_c)])
    print(f"  -> {out.status.name}: {out.detail}")
    print(f"     slashed={out.slashed}  receipts={len(out.receipts)}  "
          f"profile_remeasure={out.profile_remeasure}")


if __name__ == "__main__":
    main()
