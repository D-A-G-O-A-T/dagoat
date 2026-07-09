"""Item 4 — cross-class verification: AGREE predicate (corrected Spec C.2), escalation
outcomes, slash attribution, same-class pinning, and receipt integration with maturity."""
import unittest
from dataclasses import replace

from goathal.types import DeterminismProfile, DetKind, Task, ExecPolicy
from goathal.backends.reference_a import ReferenceBackendA
from goathal.backends.reference_b import ReferenceBackendB
from goathal.maturity import fold_receipts
from goathal.verification import (
    ExecutorRef, Submission, Status, VerificationHarness, effective_profile, agree,
    token_agreement, l_inf, pick_disjoint_executor,
)

TASK = Task(task_class_id=10, engine_build_id="build-1", payload=b"corpus-42",
            seed=7, determinism_bound=10.0)
EXACT = DeterminismProfile(DetKind.EXACT, "l_inf", 0.0)
TOL8 = DeterminismProfile(DetKind.TOLERANCE, "l_inf", 8.0)


def runner(backend):
    dev = backend.enumerate_devices()[0]
    def run(t):
        return backend.execute(backend.load(dev, t.engine_build_id), t,
                               ExecPolicy(power_cap_w=10_000))
    return run


def ex(node, class_id, cluster, asn, profile):
    return ExecutorRef(node, class_id, cluster, asn, profile)


A_REF = ex("nodeA", "cls.a.v1", "clu-1", "asn-1", EXACT)
B_REF = ex("nodeB", "cls.b.v1", "clu-2", "asn-2", TOL8)
C_A_REF = ex("nodeC", "cls.a.v1", "clu-3", "asn-3", EXACT)   # disjoint, class a
C_B_REF = ex("nodeCb", "cls.b.v1", "clu-3", "asn-3", TOL8)   # disjoint, class b

RUN_A = runner(ReferenceBackendA(0))
RUN_B = runner(ReferenceBackendB(0))


def perturbed(run, delta):
    return lambda t: (lambda r: replace(r, vector=tuple(v + delta for v in r.vector)))(run(t))


class TestMetrics(unittest.TestCase):
    def test_token_agreement_identical(self):
        self.assertEqual(token_agreement((1, 2, 3), (1, 2, 3)), 1.0)

    def test_token_agreement_partial(self):
        self.assertAlmostEqual(token_agreement((1, 2, 3, 4), (1, 2, 9, 4)), 0.75)

    def test_l_inf_length_mismatch_is_inf(self):
        self.assertEqual(l_inf((1, 2), (1, 2, 3)), float("inf"))


class TestEffectiveProfile(unittest.TestCase):
    def test_same_class_uses_own_profile(self):
        p = effective_profile(EXACT, EXACT, same_class=True, task_bound=10.0)
        self.assertEqual(p.kind, DetKind.EXACT)

    def test_cross_class_widens_to_max_band(self):
        p = effective_profile(EXACT, TOL8, same_class=False, task_bound=10.0)
        self.assertEqual(p.kind, DetKind.TOLERANCE)
        self.assertEqual(p.bound, 8.0)

    def test_cross_class_ineligible_when_band_exceeds_task_bound(self):
        self.assertIsNone(effective_profile(EXACT, TOL8, same_class=False, task_bound=2.0))

    def test_strict_task_pins_to_capable_same_class(self):
        # EXACT class can serve a strict task same-class; wide class cannot at all
        self.assertIsNotNone(effective_profile(EXACT, EXACT, same_class=True, task_bound=2.0))
        self.assertIsNone(effective_profile(TOL8, TOL8, same_class=True, task_bound=2.0))


class TestAgree(unittest.TestCase):
    def test_real_backends_agree_cross_class(self):
        ra, rb = RUN_A(TASK), RUN_B(TASK)
        prof = effective_profile(EXACT, TOL8, False, TASK.determinism_bound)
        self.assertTrue(agree(ra, rb, prof))

    def test_tampered_vector_beyond_band_disagrees(self):
        ra = RUN_A(TASK)
        cheat = replace(RUN_B(TASK), vector=tuple(v + 50 for v in RUN_B(TASK).vector))
        prof = effective_profile(EXACT, TOL8, False, TASK.determinism_bound)
        self.assertFalse(agree(ra, cheat, prof))

    def test_same_class_exact_requires_commit_equality(self):
        ra = RUN_A(TASK)
        tampered = replace(ra, vector=tuple(v + 1 for v in ra.vector))
        self.assertTrue(agree(ra, RUN_A(TASK), EXACT))
        self.assertFalse(agree(ra, tampered, EXACT))


class TestHarness(unittest.TestCase):
    def setUp(self):
        self.h = VerificationHarness(tol_ref=8.0)

    def test_settle_cross_class(self):
        out = self.h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                            Submission(B_REF, RUN_B(TASK)))
        self.assertEqual(out.status, Status.SETTLED)
        self.assertIsNone(out.slashed)
        self.assertEqual(len(out.receipts), 2)
        self.assertTrue(all(not r.diverged and not r.fault for r in out.receipts))

    def test_ineligible_strict_task_pins_same_class(self):
        strict = replace(TASK, determinism_bound=2.0)
        out = self.h.verify(strict, Submission(A_REF, RUN_A(strict)),
                            Submission(B_REF, RUN_B(strict)))
        self.assertEqual(out.status, Status.INELIGIBLE_CROSS_CLASS)
        # same-class pairing for the same strict task succeeds
        a2 = ex("nodeA2", "cls.a.v1", "clu-9", "asn-9", EXACT)
        out2 = self.h.verify(strict, Submission(A_REF, RUN_A(strict)),
                             Submission(a2, RUN_A(strict)))
        self.assertEqual(out2.status, Status.SETTLED)

    def test_escalation_c_agrees_a_slashes_b(self):
        cheat_b = perturbed(RUN_B, 50)
        out = self.h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                            Submission(B_REF, cheat_b(TASK)),
                            escalation_pool=[(C_A_REF, RUN_A)])
        self.assertEqual(out.status, Status.SETTLED_ESCALATED)
        self.assertEqual(out.winner, "nodeA")
        self.assertEqual(out.slashed, "nodeB")
        self.assertAlmostEqual(out.slash_mult, 20.0)     # band 8 == tol_ref -> cap
        faulted = [r for r in out.receipts if r.fault]
        self.assertEqual(len(faulted), 1)
        self.assertEqual(faulted[0].class_id, "cls.b.v1")

    def test_escalation_c_agrees_b_slashes_a(self):
        cheat_a = perturbed(RUN_A, 50)
        out = self.h.verify(TASK, Submission(A_REF, cheat_a(TASK)),
                            Submission(B_REF, RUN_B(TASK)),
                            escalation_pool=[(C_A_REF, RUN_A)])
        self.assertEqual(out.status, Status.SETTLED_ESCALATED)
        self.assertEqual(out.winner, "nodeB")
        self.assertEqual(out.slashed, "nodeA")
        self.assertAlmostEqual(out.slash_mult, 15.0)     # EXACT band 0 -> base slash
        faulted = [r for r in out.receipts if r.fault]
        self.assertEqual(faulted[0].class_id, "cls.a.v1")

    def test_three_way_split_quarantines(self):
        cheat_b = perturbed(RUN_B, 50)
        cheat_c = perturbed(RUN_A, -50)
        out = self.h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                            Submission(B_REF, cheat_b(TASK)),
                            escalation_pool=[(C_B_REF, cheat_c)])
        self.assertEqual(out.status, Status.QUARANTINED)
        self.assertIsNone(out.slashed)
        self.assertEqual(out.receipts, ())               # no reward, no slash pending
        self.assertTrue(out.profile_remeasure)

    def test_c_agrees_both_is_no_attribution(self):
        # non-transitive band: B = A+14 (disagrees with A at band 8), C = A+7
        # (within band 8 of BOTH). Tokens identical throughout (pinned decode).
        b14 = perturbed(RUN_A, 14)
        c7 = perturbed(RUN_A, 7)
        out = self.h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                            Submission(ex("nodeB14", "cls.b.v1", "clu-2", "asn-2", TOL8),
                                       b14(TASK)),
                            escalation_pool=[(C_B_REF, c7)])
        self.assertEqual(out.status, Status.SETTLED_ESCALATED)
        self.assertEqual(out.winner, "nodeA")            # primary settles
        self.assertIsNone(out.slashed)                   # no attribution possible
        self.assertTrue(out.profile_remeasure)           # band flagged too tight

    def test_no_disjoint_executor_quarantines(self):
        cheat_b = perturbed(RUN_B, 50)
        same_cluster = ex("nodeX", "cls.a.v1", "clu-1", "asn-9", EXACT)   # shares A's cluster
        same_asn = ex("nodeY", "cls.a.v1", "clu-9", "asn-2", EXACT)       # shares B's ASN
        out = self.h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                            Submission(B_REF, cheat_b(TASK)),
                            escalation_pool=[(same_cluster, RUN_A), (same_asn, RUN_A)])
        self.assertEqual(out.status, Status.QUARANTINED)

    def test_pick_disjoint_skips_unpairable(self):
        strictish = 2.0
        wide = ex("nodeW", "cls.b.v1", "clu-7", "asn-7", TOL8)   # band 8 > 2 -> unpairable
        ok = ex("nodeOK", "cls.a.v1", "clu-8", "asn-8", EXACT)
        picked = pick_disjoint_executor([(wide, RUN_B), (ok, RUN_A)], A_REF,
                                        ex("nodeA2", "cls.a.v1", "clu-9", "asn-9", EXACT),
                                        strictish)
        self.assertEqual(picked[0].node_id, "nodeOK")


class TestReceiptIntegration(unittest.TestCase):
    def test_faulted_class_gets_d_num(self):
        h = VerificationHarness()
        cheat_b = perturbed(RUN_B, 50)
        out = h.verify(TASK, Submission(A_REF, RUN_A(TASK)),
                       Submission(B_REF, cheat_b(TASK)),
                       escalation_pool=[(C_A_REF, RUN_A)], window=3)
        accs = fold_receipts(list(out.receipts))
        acc_b = accs[("cls.b.v1", 3)]
        acc_a = accs[("cls.a.v1", 3)]
        self.assertEqual((acc_b.V_c, acc_b.D_num, acc_b.F_num), (1, 1, 1))
        self.assertEqual((acc_a.V_c, acc_a.D_num, acc_a.F_num), (2, 0, 0))  # A + C clean


if __name__ == "__main__":
    unittest.main()
