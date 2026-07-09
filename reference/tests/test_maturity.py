"""Item 3 — Verification Maturity Controller: state machine, ratchet, coverage/F6,
slash coupling, and fraud-proof recomputation."""
import unittest
from dataclasses import replace

from goathal.maturity import (
    Stage, Receipt, ClassAccumulator, GateThresholds, RegistrationSet, ClassState,
    MaturityController, fold_receipts, gate, evaluate_transition, slash_multiple,
    cheat_ev_margin, make_posting, verify_posting, WindowPosting, P_FLOOR,
)

TH = GateThresholds(v_min=100, epsilon=0.01, phi=50.0, x_clusters=25, x_asns=10)


def good_receipts(class_id, window, n=200, clusters=30, asns=12, diverged=0, fault=0):
    out = []
    for i in range(n):
        out.append(Receipt(class_id, 10, window, f"c{i % clusters}", f"a{i % asns}",
                           diverged=(i < diverged), fault=(i < fault)))
    return out


class TestGateAndFold(unittest.TestCase):
    def test_good_window_passes_gate(self):
        acc = fold_receipts(good_receipts("x", 0))[("x", 0)]
        ok, checks = gate(acc, TH)
        self.assertTrue(ok, checks)

    def test_low_coverage_fails(self):
        acc = fold_receipts(good_receipts("x", 0, clusters=10))[("x", 0)]
        ok, checks = gate(acc, TH)
        self.assertFalse(ok)
        self.assertFalse(checks["coverage_clusters"])

    def test_fold_deterministic(self):
        r = good_receipts("x", 0)
        self.assertEqual(fold_receipts(r)[("x", 0)].root(), fold_receipts(r)[("x", 0)].root())


class TestStateMachine(unittest.TestCase):
    def _ctrl(self):
        c = MaturityController(TH)
        c.register_class("x", RegistrationSet(50, 25, 10, 5), tol_width=4.0, window=0)
        return c

    def test_registration_gates_on_diversity(self):
        c = MaturityController(TH)
        self.assertFalse(c.register_class("y", RegistrationSet(49, 25, 10, 5), 4.0, 0))
        self.assertEqual(c.states["y"].stage, Stage.CANDIDATE)
        self.assertTrue(c.register_class("x", RegistrationSet(50, 25, 10, 5), 4.0, 0))
        self.assertEqual(c.states["x"].stage, Stage.PROBATION)
        self.assertEqual(c.states["x"].p_class, 1.0)

    def test_full_progression_to_mature(self):
        c = self._ctrl()
        seq = []
        for w in range(1, 6):
            tr, _ = c.process_window("x", good_receipts("x", w), window=w)
            seq.append((tr.to_stage, round(tr.to_p, 2)))
        self.assertEqual(seq, [(Stage.RELAX, 0.5), (Stage.RELAX, 0.25),
                               (Stage.RELAX, 0.15), (Stage.MATURE, 0.15),
                               (Stage.MATURE, 0.15)])

    def test_relax_breach_snaps_up(self):
        c = self._ctrl()
        c.process_window("x", good_receipts("x", 1), window=1)   # -> RELAX 0.5
        c.process_window("x", good_receipts("x", 2), window=2)   # -> RELAX 0.25
        tr, _ = c.process_window("x", good_receipts("x", 3, diverged=10), window=3)  # breach
        self.assertEqual(tr.kind, "snap")
        self.assertEqual(tr.to_stage, Stage.RELAX)
        self.assertAlmostEqual(tr.to_p, 0.5)

    def test_snap_to_probation_when_p_returns_to_one(self):
        c = self._ctrl()
        c.process_window("x", good_receipts("x", 1), window=1)   # RELAX 0.5
        tr, _ = c.process_window("x", good_receipts("x", 2, fault=100), window=2)  # breach
        self.assertEqual(tr.to_stage, Stage.PROBATION)
        self.assertAlmostEqual(tr.to_p, 1.0)

    def test_mature_breach_reenters_relax(self):
        c = self._ctrl()
        for w in range(1, 5):
            c.process_window("x", good_receipts("x", w), window=w)   # -> MATURE 0.15
        self.assertEqual(c.states["x"].stage, Stage.MATURE)
        tr, _ = c.process_window("x", good_receipts("x", 5, diverged=10), window=5)
        self.assertEqual(tr.to_stage, Stage.RELAX)
        self.assertAlmostEqual(tr.to_p, 0.30)

    def test_anomaly_burst_forces_snap_even_when_gate_ok(self):
        c = self._ctrl()
        c.process_window("x", good_receipts("x", 1), window=1)   # RELAX 0.5
        c.process_window("x", good_receipts("x", 2), window=2)   # RELAX 0.25
        tr, _ = c.process_window("x", good_receipts("x", 3), anomaly_burst=True, window=3)
        self.assertTrue(tr.gate_ok)
        self.assertEqual(tr.kind, "snap")
        self.assertAlmostEqual(tr.to_p, 0.5)

    def test_cohort_merge_collapses_coverage_and_snaps(self):
        c = self._ctrl()
        c.process_window("x", good_receipts("x", 1), window=1)   # RELAX 0.5
        # 30 distinct clusters would pass, but F6 merges c0..c24 into one cohort
        merge = [frozenset(f"c{i}" for i in range(25))]
        tr, acc = c.process_window("x", good_receipts("x", 2), merge_groups=merge, window=2)
        self.assertLess(acc.cover_clusters, TH.x_clusters)       # coverage collapsed
        self.assertEqual(tr.kind, "snap")                        # gate failed -> snap up


class TestSlashCoupling(unittest.TestCase):
    def test_slash_scales_with_tolerance(self):
        self.assertAlmostEqual(slash_multiple(0.0, 8.0), 15.0)
        self.assertAlmostEqual(slash_multiple(8.0, 8.0), 20.0)      # coupling 1/3 -> cap
        self.assertTrue(15.0 < slash_multiple(4.0, 8.0) < 20.0)
        self.assertAlmostEqual(slash_multiple(100.0, 8.0), 20.0)    # clamped

    def test_cheat_ev_margin_safe_at_floor(self):
        self.assertGreater(cheat_ev_margin(15.0, P_FLOOR), 1.0)     # 2.25x
        self.assertGreater(cheat_ev_margin(20.0, P_FLOOR), 1.0)     # 3.0x


class TestFraudProof(unittest.TestCase):
    def _honest(self, prior, receipts, window):
        gate_ok, _ = gate(fold_receipts(receipts)[(prior_cid := "x", window)], TH)
        to_s, to_p, kind = evaluate_transition(prior.stage, prior.p_class, gate_ok, False)
        acc = fold_receipts(receipts)[("x", window)]
        from goathal.maturity import Transition
        tr = Transition("x", window, prior.stage, prior.p_class, to_s, to_p, kind, gate_ok)
        return make_posting(tr, acc), acc

    def test_valid_posting_no_fraud(self):
        prior = ClassState(Stage.PROBATION, 1.0)
        r = good_receipts("x", 1)
        posting, _ = self._honest(prior, r, 1)
        self.assertIsNone(verify_posting(posting, r, prior, TH))

    def test_root_mismatch_detected(self):
        prior = ClassState(Stage.PROBATION, 1.0)
        r = good_receipts("x", 1)
        posting, _ = self._honest(prior, r, 1)
        bad = replace(posting, accumulator_root=b"\x00" * 32)
        fp = verify_posting(bad, r, prior, TH)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.reason, "root_mismatch")

    def test_undersampling_detected(self):
        prior = ClassState(Stage.RELAX, 0.5)
        r = good_receipts("x", 2)                                # legal relax -> 0.25
        acc = fold_receipts(r)[("x", 2)]
        lie = WindowPosting("x", 2, acc.root(), Stage.RELAX, 0.5, Stage.RELAX, 0.15)
        fp = verify_posting(lie, r, prior, TH)
        self.assertEqual(fp.reason, "undersampling")

    def test_over_advanced_detected(self):
        prior = ClassState(Stage.RELAX, 0.5)
        r = good_receipts("x", 2)                                # legal -> RELAX 0.25
        acc = fold_receipts(r)[("x", 2)]
        # keep p == legal (0.25) so the undersampling check passes; only the stage is
        # illegally advanced to MATURE -> isolates the over_advanced path
        lie = WindowPosting("x", 2, acc.root(), Stage.RELAX, 0.5, Stage.MATURE, 0.25)
        fp = verify_posting(lie, r, prior, TH)
        self.assertEqual(fp.reason, "over_advanced")

    def test_bad_prior_detected(self):
        prior = ClassState(Stage.RELAX, 0.5)
        r = good_receipts("x", 2)
        acc = fold_receipts(r)[("x", 2)]
        lie = WindowPosting("x", 2, acc.root(), Stage.RELAX, 0.25, Stage.RELAX, 0.25)
        fp = verify_posting(lie, r, prior, TH)
        self.assertEqual(fp.reason, "bad_prior")

    def test_conservative_orchestrator_not_fraud(self):
        # holding at a HIGHER sampling than legal is safe -> never fraud
        prior = ClassState(Stage.RELAX, 0.5)
        r = good_receipts("x", 2)                                # legal -> 0.25
        acc = fold_receipts(r)[("x", 2)]
        conservative = WindowPosting("x", 2, acc.root(), Stage.RELAX, 0.5, Stage.RELAX, 0.5)
        self.assertIsNone(verify_posting(conservative, r, prior, TH))


if __name__ == "__main__":
    unittest.main()
