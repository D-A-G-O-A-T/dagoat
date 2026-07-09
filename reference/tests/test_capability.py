"""Item 2 — CapabilityRecord: signing round-trip, validity predicate, F6 density."""
import unittest
from dataclasses import replace

from goathal.pqsign import ReferenceSigner, AlgId
from goathal.capability import (
    verify_record_signature, node_id_from_pubkey, record_hash,
    evaluate_density, q_network_factor, DensitySignal, NetworkClass,
    validate_record, ValidationContext, ZERO32,
)
from tests._capfixtures import make_device, make_signed_record


class TestSigning(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device()])
        self.assertEqual(r.node_id, node_id_from_pubkey(s.public_key()))
        self.assertTrue(verify_record_signature(r, s.public_key()))

    def test_tamper_detected(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device()])
        tampered = replace(r, epoch=r.epoch + 1)          # signature was over old epoch
        self.assertFalse(verify_record_signature(tampered, s.public_key()))

    def test_wrong_pubkey_rejected(self):
        s, other = ReferenceSigner(), ReferenceSigner()
        r = make_signed_record(s, [make_device()])
        self.assertFalse(verify_record_signature(r, other.public_key()))


class TestDensityF6(unittest.TestCase):
    def test_residential_high_density_triggers_merge(self):
        d = make_device(density=6, netclass=NetworkClass.RESIDENTIAL)
        self.assertEqual(evaluate_density(d), DensitySignal.COHORT_MERGE)

    def test_residential_plausible_is_ok(self):
        for k in (1, 3, 5):
            self.assertEqual(evaluate_density(make_device(density=k)), DensitySignal.OK)

    def test_datacenter_high_density_not_residential_merge(self):
        d = make_device(density=60, netclass=NetworkClass.DATACENTER)
        self.assertEqual(evaluate_density(d), DensitySignal.OK)

    def test_q_network_factor_monotone(self):
        self.assertEqual(q_network_factor(3), 0.85)
        self.assertEqual(q_network_factor(5), 0.85)
        self.assertLess(q_network_factor(10), 0.85)
        self.assertGreater(q_network_factor(10), q_network_factor(30))
        self.assertEqual(q_network_factor(1000), 0.10)   # clamped floor


class TestValidityPredicate(unittest.TestCase):
    def _ctx(self, s, **kw):
        base = dict(registered_pubkey=s.public_key(), expected_nonce=b"N" * 32,
                    last_record_hash=None, tolerance_bands={10: (0.9, 1.1)})
        base.update(kw)
        return ValidationContext(**base)

    def test_full_pass(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device(gcu_rate=1.0)])
        res = validate_record(r, self._ctx(s))
        self.assertTrue(res.ok, res.reasons)
        self.assertTrue(all(res.checks[k] for k in
                            ("signature", "nonce", "chain", "gcu_tolerance", "density_consistent")))

    def test_bad_nonce_fails(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device()])
        res = validate_record(r, self._ctx(s, expected_nonce=b"X" * 32))
        self.assertFalse(res.ok)
        self.assertFalse(res.checks["nonce"])

    def test_broken_chain_fails(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device()], prev=b"\x11" * 32)
        res = validate_record(r, self._ctx(s, last_record_hash=b"\x22" * 32))
        self.assertFalse(res.ok)
        self.assertFalse(res.checks["chain"])

    def test_gcu_out_of_band_fails(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device(gcu_rate=5.0)])   # band is (0.9, 1.1)
        res = validate_record(r, self._ctx(s))
        self.assertFalse(res.ok)
        self.assertFalse(res.checks["gcu_tolerance"])

    def test_density_underclaim_fails_and_merges_on_probe(self):
        s = ReferenceSigner()
        ep = b"Z" * 32
        # node claims 1 unit; passive probe observed 60 on that endpoint
        r = make_signed_record(s, [make_device(density=1, endpoint=ep)])
        res = validate_record(r, self._ctx(s, probe_observed_equiv={ep: 60}))
        self.assertFalse(res.ok)
        self.assertFalse(res.checks["density_consistent"])
        # F6 fires on the PROBE value, defeating the under-declaration
        self.assertEqual(res.density_signals["cls.a.v1"], DensitySignal.COHORT_MERGE)

    def test_fingerprint_drift_is_soft(self):
        s = ReferenceSigner()
        r = make_signed_record(s, [make_device(fp=b"\xcd" * 32)])
        ctx = self._ctx(s, prior_fingerprints={"cls.a.v1": b"\xab" * 32})  # different prior
        res = validate_record(r, ctx)
        self.assertFalse(res.checks["fingerprint_stable"])   # flagged
        self.assertTrue(res.ok)                              # but not a hard reject


if __name__ == "__main__":
    unittest.main()
