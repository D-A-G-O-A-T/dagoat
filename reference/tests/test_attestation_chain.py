"""Item 2 — hash-chain integrity and rolling re-attestation rules."""
import unittest
from dataclasses import replace

from goathal.pqsign import ReferenceSigner
from goathal.capability import record_hash, ZERO32
from goathal.attestation_chain import (
    RecordChain, ChainError, staleness_weight, needs_rebenchmark,
    DEFAULT_MAX_BENCH_AGE_EPOCHS,
)
from tests._capfixtures import make_device, make_signed_record


class TestHashChain(unittest.TestCase):
    def _chain_of(self, s, n):
        chain = RecordChain(s.public_key())
        prev = ZERO32
        for e in range(1, n + 1):
            r = make_signed_record(s, [make_device(density=e)], epoch=e, prev=prev)
            chain.append(r)
            prev = record_hash(r)
        return chain

    def test_append_and_integrity(self):
        s = ReferenceSigner()
        chain = self._chain_of(s, 3)
        self.assertEqual(chain.length, 3)
        self.assertTrue(chain.verify_integrity())

    def test_reject_wrong_prev(self):
        s = ReferenceSigner()
        chain = self._chain_of(s, 1)
        bad = make_signed_record(s, [make_device()], epoch=2, prev=b"\x99" * 32)
        with self.assertRaises(ChainError):
            chain.append(bad)

    def test_reject_foreign_signature(self):
        s, other = ReferenceSigner(), ReferenceSigner()
        chain = RecordChain(s.public_key())
        r = make_signed_record(other, [make_device()], epoch=1, prev=ZERO32)
        with self.assertRaises(ChainError):
            chain.append(r)

    def test_reject_non_increasing_epoch(self):
        s = ReferenceSigner()
        chain = self._chain_of(s, 2)
        r = make_signed_record(s, [make_device()], epoch=2, prev=chain.head_hash)
        with self.assertRaises(ChainError):
            chain.append(r)

    def test_tampering_past_record_breaks_integrity(self):
        s = ReferenceSigner()
        chain = self._chain_of(s, 2)
        # Re-sign a mutated record0 with the SAME linkage; its hash changes, so record1's
        # prev_record no longer matches -> integrity must fail.
        r0 = chain._records[0]
        r0_tampered = make_signed_record(s, [make_device(density=99)],
                                         epoch=r0.epoch, prev=r0.prev_record)
        self.assertNotEqual(record_hash(r0), record_hash(r0_tampered))
        chain._records[0] = r0_tampered
        self.assertFalse(chain.verify_integrity())


class TestRollingReattestation(unittest.TestCase):
    def test_staleness_within_cadence_full_weight(self):
        self.assertEqual(staleness_weight(100, 105, declared_cadence_epochs=24), 1.0)

    def test_staleness_beyond_cadence_decays(self):
        w = staleness_weight(100, 100 + 48, declared_cadence_epochs=24)
        self.assertLess(w, 1.0)
        self.assertGreaterEqual(w, 0.1)

    def test_needs_rebenchmark_triggers(self):
        self.assertTrue(needs_rebenchmark(0, DEFAULT_MAX_BENCH_AGE_EPOCHS, False, False))
        self.assertTrue(needs_rebenchmark(0, 1, fingerprint_changed=True, profile_version_changed=False))
        self.assertTrue(needs_rebenchmark(0, 1, fingerprint_changed=False, profile_version_changed=True))

    def test_needs_rebenchmark_stable(self):
        self.assertFalse(needs_rebenchmark(0, 10, False, False))


if __name__ == "__main__":
    unittest.main()
