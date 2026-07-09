"""Canonical commitment tests (Spec A/D4): determinism, cross-node identity, and
cross-class agreement of the commitment as a function of task semantics only."""
import unittest
from goathal.commit import commit, canonical_serialize
from goathal.types import Task, ExecPolicy
from goathal.backends.reference_a import ReferenceBackendA
from goathal.backends.reference_b import ReferenceBackendB


def _run(backend, task):
    dev = backend.enumerate_devices()[0]
    return backend.execute(backend.load(dev, task.engine_build_id), task,
                           ExecPolicy(power_cap_w=10_000))


class TestCanonicalCommit(unittest.TestCase):
    def test_deterministic_serialization(self):
        t = Task(10, "b1", b"payload", 7, 10.0)
        r1 = _run(ReferenceBackendA(0), t)
        self.assertEqual(canonical_serialize(r1), canonical_serialize(r1))
        self.assertEqual(len(commit(r1).digest), 32)

    def test_identical_across_independent_nodes(self):
        t = Task(10, "b1", b"payload", 7, 10.0)
        a = commit(_run(ReferenceBackendA(1), t)).digest
        b = commit(_run(ReferenceBackendA(42), t)).digest
        self.assertEqual(a, b, "same task/build must commit identically on any node")

    def test_different_payload_differs(self):
        r1 = _run(ReferenceBackendA(0), Task(10, "b1", b"payload-1", 7, 10.0))
        r2 = _run(ReferenceBackendA(0), Task(10, "b1", b"payload-2", 7, 10.0))
        self.assertNotEqual(commit(r1).digest, commit(r2).digest)

    def test_tokens_agree_across_classes(self):
        """Pinned decode: both classes emit identical tokens for the same task."""
        t = Task(10, "b1", b"payload", 7, 10.0)
        ra = _run(ReferenceBackendA(0), t)
        rb = _run(ReferenceBackendB(0), t)
        self.assertEqual(ra.tokens, rb.tokens)


if __name__ == "__main__":
    unittest.main()
