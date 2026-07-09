"""D.1 conformance suite tests — must pass for BOTH reference backends, via the trait
only, with no per-device special-casing in the runner."""
import unittest
from goathal.conformance import run_conformance
from goathal.backends.reference_a import ReferenceBackendA
from goathal.backends.reference_b import ReferenceBackendB


class TestConformanceBackendA(unittest.TestCase):
    def test_all_criteria_pass(self):
        report = run_conformance(lambda seed: ReferenceBackendA(seed))
        for name, res in report.results.items():
            self.assertTrue(res.passed, f"A failed {name}: {res.detail}")
        self.assertTrue(report.all_passed)


class TestConformanceBackendB(unittest.TestCase):
    def test_all_criteria_pass(self):
        report = run_conformance(lambda seed: ReferenceBackendB(seed))
        for name, res in report.results.items():
            self.assertTrue(res.passed, f"B failed {name}: {res.detail}")
        self.assertTrue(report.all_passed)


class TestRunnerIsDeviceAgnostic(unittest.TestCase):
    """The runner must produce the same set of criteria regardless of backend class."""
    def test_same_criteria_keys(self):
        ra = run_conformance(lambda s: ReferenceBackendA(s))
        rb = run_conformance(lambda s: ReferenceBackendB(s))
        self.assertEqual(set(ra.results.keys()), set(rb.results.keys()))


class TestD6EnvelopeIsHard(unittest.TestCase):
    """Envelope enforcement must hold even when the policy passes a huge cap:
    enforce_envelope is the binding limit."""
    def test_envelope_binds_over_policy(self):
        from goathal.types import Task, ExecPolicy
        b = ReferenceBackendA(0)
        dev = b.enumerate_devices()[0]
        b.enforce_envelope(dev, 30)
        task = Task(10, "build-1", b"x", 1, 10.0)
        b.execute(b.load(dev, "build-1"), task, ExecPolicy(power_cap_w=100_000))
        self.assertLessEqual(b.peak_power_w, 30)


if __name__ == "__main__":
    unittest.main()
