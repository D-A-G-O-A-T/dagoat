"""Capstone smoke test: the integration demo must run end-to-end and hit every
expected outcome marker. Keeps the demo covered by the suite so it cannot rot."""
import io
import unittest
from contextlib import redirect_stdout

import demo_integration


class TestIntegrationDemo(unittest.TestCase):
    def test_demo_runs_and_hits_all_markers(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            demo_integration.main()
        out = buf.getvalue()
        for marker in (
            "ALL 8 CRITERIA PASS",                       # Act 1 conformance
            "valid=True  density=OK",                    # Act 2 registration
            "length=2 integrity=True",                   # Act 2 hash-chain
            "COHORT_MERGE",                              # Act 2 F6
            "MATURE/0.15 (mature)",                      # Act 3 lifecycle
            "SETTLED (agree under TOLERANCE band=8.0)",  # Act 4 cross-class
            "slashed=node-B at 20x",                     # Act 5 slash sizing
            "one fault absorbed, no hair-trigger",       # Act 5 tolerance to isolated fault
            "SNAP: MATURE/0.15 -> RELAX/0.30",           # Act 5 pattern snap
            "INELIGIBLE_CROSS_CLASS",                    # Act 6 strict pinning
            "profile_remeasure=True",                    # Act 6 C-agrees-both
            "CLEAN",                                     # Act 7 neutrality
        ):
            self.assertIn(marker, out, f"missing marker: {marker}")


if __name__ == "__main__":
    unittest.main()
