"""Spec D8 neutrality — the protocol layer must name no device type and inspect no
content/model/license. This is the machine-checkable half of the standing invariant."""
import os
import unittest
from goathal import neutrality


PKG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "goathal")


class TestProtocolLayerNeutrality(unittest.TestCase):
    def test_no_forbidden_terms_in_protocol_modules(self):
        findings = neutrality.audit_protocol_layer(PKG_DIR)
        msg = "\n".join(f"{f.module}:{f.line_no} '{f.term}' -> {f.line}" for f in findings)
        self.assertEqual(findings, [], f"protocol layer is not neutral:\n{msg}")

    def test_auditor_actually_detects_violations(self):
        # sanity: the auditor is not vacuously passing. Inject a device-type branch
        # (string operand) and a content-policy identifier IN CODE and detect both.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "commit.py"), "w", encoding="utf-8") as f:
                f.write("def f(class_id, payload):\n"
                        "    if class_id == 'gpu':\n"
                        "        model_name = payload\n"
                        "    return 0\n")
            findings = neutrality.audit_protocol_layer(d)
            terms = {f.term for f in findings}
            self.assertIn("gpu", terms)          # device-type literal in a branch
            self.assertIn("model_name", terms)   # content-policy identifier in code

    def test_auditor_catches_device_term_inside_identifier(self):
        # justifies the observed_gpu_equiv -> observed_compute_equiv rename: a device
        # term embedded in an identifier is caught via sub-token splitting...
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "capability.py"), "w", encoding="utf-8") as f:
                f.write("def f(observed_gpu_equiv):\n    return observed_gpu_equiv\n")
            terms = {x.term for x in neutrality.audit_protocol_layer(d)}
            self.assertIn("gpu", terms)

    def test_auditor_no_substring_false_positive(self):
        # ...without substring false positives: 'input' must NOT match 'npu'
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "capability.py"), "w", encoding="utf-8") as f:
                f.write("def f(input_bytes):\n    return input_bytes\n")
            self.assertEqual(neutrality.audit_protocol_layer(d), [])

    def test_auditor_ignores_prose_in_comments_and_docstrings(self):
        # a module that only *mentions* the terms in a docstring/comment is neutral
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "commit.py"), "w", encoding="utf-8") as f:
                f.write('"""This module never inspects a license or a gpu type."""\n'
                        "x = 1  # not a gpu check, no license here\n")
            self.assertEqual(neutrality.audit_protocol_layer(d), [])


class TestTaskHasNoContentFields(unittest.TestCase):
    """Structural Core-Principle-7 guarantee: there is nowhere to put a content policy."""
    def test_task_fields(self):
        from goathal.types import Task
        import dataclasses
        fields = {f.name for f in dataclasses.fields(Task)}
        for banned in ("model_name", "license", "content", "policy"):
            self.assertNotIn(banned, fields)
        self.assertIn("payload", fields)  # opaque bytes only


if __name__ == "__main__":
    unittest.main()
