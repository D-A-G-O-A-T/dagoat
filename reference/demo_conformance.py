"""
Item-1 demo: run the D.1 conformance suite against both reference backends and print
the report, then run the neutrality source-scan. Device-agnostic: the same runner is
applied to two different device classes with no special-casing.

Run from the `reference/` directory:  python demo_conformance.py
"""
import os
from goathal.conformance import run_conformance
from goathal.neutrality import audit_protocol_layer
from goathal.backends.reference_a import ReferenceBackendA, CLASS_ID as A_ID
from goathal.backends.reference_b import ReferenceBackendB, CLASS_ID as B_ID


def show(label, class_id, factory):
    rep = run_conformance(factory)
    print(f"\n=== D.1 conformance: {label}  (class_id={class_id!r}) ===")
    for name, res in rep.results.items():
        print(f"  [{'PASS' if res.passed else 'FAIL'}] {name:<26} {res.detail}")
    print(f"  ---> {'ALL PASS' if rep.all_passed else 'FAILURES PRESENT'}")


if __name__ == "__main__":
    show("Backend A (high-throughput, EXACT profile)", A_ID, lambda s: ReferenceBackendA(s))
    show("Backend B (low-power, TOLERANCE profile)", B_ID, lambda s: ReferenceBackendB(s))

    pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "goathal")
    findings = audit_protocol_layer(pkg)
    print("\n=== D8 neutrality source-scan (protocol layer) ===")
    if not findings:
        print("  [PASS] protocol layer names no device type and inspects no content/license")
    else:
        for f in findings:
            print(f"  [FAIL] {f.module}:{f.line_no} '{f.term}' -> {f.line}")
