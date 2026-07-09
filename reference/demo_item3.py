"""
Item-3 demo: a new device class progresses PROBATION -> RELAX -> MATURE over held
windows, a violation causes an immediate snap-up, and a lying orchestrator posting is
caught by fraud-proof recomputation.

Run from `reference/`:  python demo_item3.py
"""
from goathal.maturity import (
    Stage, Receipt, GateThresholds, RegistrationSet, ClassState, MaturityController,
    fold_receipts, gate, evaluate_transition, make_posting, verify_posting,
    WindowPosting, slash_multiple, cheat_ev_margin, P_FLOOR, Transition,
)

TH = GateThresholds(v_min=100, epsilon=0.01, phi=50.0, x_clusters=25, x_asns=10)


def good(cid, w, n=200, clusters=30, asns=12, diverged=0, fault=0):
    return [Receipt(cid, 10, w, f"c{i % clusters}", f"a{i % asns}",
                    i < diverged, i < fault) for i in range(n)]


def main():
    c = MaturityController(TH, tol_ref=8.0)
    ok = c.register_class("cls.new.v1", RegistrationSet(60, 30, 12, 6), tol_width=6.0, window=0)
    st = c.states["cls.new.v1"]
    print("=== Stage-1 registration ===")
    print(f"  diverse set accepted={ok} -> {st.stage.name} p={st.p_class} "
          f"slash={st.slash_mult:.1f}x (cheat-EV margin at floor = "
          f"{cheat_ev_margin(st.slash_mult, P_FLOOR):.2f}x)")

    print("\n=== held windows: PROBATION -> RELAX -> MATURE ===")
    for w in range(1, 5):
        tr, _ = c.process_window("cls.new.v1", good("cls.new.v1", w), window=w)
        print(f"  window {w}: {tr.from_stage.name}/{tr.from_p:.2f} -> "
              f"{tr.to_stage.name}/{tr.to_p:.2f}  ({tr.kind})")

    print("\n=== violation in MATURE -> immediate snap-up ===")
    tr, _ = c.process_window("cls.new.v1", good("cls.new.v1", 5, diverged=10), window=5)
    print(f"  window 5: {tr.from_stage.name}/{tr.from_p:.2f} -> "
          f"{tr.to_stage.name}/{tr.to_p:.2f}  ({tr.kind}); breached={tr.reasons}")

    print("\n=== fraud-proof recomputation ===")
    prior = ClassState(Stage.RELAX, 0.5)
    receipts = good("cls.new.v1", 9)
    acc = fold_receipts(receipts)[("cls.new.v1", 9)]
    gate_ok, _ = gate(acc, TH)
    to_s, to_p, kind = evaluate_transition(prior.stage, prior.p_class, gate_ok, False)
    honest = make_posting(Transition("cls.new.v1", 9, prior.stage, prior.p_class,
                                     to_s, to_p, kind, gate_ok), acc)
    print(f"  honest posting (-> {to_s.name}/{to_p:.2f}) verified: "
          f"{verify_posting(honest, receipts, prior, TH)}")
    lie = WindowPosting("cls.new.v1", 9, acc.root(), Stage.RELAX, 0.5, Stage.RELAX, P_FLOOR)
    fp = verify_posting(lie, receipts, prior, TH)
    print(f"  lying posting (claims p={P_FLOOR} instead of {to_p:.2f}) caught: "
          f"{fp.reason} - {fp.detail}")


if __name__ == "__main__":
    main()
