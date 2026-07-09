"""
D.1 conformance suite runner (PROTOCOL layer — device-agnostic).

Runs Spec D criteria D1-D8 against ANY GoatBackend via the trait only. It never reads
class_id to decide behavior; a backend's class is opaque. Returns a structured report.
This is the objective gate for Backend Bounty award at Stage 1 and (via the
maintenance-stream CI predicate, D.2) for continuation.

`backend_factory(node_seed) -> GoatBackend` produces an independent "node".
"""
from dataclasses import dataclass
from typing import Dict
from .types import Task, TaskResult, ExecPolicy, Preempt, DetKind
from .commit import commit


@dataclass
class CriterionResult:
    passed: bool
    detail: str


@dataclass
class ConformanceReport:
    results: Dict[str, CriterionResult]

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results.values())


def _l_inf(a, b):
    return max(abs(x - y) for x, y in zip(a, b)) if a and b else 0


def run_conformance(backend_factory, node_count: int = 25) -> ConformanceReport:
    r: Dict[str, CriterionResult] = {}
    build = "build-1"
    task = Task(task_class_id=10, engine_build_id=build, payload=b"opaque-corpus-0",
                seed=1, determinism_bound=10.0)
    ref = backend_factory(0)
    dev = ref.enumerate_devices()[0]

    # D1 interface completeness
    required = ("enumerate_devices", "benchmark", "determinism_profile", "load",
                "execute", "commit", "preempt", "telemetry", "enforce_envelope",
                "idle_signals")
    missing = [m for m in required if not callable(getattr(ref, m, None))]
    r["D1_interface"] = CriterionResult(not missing, f"missing={missing}")

    # D2 capability honesty: benchmark reproduces within tolerance across N nodes
    rates = [backend_factory(i).benchmark(dev).task_class_caps[0].measured_gcu_rate
             for i in range(node_count)]
    median = sorted(rates)[len(rates) // 2]
    spread = max(abs(x - median) / median for x in rates)
    r["D2_capability_honesty"] = CriterionResult(spread <= 0.02, f"rel_spread={spread:.4f}")

    # D3 determinism declaration holds empirically
    prof = ref.determinism_profile(dev, 10)
    outs = [backend_factory(0).execute(backend_factory(0).load(dev, build), task,
                                       ExecPolicy(power_cap_w=10_000)).vector
            for _ in range(5)]
    worst = max(_l_inf(outs[0], o) for o in outs[1:]) if len(outs) > 1 else 0
    d3_ok = worst <= (0.0 if prof.kind == DetKind.EXACT else prof.bound)
    r["D3_determinism"] = CriterionResult(
        d3_ok, f"kind={prof.kind.name} worst_l_inf={worst} bound={prof.bound}")

    # D4 canonical commitment: byte-identical commit across independent nodes
    res_a = backend_factory(3).execute(backend_factory(3).load(dev, build), task,
                                       ExecPolicy(power_cap_w=10_000))
    res_b = backend_factory(9).execute(backend_factory(9).load(dev, build), task,
                                       ExecPolicy(power_cap_w=10_000))
    d4_ok = commit(res_a).digest == commit(res_b).digest
    r["D4_canonical_commit"] = CriterionResult(d4_ok, f"match={d4_ok}")

    # D5 preemption: a preempt request yields SavedState (not a full result), p95 declared
    p95 = getattr(ref, "preempt_p95_ms", None)
    saved = ref.execute(ref.load(dev, build), task, ExecPolicy(power_cap_w=10_000),
                        preempt=Preempt(requested=True))
    d5_ok = (p95 is not None) and (not isinstance(saved, TaskResult)) and hasattr(saved, "progress_chunks")
    r["D5_preemption"] = CriterionResult(bool(d5_ok), f"p95_ms={p95} yielded_savedstate={not isinstance(saved, TaskResult)}")

    # D6 envelope enforcement: peak power under load never exceeds the cap
    cap_w = 50
    b6 = backend_factory(0)
    b6.enforce_envelope(dev, cap_w)
    b6.execute(b6.load(dev, build), task, ExecPolicy(power_cap_w=cap_w))
    peak = b6.peak_power_w
    r["D6_envelope"] = CriterionResult(0 < peak <= cap_w, f"peak_power_w={peak} cap={cap_w}")

    # D7 telemetry fidelity: values in range, util normalized
    t = backend_factory(0).telemetry(dev)
    d7_ok = t.power_w >= 0 and 0.0 <= t.util <= 1.0 and t.mem_used_mb >= 0
    r["D7_telemetry"] = CriterionResult(d7_ok, f"power={t.power_w} util={t.util}")

    # D8 neutrality (behavioral half): commit is a function of task semantics only,
    # never device identity -> an identical result twin commits identically.
    twin = TaskResult(task_class_id=res_a.task_class_id, tokens=res_a.tokens,
                      vector=res_a.vector, engine_build_id=res_a.engine_build_id)
    r["D8_neutrality_behavioral"] = CriterionResult(
        commit(res_a).digest == commit(twin).digest,
        "commit depends on task semantics only, not device identity")

    return ConformanceReport(results=r)
