"""
Cross-class verification: AGREE predicate + escalation harness (PROTOCOL layer —
device-agnostic). Spec C, with the corrected tolerance rule accepted after Item 1:

  * Same-class pair : compare under that class's OWN determinism profile.
  * Cross-class pair: compare under the WIDENED band max(band_A, band_B) — never the
    stricter one (an EXACT verifier would false-reject a TOLERANCE executor's
    legitimate roundoff) — CAPPED by the task's determinism requirement: if the
    widened band exceeds the task bound, the pairing is INELIGIBLE and the task must
    pin to same-class verification.

Escalation (Spec C.3): on disagreement, a third executor C — cluster- AND ASN-disjoint
from both A and B, and pairable with both under the task bound — re-executes.
  C agrees with A only -> settle A, slash B, D_num += for B's class
  C agrees with B only -> settle B, slash A, D_num += for A's class
  C agrees with NEITHER -> 3-way split -> quarantine, no reward, no slash,
                           flag the determinism profile for re-measurement
  C agrees with BOTH    -> (edge Spec C.3 omits; see clarifications) tolerance bands
                           are not transitive: A and B can both sit within band of C
                           while disagreeing with each other. No fault is attributable;
                           settle the primary result, slash nobody, flag the profile —
                           the observed spread (~2x band) says the band is too tight.

Slashing uses maturity.slash_multiple (Spec B.5): the FAULTED executor's class
tolerance width sizes the slash — wider band, bigger slash, cheat-EV stays negative.
Outcomes are emitted as maturity.Receipt objects so they feed fold_receipts directly:
verification -> receipts -> accumulators -> maturity gate, closing the item 2-3-4 loop.

Everything here is class_id-opaque; nothing branches on a device type.
"""
from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, List, Optional, Sequence, Tuple

from .types import DeterminismProfile, DetKind, Task, TaskResult
from .commit import commit
from .maturity import Receipt, slash_multiple

_EPS = 1e-9
TOKEN_THRESHOLD = 0.98


# ---- executors ----
@dataclass(frozen=True)
class ExecutorRef:
    node_id: str
    class_id: str          # opaque registry ref
    cluster_id: str        # operator cluster (post-merge view from clustering/F6)
    asn: str
    profile: DeterminismProfile


@dataclass(frozen=True)
class Submission:
    executor: ExecutorRef
    result: TaskResult


RunFn = Callable[[Task], TaskResult]


# ---- comparison metrics ----
def l_inf(a: Sequence[int], b: Sequence[int]) -> float:
    if len(a) != len(b):
        return float("inf")
    if not a:
        return 0.0
    return float(max(abs(x - y) for x, y in zip(a, b)))


def token_agreement(a: Sequence[int], b: Sequence[int]) -> float:
    """LCS-based agreement in [0,1]: 2*LCS/(|a|+|b|). Identical sequences -> 1.0."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            dp[i][j] = dp[i - 1][j - 1] + 1 if a[i - 1] == b[j - 1] \
                else max(dp[i - 1][j], dp[i][j - 1])
    return 2.0 * dp[n][m] / (n + m)


# ---- effective profile (corrected Spec C.2) ----
def effective_profile(prof_a: DeterminismProfile, prof_b: DeterminismProfile,
                      same_class: bool, task_bound: float) -> Optional[DeterminismProfile]:
    """Comparison profile for a pair, or None if the pairing is ineligible for this task
    (widened band exceeds the task's determinism requirement -> pin same-class)."""
    band = prof_a.bound if same_class else max(prof_a.bound, prof_b.bound)
    if band > task_bound + _EPS:
        return None
    if band <= _EPS and prof_a.kind == DetKind.EXACT and \
            (same_class or prof_b.kind == DetKind.EXACT):
        return DeterminismProfile(DetKind.EXACT, "exact_match", 0.0)
    return DeterminismProfile(DetKind.TOLERANCE, "l_inf", band)


def agree(res_a: TaskResult, res_b: TaskResult, prof: DeterminismProfile,
          token_threshold: float = TOKEN_THRESHOLD) -> bool:
    """AGREE(R_A, R_B) under an effective profile."""
    if prof.kind == DetKind.EXACT:
        return commit(res_a).digest == commit(res_b).digest
    tok_ok = token_agreement(res_a.tokens, res_b.tokens) >= token_threshold
    vec_ok = l_inf(res_a.vector, res_b.vector) <= prof.bound + _EPS
    return tok_ok and vec_ok


# ---- outcome ----
class Status(Enum):
    SETTLED = 0                    # A,B agree
    SETTLED_ESCALATED = 1          # resolved by third executor C
    QUARANTINED = 2                # unresolved: 3-way split / no disjoint executor
    INELIGIBLE_CROSS_CLASS = 3     # task must pin to same-class verification


@dataclass(frozen=True)
class VerificationOutcome:
    status: Status
    winner: Optional[str]                  # node_id whose result settles
    slashed: Optional[str]                 # node_id slashed, if any
    slash_mult: Optional[float]
    receipts: Tuple[Receipt, ...]          # feed maturity.fold_receipts directly
    profile_remeasure: bool                # flag determinism profile for re-measurement
    detail: str


def _receipt(ex: ExecutorRef, task: Task, window: int,
             diverged: bool, fault: bool) -> Receipt:
    return Receipt(ex.class_id, task.task_class_id, window,
                   ex.cluster_id, ex.asn, diverged, fault)


def pick_disjoint_executor(pool: Sequence[Tuple[ExecutorRef, RunFn]],
                           a: ExecutorRef, b: ExecutorRef,
                           task_bound: float) -> Optional[Tuple[ExecutorRef, RunFn]]:
    """First pool member cluster- AND ASN-disjoint from both A and B, and pairable
    with both under the task bound (its pair profiles must exist)."""
    for ref, fn in pool:
        if ref.cluster_id in (a.cluster_id, b.cluster_id):
            continue
        if ref.asn in (a.asn, b.asn):
            continue
        if effective_profile(ref.profile, a.profile,
                             ref.class_id == a.class_id, task_bound) is None:
            continue
        if effective_profile(ref.profile, b.profile,
                             ref.class_id == b.class_id, task_bound) is None:
            continue
        return ref, fn
    return None


# ---- harness ----
class VerificationHarness:
    def __init__(self, tol_ref: float = 8.0, token_threshold: float = TOKEN_THRESHOLD):
        self.tol_ref = tol_ref
        self.token_threshold = token_threshold

    def _slash(self, faulted: ExecutorRef) -> float:
        return slash_multiple(faulted.profile.bound, self.tol_ref)

    def verify(self, task: Task, sub_a: Submission, sub_b: Submission,
               escalation_pool: Sequence[Tuple[ExecutorRef, RunFn]] = (),
               window: int = 0) -> VerificationOutcome:
        a, b = sub_a.executor, sub_b.executor
        prof_ab = effective_profile(a.profile, b.profile,
                                    a.class_id == b.class_id, task.determinism_bound)
        if prof_ab is None:
            return VerificationOutcome(
                Status.INELIGIBLE_CROSS_CLASS, None, None, None, (), False,
                "widened band exceeds task determinism bound; pin to same-class")

        if agree(sub_a.result, sub_b.result, prof_ab, self.token_threshold):
            return VerificationOutcome(
                Status.SETTLED, a.node_id, None, None,
                (_receipt(a, task, window, False, False),
                 _receipt(b, task, window, False, False)),
                False, f"agree under {prof_ab.kind.name} band={prof_ab.bound}")

        # --- escalate: disjoint third executor ---
        picked = pick_disjoint_executor(escalation_pool, a, b, task.determinism_bound)
        if picked is None:
            return VerificationOutcome(
                Status.QUARANTINED, None, None, None, (), True,
                "disagreement and no cluster/ASN-disjoint pairable executor available")
        c_ref, c_run = picked
        c_res = c_run(task)
        prof_ca = effective_profile(c_ref.profile, a.profile,
                                    c_ref.class_id == a.class_id, task.determinism_bound)
        prof_cb = effective_profile(c_ref.profile, b.profile,
                                    c_ref.class_id == b.class_id, task.determinism_bound)
        ca = agree(c_res, sub_a.result, prof_ca, self.token_threshold)
        cb = agree(c_res, sub_b.result, prof_cb, self.token_threshold)

        if ca and cb:
            # non-transitive tolerance: both within band of C, yet A,B disagree.
            # no fault attributable; settle primary; band flagged as too tight.
            return VerificationOutcome(
                Status.SETTLED_ESCALATED, a.node_id, None, None,
                (_receipt(a, task, window, False, False),
                 _receipt(b, task, window, False, False),
                 _receipt(c_ref, task, window, False, False)),
                True, "C within band of both; no attribution; profile re-measurement")
        if ca:
            return VerificationOutcome(
                Status.SETTLED_ESCALATED, a.node_id, b.node_id, self._slash(b),
                (_receipt(a, task, window, False, False),
                 _receipt(c_ref, task, window, False, False),
                 _receipt(b, task, window, True, True)),
                False, "C agrees with A; B faulted")
        if cb:
            return VerificationOutcome(
                Status.SETTLED_ESCALATED, b.node_id, a.node_id, self._slash(a),
                (_receipt(b, task, window, False, False),
                 _receipt(c_ref, task, window, False, False),
                 _receipt(a, task, window, True, True)),
                False, "C agrees with B; A faulted")
        return VerificationOutcome(
            Status.QUARANTINED, None, None, None, (), True,
            "3-way split; no reward, no slash pending review; profile re-measurement")
