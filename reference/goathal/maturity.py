"""
Verification Maturity Controller (PROTOCOL layer — device-agnostic). Spec B.

A device class advances CANDIDATE -> PROBATION -> RELAX -> MATURE by holding on-chain
accumulators (V_c, divergence, faults, coverage) over 30-day windows. Sampling relaxes
one step per fully-held window (slow) and SNAPS UP immediately on any breach (fast) — the
asymmetric ratchet. All accumulators are pure functions of published receipts, so anyone
can recompute the window root and fraud-prove an illegal transition (Spec B.4).

Everything here is device-type-agnostic: class_id is an opaque registry string; coverage,
clusters, and ASNs are network/operator concepts, never device types.

Parameters incorporate the accepted fixes: p_floor = 0.15, min slash 15x, cap 20x (F3);
COHORT_MERGE from capability.py (F6) collapses coverage and can force a snap-up.
"""
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple

from .capability import DensitySignal

# ---- constants (F3 fixes) ----
P_FLOOR = 0.15
RELAX_STEPS = (1.0, 0.5, 0.25, P_FLOOR)      # PROBATION starts at 1.0; relax halves to floor
BASE_SLASH = 15.0
SLASH_CAP = 20.0
_EPS = 1e-9

# Stage-1 registration diversity thresholds (nodes, clusters, ASNs, regions)
REG_MIN_NODES, REG_MIN_CLUSTERS, REG_MIN_ASNS, REG_MIN_REGIONS = 50, 25, 10, 5


class Stage(Enum):
    CANDIDATE = 0
    PROBATION = 1
    RELAX = 2
    MATURE = 3


def _rank(s: Stage) -> int:
    return s.value


# ---- receipts & accumulators (Spec B.1) ----
@dataclass(frozen=True)
class Receipt:
    class_id: str
    task_class_id: int
    window: int
    cluster_id: str          # contributing operator cluster (opaque)
    asn: str                 # network ASN (opaque)
    diverged: bool           # result diverged from determinism profile beyond tolerance
    fault: bool              # fault / challenge upheld


@dataclass(frozen=True)
class ClassAccumulator:
    class_id: str
    window: int
    V_c: int
    D_num: int
    F_num: int
    cover_clusters: int
    cover_asns: int

    @property
    def divergence_rate(self) -> float:
        return self.D_num / self.V_c if self.V_c else 0.0

    @property
    def fault_rate_10k(self) -> float:
        return self.F_num / self.V_c * 10_000 if self.V_c else 0.0

    def serialize(self) -> bytes:
        out = bytearray(b"GACC\x01")
        b = self.class_id.encode("utf-8")
        out += len(b).to_bytes(4, "big") + b
        for n in (self.window, self.V_c, self.D_num, self.F_num,
                  self.cover_clusters, self.cover_asns):
            out += int(n).to_bytes(8, "big")
        return bytes(out)

    def root(self) -> bytes:
        return hashlib.sha3_256(self.serialize()).digest()


def _cluster_representative(merge_groups: Optional[List[FrozenSet[str]]]):
    rep: Dict[str, str] = {}
    if merge_groups:
        for grp in merge_groups:
            r = sorted(grp)[0]
            for c in grp:
                rep[c] = r
    return rep


def fold_receipts(receipts: List[Receipt],
                  merge_groups: Optional[List[FrozenSet[str]]] = None
                  ) -> Dict[Tuple[str, int], ClassAccumulator]:
    """Pure fold of published receipts into per-(class, window) accumulators. COHORT_MERGE
    groups (F6) collapse multiple cluster ids into one representative BEFORE coverage is
    counted, so overstated diversity cannot pass the gate."""
    rep = _cluster_representative(merge_groups)
    tmp: Dict[Tuple[str, int], Dict] = {}
    for r in receipts:
        k = (r.class_id, r.window)
        a = tmp.setdefault(k, dict(V=0, D=0, F=0, clusters=set(), asns=set()))
        a["V"] += 1
        a["D"] += 1 if r.diverged else 0
        a["F"] += 1 if r.fault else 0
        a["clusters"].add(rep.get(r.cluster_id, r.cluster_id))
        a["asns"].add(r.asn)
    return {k: ClassAccumulator(k[0], k[1], a["V"], a["D"], a["F"],
                                len(a["clusters"]), len(a["asns"]))
            for k, a in tmp.items()}


def window_root(accumulators: List[ClassAccumulator]) -> bytes:
    """Merkle-ish root over all class accumulators in a window (sorted by class_id)."""
    h = hashlib.sha3_256()
    for a in sorted(accumulators, key=lambda x: x.class_id):
        h.update(a.root())
    return h.digest()


# ---- GATE predicate (Spec B.2) ----
@dataclass(frozen=True)
class GateThresholds:
    v_min: int
    epsilon: float          # max divergence rate
    phi: float              # max fault rate per 10k
    x_clusters: int         # min distinct clusters (coverage)
    x_asns: int             # min distinct ASNs


def gate(acc: ClassAccumulator, th: GateThresholds) -> Tuple[bool, Dict[str, bool]]:
    checks = {
        "volume": acc.V_c >= th.v_min,
        "divergence": acc.divergence_rate < th.epsilon,
        "faults": acc.fault_rate_10k < th.phi,
        "coverage_clusters": acc.cover_clusters >= th.x_clusters,
        "coverage_asns": acc.cover_asns >= th.x_asns,
    }
    return all(checks.values()), checks


# ---- slash sizing coupled to tolerance width (Spec B.5) ----
def slash_multiple(tol_width: float, tol_ref: float,
                   base: float = BASE_SLASH, cap: float = SLASH_CAP,
                   coupling: float = 1.0 / 3.0) -> float:
    """Wider acceptable divergence -> more room to cheat under tolerance -> larger slash.
    `coupling` maps tol_width == tol_ref to the cap (default), rather than the spec's
    implicit coupling=1 which saturates at tol_ref/3 (see clarifications)."""
    if tol_ref <= 0:
        return base
    raw = base * (1.0 + coupling * (tol_width / tol_ref))
    return max(base, min(cap, raw))


def cheat_ev_margin(slash: float, p_effective: float) -> float:
    """cheat_EV < 0 iff slash*p_effective > 1. Returns the margin (safe when > 1)."""
    return slash * p_effective


# ---- state machine (Spec B.3) ----
@dataclass(frozen=True)
class ClassState:
    stage: Stage
    p_class: float
    last_transition_window: int = -1
    slash_mult: float = BASE_SLASH
    pioneer_armed: bool = False


@dataclass(frozen=True)
class Transition:
    class_id: str
    window: int
    from_stage: Stage
    from_p: float
    to_stage: Stage
    to_p: float
    kind: str                 # 'promote' | 'relax' | 'mature' | 'snap' | 'hold'
    gate_ok: bool
    reasons: Tuple[str, ...] = ()


def _snap(stage: Stage, p: float) -> Tuple[Stage, float, str]:
    new_p = min(1.0, p * 2.0)
    new_stage = Stage.PROBATION if new_p >= 1.0 - _EPS else Stage.RELAX
    return new_stage, new_p, "snap"


def evaluate_transition(from_stage: Stage, from_p: float, gate_ok: bool,
                        force_snap: bool) -> Tuple[Stage, float, str]:
    """Pure transition function — shared by the controller and the fraud verifier so they
    cannot disagree. `force_snap` models an immediate intra-window trigger (anomaly burst)."""
    if force_snap and from_stage in (Stage.RELAX, Stage.MATURE) and from_p < 1.0 - _EPS:
        return _snap(from_stage, from_p)
    if from_stage == Stage.CANDIDATE:
        return Stage.CANDIDATE, from_p, "hold"          # leaves CANDIDATE only via registration
    if from_stage == Stage.PROBATION:
        return (Stage.RELAX, 0.5, "promote") if gate_ok else (Stage.PROBATION, 1.0, "hold")
    if from_stage == Stage.RELAX:
        if not gate_ok:
            return _snap(Stage.RELAX, from_p)
        if from_p > P_FLOOR + _EPS:
            return Stage.RELAX, max(P_FLOOR, from_p / 2.0), "relax"
        return Stage.MATURE, P_FLOOR, "mature"
    # MATURE
    if not gate_ok:
        return _snap(Stage.MATURE, from_p)
    return Stage.MATURE, from_p, "hold"


@dataclass(frozen=True)
class RegistrationSet:
    nodes: int
    clusters: int
    asns: int
    regions: int

    def meets_diversity(self) -> bool:
        return (self.nodes >= REG_MIN_NODES and self.clusters >= REG_MIN_CLUSTERS
                and self.asns >= REG_MIN_ASNS and self.regions >= REG_MIN_REGIONS)


class MaturityController:
    def __init__(self, thresholds: GateThresholds, tol_ref: float = 8.0):
        self.th = thresholds
        self.tol_ref = tol_ref
        self.states: Dict[str, ClassState] = {}

    def register_class(self, class_id: str, reg: RegistrationSet, tol_width: float,
                       window: int) -> bool:
        """CANDIDATE -> PROBATION iff the registration set meets diversity thresholds.
        Arms the Pioneer multiplier and sizes slashing to the class tolerance (B.5)."""
        if not reg.meets_diversity():
            self.states[class_id] = ClassState(Stage.CANDIDATE, 1.0, window)
            return False
        self.states[class_id] = ClassState(
            stage=Stage.PROBATION, p_class=1.0, last_transition_window=window,
            slash_mult=slash_multiple(tol_width, self.tol_ref), pioneer_armed=True)
        return True

    def process_window(self, class_id: str, receipts: List[Receipt],
                       merge_groups: Optional[List[FrozenSet[str]]] = None,
                       anomaly_burst: bool = False, window: int = 0
                       ) -> Tuple[Transition, ClassAccumulator]:
        st = self.states[class_id]
        acc = fold_receipts(receipts, merge_groups).get(
            (class_id, window), ClassAccumulator(class_id, window, 0, 0, 0, 0, 0))
        gate_ok, checks = gate(acc, self.th)
        to_stage, to_p, kind = evaluate_transition(st.stage, st.p_class, gate_ok, anomaly_burst)
        reasons = tuple(k for k, v in checks.items() if not v)
        tr = Transition(class_id, window, st.stage, st.p_class, to_stage, to_p, kind,
                        gate_ok, reasons)
        self.states[class_id] = ClassState(to_stage, to_p, window, st.slash_mult, st.pioneer_armed)
        return tr, acc


def cohort_merge_groups(signals: Dict[str, DensitySignal],
                        endpoint_clusters: Dict[str, FrozenSet[str]]
                        ) -> List[FrozenSet[str]]:
    """Translate Item-2 COHORT_MERGE density signals into cluster merge groups the
    accumulator fold uses to collapse overstated diversity."""
    groups = []
    for key, sig in signals.items():
        if sig == DensitySignal.COHORT_MERGE and key in endpoint_clusters:
            groups.append(endpoint_clusters[key])
    return groups


# ---- fraud proof (Spec B.4) ----
@dataclass(frozen=True)
class WindowPosting:
    class_id: str
    window: int
    accumulator_root: bytes
    claimed_from_stage: Stage
    claimed_from_p: float
    claimed_to_stage: Stage
    claimed_to_p: float


@dataclass(frozen=True)
class FraudProof:
    reason: str
    detail: str


def make_posting(tr: Transition, acc: ClassAccumulator) -> WindowPosting:
    return WindowPosting(tr.class_id, tr.window, acc.root(),
                         tr.from_stage, tr.from_p, tr.to_stage, tr.to_p)


def verify_posting(posting: WindowPosting, receipts: List[Receipt],
                   prior: ClassState, th: GateThresholds,
                   merge_groups: Optional[List[FrozenSet[str]]] = None
                   ) -> Optional[FraudProof]:
    """Recompute accumulators from published receipts and detect an illegal posting.
    Fraud iff: (a) the accumulator root does not match; (b) the claimed prior state is
    wrong; (c) the claimed transition is LESS SAFE than the recomputable lower bound —
    i.e. lower sampling (p) or a more advanced stage than the gate justifies. An
    orchestrator may always be MORE conservative (higher p / snap) without being fraudulent."""
    acc = fold_receipts(receipts, merge_groups).get(
        (posting.class_id, posting.window),
        ClassAccumulator(posting.class_id, posting.window, 0, 0, 0, 0, 0))

    if acc.root() != posting.accumulator_root:
        return FraudProof("root_mismatch", "recomputed accumulator root != posted root")

    if (posting.claimed_from_stage, abs(posting.claimed_from_p - prior.p_class) < _EPS) != \
       (prior.stage, True):
        return FraudProof("bad_prior",
                          f"claimed prior {posting.claimed_from_stage.name}/{posting.claimed_from_p} "
                          f"!= known {prior.stage.name}/{prior.p_class}")

    gate_ok, _ = gate(acc, th)
    legal_stage, legal_p, _ = evaluate_transition(prior.stage, prior.p_class, gate_ok, False)

    if posting.claimed_to_p < legal_p - _EPS:
        return FraudProof("undersampling",
                          f"claimed p={posting.claimed_to_p} < legal p={legal_p}")
    if _rank(posting.claimed_to_stage) > _rank(legal_stage):
        return FraudProof("over_advanced",
                          f"claimed stage {posting.claimed_to_stage.name} more advanced than "
                          f"legal {legal_stage.name}")
    return None
