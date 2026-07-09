"""
Reference backend B — models a lower-power class with a TOLERANCE numeric profile
(cross-vendor FP roundoff). In production this is the ONNX-Runtime-style path; here it
is a deterministic reference that shares the same reference compute as backend A but
adds a small BOUNDED perturbation to the numeric vector. Tokens are identical to A
(pinned decode), so cross-class token agreement is exact and the numeric vector agrees
within the widened tolerance band.
"""
from typing import List, Optional
from ..backend import GoatBackend, Session
from ..commit import commit as _commit
from ..types import (
    DeviceDescriptor, BenchmarkReport, TaskClassCap, DeterminismProfile, DetKind,
    Task, TaskResult, OutputCommitment, ExecPolicy, SavedState, Telemetry,
    DeviceIdleState, Preempt,
)
from . import _refcompute as rc

CLASS_ID = "cls.b.v1"
TASK_CLASSES = (10, 11)
NOMINAL_GCU = {10: 0.15, 11: 0.12}   # lower throughput class
BASE_POWER_W = 12                    # very low power -> high energy multiple
IDLE_POWER_W = 2
CHUNK_MS = 25
PERTURBATION = 5                     # actual roundoff magnitude (<= declared bound)
DECLARED_BOUND = 8.0                 # declared tolerance band (must hold empirically)


class ReferenceBackendB(GoatBackend):
    def __init__(self, node_seed: int = 0, endpoint_id: str = "endpoint-B"):
        self._node_seed = node_seed
        self._endpoint = endpoint_id
        self._power_cap = BASE_POWER_W
        self._last_power = IDLE_POWER_W
        self._peak_power = 0.0

    def enumerate_devices(self) -> List[DeviceDescriptor]:
        return [DeviceDescriptor(class_id=CLASS_ID, device_index=0, endpoint_id=self._endpoint)]

    def benchmark(self, dev: DeviceDescriptor) -> BenchmarkReport:
        jitter = 1.0 + ((self._node_seed % 7) - 3) / 1000.0
        caps = tuple(
            TaskClassCap(task_class_id=tc, measured_gcu_rate=round(NOMINAL_GCU[tc] * jitter, 6),
                         mem_capacity_mb=8000, batch_limit=8, last_bench_epoch=0)
            for tc in TASK_CLASSES
        )
        import hashlib
        fp = hashlib.sha3_256(f"{CLASS_ID}:{self._node_seed}".encode()).digest()
        return BenchmarkReport(fingerprint=fp, task_class_caps=caps)

    def determinism_profile(self, dev: DeviceDescriptor, task_class_id: int) -> DeterminismProfile:
        return DeterminismProfile(kind=DetKind.TOLERANCE, metric="l_inf", bound=DECLARED_BOUND)

    def load(self, dev: DeviceDescriptor, engine_build_id: str) -> Session:
        return Session(dev, engine_build_id)

    def execute(self, session: Session, task: Task, policy: ExecPolicy,
                preempt: Optional[Preempt] = None):
        cap = min(policy.power_cap_w, self._power_cap)
        total_chunks = 6
        for c in range(total_chunks):
            if preempt is not None and preempt.requested:
                self._last_power = IDLE_POWER_W
                session.progress_chunks = c
                return SavedState(progress_chunks=c, partial=None)
            self._last_power = min(BASE_POWER_W, cap)
            self._peak_power = max(self._peak_power, self._last_power)
            session.progress_chunks = c + 1
        tokens = rc.reference_tokens(task.payload, task.seed)                    # identical to A
        base = rc.reference_vector_base(task.payload, task.seed)
        vector = rc.bounded_perturbation(base, PERTURBATION)                     # bounded roundoff
        self._last_power = IDLE_POWER_W
        return TaskResult(task_class_id=task.task_class_id, tokens=tokens,
                          vector=vector, engine_build_id=task.engine_build_id)

    def commit(self, result: TaskResult) -> OutputCommitment:
        return _commit(result)

    def preempt(self, session: Session, grace_chunks: int) -> Optional[SavedState]:
        return SavedState(progress_chunks=session.progress_chunks, partial=None)

    def telemetry(self, dev: DeviceDescriptor) -> Telemetry:
        return Telemetry(util=0.0 if self._last_power <= IDLE_POWER_W else 0.8,
                         power_w=self._last_power, temp_c=38.0,
                         mem_used_mb=0 if self._last_power <= IDLE_POWER_W else 1500)

    def enforce_envelope(self, dev: DeviceDescriptor, max_power_w: int) -> None:
        self._power_cap = int(max_power_w)

    def idle_signals(self, dev: DeviceDescriptor) -> DeviceIdleState:
        return DeviceIdleState(idle=True, input_idle_ms=120_000, screen_locked=False)

    @property
    def preempt_p95_ms(self) -> int:
        return CHUNK_MS

    @property
    def peak_power_w(self) -> float:
        return self._peak_power
