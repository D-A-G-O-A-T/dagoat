"""
Reference backend A — models a high-throughput class with an EXACT numeric profile
(pinned integer kernels). In production this is the llama.cpp-style path; here it is a
deterministic reference. Class ids are opaque registry strings; nothing in the protocol
layer interprets them.
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

CLASS_ID = "cls.a.v1"          # opaque; the registry assigns these
TASK_CLASSES = (10, 11)        # embedding-class, generative-class (ids only)
NOMINAL_GCU = {10: 1.00, 11: 0.90}
BASE_POWER_W = 200
IDLE_POWER_W = 12
CHUNK_MS = 40                  # preemption granularity -> declared p95


class ReferenceBackendA(GoatBackend):
    def __init__(self, node_seed: int = 0, endpoint_id: str = "endpoint-A"):
        self._node_seed = node_seed
        self._endpoint = endpoint_id
        self._power_cap = BASE_POWER_W
        self._last_power = IDLE_POWER_W
        self._peak_power = 0.0

    def enumerate_devices(self) -> List[DeviceDescriptor]:
        return [DeviceDescriptor(class_id=CLASS_ID, device_index=0, endpoint_id=self._endpoint)]

    def benchmark(self, dev: DeviceDescriptor) -> BenchmarkReport:
        # deterministic per-node jitter models real hardware variance (<=1%)
        jitter = 1.0 + ((self._node_seed % 7) - 3) / 1000.0
        caps = tuple(
            TaskClassCap(task_class_id=tc, measured_gcu_rate=round(NOMINAL_GCU[tc] * jitter, 6),
                         mem_capacity_mb=24000, batch_limit=32, last_bench_epoch=0)
            for tc in TASK_CLASSES
        )
        import hashlib
        fp = hashlib.sha3_256(f"{CLASS_ID}:{self._node_seed}".encode()).digest()
        return BenchmarkReport(fingerprint=fp, task_class_caps=caps)

    def determinism_profile(self, dev: DeviceDescriptor, task_class_id: int) -> DeterminismProfile:
        return DeterminismProfile(kind=DetKind.EXACT, metric="l_inf", bound=0.0)

    def load(self, dev: DeviceDescriptor, engine_build_id: str) -> Session:
        return Session(dev, engine_build_id)

    def execute(self, session: Session, task: Task, policy: ExecPolicy,
                preempt: Optional[Preempt] = None):
        cap = min(policy.power_cap_w, self._power_cap)
        total_chunks = 8
        for c in range(total_chunks):
            if preempt is not None and preempt.requested:
                # cooperative yield at chunk boundary; latency <= one CHUNK_MS
                self._last_power = IDLE_POWER_W
                session.progress_chunks = c
                return SavedState(progress_chunks=c, partial=None)
            # envelope enforcement: reported power never exceeds the cap
            self._last_power = min(BASE_POWER_W, cap)
            self._peak_power = max(self._peak_power, self._last_power)
            session.progress_chunks = c + 1
        tokens = rc.reference_tokens(task.payload, task.seed)
        vector = rc.reference_vector_base(task.payload, task.seed)  # EXACT: no perturbation
        self._last_power = IDLE_POWER_W
        return TaskResult(task_class_id=task.task_class_id, tokens=tokens,
                          vector=vector, engine_build_id=task.engine_build_id)

    def commit(self, result: TaskResult) -> OutputCommitment:
        return _commit(result)

    def preempt(self, session: Session, grace_chunks: int) -> Optional[SavedState]:
        return SavedState(progress_chunks=session.progress_chunks, partial=None)

    def telemetry(self, dev: DeviceDescriptor) -> Telemetry:
        return Telemetry(util=0.0 if self._last_power <= IDLE_POWER_W else 0.9,
                         power_w=self._last_power, temp_c=45.0,
                         mem_used_mb=0 if self._last_power <= IDLE_POWER_W else 8000)

    def enforce_envelope(self, dev: DeviceDescriptor, max_power_w: int) -> None:
        self._power_cap = int(max_power_w)

    def idle_signals(self, dev: DeviceDescriptor) -> DeviceIdleState:
        return DeviceIdleState(idle=True, input_idle_ms=600_000, screen_locked=True)

    # exposed for conformance (declared preemption p95)
    @property
    def preempt_p95_ms(self) -> int:
        return CHUNK_MS

    @property
    def peak_power_w(self) -> float:
        return self._peak_power
