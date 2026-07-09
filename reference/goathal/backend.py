"""
GoatBackend trait (PROTOCOL layer — the abstraction boundary itself).

Everything ABOVE this trait (scheduler, rewards, verification, conformance) must be
device-agnostic. Everything BELOW it (backends/*) is device-specific. The conformance
suite and all protocol logic call ONLY these methods and never inspect class_id for
behavior — that is what keeps "if it names a device type, it's wrong" true above the line.
"""
from abc import ABC, abstractmethod
from typing import List, Optional
from .types import (
    DeviceDescriptor, BenchmarkReport, DeterminismProfile, Task, TaskResult,
    OutputCommitment, ExecPolicy, SavedState, Telemetry, DeviceIdleState, Preempt,
)


class GoatBackend(ABC):
    # --- discovery & identity ---
    @abstractmethod
    def enumerate_devices(self) -> List[DeviceDescriptor]: ...

    @abstractmethod
    def benchmark(self, dev: DeviceDescriptor) -> BenchmarkReport: ...

    # --- capability ---
    @abstractmethod
    def determinism_profile(self, dev: DeviceDescriptor, task_class_id: int) -> DeterminismProfile: ...

    # --- execution ---
    @abstractmethod
    def load(self, dev: DeviceDescriptor, engine_build_id: str) -> "Session": ...

    @abstractmethod
    def execute(self, session: "Session", task: Task,
                policy: ExecPolicy, preempt: Optional[Preempt] = None): ...

    @abstractmethod
    def commit(self, result: TaskResult) -> OutputCommitment: ...

    @abstractmethod
    def preempt(self, session: "Session", grace_chunks: int) -> Optional[SavedState]: ...

    # --- telemetry & safety ---
    @abstractmethod
    def telemetry(self, dev: DeviceDescriptor) -> Telemetry: ...

    @abstractmethod
    def enforce_envelope(self, dev: DeviceDescriptor, max_power_w: int) -> None: ...

    @abstractmethod
    def idle_signals(self, dev: DeviceDescriptor) -> DeviceIdleState: ...


class Session:
    """Opaque handle a backend returns from load(); protocol code never introspects it."""
    def __init__(self, dev: DeviceDescriptor, engine_build_id: str):
        self.dev = dev
        self.engine_build_id = engine_build_id
        self.progress_chunks = 0
        self.last_power_w = 0.0
