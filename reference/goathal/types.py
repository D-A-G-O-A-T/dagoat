"""
Shared protocol types (PROTOCOL layer — device-agnostic).

Deliberate structural guarantee for Core Principle 7 (no compliance logic):
`Task` carries an OPAQUE payload and NO model name / license / content field.
There is nowhere in these types to put a content policy, by construction.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple


# --- capability / device description (a class_id is an opaque registry string) ---
@dataclass(frozen=True)
class DeviceDescriptor:
    class_id: str          # opaque registry ref, e.g. "cls.a.v1" — never interpreted
    device_index: int
    endpoint_id: str       # network endpoint (feeds F6 density accounting, item 2)


@dataclass(frozen=True)
class TaskClassCap:
    task_class_id: int
    measured_gcu_rate: float   # GCU/h, from benchmark (measured, never spec-sheet)
    mem_capacity_mb: int
    batch_limit: int
    last_bench_epoch: int


@dataclass(frozen=True)
class BenchmarkReport:
    fingerprint: bytes                 # timing-signature commitment (hardware fingerprint)
    task_class_caps: Tuple[TaskClassCap, ...]


class DetKind(Enum):
    EXACT = 0          # bit-identical commitments required
    TOLERANCE = 1      # numeric band
    STATISTICAL = 2    # agreement within a distribution at confidence alpha


@dataclass(frozen=True)
class DeterminismProfile:
    kind: DetKind
    metric: str        # 'l_inf' | 'cosine' | 'token_agreement_rate' | 'exact_match'
    bound: float       # tolerance bound (ignored for EXACT)
    profile_version: int = 1


# --- work ---
@dataclass(frozen=True)
class Task:
    task_class_id: int
    engine_build_id: str      # pins kernels/seed -> removes sampling nondeterminism
    payload: bytes            # OPAQUE. never parsed for content/model/license.
    seed: int
    determinism_bound: float  # task's determinism_class requirement (widened cap)


@dataclass(frozen=True)
class TaskResult:
    task_class_id: int        # semantic (part of the task), NOT device identity
    tokens: Tuple[int, ...]
    vector: Tuple[int, ...]   # fixed-point numeric outputs
    engine_build_id: str


@dataclass(frozen=True)
class OutputCommitment:
    digest: bytes             # 32-byte SHA3-256 over canonical serialization


@dataclass
class ExecPolicy:
    power_cap_w: int          # from enforce_envelope; execution must never exceed
    chunk_limit: int = 0      # 0 = run to completion


@dataclass
class SavedState:
    progress_chunks: int
    partial: TaskResult = None


@dataclass
class Telemetry:
    util: float
    power_w: float
    temp_c: float
    mem_used_mb: int


@dataclass
class DeviceIdleState:
    idle: bool
    input_idle_ms: int
    screen_locked: bool


@dataclass
class Preempt:
    """Cooperative preemption signal handed to execute(); Sentinel/owner sets it."""
    requested: bool = False
