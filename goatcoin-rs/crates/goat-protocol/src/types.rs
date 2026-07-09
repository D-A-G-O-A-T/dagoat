//! Shared protocol types (device-agnostic).
//!
//! Structural guarantee for Core Principle 7 (no compliance logic): `Task` carries an
//! OPAQUE payload and NO model name / license / content field. There is nowhere in these
//! types to put a content policy, by construction.

/// A device class is an opaque registry string. The protocol never interprets it.
pub type ClassId = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetKind {
    /// bit-identical commitments required
    Exact,
    /// numeric band
    Tolerance,
    /// agreement within a distribution at confidence alpha
    Statistical,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeterminismProfile {
    pub kind: DetKind,
    pub metric: String, // "l_inf" | "cosine" | "token_agreement_rate" | "exact_match"
    pub bound: f64,     // tolerance bound (ignored for Exact)
    pub profile_version: u32,
}

impl DeterminismProfile {
    pub fn exact() -> Self {
        Self {
            kind: DetKind::Exact,
            metric: "l_inf".into(),
            bound: 0.0,
            profile_version: 1,
        }
    }
    pub fn tolerance(bound: f64) -> Self {
        Self {
            kind: DetKind::Tolerance,
            metric: "l_inf".into(),
            bound,
            profile_version: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskClassCap {
    pub task_class_id: u32,
    pub measured_gcu_rate: f64, // GCU/h, from benchmark (measured, never spec-sheet)
    pub mem_capacity_mb: u32,
    pub batch_limit: u16,
    pub last_bench_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct BenchmarkReport {
    pub fingerprint: Vec<u8>, // timing-signature commitment (hardware fingerprint)
    pub task_class_caps: Vec<TaskClassCap>,
}

#[derive(Clone, Debug)]
pub struct Task {
    pub task_class_id: u32,
    pub engine_build_id: String, // pins kernels/seed -> removes sampling nondeterminism
    pub payload: Vec<u8>,        // OPAQUE. never parsed for content/model/license.
    pub seed: u64,
    pub determinism_bound: f64, // task determinism_class requirement (widened cap)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaskResult {
    pub task_class_id: u32, // semantic (part of the task), NOT device identity
    pub tokens: Vec<u32>,
    pub vector: Vec<i64>, // fixed-point numeric outputs
    pub engine_build_id: String,
}

#[derive(Clone, Debug)]
pub struct DeviceDescriptor {
    pub class_id: ClassId,
    pub device_index: u32,
    pub endpoint_id: String, // feeds F6 density accounting
}

#[derive(Clone, Copy, Debug)]
pub struct ExecPolicy {
    pub power_cap_w: u32,
}

#[derive(Clone, Debug)]
pub struct SavedState {
    pub progress_chunks: u32,
}

/// Result of `execute`: either a completed result or a cooperative-preemption yield.
#[derive(Clone, Debug)]
pub enum ExecOutcome {
    Completed(TaskResult),
    Preempted(SavedState),
}

#[derive(Clone, Copy, Debug)]
pub struct Telemetry {
    pub util: f64,
    pub power_w: f64,
    pub temp_c: f64,
    pub mem_used_mb: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct DeviceIdleState {
    pub idle: bool,
    pub input_idle_ms: u64,
    pub screen_locked: bool,
}

/// Cooperative preemption signal handed to `execute`; the Sentinel/owner sets it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Preempt {
    pub requested: bool,
}
