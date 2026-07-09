//! GoatBackend trait — the abstraction boundary. Everything ABOVE this trait is
//! device-agnostic; backends (below the line, in goat-backends) are device-specific.
//! Protocol code calls only these methods and never inspects class_id for behavior.

use crate::types::{
    BenchmarkReport, DeterminismProfile, DeviceDescriptor, DeviceIdleState, ExecOutcome,
    ExecPolicy, Preempt, Task, TaskResult, Telemetry,
};

/// Opaque session handle a backend returns from `load`.
pub trait Session {}

pub trait GoatBackend {
    // discovery & identity
    fn enumerate_devices(&self) -> Vec<DeviceDescriptor>;
    fn benchmark(&self, dev: &DeviceDescriptor) -> BenchmarkReport;
    // capability
    fn determinism_profile(&self, dev: &DeviceDescriptor, task_class_id: u32)
        -> DeterminismProfile;
    // execution (Session is modeled by an opaque per-call handle; the reference backends
    // are stateless between calls, so we thread state through &mut self on the backend)
    fn execute(
        &mut self,
        dev: &DeviceDescriptor,
        task: &Task,
        policy: ExecPolicy,
        preempt: Preempt,
    ) -> ExecOutcome;
    fn commit(&self, result: &TaskResult) -> [u8; 32];
    // telemetry & safety
    fn telemetry(&self, dev: &DeviceDescriptor) -> Telemetry;
    fn enforce_envelope(&mut self, dev: &DeviceDescriptor, max_power_w: u32);
    fn idle_signals(&self, dev: &DeviceDescriptor) -> DeviceIdleState;
    // conformance observables (D-1)
    fn preempt_p95_ms(&self) -> u32;
    fn peak_power_w(&self) -> f64;
}
