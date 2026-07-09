//! Reference backend B — low-power class, TOLERANCE numeric profile (cross-vendor roundoff).
//! Tokens identical to A (pinned decode); numeric vector carries a bounded perturbation.

use goat_protocol::backend::GoatBackend;
use goat_protocol::commit::commit;
use goat_protocol::types::{
    BenchmarkReport, DeterminismProfile, DeviceDescriptor, DeviceIdleState, ExecOutcome,
    ExecPolicy, Preempt, SavedState, Task, TaskClassCap, TaskResult, Telemetry,
};
use sha3::{Digest, Sha3_256};

use crate::refcompute;

pub const CLASS_ID: &str = "cls.b.v1";
const NOMINAL_10: f64 = 0.15;
const NOMINAL_11: f64 = 0.12;
const BASE_POWER_W: f64 = 12.0;
const IDLE_POWER_W: f64 = 2.0;
const CHUNK_MS: u32 = 25;
const PERTURBATION: i64 = 5;
pub const DECLARED_BOUND: f64 = 8.0;

pub struct ReferenceBackendB {
    node_seed: u64,
    endpoint: String,
    power_cap: u32,
    last_power: f64,
    peak_power: f64,
}

impl ReferenceBackendB {
    pub fn new(node_seed: u64) -> Self {
        Self {
            node_seed,
            endpoint: "endpoint-B".into(),
            power_cap: BASE_POWER_W as u32,
            last_power: IDLE_POWER_W,
            peak_power: 0.0,
        }
    }
}

impl GoatBackend for ReferenceBackendB {
    fn enumerate_devices(&self) -> Vec<DeviceDescriptor> {
        vec![DeviceDescriptor {
            class_id: CLASS_ID.into(),
            device_index: 0,
            endpoint_id: self.endpoint.clone(),
        }]
    }

    fn benchmark(&self, _dev: &DeviceDescriptor) -> BenchmarkReport {
        let jitter = 1.0 + ((self.node_seed % 7) as f64 - 3.0) / 1000.0;
        let caps = vec![
            TaskClassCap {
                task_class_id: 10,
                measured_gcu_rate: (NOMINAL_10 * jitter * 1e6).round() / 1e6,
                mem_capacity_mb: 8000,
                batch_limit: 8,
                last_bench_epoch: 0,
            },
            TaskClassCap {
                task_class_id: 11,
                measured_gcu_rate: (NOMINAL_11 * jitter * 1e6).round() / 1e6,
                mem_capacity_mb: 8000,
                batch_limit: 8,
                last_bench_epoch: 0,
            },
        ];
        let mut h = Sha3_256::new();
        h.update(format!("{CLASS_ID}:{}", self.node_seed).as_bytes());
        BenchmarkReport {
            fingerprint: h.finalize().to_vec(),
            task_class_caps: caps,
        }
    }

    fn determinism_profile(&self, _dev: &DeviceDescriptor, _tc: u32) -> DeterminismProfile {
        DeterminismProfile::tolerance(DECLARED_BOUND)
    }

    fn execute(
        &mut self,
        _dev: &DeviceDescriptor,
        task: &Task,
        policy: ExecPolicy,
        preempt: Preempt,
    ) -> ExecOutcome {
        let cap = policy.power_cap_w.min(self.power_cap);
        for c in 0..6u32 {
            if preempt.requested {
                self.last_power = IDLE_POWER_W;
                return ExecOutcome::Preempted(SavedState { progress_chunks: c });
            }
            self.last_power = BASE_POWER_W.min(cap as f64);
            self.peak_power = self.peak_power.max(self.last_power);
        }
        let tokens = refcompute::reference_tokens(&task.payload, task.seed, 16); // identical to A
        let base = refcompute::reference_vector_base(&task.payload, task.seed, 8);
        let vector = refcompute::bounded_perturbation(&base, PERTURBATION);
        self.last_power = IDLE_POWER_W;
        ExecOutcome::Completed(TaskResult {
            task_class_id: task.task_class_id,
            tokens,
            vector,
            engine_build_id: task.engine_build_id.clone(),
        })
    }

    fn commit(&self, result: &TaskResult) -> [u8; 32] {
        commit(result)
    }

    fn telemetry(&self, _dev: &DeviceDescriptor) -> Telemetry {
        let active = self.last_power > IDLE_POWER_W;
        Telemetry {
            util: if active { 0.8 } else { 0.0 },
            power_w: self.last_power,
            temp_c: 38.0,
            mem_used_mb: if active { 1500 } else { 0 },
        }
    }

    fn enforce_envelope(&mut self, _dev: &DeviceDescriptor, max_power_w: u32) {
        self.power_cap = max_power_w;
    }

    fn idle_signals(&self, _dev: &DeviceDescriptor) -> DeviceIdleState {
        DeviceIdleState {
            idle: true,
            input_idle_ms: 120_000,
            screen_locked: false,
        }
    }

    fn preempt_p95_ms(&self) -> u32 {
        CHUNK_MS
    }

    fn peak_power_w(&self) -> f64 {
        self.peak_power
    }
}
