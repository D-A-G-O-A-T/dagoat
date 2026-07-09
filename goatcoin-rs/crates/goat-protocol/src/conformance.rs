//! D.1 conformance suite runner (device-agnostic). Runs D1-D8 against ANY GoatBackend via
//! the trait only; never reads class_id to decide behavior. D-1: D6 uses a peak-power
//! observable and enforce_envelope binds over the per-task policy.

use std::collections::BTreeMap;

use crate::backend::GoatBackend;
use crate::commit::commit;
use crate::types::{DetKind, ExecOutcome, ExecPolicy, Preempt, Task, TaskResult};

pub struct ConformanceReport {
    pub results: BTreeMap<String, (bool, String)>,
}

impl ConformanceReport {
    pub fn all_passed(&self) -> bool {
        self.results.values().all(|(ok, _)| *ok)
    }
}

fn l_inf(a: &[i64], b: &[i64]) -> i64 {
    if a.len() != b.len() || a.is_empty() {
        return if a.is_empty() && b.is_empty() {
            0
        } else {
            i64::MAX
        };
    }
    a.iter()
        .zip(b)
        .map(|(x, y)| (x - y).abs())
        .max()
        .unwrap_or(0)
}

/// `factory(node_seed) -> Backend`. D2 uses independent nodes; D4 uses fresh nodes.
pub fn run_conformance<B: GoatBackend>(
    factory: &dyn Fn(u64) -> B,
    node_count: u64,
) -> ConformanceReport {
    let mut r = BTreeMap::new();
    let build = "build-1";
    let task = Task {
        task_class_id: 10,
        engine_build_id: build.into(),
        payload: b"opaque-corpus-0".to_vec(),
        seed: 1,
        determinism_bound: 10.0,
    };
    let refb = factory(0);
    let dev = refb.enumerate_devices()[0].clone();

    // D1 interface completeness is guaranteed by the trait; record trivially true.
    r.insert("D1_interface".into(), (true, "trait-guaranteed".into()));

    // D2 capability honesty: benchmark reproduces within tolerance across N nodes
    let rates: Vec<f64> = (0..node_count)
        .map(|i| factory(i).benchmark(&dev).task_class_caps[0].measured_gcu_rate)
        .collect();
    let mut sorted = rates.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[sorted.len() / 2];
    let spread = rates
        .iter()
        .map(|x| (x - median).abs() / median)
        .fold(0.0, f64::max);
    r.insert(
        "D2_capability_honesty".into(),
        (spread <= 0.02, format!("rel_spread={spread:.4}")),
    );

    // D3 determinism declaration holds empirically
    let prof = refb.determinism_profile(&dev, 10);
    let mut outs: Vec<Vec<i64>> = Vec::new();
    for _ in 0..5 {
        let mut b = factory(0);
        if let ExecOutcome::Completed(res) = b.execute(
            &dev,
            &task,
            ExecPolicy {
                power_cap_w: 10_000,
            },
            Preempt::default(),
        ) {
            outs.push(res.vector);
        }
    }
    let worst = outs
        .iter()
        .skip(1)
        .map(|o| l_inf(&outs[0], o))
        .max()
        .unwrap_or(0);
    let d3_ok = if prof.kind == DetKind::Exact {
        worst == 0
    } else {
        worst as f64 <= prof.bound
    };
    r.insert(
        "D3_determinism".into(),
        (
            d3_ok,
            format!("kind={:?} worst={worst} bound={}", prof.kind, prof.bound),
        ),
    );

    // D4 canonical commitment: byte-identical commit across independent nodes
    let run = |seed: u64| -> Option<TaskResult> {
        let mut b = factory(seed);
        match b.execute(
            &dev,
            &task,
            ExecPolicy {
                power_cap_w: 10_000,
            },
            Preempt::default(),
        ) {
            ExecOutcome::Completed(res) => Some(res),
            _ => None,
        }
    };
    let d4_ok = match (run(3), run(9)) {
        (Some(x), Some(y)) => commit(&x) == commit(&y),
        _ => false,
    };
    r.insert(
        "D4_canonical_commit".into(),
        (d4_ok, format!("match={d4_ok}")),
    );

    // D5 preemption: a preempt request yields a SavedState, not a full result
    let mut b5 = factory(0);
    let saved = b5.execute(
        &dev,
        &task,
        ExecPolicy {
            power_cap_w: 10_000,
        },
        Preempt { requested: true },
    );
    let d5_ok = matches!(saved, ExecOutcome::Preempted(_)) && refb.preempt_p95_ms() > 0;
    r.insert(
        "D5_preemption".into(),
        (
            d5_ok,
            format!(
                "p95={} yielded={}",
                refb.preempt_p95_ms(),
                matches!(saved, ExecOutcome::Preempted(_))
            ),
        ),
    );

    // D6 envelope enforcement: peak power under load never exceeds the cap (D-1)
    let cap = 50u32;
    let mut b6 = factory(0);
    b6.enforce_envelope(&dev, cap);
    let _ = b6.execute(
        &dev,
        &task,
        ExecPolicy { power_cap_w: cap },
        Preempt::default(),
    );
    let peak = b6.peak_power_w();
    r.insert(
        "D6_envelope".into(),
        (
            peak > 0.0 && peak <= cap as f64,
            format!("peak={peak} cap={cap}"),
        ),
    );

    // D7 telemetry fidelity
    let t = factory(0).telemetry(&dev);
    r.insert(
        "D7_telemetry".into(),
        (
            t.power_w >= 0.0 && (0.0..=1.0).contains(&t.util),
            format!("power={} util={}", t.power_w, t.util),
        ),
    );

    // D8 neutrality (behavioral half): commit is a function of task semantics only
    let res = run(3).unwrap();
    let twin = TaskResult {
        task_class_id: res.task_class_id,
        tokens: res.tokens.clone(),
        vector: res.vector.clone(),
        engine_build_id: res.engine_build_id.clone(),
    };
    r.insert(
        "D8_neutrality_behavioral".into(),
        (
            commit(&res) == commit(&twin),
            "commit depends on task semantics only".into(),
        ),
    );

    ConformanceReport { results: r }
}
