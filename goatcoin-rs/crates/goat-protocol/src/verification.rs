//! Cross-class verification: AGREE + escalation (device-agnostic). Spec C amendments:
//! C-1 (widened band max, capped by task bound; ineligible -> same-class pin), C-2 (fourth
//! outcome: C agrees with both -> no attribution), C-3 (disjoint AND pairable third
//! executor), C-5 (tokens AND numerics; length-mismatch = disagree). Slash from maturity B-1.

use crate::commit::commit;
use crate::maturity::{slash_multiple, Receipt, SUB_WINDOWS};
use crate::types::{ClassId, DetKind, DeterminismProfile, Task, TaskResult};

const EPS: f64 = 1e-9;
pub const TOKEN_THRESHOLD: f64 = 0.98;

#[derive(Clone, Debug)]
pub struct ExecutorRef {
    pub node_id: String,
    pub class_id: ClassId,
    pub cluster_id: String,
    pub asn: String,
    pub profile: DeterminismProfile,
}

#[derive(Clone, Debug)]
pub struct Submission {
    pub executor: ExecutorRef,
    pub result: TaskResult,
}

pub type RunFn<'a> = Box<dyn Fn(&Task) -> TaskResult + 'a>;

// ---- metrics ----
pub fn l_inf(a: &[i64], b: &[i64]) -> f64 {
    if a.len() != b.len() {
        return f64::INFINITY;
    }
    a.iter()
        .zip(b)
        .map(|(x, y)| (x - y).abs())
        .max()
        .unwrap_or(0) as f64
}

pub fn token_agreement(a: &[u32], b: &[u32]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    2.0 * dp[n][m] as f64 / (n + m) as f64
}

/// Effective comparison profile for a pair, or None if the pairing is ineligible for this
/// task (widened band exceeds the task requirement -> pin same-class). C-1.
pub fn effective_profile(
    prof_a: &DeterminismProfile,
    prof_b: &DeterminismProfile,
    same_class: bool,
    task_bound: f64,
) -> Option<DeterminismProfile> {
    let band = if same_class {
        prof_a.bound
    } else {
        prof_a.bound.max(prof_b.bound)
    };
    if band > task_bound + EPS {
        return None;
    }
    if band <= EPS && prof_a.kind == DetKind::Exact && (same_class || prof_b.kind == DetKind::Exact)
    {
        return Some(DeterminismProfile::exact());
    }
    Some(DeterminismProfile::tolerance(band))
}

pub fn agree(
    a: &TaskResult,
    b: &TaskResult,
    prof: &DeterminismProfile,
    token_threshold: f64,
) -> bool {
    if prof.kind == DetKind::Exact {
        return commit(a) == commit(b);
    }
    let tok_ok = token_agreement(&a.tokens, &b.tokens) >= token_threshold;
    let vec_ok = l_inf(&a.vector, &b.vector) <= prof.bound + EPS;
    tok_ok && vec_ok
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Settled,
    SettledEscalated,
    Quarantined,
    IneligibleCrossClass,
}

#[derive(Clone, Debug)]
pub struct VerificationOutcome {
    pub status: Status,
    pub winner: Option<String>,
    pub slashed: Option<String>,
    pub slash_mult: Option<f64>,
    pub receipts: Vec<Receipt>,
    pub profile_remeasure: bool,
    pub detail: &'static str,
}

fn receipt(ex: &ExecutorRef, task: &Task, window: u64, diverged: bool, fault: bool) -> Receipt {
    Receipt {
        class_id: ex.class_id.clone(),
        task_class_id: task.task_class_id,
        window,
        // MVP sub-window stamp (R-MAT2): derived from the task's beacon-driven seed so any
        // observer recomputes the same bucket. Production stamps the attested completion
        // sub-window from the signed assignment log.
        sub_window: (task.seed % SUB_WINDOWS as u64) as u32,
        cluster_id: ex.cluster_id.clone(),
        asn: ex.asn.clone(),
        diverged,
        fault,
    }
}

/// First pool member cluster- AND ASN-disjoint from both A and B, and pairable with both
/// under the task bound. C-3. (Production replaces first-match with lottery selection.)
pub fn pick_disjoint_executor<'a>(
    pool: &'a [(ExecutorRef, RunFn<'a>)],
    a: &ExecutorRef,
    b: &ExecutorRef,
    task_bound: f64,
) -> Option<&'a (ExecutorRef, RunFn<'a>)> {
    pool.iter().find(|(r, _)| {
        r.cluster_id != a.cluster_id
            && r.cluster_id != b.cluster_id
            && r.asn != a.asn
            && r.asn != b.asn
            && effective_profile(&r.profile, &a.profile, r.class_id == a.class_id, task_bound)
                .is_some()
            && effective_profile(&r.profile, &b.profile, r.class_id == b.class_id, task_bound)
                .is_some()
    })
}

pub struct VerificationHarness {
    pub tol_ref: f64,
    pub token_threshold: f64,
}

impl VerificationHarness {
    pub fn new(tol_ref: f64) -> Self {
        Self {
            tol_ref,
            token_threshold: TOKEN_THRESHOLD,
        }
    }

    fn slash(&self, faulted: &ExecutorRef) -> f64 {
        slash_multiple(faulted.profile.bound, self.tol_ref)
    }

    pub fn verify(
        &self,
        task: &Task,
        sub_a: &Submission,
        sub_b: &Submission,
        escalation_pool: &[(ExecutorRef, RunFn<'_>)],
        window: u64,
    ) -> VerificationOutcome {
        let a = &sub_a.executor;
        let b = &sub_b.executor;
        let prof_ab = effective_profile(
            &a.profile,
            &b.profile,
            a.class_id == b.class_id,
            task.determinism_bound,
        );
        let prof_ab = match prof_ab {
            None => {
                return VerificationOutcome {
                    status: Status::IneligibleCrossClass,
                    winner: None,
                    slashed: None,
                    slash_mult: None,
                    receipts: vec![],
                    profile_remeasure: false,
                    detail: "widened band exceeds task bound; pin to same-class",
                };
            }
            Some(p) => p,
        };

        if agree(&sub_a.result, &sub_b.result, &prof_ab, self.token_threshold) {
            return VerificationOutcome {
                status: Status::Settled,
                winner: Some(a.node_id.clone()),
                slashed: None,
                slash_mult: None,
                receipts: vec![
                    receipt(a, task, window, false, false),
                    receipt(b, task, window, false, false),
                ],
                profile_remeasure: false,
                detail: "agree",
            };
        }

        // escalate: disjoint + pairable third executor
        let picked = pick_disjoint_executor(escalation_pool, a, b, task.determinism_bound);
        let (c_ref, c_run) = match picked {
            None => {
                return VerificationOutcome {
                    status: Status::Quarantined,
                    winner: None,
                    slashed: None,
                    slash_mult: None,
                    receipts: vec![],
                    profile_remeasure: true,
                    detail: "disagreement and no cluster/ASN-disjoint pairable executor",
                };
            }
            Some(p) => p,
        };
        let c_res = c_run(task);
        let prof_ca = effective_profile(
            &c_ref.profile,
            &a.profile,
            c_ref.class_id == a.class_id,
            task.determinism_bound,
        )
        .unwrap();
        let prof_cb = effective_profile(
            &c_ref.profile,
            &b.profile,
            c_ref.class_id == b.class_id,
            task.determinism_bound,
        )
        .unwrap();
        let ca = agree(&c_res, &sub_a.result, &prof_ca, self.token_threshold);
        let cb = agree(&c_res, &sub_b.result, &prof_cb, self.token_threshold);

        if ca && cb {
            // C-2: non-transitive tolerance -> no attribution; settle primary; flag profile.
            return VerificationOutcome {
                status: Status::SettledEscalated,
                winner: Some(a.node_id.clone()),
                slashed: None,
                slash_mult: None,
                receipts: vec![
                    receipt(a, task, window, false, false),
                    receipt(b, task, window, false, false),
                    receipt(c_ref, task, window, false, false),
                ],
                profile_remeasure: true,
                detail: "C within band of both; no attribution; profile re-measurement",
            };
        }
        if ca {
            return VerificationOutcome {
                status: Status::SettledEscalated,
                winner: Some(a.node_id.clone()),
                slashed: Some(b.node_id.clone()),
                slash_mult: Some(self.slash(b)),
                receipts: vec![
                    receipt(a, task, window, false, false),
                    receipt(c_ref, task, window, false, false),
                    receipt(b, task, window, true, true),
                ],
                profile_remeasure: false,
                detail: "C agrees with A; B faulted",
            };
        }
        if cb {
            return VerificationOutcome {
                status: Status::SettledEscalated,
                winner: Some(b.node_id.clone()),
                slashed: Some(a.node_id.clone()),
                slash_mult: Some(self.slash(a)),
                receipts: vec![
                    receipt(b, task, window, false, false),
                    receipt(c_ref, task, window, false, false),
                    receipt(a, task, window, true, true),
                ],
                profile_remeasure: false,
                detail: "C agrees with B; A faulted",
            };
        }
        VerificationOutcome {
            status: Status::Quarantined,
            winner: None,
            slashed: None,
            slash_mult: None,
            receipts: vec![],
            profile_remeasure: true,
            detail: "3-way split; no reward, no slash pending review",
        }
    }
}
