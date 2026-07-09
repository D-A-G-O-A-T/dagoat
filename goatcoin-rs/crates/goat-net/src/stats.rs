//! Live-stats collector (WP-3.5a). Instruments distributed rounds to produce exactly the
//! statistics the Q1 Iteration-3 model consumes: escalation-outcome distribution, l_inf
//! divergence per class pair, escalation-pool composition (disjoint-pairable fraction),
//! profile_remeasure frequency, and F6 merge / coverage-inflation stats. Exports hand-written
//! JSON (no serde dependency). Device-agnostic — class ids are opaque strings.

use std::collections::BTreeMap;

use goat_protocol::verification::Status;

use crate::distributed::RoundOutcome;

#[derive(Default)]
pub struct LiveStatsCollector {
    pub rounds: u64,
    pub settle: u64,
    pub c_agrees_a: u64,
    pub c_agrees_b: u64,
    pub c_agrees_both: u64,
    pub quarantine: u64,
    pub ineligible: u64,
    pub profile_remeasure: u64,
    pub divergence_l_inf: Vec<f64>,
    pub escalation_l_inf: Vec<(f64, f64)>,
    pub disjoint_pairable: Vec<usize>,
    pub by_pair: BTreeMap<String, Vec<f64>>,
    // F6 (from the density probe / testnet driver)
    pub f6_merge_events: u64,
    pub coverage_naive: u64,
    pub coverage_effective: u64,
    // F6 detection campaign (WP-3.5d): true/false positive accounting
    pub f6_scenarios: u64,    // concentrated (Sybil) endpoints presented
    pub f6_sybil_merged: u64, // correctly flagged as cohort (true positives)
    pub f6_home_checked: u64, // home endpoints presented (should NOT merge)
    pub f6_home_flagged: u64, // home endpoints wrongly flagged (false positives)
    // band-edge (R-VER2) outcomes, isolated from clearly-faulty rounds
    pub be_rounds: u64,
    pub be_settle: u64,
    pub be_no_attribution: u64, // adversarial-node goal: free retry, no slash
    pub be_attribution: u64,    // backfired: one of the pair slashed
    pub be_quarantine: u64,
}

impl LiveStatsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one distributed round's outcome + telemetry.
    pub fn record(&mut self, out: &RoundOutcome) {
        self.rounds += 1;
        match out.status {
            Status::Settled => self.settle += 1,
            Status::SettledEscalated => {
                if out.slashed.is_none() {
                    self.c_agrees_both += 1; // no attribution (R-VER2 signal)
                } else if out.detail.contains("B faulted") {
                    self.c_agrees_a += 1;
                } else {
                    self.c_agrees_b += 1;
                }
            }
            Status::Quarantined => self.quarantine += 1,
            Status::IneligibleCrossClass => self.ineligible += 1,
        }
        if let Some(t) = &out.telemetry {
            self.divergence_l_inf.push(t.l_inf_ab);
            self.disjoint_pairable.push(t.disjoint_pairable);
            self.by_pair
                .entry(pair_key(&t.class_a, &t.class_b))
                .or_default()
                .push(t.l_inf_ab);
            if t.escalated {
                self.escalation_l_inf.push((t.l_inf_ca, t.l_inf_cb));
            }
            if t.profile_remeasure {
                self.profile_remeasure += 1;
            }
        }
    }

    /// Record an F6 cohort-merge event and the naive vs effective cluster coverage (SC6).
    pub fn record_f6(&mut self, merge_events: u64, coverage_naive: u64, coverage_effective: u64) {
        self.f6_merge_events += merge_events;
        self.coverage_naive = coverage_naive;
        self.coverage_effective = coverage_effective;
    }

    /// Record a band-edge (R-VER2) round separately, so the no-attribution success rate can be
    /// measured among genuine straddle attempts (not diluted by clearly-faulty rounds).
    pub fn record_bandedge(&mut self, out: &RoundOutcome) {
        self.be_rounds += 1;
        match out.status {
            Status::Settled => self.be_settle += 1,
            Status::SettledEscalated => {
                if out.slashed.is_none() {
                    self.be_no_attribution += 1;
                } else {
                    self.be_attribution += 1;
                }
            }
            Status::Quarantined => self.be_quarantine += 1,
            Status::IneligibleCrossClass => {}
        }
    }

    /// Record one F6 detection scenario: whether the concentrated endpoint was correctly
    /// merged (true positive), and how many honest home endpoints were checked / wrongly
    /// flagged (false positives). Builds the F6 detection- and false-positive-rate stats.
    pub fn record_f6_detection(
        &mut self,
        sybil_merged: bool,
        home_checked: u64,
        home_flagged: u64,
    ) {
        self.f6_scenarios += 1;
        if sybil_merged {
            self.f6_sybil_merged += 1;
        }
        self.f6_home_checked += home_checked;
        self.f6_home_flagged += home_flagged;
    }

    fn ratio(&self, num: u64) -> f64 {
        if self.rounds == 0 {
            0.0
        } else {
            num as f64 / self.rounds as f64
        }
    }

    /// Hand-written JSON export consumed by q1_iteration3_skeleton.py.
    pub fn to_json(&self) -> String {
        let mean_pool = if self.disjoint_pairable.is_empty() {
            0.0
        } else {
            self.disjoint_pairable.iter().sum::<usize>() as f64
                / self.disjoint_pairable.len() as f64
        };
        let inflation = if self.coverage_effective == 0 {
            1.0
        } else {
            self.coverage_naive as f64 / self.coverage_effective as f64
        };
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"rounds\": {},\n", self.rounds));
        s.push_str("  \"escalation_outcomes\": {");
        s.push_str(&format!(
            "\"settle\": {}, \"c_agrees_a\": {}, \"c_agrees_b\": {}, \"c_agrees_both\": {}, \"quarantine\": {}, \"ineligible\": {}",
            self.settle, self.c_agrees_a, self.c_agrees_b, self.c_agrees_both, self.quarantine, self.ineligible
        ));
        s.push_str("},\n");
        s.push_str(&format!(
            "  \"no_attribution_rate\": {:.6},\n",
            self.ratio(self.c_agrees_both)
        ));
        s.push_str(&format!(
            "  \"profile_remeasure_rate\": {:.6},\n",
            self.ratio(self.profile_remeasure)
        ));
        s.push_str(&format!(
            "  \"escalation_pool_disjoint_pairable_mean\": {mean_pool:.4},\n"
        ));
        s.push_str(&format!(
            "  \"divergence_l_inf\": {},\n",
            f64_array(&self.divergence_l_inf)
        ));
        s.push_str("  \"escalation_l_inf\": [");
        for (i, (ca, cb)) in self.escalation_l_inf.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("[{ca:.3}, {cb:.3}]"));
        }
        s.push_str("],\n");
        s.push_str("  \"divergence_l_inf_by_pair\": {");
        for (i, (k, v)) in self.by_pair.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("\"{k}\": {}", f64_array(v)));
        }
        s.push_str("},\n");
        s.push_str("  \"f6\": {");
        s.push_str(&format!(
            "\"merge_events\": {}, \"coverage_naive\": {}, \"coverage_effective\": {}, \"inflation_prevented\": {:.4}, \"scenarios\": {}, \"sybil_merged\": {}, \"home_checked\": {}, \"home_flagged\": {}",
            self.f6_merge_events, self.coverage_naive, self.coverage_effective, inflation,
            self.f6_scenarios, self.f6_sybil_merged, self.f6_home_checked, self.f6_home_flagged
        ));
        s.push_str("},\n");
        s.push_str("  \"band_edge\": {");
        s.push_str(&format!(
            "\"rounds\": {}, \"settle\": {}, \"no_attribution\": {}, \"attribution\": {}, \"quarantine\": {}",
            self.be_rounds, self.be_settle, self.be_no_attribution, self.be_attribution, self.be_quarantine
        ));
        s.push_str("}\n}\n");
        s
    }
}

fn pair_key(a: &str, b: &str) -> String {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    format!("{x}|{y}")
}

fn f64_array(v: &[f64]) -> String {
    let mut s = String::from("[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("{x:.3}"));
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::{RoundOutcome, RoundTelemetry};

    fn out(
        status: Status,
        slashed: Option<&str>,
        detail: &'static str,
        tele: Option<RoundTelemetry>,
    ) -> RoundOutcome {
        RoundOutcome {
            status,
            winner: None,
            slashed: slashed.map(|s| s.to_string()),
            slash_mult: None,
            selected_c: None,
            receipts: vec![],
            signed_receipts: vec![],
            escalation: None,
            profile_remeasure: false,
            log: None,
            detail,
            telemetry: tele,
        }
    }

    #[test]
    fn classifies_outcomes_and_exports_valid_json() {
        let mut c = LiveStatsCollector::new();
        c.record(&out(
            Status::Settled,
            None,
            "agree",
            Some(RoundTelemetry {
                class_a: "cls.a.v1".into(),
                class_b: "cls.b.v1".into(),
                l_inf_ab: 3.0,
                disjoint_pairable: 5,
                ..Default::default()
            }),
        ));
        c.record(&out(
            Status::SettledEscalated,
            Some("B"),
            "C agrees with A; B faulted",
            Some(RoundTelemetry {
                class_a: "cls.a.v1".into(),
                class_b: "cls.b.v1".into(),
                l_inf_ab: 50.0,
                escalated: true,
                l_inf_ca: 0.0,
                l_inf_cb: 50.0,
                disjoint_pairable: 4,
                ..Default::default()
            }),
        ));
        c.record(&out(
            Status::SettledEscalated,
            None,
            "C within band of both; no attribution",
            Some(RoundTelemetry {
                escalated: true,
                profile_remeasure: true,
                disjoint_pairable: 4,
                ..Default::default()
            }),
        ));
        c.record_f6(1, 50, 21);
        assert_eq!((c.settle, c.c_agrees_a, c.c_agrees_both), (1, 1, 1));
        let json = c.to_json();
        assert!(json.contains("\"rounds\": 3"));
        assert!(json.contains("\"no_attribution_rate\""));
        assert!(json.contains("\"inflation_prevented\""));
        assert!(json.contains("cls.a.v1|cls.b.v1"));
    }
}
