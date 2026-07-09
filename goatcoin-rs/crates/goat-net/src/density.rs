//! Density probe + F6 on real infrastructure (WP-3.1). Device-agnostic.
//!
//! A passive per-endpoint observer: it watches sustained work throughput attributable to each
//! network endpoint (bytes/tasks completed per unit time), converts that to
//! reference-device-equivalents, and applies F4/F6:
//!   * F4: q_network degrades sharply past the residential-plausible device count.
//!   * F6: on a residential endpoint whose OBSERVED density exceeds the plausible count, emit
//!     COHORT_MERGE — the identities behind that endpoint are one concentrated cohort.
//!
//! Crucially, F6 evaluates on the PROBE-OBSERVED value, never a node's self-declared density
//! (Rev D/B6: the probe is ground truth; self-reports only detect dishonesty). This is what
//! makes a co-located Sybil (many identities, one fat pipe) collapse to one cluster.
//!
//! "Realistic enough": the probe measures sustained throughput per endpoint over a window and
//! divides by the reference-device throughput. A home endpoint hosting 1-3 devices lands at
//! density ~1-3; a warehouse pushing 40 devices' worth of work through one residential IP lands
//! at ~40 regardless of how many node identities it presents. The distinguishing signal is
//! physical (aggregate throughput per endpoint), not declared.

use std::collections::HashMap;

use goat_protocol::capability::{
    q_network_factor, DensitySignal, NetworkClass, RESIDENTIAL_DENSITY_PLAUSIBLE,
};

/// Throughput of one reference-device-equivalent over the probe window (work units). Tunable;
/// the ratio observed/reference is what matters, so the unit cancels.
pub const REFERENCE_THROUGHPUT_PER_WINDOW: f64 = 1.0;

/// Passive observer accumulating per-endpoint work throughput. `endpoint_id` is an opaque
/// network identifier (e.g. a commitment to the observed last-mile), NOT a node identity.
#[derive(Default)]
pub struct DensityProbe {
    observed_work: HashMap<String, f64>, // endpoint -> summed work units this window
    network_class: HashMap<String, NetworkClass>,
    endpoint_nodes: HashMap<String, Vec<String>>, // endpoint -> node identities seen behind it
}

impl DensityProbe {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the observed network class of an endpoint (probe-derived: multilateration +
    /// last-mile characterization, per Rev D). Residential vs datacenter is a *network*
    /// property, not a device type.
    pub fn set_network_class(&mut self, endpoint: &str, class: NetworkClass) {
        self.network_class.insert(endpoint.to_string(), class);
    }

    /// Record observed work completed that the probe attributes to `endpoint` by node `node_id`.
    /// This is passive: the probe measures throughput it sees, not what a node claims.
    pub fn observe(&mut self, endpoint: &str, node_id: &str, work_units: f64) {
        *self.observed_work.entry(endpoint.to_string()).or_default() += work_units;
        let nodes = self.endpoint_nodes.entry(endpoint.to_string()).or_default();
        if !nodes.contains(&node_id.to_string()) {
            nodes.push(node_id.to_string());
        }
    }

    /// Probe-observed density (reference-device-equivalents) for an endpoint.
    pub fn observed_density(&self, endpoint: &str) -> u32 {
        let w = self.observed_work.get(endpoint).copied().unwrap_or(0.0);
        (w / REFERENCE_THROUGHPUT_PER_WINDOW).round().max(0.0) as u32
    }

    /// F4 network-score factor from the OBSERVED density.
    pub fn q_network(&self, endpoint: &str) -> f64 {
        q_network_factor(self.observed_density(endpoint))
    }

    /// F6 evaluated on the PROBE-OBSERVED density (not any declared value).
    pub fn density_signal(&self, endpoint: &str) -> DensitySignal {
        let d = self.observed_density(endpoint);
        let nc = self
            .network_class
            .get(endpoint)
            .copied()
            .unwrap_or(NetworkClass::Unknown);
        if nc == NetworkClass::Residential && d > RESIDENTIAL_DENSITY_PLAUSIBLE {
            DensitySignal::CohortMerge
        } else {
            DensitySignal::Ok
        }
    }

    /// Endpoints whose observed density triggers F6 cohort-merge.
    pub fn merged_endpoints(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .observed_work
            .keys()
            .filter(|e| self.density_signal(e) == DensitySignal::CohortMerge)
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Build cluster merge groups for the maturity fold: every node identity behind a
    /// cohort-merged endpoint collapses into one group (its cluster ids merge). This is what
    /// defeats coverage inflation — 40 identities behind one fat residential pipe count as one.
    /// `node_to_cluster` maps a node identity to the cluster id used in receipts.
    pub fn cohort_merge_groups(
        &self,
        node_to_cluster: &HashMap<String, String>,
    ) -> Vec<Vec<String>> {
        let mut groups = Vec::new();
        for endpoint in self.merged_endpoints() {
            let mut clusters: Vec<String> = self
                .endpoint_nodes
                .get(&endpoint)
                .map(|nodes| {
                    nodes
                        .iter()
                        .filter_map(|n| node_to_cluster.get(n).cloned())
                        .collect()
                })
                .unwrap_or_default();
            clusters.sort();
            clusters.dedup();
            if clusters.len() > 1 {
                groups.push(clusters);
            }
        }
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_endpoint_is_ok() {
        let mut p = DensityProbe::new();
        p.set_network_class("home", NetworkClass::Residential);
        p.observe("home", "n1", 2.0); // ~2 devices
        assert_eq!(p.observed_density("home"), 2);
        assert_eq!(p.density_signal("home"), DensitySignal::Ok);
        assert_eq!(p.q_network("home"), 0.85);
    }

    #[test]
    fn concentrated_residential_endpoint_triggers_merge() {
        let mut p = DensityProbe::new();
        p.set_network_class("warehouse", NetworkClass::Residential);
        for i in 0..40 {
            p.observe("warehouse", &format!("id{i}"), 1.0); // 40 identities, 40 devices' work
        }
        assert_eq!(p.observed_density("warehouse"), 40);
        assert_eq!(p.density_signal("warehouse"), DensitySignal::CohortMerge);
        assert!(p.q_network("warehouse") < 0.2); // F4 degrades sharply
    }

    #[test]
    fn datacenter_high_density_not_residential_merge() {
        let mut p = DensityProbe::new();
        p.set_network_class("dc", NetworkClass::Datacenter);
        for i in 0..40 {
            p.observe("dc", &format!("id{i}"), 1.0);
        }
        // datacenter is handled by ordinary clustering, not the residential-merge path
        assert_eq!(p.density_signal("dc"), DensitySignal::Ok);
    }

    #[test]
    fn merge_groups_collapse_sybil_clusters() {
        let mut p = DensityProbe::new();
        p.set_network_class("warehouse", NetworkClass::Residential);
        let mut node_to_cluster = HashMap::new();
        for i in 0..40 {
            let node = format!("id{i}");
            p.observe("warehouse", &node, 1.0);
            node_to_cluster.insert(node, format!("c{i}")); // 40 distinct declared clusters
        }
        let groups = p.cohort_merge_groups(&node_to_cluster);
        assert_eq!(groups.len(), 1); // all 40 collapse into ONE merge group
        assert_eq!(groups[0].len(), 40);
    }

    #[test]
    fn f6_uses_observed_not_declared() {
        // even if a node "declares" density 1, the probe sees 40 -> merge fires on observed
        let mut p = DensityProbe::new();
        p.set_network_class("warehouse", NetworkClass::Residential);
        for i in 0..40 {
            p.observe("warehouse", &format!("id{i}"), 1.0);
        }
        assert_eq!(p.density_signal("warehouse"), DensitySignal::CohortMerge);
    }
}
