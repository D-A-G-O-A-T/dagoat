//! WP-3.5d/e live-stats collection CAMPAIGN. Runs a large, randomized-but-reproducible
//! workload over the PQ transport — honest cross-class rounds, injected faulty submissions (both
//! attribution directions), band-edge straddle attempts (R-VER2), and an F6 detection campaign
//! (true/false positives) — and writes livestats.json for the Q1 Iteration-3 model.
//!
//! Reproducible: a seeded splitmix64 PRNG drives the scenario mix, so a given (seed, rounds)
//! reproduces byte-identically. Run in RELEASE for speed (many ML-KEM/ML-DSA keygens):
//!   cargo run --release -p goat-net --bin goat-collect -- [out.json] [rounds] [seed]

use std::io::Write;

use goat_net::density::DensityProbe;
use goat_net::distributed::{run_round, ExecutorNode, Orchestrator};
use goat_net::stats::LiveStatsCollector;
use goat_net::testnet::{run, Testnet};
use goat_net::transport::Network;
use goat_protocol::capability::{DensitySignal, NetworkClass};
use goat_protocol::types::{DeterminismProfile, Task};

const BEACON: &[u8] = &[0x5au8; 32];
const BAND: i64 = 8;

/// Deterministic splitmix64 — reproducible scenario sampling, no external RNG crate.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn f01(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn exact() -> DeterminismProfile {
    DeterminismProfile::exact()
}
fn tol8() -> DeterminismProfile {
    DeterminismProfile::tolerance(8.0)
}

fn node(
    id: String,
    class: &str,
    cl: String,
    asn: String,
    delta: i64,
    prof: DeterminismProfile,
) -> ExecutorNode {
    ExecutorNode::new(&id, class, &cl, &asn, "r0", prof, run(delta))
}

/// Build a pool for round `r`: scenario-specific A, B at indices 0/1, then `fillers` honest
/// truth-computing verifiers on distinct clusters/ASNs (a realistic escalation pool).
#[allow(clippy::too_many_arguments)]
fn build_pool(
    r: u64,
    class_a: &str,
    prof_a: DeterminismProfile,
    delta_a: i64,
    class_b: &str,
    prof_b: DeterminismProfile,
    delta_b: i64,
    fillers: usize,
) -> Vec<ExecutorNode> {
    let mut pool = Vec::with_capacity(2 + fillers);
    pool.push(node(
        format!("r{r}A"),
        class_a,
        format!("r{r}cA"),
        format!("r{r}aA"),
        delta_a,
        prof_a,
    ));
    pool.push(node(
        format!("r{r}B"),
        class_b,
        format!("r{r}cB"),
        format!("r{r}aB"),
        delta_b,
        prof_b,
    ));
    for k in 0..fillers {
        // alternate filler class; all compute the true value (delta 0) = honest verifiers
        let (cls, prof) = if k % 2 == 0 {
            ("cls.a.v1", exact())
        } else {
            ("cls.b.v1", tol8())
        };
        pool.push(node(
            format!("r{r}f{k}"),
            cls,
            format!("r{r}cf{k}"),
            format!("r{r}af{k}"),
            0,
            prof,
        ));
    }
    pool
}

fn task(seed: u64) -> Task {
    Task {
        task_class_id: 10,
        engine_build_id: "b1".into(),
        payload: b"campaign".to_vec(),
        seed,
        determinism_bound: 10.0,
    }
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "livestats.json".to_string());
    let n_rounds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let seed: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x00C0_FFEE);

    let mut rng = Rng(seed);
    let orch = Orchestrator::new("orchestrator");
    let mut net = Network::new();
    let mut sc = LiveStatsCollector::new();

    // --- verification rounds: 65% honest, 20% faulty submission, 15% band-edge straddle ---
    let fillers = 20;
    for r in 0..n_rounds {
        let dice = rng.f01();
        let mut band_edge = false;
        let pool = if dice < 0.65 {
            // honest cross-class: A exact truth, B tol8 with small roundoff within band
            let b_off = rng.below(BAND as u64) as i64; // 0..7 -> agree
            build_pool(
                r,
                "cls.a.v1",
                exact(),
                0,
                "cls.b.v1",
                tol8(),
                b_off,
                fillers,
            )
        } else if dice < 0.85 {
            // faulty submission: one side clearly out of band (> band); honest C attributes and slashes it
            if rng.below(2) == 0 {
                build_pool(r, "cls.a.v1", exact(), 0, "cls.b.v1", tol8(), 50, fillers)
            // B submits a fault
            } else {
                build_pool(r, "cls.a.v1", exact(), 50, "cls.b.v1", tol8(), 0, fillers)
                // A submits a fault
            }
        } else {
            // band-edge straddle (R-VER2): A=truth-x, B=truth+y around band/2; honest C=truth.
            // Outcome depends on (x,y): no-attribution iff both <= band and x+y > band.
            band_edge = true;
            let x = 1 + rng.below(2 * BAND as u64 - 1) as i64; // 1..15
            let y = 1 + rng.below(2 * BAND as u64 - 1) as i64;
            build_pool(r, "cls.b.v1", tol8(), -x, "cls.b.v1", tol8(), y, fillers)
        };
        let out = run_round(&mut net, &orch, &pool, &task(r), BEACON, 1, 8.0, 3, r);
        sc.record(&out);
        if band_edge {
            sc.record_bandedge(&out);
        }
    }

    // --- F6 detection campaign: many Sybil endpoints (true positives) + home endpoints
    //     (false-positive check). Density > 5 must merge; density 1..5 must not. ---
    for _ in 0..40 {
        let mut probe = DensityProbe::new();
        probe.set_network_class("sybil", NetworkClass::Residential);
        let count = 6 + rng.below(45); // 6..50 concentrated identities
        for i in 0..count {
            probe.observe("sybil", &format!("s{i}"), 1.0);
        }
        let sybil_merged = probe.density_signal("sybil") == DensitySignal::CohortMerge;
        let home_checked = 5u64;
        let mut home_flagged = 0u64;
        for h in 0..home_checked {
            let ep = format!("home{h}");
            probe.set_network_class(&ep, NetworkClass::Residential);
            let hc = 1 + rng.below(5); // 1..5 plausible home devices
            for i in 0..hc {
                probe.observe(&ep, &format!("h{h}_{i}"), 1.0);
            }
            if probe.density_signal(&ep) == DensitySignal::CohortMerge {
                home_flagged += 1;
            }
        }
        sc.record_f6_detection(sybil_merged, home_checked, home_flagged);
    }

    // representative coverage-inflation scenario (SC6): 30 identities, one endpoint
    let mut sybil = Testnet::honest(40, 5);
    let naive = {
        sybil.add_sybil("warehouse", "cls.b.v1", 30);
        sybil
            .effective_registration(&DensityProbe::new(), "cls.b.v1")
            .1
    };
    let mut probe = DensityProbe::new();
    probe.set_network_class("warehouse", NetworkClass::Residential);
    for j in 0..30 {
        probe.observe("warehouse", &format!("S{}", 40 + j), 1.0);
    }
    let eff = sybil.effective_registration(&probe, "cls.b.v1").1;
    sc.record_f6(1, naive as u64, eff as u64);

    let json = sc.to_json();
    std::fs::File::create(&out_path)
        .expect("create")
        .write_all(json.as_bytes())
        .expect("write");
    println!("campaign: {n_rounds} rounds (seed {seed:#x}) -> {out_path}");
    println!(
        "  settle={} slashB={} slashA={} no-attribution={} quarantine={} ineligible={}",
        sc.settle, sc.c_agrees_a, sc.c_agrees_b, sc.c_agrees_both, sc.quarantine, sc.ineligible
    );
    println!(
        "  F6: {} scenarios, {} sybil-merged, {}/{} home false-positives",
        sc.f6_scenarios, sc.f6_sybil_merged, sc.f6_home_flagged, sc.f6_home_checked
    );
}
