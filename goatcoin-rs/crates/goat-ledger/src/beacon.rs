//! Epoch beacon (WP-1.2, closes R-CAP3; H2 last-revealer-bias hardening). A public,
//! non-grindable randomness beacon that supplies capability-record nonces (anti-replay) and the
//! seed for lottery third-executor selection.
//!
//! ## Construction and the last-revealer bias (analysis)
//!
//! Base construction: commit-reveal. Each participant commits to `H(r || salt)` during the
//! commit phase (before any reveal is known), then reveals `(r, salt)`; the combined seed is
//! `H(epoch || sorted reveals)`. Because commits are BINDING and locked before any reveal, no
//! participant can bias the output toward a chosen target at commit time (avalanche: one revealed
//! bit flips the whole seed).
//!
//! The residual weakness is at REVEAL time. A participant who reveals last has already observed
//! every other reveal, so it can compute the resulting seed BEFORE deciding whether to reveal.
//! It therefore holds a one-bit veto: reveal (producing seed S_with) or withhold (producing
//! either a re-roll or, if the protocol proceeds over the revealed subset, seed S_without). By
//! choosing, it selects the more favourable of the two outcomes. `k` colluding potential
//! withholders raise this to a choice among up to `2^k` outcomes. Because the seed feeds lottery
//! C-selection and nonces, this is a real (if bounded) grinding surface. In the permissioned MVP
//! it is mitigated economically: `finalize` requires all reveals, a withholder is detected via
//! `non_revealers`, and it is slashable/excluded with an offline re-roll — acceptable for a
//! trusted set, but only economic (not cryptographic) protection, and it costs liveness.
//!
//! ## H2 hardening: delay-sealed finalization
//!
//! `finalize_sealed` passes the combined seed through a Verifiable Delay Function (VDF) whose
//! evaluation takes longer than the reveal/decision window. The output is then unknowable within
//! that window, so a would-be last revealer cannot compute EITHER outcome in time to decide
//! whether to withhold — the "see-then-decide" capability that IS the last-revealer bias is
//! removed. This also makes a graceful subset fallback safe (`NonRevealerPolicy::SubsetWithSlashing`):
//! liveness is restored (no forced re-roll) without reintroducing bias, because a withholder
//! cannot predict the delayed value it would be forgoing.
//!
//! The VDF here (`delay_eval`) is a PLACEHOLDER: iterated SHA3-256, which has the required
//! sequentiality/delay property but verifies in O(iterations) (re-execution), not the O(log T) a
//! production VDF gives. A public deployment MUST replace it with a real VDF (Wesolowski /
//! Pietrzak over an RSA or class group) or move to a threshold VRF (drand-style). The type shape
//! (`BeaconMode`, `DelayProof`, `SealedBeacon`) is chosen so that swap is localized. See
//! `BeaconMode` for the strategy space and the module tests for the properties.
//!
//! Device-agnostic: nothing here references a device type or inspects content.

use std::collections::BTreeMap;

use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Commit,
    Reveal,
    Final,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BeaconError {
    WrongPhase,
    UnknownCommitter,
    BindingFailed,
    MissingReveals,
    AlreadyCommitted,
    /// The requested finalization mode is not implemented in this build (e.g. `ThresholdVrf`).
    UnsupportedMode,
}

/// Beacon finalization strategy — the design space for last-revealer-bias resistance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconMode {
    /// Plain commit-reveal. Unbiasable at commit time, but subject to last-revealer bias (a
    /// withholder can veto an unfavourable outcome). Acceptable ONLY for a permissioned set with
    /// economic slashing; not for public/adversarial settings.
    CommitReveal,
    /// Commit-reveal whose combined seed is sealed by a Verifiable Delay Function of
    /// `delay_iterations`. The delay exceeds the reveal window, so no participant can learn the
    /// output in time to decide whether to withhold — this removes last-revealer bias. Targeted
    /// at public/adversarial settings, pending replacement of the placeholder VDF with a
    /// production one.
    DelaySealed { delay_iterations: u64 },
    /// Threshold VRF / distributed randomness (drand-style): the canonical unbiasable approach,
    /// but it requires a DKG and pairing crypto. Documented as the target for full production;
    /// not implemented in this build (`finalize_for` returns `UnsupportedMode`).
    ThresholdVrf,
}

/// Recommend a finalization mode for a setting. Permissioned testnet: plain commit-reveal with
/// slashing is acceptable. Public/adversarial: delay-sealing (or, ultimately, a threshold VRF).
pub fn recommended_mode(public_setting: bool, delay_iterations: u64) -> BeaconMode {
    if public_setting {
        BeaconMode::DelaySealed { delay_iterations }
    } else {
        BeaconMode::CommitReveal
    }
}

// ---------------------------------------------------------------------------------------------
// Delay calibration (H2 usability). Choosing `delay_iterations` is a WALL-CLOCK exercise, not a
// security parameter: the evaluation must take longer than the reveal/decision window on the
// FASTEST honest evaluator, so no one can compute the output in time to see-then-withhold. These
// helpers turn "how long is the reveal window?" into an iteration count and sanity-check it.
// ---------------------------------------------------------------------------------------------

/// Rough throughput of the PLACEHOLDER VDF (sequential SHA3-256 steps/sec) on a representative
/// evaluator. An order-of-magnitude anchor for calibrating the iterated-SHA3 placeholder ONLY — a
/// real VDF (Wesolowski/Pietrzak) has entirely different timing and MUST be re-calibrated against
/// its own evaluator. Measure on the target hardware before any non-toy use.
pub const PLACEHOLDER_VDF_HASHES_PER_SEC: f64 = 5_000_000.0;

/// Default margin: size the delay to this multiple of the reveal window, covering evaluator-speed
/// variance so even a fast participant cannot finish within the window.
pub const DEFAULT_DELAY_SAFETY_MARGIN: f64 = 4.0;

/// Soft upper bound (seconds) beyond which a delay is considered impractical for beacon throughput.
pub const DEFAULT_MAX_PRACTICAL_DELAY_SECS: f64 = 60.0;

/// Choose `delay_iterations` so evaluation takes about `reveal_window_secs * safety_margin` on an
/// evaluator running `hashes_per_sec` sequential steps. Returns at least 1. Inputs are clamped to
/// sane minimums (`safety_margin >= 1`, non-negative window, `hashes_per_sec >= 1`).
pub fn calibrate_delay_iterations(
    reveal_window_secs: f64,
    hashes_per_sec: f64,
    safety_margin: f64,
) -> u64 {
    let secs = reveal_window_secs.max(0.0) * safety_margin.max(1.0);
    ((secs * hashes_per_sec.max(1.0)).ceil() as u64).max(1)
}

/// Convenience: calibrate against the placeholder-VDF throughput and default safety margin, and
/// return a ready `DelaySealed` mode. For the placeholder VDF only — see `PLACEHOLDER_VDF_*`.
pub fn delay_sealed_for_window(reveal_window_secs: f64) -> BeaconMode {
    BeaconMode::DelaySealed {
        delay_iterations: calibrate_delay_iterations(
            reveal_window_secs,
            PLACEHOLDER_VDF_HASHES_PER_SEC,
            DEFAULT_DELAY_SAFETY_MARGIN,
        ),
    }
}

/// Estimated evaluation time (seconds) for `iterations` at `hashes_per_sec`.
pub fn estimated_delay_secs(iterations: u64, hashes_per_sec: f64) -> f64 {
    iterations as f64 / hashes_per_sec.max(1.0)
}

/// Advisory result of a delay sanity-check (no panics — the caller decides what to do).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelayAssessment {
    /// Estimated evaluation comfortably exceeds the reveal window and stays under the practical cap.
    Adequate,
    /// Estimated evaluation does NOT exceed the reveal window: a fast evaluator could finish in
    /// time to see-then-withhold, so last-revealer bias is not removed. Increase the delay.
    TooShort,
    /// Estimated evaluation exceeds the practical cap: finalization is impractically slow. Decrease.
    TooLong,
}

/// Sanity-check a delay against the reveal window (advisory; uses `DEFAULT_MAX_PRACTICAL_DELAY_SECS`
/// as the upper cap). `TooShort` is the security-relevant one — the delay must exceed the window.
pub fn assess_delay(
    iterations: u64,
    hashes_per_sec: f64,
    reveal_window_secs: f64,
) -> DelayAssessment {
    let est = estimated_delay_secs(iterations, hashes_per_sec);
    if est < reveal_window_secs {
        DelayAssessment::TooShort
    } else if est > DEFAULT_MAX_PRACTICAL_DELAY_SECS {
        DelayAssessment::TooLong
    } else {
        DelayAssessment::Adequate
    }
}

/// Policy for committers that never revealed, applied at finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonRevealerPolicy {
    /// Require every committer to reveal; a missing reveal fails finalization (offline re-roll).
    /// This is the MVP behaviour and the only safe policy under plain `CommitReveal`.
    Strict,
    /// Finalize over the revealed subset, recording non-revealers for slashing. Preserves liveness
    /// (no forced re-roll). SAFE ONLY under `DelaySealed`, where a withholder cannot predict the
    /// delayed value and so gains nothing by withholding.
    SubsetWithSlashing,
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha3_256::new();
    for p in parts {
        d.update(p);
    }
    let out = d.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

/// A participant's commitment: `H(r || salt)`.
pub fn commitment(r: &[u8], salt: &[u8]) -> [u8; 32] {
    h(&[r, salt])
}

/// Output of the delay function, re-verifiable by `delay_verify`.
///
/// PLACEHOLDER VDF: `delay_eval` is iterated SHA3-256. It has the sequentiality/delay property
/// (evaluation cannot be parallelized or short-circuited) that defeats last-revealer bias, but it
/// verifies by RE-EXECUTION (O(iterations)), not succinctly. A production deployment replaces this
/// with a real VDF whose proof verifies in O(log T)/O(1). `input` and `iterations` are retained so
/// the swap keeps the same call shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayProof {
    pub input: [u8; 32],
    pub iterations: u64,
    pub output: [u8; 32],
}

/// Evaluate the (placeholder) VDF: `iterations` sequential SHA3-256 steps from `input`.
pub fn delay_eval(input: [u8; 32], iterations: u64) -> DelayProof {
    let mut x = input;
    for _ in 0..iterations {
        x = h(&[&x[..]]);
    }
    DelayProof {
        input,
        iterations,
        output: x,
    }
}

/// Verify a delay proof by re-execution (placeholder; a real VDF verifies succinctly).
pub fn delay_verify(proof: &DelayProof) -> bool {
    delay_eval(proof.input, proof.iterations).output == proof.output
}

/// A delay-sealed beacon: the final value, the re-verifiable delay proof, and any non-revealers
/// recorded for slashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBeacon {
    pub value: [u8; 32],
    pub proof: DelayProof,
    pub non_revealers: Vec<String>,
}

pub struct EpochBeacon {
    pub epoch: u64,
    phase: Phase,
    commits: BTreeMap<String, [u8; 32]>,
    reveals: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    value: Option<[u8; 32]>,
}

impl EpochBeacon {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            phase: Phase::Commit,
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
            value: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Commit phase only; a participant may commit at most once.
    pub fn commit(&mut self, participant: &str, commitment: [u8; 32]) -> Result<(), BeaconError> {
        if self.phase != Phase::Commit {
            return Err(BeaconError::WrongPhase);
        }
        if self.commits.contains_key(participant) {
            return Err(BeaconError::AlreadyCommitted);
        }
        self.commits.insert(participant.to_string(), commitment);
        Ok(())
    }

    /// Close the commit phase. No new commits accepted after this; reveals begin.
    pub fn close_commit(&mut self) -> Result<(), BeaconError> {
        if self.phase != Phase::Commit {
            return Err(BeaconError::WrongPhase);
        }
        self.phase = Phase::Reveal;
        Ok(())
    }

    /// Reveal phase only. The reveal must match the earlier commitment (binding).
    pub fn reveal(&mut self, participant: &str, r: &[u8], salt: &[u8]) -> Result<(), BeaconError> {
        if self.phase != Phase::Reveal {
            return Err(BeaconError::WrongPhase);
        }
        let commit = self
            .commits
            .get(participant)
            .ok_or(BeaconError::UnknownCommitter)?;
        if &commitment(r, salt) != commit {
            return Err(BeaconError::BindingFailed);
        }
        self.reveals
            .insert(participant.to_string(), (r.to_vec(), salt.to_vec()));
        Ok(())
    }

    /// Combine the current reveals into the pre-seal seed `H(epoch || sorted reveals)`.
    /// BTreeMap iterates in sorted participant order -> deterministic across recomputers.
    fn combine_reveals(&self) -> [u8; 32] {
        let mut d = Sha3_256::new();
        d.update(self.epoch.to_be_bytes());
        for (r, salt) in self.reveals.values() {
            d.update((r.len() as u32).to_be_bytes());
            d.update(r);
            d.update((salt.len() as u32).to_be_bytes());
            d.update(salt);
        }
        let out = d.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        b
    }

    /// Finalize (plain commit-reveal, MVP): requires every committer to have revealed.
    /// beacon = `H(epoch || sorted reveals)`. Subject to last-revealer bias — see the module doc
    /// and `finalize_sealed` for the H2 hardening.
    pub fn finalize(&mut self) -> Result<[u8; 32], BeaconError> {
        if self.phase != Phase::Reveal {
            return Err(BeaconError::WrongPhase);
        }
        if self.reveals.len() != self.commits.len() {
            return Err(BeaconError::MissingReveals);
        }
        let b = self.combine_reveals();
        self.value = Some(b);
        self.phase = Phase::Final;
        Ok(b)
    }

    /// Finalize with delay-sealing (H2): combine the reveals, then pass the seed through the delay
    /// function so the value is unknowable within the reveal window — removing last-revealer bias.
    /// Under `Strict`, a missing reveal fails (as `finalize`). Under `SubsetWithSlashing`, the
    /// revealed subset is sealed and non-revealers are recorded (safe here BECAUSE of the delay).
    pub fn finalize_sealed(
        &mut self,
        delay_iterations: u64,
        policy: NonRevealerPolicy,
    ) -> Result<SealedBeacon, BeaconError> {
        if self.phase != Phase::Reveal {
            return Err(BeaconError::WrongPhase);
        }
        let missing = self.non_revealers();
        if !missing.is_empty() && policy == NonRevealerPolicy::Strict {
            return Err(BeaconError::MissingReveals);
        }
        let seed = self.combine_reveals();
        let proof = delay_eval(seed, delay_iterations);
        self.value = Some(proof.output);
        self.phase = Phase::Final;
        Ok(SealedBeacon {
            value: proof.output,
            proof,
            non_revealers: missing,
        })
    }

    /// Finalize by strategy. `CommitReveal` seals with zero delay (value == plain `finalize`);
    /// `DelaySealed` applies the delay; `ThresholdVrf` is not implemented (`UnsupportedMode`).
    pub fn finalize_for(
        &mut self,
        mode: BeaconMode,
        policy: NonRevealerPolicy,
    ) -> Result<SealedBeacon, BeaconError> {
        match mode {
            BeaconMode::CommitReveal => self.finalize_sealed(0, policy),
            BeaconMode::DelaySealed { delay_iterations } => {
                self.finalize_sealed(delay_iterations, policy)
            }
            BeaconMode::ThresholdVrf => Err(BeaconError::UnsupportedMode),
        }
    }

    pub fn value(&self) -> Option<[u8; 32]> {
        self.value
    }

    /// Participants who committed but never revealed (slashable/excluded in production).
    pub fn non_revealers(&self) -> Vec<String> {
        self.commits
            .keys()
            .filter(|p| !self.reveals.contains_key(*p))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(reveals: &[(&str, &[u8], &[u8])]) -> [u8; 32] {
        let mut b = EpochBeacon::new(1);
        for (p, r, s) in reveals {
            b.commit(p, commitment(r, s)).unwrap();
        }
        b.close_commit().unwrap();
        for (p, r, s) in reveals {
            b.reveal(p, r, s).unwrap();
        }
        b.finalize().unwrap()
    }

    #[test]
    fn deterministic() {
        let v1 = run(&[("a", b"ra", b"sa"), ("b", b"rb", b"sb")]);
        let v2 = run(&[("b", b"rb", b"sb"), ("a", b"ra", b"sa")]); // order-independent (sorted)
        assert_eq!(v1, v2);
    }

    #[test]
    fn binding_enforced() {
        let mut b = EpochBeacon::new(1);
        b.commit("a", commitment(b"secret", b"salt")).unwrap();
        b.close_commit().unwrap();
        assert_eq!(
            b.reveal("a", b"WRONG", b"salt"),
            Err(BeaconError::BindingFailed)
        );
        assert_eq!(b.reveal("a", b"secret", b"salt"), Ok(()));
    }

    #[test]
    fn commit_before_reveal_phase_enforced() {
        let mut b = EpochBeacon::new(1);
        // cannot reveal before commit phase closes
        assert_eq!(b.reveal("a", b"r", b"s"), Err(BeaconError::WrongPhase));
        b.commit("a", commitment(b"r", b"s")).unwrap();
        b.close_commit().unwrap();
        // cannot commit after close
        assert_eq!(
            b.commit("z", commitment(b"r", b"s")),
            Err(BeaconError::WrongPhase)
        );
    }

    #[test]
    fn avalanche_one_bit_changes_beacon() {
        let v1 = run(&[("a", b"ra", b"sa"), ("b", b"rb0", b"sb")]);
        let v2 = run(&[("a", b"ra", b"sa"), ("b", b"rb1", b"sb")]); // one participant flips value
        assert_ne!(v1, v2);
    }

    #[test]
    fn finalize_requires_all_reveals() {
        let mut b = EpochBeacon::new(1);
        b.commit("a", commitment(b"ra", b"sa")).unwrap();
        b.commit("b", commitment(b"rb", b"sb")).unwrap();
        b.close_commit().unwrap();
        b.reveal("a", b"ra", b"sa").unwrap();
        assert_eq!(b.finalize(), Err(BeaconError::MissingReveals));
        assert_eq!(b.non_revealers(), vec!["b".to_string()]);
    }

    // ---- H2: delay-sealed finalization ----

    const ITERS: u64 = 512; // small, for fast tests; production calibrates to exceed the window

    fn run_sealed(
        reveals: &[(&str, &[u8], &[u8])],
        iters: u64,
        policy: NonRevealerPolicy,
    ) -> SealedBeacon {
        let mut b = EpochBeacon::new(1);
        for (p, r, s) in reveals {
            b.commit(p, commitment(r, s)).unwrap();
        }
        b.close_commit().unwrap();
        for (p, r, s) in reveals {
            b.reveal(p, r, s).unwrap();
        }
        b.finalize_sealed(iters, policy).unwrap()
    }

    #[test]
    fn delay_eval_verify_roundtrip_and_tamper() {
        let p = delay_eval([7u8; 32], ITERS);
        assert!(delay_verify(&p));
        let mut bad = p.clone();
        bad.output[0] ^= 1;
        assert!(!delay_verify(&bad)); // wrong output
        let mut bad2 = p;
        bad2.iterations += 1;
        assert!(!delay_verify(&bad2)); // wrong iteration count
    }

    #[test]
    fn sealed_value_is_the_delayed_output_and_verifies() {
        let s = run_sealed(
            &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")],
            ITERS,
            NonRevealerPolicy::Strict,
        );
        assert_eq!(s.value, s.proof.output);
        assert!(delay_verify(&s.proof));
        assert!(s.non_revealers.is_empty());
    }

    #[test]
    fn sealed_is_deterministic_across_recomputers() {
        // same reveals + iterations -> identical sealed value (order-independent, sorted)
        let v1 = run_sealed(
            &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")],
            ITERS,
            NonRevealerPolicy::Strict,
        );
        let v2 = run_sealed(
            &[("b", b"rb", b"sb"), ("a", b"ra", b"sa")],
            ITERS,
            NonRevealerPolicy::Strict,
        );
        assert_eq!(v1.value, v2.value);
    }

    #[test]
    fn sealing_changes_the_value_versus_plain_finalize() {
        // the delay is actually applied: sealed value != the plain combined seed
        let plain = run(&[("a", b"ra", b"sa"), ("b", b"rb", b"sb")]);
        let sealed = run_sealed(
            &[("a", b"ra", b"sa"), ("b", b"rb", b"sb")],
            ITERS,
            NonRevealerPolicy::Strict,
        );
        assert_ne!(plain, sealed.value);
        // whereas zero-delay CommitReveal mode reproduces the plain value
        let mut b = EpochBeacon::new(1);
        for (p, r, s) in [
            ("a", b"ra".as_slice(), b"sa".as_slice()),
            ("b", b"rb", b"sb"),
        ] {
            b.commit(p, commitment(r, s)).unwrap();
        }
        b.close_commit().unwrap();
        for (p, r, s) in [
            ("a", b"ra".as_slice(), b"sa".as_slice()),
            ("b", b"rb", b"sb"),
        ] {
            b.reveal(p, r, s).unwrap();
        }
        let zero = b
            .finalize_for(BeaconMode::CommitReveal, NonRevealerPolicy::Strict)
            .unwrap();
        assert_eq!(zero.value, plain);
    }

    #[test]
    fn subset_policy_seals_over_revealers_and_records_non_revealers() {
        // one committer withholds; under SubsetWithSlashing the beacon still finalizes (liveness),
        // sealing the revealed subset and recording the withholder for slashing.
        let mut b = EpochBeacon::new(1);
        b.commit("a", commitment(b"ra", b"sa")).unwrap();
        b.commit("b", commitment(b"rb", b"sb")).unwrap();
        b.close_commit().unwrap();
        b.reveal("a", b"ra", b"sa").unwrap();
        // strict fails on the missing reveal ...
        // (use a fresh beacon to test strict, since finalize consumes phase)
        let sealed = b
            .finalize_sealed(ITERS, NonRevealerPolicy::SubsetWithSlashing)
            .unwrap();
        assert!(delay_verify(&sealed.proof));
        assert_eq!(sealed.non_revealers, vec!["b".to_string()]);
    }

    #[test]
    fn strict_sealed_still_requires_all_reveals() {
        let mut b = EpochBeacon::new(1);
        b.commit("a", commitment(b"ra", b"sa")).unwrap();
        b.commit("b", commitment(b"rb", b"sb")).unwrap();
        b.close_commit().unwrap();
        b.reveal("a", b"ra", b"sa").unwrap();
        assert_eq!(
            b.finalize_sealed(ITERS, NonRevealerPolicy::Strict),
            Err(BeaconError::MissingReveals)
        );
    }

    #[test]
    fn threshold_vrf_mode_is_unsupported() {
        let mut b = EpochBeacon::new(1);
        b.commit("a", commitment(b"ra", b"sa")).unwrap();
        b.close_commit().unwrap();
        b.reveal("a", b"ra", b"sa").unwrap();
        assert_eq!(
            b.finalize_for(BeaconMode::ThresholdVrf, NonRevealerPolicy::Strict),
            Err(BeaconError::UnsupportedMode)
        );
    }

    #[test]
    fn recommended_mode_by_setting() {
        assert_eq!(recommended_mode(false, 1000), BeaconMode::CommitReveal);
        assert_eq!(
            recommended_mode(true, 1000),
            BeaconMode::DelaySealed {
                delay_iterations: 1000
            }
        );
    }

    #[test]
    fn calibration_sizes_delay_to_window_with_margin() {
        // 2s reveal window at 1e6 steps/s with 4x margin -> 8e6 iterations
        assert_eq!(calibrate_delay_iterations(2.0, 1_000_000.0, 4.0), 8_000_000);
        // degenerate inputs clamp sane: at least one iteration, margin >= 1
        assert_eq!(calibrate_delay_iterations(0.0, 1_000_000.0, 4.0), 1);
        assert_eq!(calibrate_delay_iterations(1.0, 1_000_000.0, 0.5), 1_000_000);
        // the convenience constructor returns a DelaySealed mode sized from the placeholder anchor
        match delay_sealed_for_window(2.0) {
            BeaconMode::DelaySealed { delay_iterations } => {
                assert_eq!(
                    delay_iterations,
                    calibrate_delay_iterations(
                        2.0,
                        PLACEHOLDER_VDF_HASHES_PER_SEC,
                        DEFAULT_DELAY_SAFETY_MARGIN
                    )
                );
            }
            other => panic!("expected DelaySealed, got {other:?}"),
        }
    }

    #[test]
    fn delay_assessment_flags_short_and_long() {
        // 1e6 iterations at 1e6 steps/s = 1s estimated evaluation
        assert_eq!(
            assess_delay(1_000_000, 1_000_000.0, 2.0),
            DelayAssessment::TooShort // 1s < 2s window: a fast evaluator could see-then-withhold
        );
        assert_eq!(
            assess_delay(4_000_000, 1_000_000.0, 2.0),
            DelayAssessment::Adequate // 4s > window, under the practical cap
        );
        assert_eq!(
            assess_delay(100_000_000, 1_000_000.0, 2.0),
            DelayAssessment::TooLong // 100s > DEFAULT_MAX_PRACTICAL_DELAY_SECS
        );
    }
}
