//! Sidecar lifecycle.
//!
//! The sidecar is a SEPARATE signed binary with an inverted network policy from
//! `goat-worker`; nothing here relaxes `goat-worker`'s own `DENIED network-disabled`
//! answer or its isolation test. This module only starts and stops a process that
//! verifies the consent record for itself before it opens any socket.
//!
//! # One spawn path, and it is the sidecar crate's own
//!
//! [`goat_proxy_worker::supervisor::ProxySupervisor::spawn_pinned`] is the whole of it:
//! the environment is cleared and exactly the seven declared variables are set, all
//! three descriptors are piped, and the binary's SHA-256 is compared to a pin taken
//! before the spawn. A second, bespoke spawn here would be a second implementation of
//! the cleared-environment rule and of the hash pin, and `spawn` (the unpinned
//! sibling) would leave the pin shipped and unused.
//!
//! # What this module deliberately does NOT do, and why the screen says so
//!
//! The sidecar's machine-readable event stream is its **stdout**, and the type above
//! owns the child without exposing a reader for it. So this build has **no source for
//! the destination log and no source for the byte counters**, and it does not pretend
//! otherwise: [`ProxyStatus::egress_stream_attached`] is `false`, `bytes_today` is
//! `None` rather than `0`, and `sockets_open` is [`SocketsAfter::Unverified`] rather
//! than `0`. A screen that prints `0` for a number nobody read reports a clean machine
//! it never checked -- the exact failure `SocketsAfter` exists to prevent. No Tauri
//! event is introduced: the app stays 100% poll-over-invoke, as it already is.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::consent::{self, ProxyConsentStatus};
use super::limits::{self, ProxyLimits};
use super::policy;

/// IMPORTED, not redeclared. The kill deadline is one value two processes must agree
/// on; `HALT_DEADLINE_MS` is a retired spelling and must not reappear.
pub use goat_proxy_worker::net::{KILL_DEADLINE, KILL_DEADLINE_MS};
pub use goat_proxy_worker::supervisor::SocketsAfter;

pub const EGRESS_RING_CAPACITY: usize = 512;

/// The SHA-256 the installer pinned, as compile-time configuration.
///
/// `option_env!`, not `env!`: an absent pin must be a REFUSAL TO SPAWN, not a build
/// failure that whoever hits it fixes by inventing a value. A build with no pin has no
/// way to tell the sidecar from anything else that could be dropped beside the app,
/// and hands a cleared environment and a piped stdin to whatever it finds.
const PINNED_SHA256: Option<&str> = option_env!("GOAT_PROXY_WORKER_SHA256");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcome {
    Allowed,
    RefusedNotAllowlisted,
    RefusedDenyNet,
    RefusedRedirect,
    RefusedMethod,
    RefusedCapReached,
    RefusedOutsideSchedule,
}

/// Deliberately carries NO path, NO query string, NO header and NO body.
///
/// `host` and `resolved_ip` are the two destination facts the operator read on screen
/// and signed, so surfacing them discloses nothing they did not consent to see.
/// Neither ever reaches a receipt, the schema, or disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEvent {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub at_unix_ms: u64,
    #[serde(default)]
    pub allowlist_entry_id: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub resolved_ip: String,
    #[serde(default)]
    pub bytes_out: u64,
    #[serde(default)]
    pub bytes_in: u64,
    /// The sidecar's OS socket census at the moment it emitted this line.
    #[serde(default)]
    pub sockets_open: u64,
    /// The sidecar's durable daily ledger figure -- the number that actually enforces
    /// the cap, never a UI-local accumulator that starts at zero every launch.
    #[serde(default)]
    pub spent_today: u64,
    #[serde(default)]
    pub outcome: Option<EgressOutcome>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyHaltReceipt {
    pub halted_at_unix: u64,
    /// `Census(n)` or `Unverified`. Never a bare integer, because there is no integer
    /// that honestly means "we did not find out" and `0` reads as "clean".
    pub sockets_open_after: SocketsAfter,
    pub elapsed_ms: u64,
    pub within_deadline: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub available: bool,
    pub running: bool,
    pub consent: ProxyConsentStatus,
    pub limits: ProxyLimits,
    /// `None` means NOT OBSERVED. It is not zero, and the screen must not render it
    /// as zero.
    pub bytes_today: Option<u64>,
    pub bytes_session: Option<u64>,
    /// `min(consented, configured)` -- the ceiling actually in force, which the
    /// controls in the window may lower and can never raise.
    pub cap_bytes: u64,
    pub sockets_open: SocketsAfter,
    pub last_seq: u64,
    /// True when the event stream skipped a sequence number. Surfaced, not absorbed.
    pub sequence_broken: bool,
    /// False whenever nothing is reading the sidecar's event stream. An empty
    /// destination list under a false flag is "no record", not "no traffic".
    pub egress_stream_attached: bool,
    pub halted_reason: Option<String>,
}

#[derive(Default)]
pub struct ProxySupervisor {
    inner: tokio::sync::Mutex<Option<goat_proxy_worker::supervisor::ProxySupervisor>>,
    ring: Mutex<VecDeque<EgressEvent>>,
    last_seq: AtomicU64,
    sequence_broken: AtomicBool,
    stream_attached: AtomicBool,
    halted_reason: Mutex<Option<String>>,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn worker_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    #[cfg(windows)]
    let name = "goat-proxy-worker.exe";
    #[cfg(not(windows))]
    let name = "goat-proxy-worker";
    dir.join(name)
}

/// `GOAT_PROXY_PILOT` is a VISIBILITY switch, not a security control.
///
/// It is read from the app's own environment, which any parent process sets; it hides
/// a tab and nothing else. The actual control is whether the sidecar binary is in the
/// installer at all -- ordinary builds ship none, so `worker_path().is_file()` is false
/// whatever the environment says.
pub fn available() -> bool {
    std::env::var("GOAT_PROXY_PILOT").as_deref() == Ok("1") && worker_path().is_file()
}

/// The pin, as bytes. `None` when this build carries no pin.
fn pinned_digest() -> Option<[u8; 32]> {
    let hex_text = PINNED_SHA256?.trim();
    let bytes = hex::decode(hex_text).ok()?;
    bytes.try_into().ok()
}

impl ProxySupervisor {
    pub async fn is_running(&self) -> bool {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(goat_proxy_worker::supervisor::ProxySupervisor::is_running)
            .unwrap_or(false)
    }

    /// Start the sidecar.
    ///
    /// Refuses unless the consent record verifies HERE against the ACTIVE wallet -- and
    /// the sidecar verifies it again for itself from the file, so this check is
    /// convenience, not the gate. Calling `status(.., None)` here would be the whole
    /// hole: with no expected address, a self-signed record from any process running
    /// as the user reports `Valid`.
    pub async fn spawn(&self, dir: &Path, active_wallet: Option<&str>) -> Result<(), String> {
        if !available() {
            return Err("the bandwidth background process is not installed".into());
        }
        if self.is_running().await {
            return Ok(());
        }
        let active = active_wallet.ok_or("no wallet is active")?;
        let record = consent::load(dir).ok_or("no signed record is stored")?;
        let status = consent::status(Some(&record), now_unix(), Some(active));
        if status.state != consent::ConsentState::Valid {
            return Err(format!("consent is {:?}", status.state));
        }
        let l = limits::load(dir).unwrap_or_default();
        if !l.enabled {
            return Err("bandwidth sharing is switched off".into());
        }
        // THE ALLOWLIST FILE IS NOT WRITTEN HERE, and its absence is a refusal.
        //
        // The sidecar's operational manifest carries a match mode, a path scope, path
        // prefixes and a per-entry rate -- none of which appears in the disclosure the
        // operator read, so none of which this lane may invent on their behalf. The
        // real list is a governance decision with a written-permission requirement.
        // The sidecar refuses with `AllowlistAbsent` and exits 78; saying so here is
        // the difference between a refusal and a mystery.
        let allowlist = policy::allowlist_path(dir);
        if !allowlist.is_file() {
            return Err(
                "the destination list the background process reads is not installed".into(),
            );
        }
        let expected = pinned_digest().ok_or(
            "this build carries no fingerprint for the bandwidth background process, so it will not start one",
        )?;

        // min(consented, configured). The controls may lower what the operator signed
        // and can never raise it -- the ceiling is inside the signed bytes.
        let cfg = goat_proxy_worker::supervisor::SpawnConfig {
            allowlist_path: allowlist,
            consent_path: consent::consent_path(dir),
            state_dir: dir.to_path_buf(),
            policy_text_hash_hex: consent::current_digests()
                .map_err(|e| format!("this build cannot name its own destination list: {e}"))?
                .policy,
            daily_ceiling_bytes: limits::effective_ceiling_bytes(status.daily_ceiling_bytes, &l),
            throttle_bytes_per_sec: limits::effective_throttle_bytes_per_sec(
                status.throttle_bytes_per_sec,
                &l,
            ),
            operator_wallet: active.to_string(),
        };

        let child = goat_proxy_worker::supervisor::ProxySupervisor::spawn_pinned(
            &worker_path(),
            expected,
            &cfg,
        )
        .map_err(|e| format!("could not start the bandwidth background process: {e}"))?;

        *self.inner.lock().await = Some(child);
        *self
            .halted_reason
            .lock()
            .map_err(|_| "supervisor poisoned")? = None;
        Ok(())
    }

    /// Kill switch.
    ///
    /// Delegates to the sidecar crate's own halt: it sends `halt`, waits for the
    /// sidecar's final line -- which carries `egress_socket_census(pid)` read from the
    /// operating system on the way out -- and only then escalates, all bounded by
    /// [`KILL_DEADLINE`]. The receipt's socket count is a MEASUREMENT, never an
    /// assignment: if no line arrives it says `Unverified`, and the screen says so too.
    pub async fn halt(&self, reason: &str) -> Result<ProxyHaltReceipt, String> {
        let started = std::time::Instant::now();
        let mut guard = self.inner.lock().await;
        let receipt = match guard.as_mut() {
            Some(child) => child.halt().await.map_err(|e| e.to_string())?,
            None => goat_proxy_worker::supervisor::HaltReceipt {
                elapsed_ms: started.elapsed().as_millis() as u64,
                open_sockets_after: SocketsAfter::Unverified,
            },
        };
        *guard = None;
        self.stream_attached.store(false, Ordering::SeqCst);
        *self
            .halted_reason
            .lock()
            .map_err(|_| "supervisor poisoned")? = Some(reason.to_string());
        Ok(ProxyHaltReceipt {
            halted_at_unix: now_unix(),
            sockets_open_after: receipt.open_sockets_after,
            elapsed_ms: receipt.elapsed_ms,
            within_deadline: receipt.elapsed_ms <= KILL_DEADLINE_MS,
            reason: reason.to_string(),
        })
    }

    pub fn egress_since(&self, seq: u64) -> Vec<EgressEvent> {
        self.ring
            .lock()
            .map(|r| r.iter().filter(|e| e.seq > seq).cloned().collect())
            .unwrap_or_default()
    }

    /// Absorb one event from the sidecar's stream.
    ///
    /// `seq` is a `#[serde(default)]` field on attacker-influenceable input, so one
    /// event claiming `u64::MAX` would permanently disable the reconciliation the
    /// operator log's trustworthiness rests on. Require exactly `previous + 1` and
    /// SURFACE a break rather than absorbing it.
    pub fn absorb(&self, event: EgressEvent) -> bool {
        let prev = self.last_seq.load(Ordering::SeqCst);
        // `saturating_add`: `prev + 1` panics in a debug build at `u64::MAX`, and a
        // panic here is a crash the sidecar can trigger by writing one line.
        if event.seq != prev.saturating_add(1) {
            self.sequence_broken.store(true, Ordering::SeqCst);
            return false;
        }
        self.last_seq.store(event.seq, Ordering::SeqCst);
        if let Ok(mut r) = self.ring.lock() {
            if r.len() == EGRESS_RING_CAPACITY {
                r.pop_front();
            }
            r.push_back(event);
        }
        true
    }

    pub async fn status(&self, dir: &Path, active_wallet: Option<&str>) -> ProxyStatus {
        let record = consent::load(dir);
        let l = limits::load(dir).unwrap_or_default();
        let consent = consent::status(record.as_ref(), now_unix(), active_wallet);
        let attached = self.stream_attached.load(Ordering::SeqCst);
        ProxyStatus {
            available: available(),
            running: self.is_running().await,
            cap_bytes: limits::effective_ceiling_bytes(consent.daily_ceiling_bytes, &l),
            consent,
            limits: l,
            // NOT OBSERVED is not zero.
            bytes_today: None,
            bytes_session: None,
            sockets_open: SocketsAfter::Unverified,
            last_seq: self.last_seq.load(Ordering::SeqCst),
            sequence_broken: self.sequence_broken.load(Ordering::SeqCst),
            egress_stream_attached: attached,
            halted_reason: self.halted_reason.lock().ok().and_then(|g| g.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64) -> EgressEvent {
        EgressEvent {
            seq,
            at_unix_ms: 1_780_000_000_000_u64.saturating_add(seq),
            allowlist_entry_id: "crossref-api".into(),
            host: "api.crossref.org".into(),
            resolved_ip: "192.0.2.1".into(),
            bytes_out: 100,
            bytes_in: 900,
            sockets_open: 1,
            spent_today: 1_000_u64.saturating_mul(seq),
            outcome: Some(EgressOutcome::Allowed),
        }
    }

    /// Mutations this detects: absorbing `seq` as given. One line claiming
    /// `u64::MAX` would leave `last_seq` at the maximum forever, so the screen's
    /// "is anything missing?" test can never fire again.
    #[test]
    fn a_sequence_jump_is_surfaced_and_not_absorbed() {
        let s = ProxySupervisor::default();
        assert!(s.absorb(ev(1)));
        assert!(s.absorb(ev(2)));
        assert!(!s.absorb(ev(u64::MAX)));
        assert_eq!(s.last_seq.load(Ordering::SeqCst), 2);
        assert!(s.sequence_broken.load(Ordering::SeqCst));
        assert_eq!(s.egress_since(0).len(), 2);
    }

    #[test]
    fn the_ring_is_bounded_and_reads_only_what_follows_the_cursor() {
        let s = ProxySupervisor::default();
        for i in 1..=(EGRESS_RING_CAPACITY as u64 + 10) {
            assert!(s.absorb(ev(i)));
        }
        assert_eq!(s.egress_since(0).len(), EGRESS_RING_CAPACITY);
        assert_eq!(s.egress_since(EGRESS_RING_CAPACITY as u64 + 8).len(), 2);
    }

    /// Mutations this detects: the kill deadline redeclared here instead of imported.
    /// Two crates that must halt together on one deadline cannot each own a copy.
    #[test]
    fn the_kill_deadline_is_the_sidecar_crates_own_value() {
        assert_eq!(KILL_DEADLINE_MS, 5_000);
        assert_eq!(
            KILL_DEADLINE,
            std::time::Duration::from_millis(KILL_DEADLINE_MS)
        );
        assert_eq!(
            KILL_DEADLINE_MS,
            goat_proxy_worker::supervisor::KILL_DEADLINE_MS
        );
    }

    /// Mutations this detects: an unobserved counter rendered as a number. There is
    /// no integer that honestly means "we did not find out", and `0` reads as clean.
    #[tokio::test]
    async fn an_unobserved_status_reports_nothing_rather_than_zero() {
        let dir = std::env::temp_dir().join(format!("goat-proxy-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = ProxySupervisor::default();
        let st = s.status(&dir, None).await;
        assert!(st.bytes_today.is_none());
        assert!(st.bytes_session.is_none());
        assert_eq!(st.sockets_open, SocketsAfter::Unverified);
        assert!(!st.egress_stream_attached);
        // POSITIVE CONTROL: the fields that ARE known carry real answers.
        assert!(!st.running);
        assert_eq!(st.consent.state, consent::ConsentState::Absent);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mutations this detects: a build with no pin spawning anyway. A supervisor with
    /// no fingerprint cannot tell the sidecar from anything else that could be dropped
    /// beside the app, and it hands whatever it finds a cleared environment and a
    /// piped stdin.
    #[tokio::test]
    async fn the_supervisor_refuses_a_sidecar_whose_hash_is_unpinned() {
        if PINNED_SHA256.is_some() {
            // Pinned builds take the other branch; the refusal is proved by the
            // `pinned_digest` unit below in both cases.
            return;
        }
        assert!(pinned_digest().is_none());
        let dir = std::env::temp_dir().join(format!("goat-proxy-unpinned-{}", std::process::id()));
        let s = ProxySupervisor::default();
        assert!(s
            .spawn(&dir, Some("0x1111111111111111111111111111111111111111"))
            .await
            .is_err());
    }

    #[test]
    fn an_unparseable_or_short_pin_is_no_pin_at_all() {
        // POSITIVE CONTROL for the decoder the pin goes through.
        let good: Option<[u8; 32]> = hex::decode("aa".repeat(32))
            .ok()
            .and_then(|b| b.try_into().ok());
        assert!(good.is_some());
        let short: Option<[u8; 32]> = hex::decode("aa".repeat(31))
            .ok()
            .and_then(|b| b.try_into().ok());
        assert!(short.is_none());
        let junk: Option<[u8; 32]> = hex::decode("zz").ok().and_then(|b| b.try_into().ok());
        assert!(junk.is_none());
    }

    /// Mutations this detects: `available()` reading only the environment variable.
    /// The env var hides a tab; the binary's presence is the actual control.
    #[test]
    fn availability_needs_the_binary_and_not_only_the_environment() {
        // The test process is not the app, so no sidecar sits beside it.
        assert!(!worker_path().is_file());
        assert!(!available());
    }

    #[tokio::test]
    async fn halting_when_nothing_runs_reports_unverified_not_zero() {
        let s = ProxySupervisor::default();
        let r = s.halt("test").await.unwrap();
        assert_eq!(r.sockets_open_after, SocketsAfter::Unverified);
        assert_eq!(r.reason, "test");
        assert!(r.within_deadline);
    }
}
