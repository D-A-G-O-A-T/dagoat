//! Spawn and halt of the sidecar.
//!
//! # This is NOT the isolation supervisor
//!
//! The root spine already has a supervisor whose whole purpose is to prove a
//! payload executor cannot reach the network, and whose `network_connect_denied`
//! test asserts exactly that. It is left exactly as it is. **This** one
//! supervises a process whose entire purpose is to reach the network, so it is
//! a separate binary with a separate policy, and the two share no code, no
//! configuration and no test.
//!
//! # The environment is CLEARED, then seven names are set
//!
//! An inherited proxy variable, an inherited key path or an inherited API token
//! has no business in this process (INV-19). [`SpawnConfig::env`] is the whole
//! surface, and a test asserts it is exactly [`crate::config::DECLARED_ENV`].
//!
//! # The halt's socket count is the SIDECAR'S, read from the operating system
//!
//! [`ProxySupervisor::halt`] never assigns the number itself. It sends `halt`,
//! then waits for the sidecar's own final line — which carries
//! `census::egress_socket_census(pid)`, read from the OS on the way out — and
//! reports [`SocketsAfter::Unverified`] if that line does not arrive inside
//! [`KILL_DEADLINE`]. An earlier draft of this component returned a literal
//! zero that a surface then rendered under "Stopped. Open sockets:" as if it
//! were evidence, which is the exact check-that-cannot-fail INV-10 exists to
//! forbid.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 34 and its Security invariants section (INV-10, INV-19).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// The kill deadline, imported from the tunnel through `net.rs`. Never
/// redeclared: two crates that must halt together on one deadline cannot each
/// own a copy of the number.
pub use crate::net::{KILL_DEADLINE, KILL_DEADLINE_MS};
/// `EX_CONFIG`. Declared once, at the crate root; re-exported here so a caller
/// that only imports the supervisor still sees the one value.
pub use crate::EXIT_CONFIG;

/// Line protocol on the child's stdin. There is no control socket, no control
/// port and no local console API — a local console API is precisely the design
/// this avoids.
pub const CMD_HALT: &str = "halt\n";
/// The heartbeat. Stopping it is itself a soft kill: the indicator goes stale
/// and egress ceases.
pub const CMD_BEAT: &str = "beat\n";

/// The event kind the sidecar's final line carries. One spelling, shared with
/// `logging::SafeEvent::kind`.
const HALT_LINE_KIND: &str = "halt_completed";

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("sidecar binary not found at {0}")]
    BinaryMissing(PathBuf),
    #[error("the sidecar binary could not be read for hashing: {0}")]
    BinaryUnreadable(String),
    #[error("the sidecar binary does not match the pinned hash")]
    BinaryHashMismatch,
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("the sidecar is not running")]
    NotRunning,
}

#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub allowlist_path: PathBuf,
    pub consent_path: PathBuf,
    pub state_dir: PathBuf,
    pub policy_text_hash_hex: String,
    pub daily_ceiling_bytes: u64,
    pub throttle_bytes_per_sec: u64,
    /// The address the supervisor believes is the active operator key. Without
    /// it the sidecar's consent check degenerates to "is this blob
    /// self-consistent", which every self-signed blob satisfies.
    pub operator_wallet: String,
}

impl SpawnConfig {
    /// EXACTLY the seven declared variables, nothing inherited.
    pub fn env(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            crate::config::ENV_OPERATOR_WALLET.into(),
            self.operator_wallet.clone(),
        );
        m.insert(
            crate::config::ENV_ALLOWLIST.into(),
            self.allowlist_path.display().to_string(),
        );
        m.insert(
            crate::config::ENV_CONSENT.into(),
            self.consent_path.display().to_string(),
        );
        m.insert(
            crate::config::ENV_STATE_DIR.into(),
            self.state_dir.display().to_string(),
        );
        m.insert(
            crate::config::ENV_POLICY_TEXT_HASH.into(),
            self.policy_text_hash_hex.clone(),
        );
        m.insert(
            crate::config::ENV_DAILY_CEILING_BYTES.into(),
            self.daily_ceiling_bytes.to_string(),
        );
        m.insert(
            crate::config::ENV_THROTTLE_BPS.into(),
            self.throttle_bytes_per_sec.to_string(),
        );
        m
    }
}

/// How many egress sockets the operating system still attributed to the sidecar
/// when it halted.
///
/// Deliberately not a `u64`. There is no number that honestly means "we did not
/// find out", and `0` is the one that reads as "clean".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum SocketsAfter {
    Census(usize),
    Unverified,
}

impl SocketsAfter {
    /// Read the count out of the sidecar's final line, or report `Unverified`.
    ///
    /// **This is the only constructor the halt path uses.** Every other route
    /// to a number would be a field the reporter assigns to itself.
    pub fn from_halt_line(line: Option<&str>) -> Self {
        let Some(text) = line else {
            return SocketsAfter::Unverified;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return SocketsAfter::Unverified;
        };
        if value.get("kind").and_then(serde_json::Value::as_str) != Some(HALT_LINE_KIND) {
            return SocketsAfter::Unverified;
        }
        match value
            .get("open_sockets")
            .and_then(serde_json::Value::as_u64)
        {
            Some(n) => SocketsAfter::Census(n as usize),
            None => SocketsAfter::Unverified,
        }
    }
}

/// What a halt is allowed to claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HaltReceipt {
    pub elapsed_ms: u64,
    pub open_sockets_after: SocketsAfter,
}

impl HaltReceipt {
    /// A halt is a success only when the operating system was asked **and**
    /// answered zero, inside the deadline. `Unverified` is never a success, and
    /// neither is a verified non-zero count.
    pub fn is_verified_clean(&self) -> bool {
        self.elapsed_ms <= KILL_DEADLINE_MS
            && matches!(self.open_sockets_after, SocketsAfter::Census(0))
    }
}

/// SHA-256 of a file on disk, for the binary pin.
pub fn binary_digest(path: &Path) -> Result<[u8; 32], SupervisorError> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|e| SupervisorError::BinaryUnreadable(format!("{}", e.kind())))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().into())
}

pub struct ProxySupervisor {
    child: Option<Child>,
}

impl ProxySupervisor {
    /// Spawn the sidecar.
    ///
    /// The environment is cleared first and exactly the seven declared names
    /// are set; the working directory is the state directory the daemon owns;
    /// all three standard descriptors are piped, because stdin is the control
    /// plane, stdout is the machine stream and stderr is the human log.
    pub fn spawn(binary: &Path, cfg: &SpawnConfig) -> Result<Self, SupervisorError> {
        if !binary.exists() {
            return Err(SupervisorError::BinaryMissing(binary.to_path_buf()));
        }
        let _ = std::fs::create_dir_all(&cfg.state_dir);
        let mut cmd = Command::new(binary);
        cmd.env_clear();
        for (k, v) in cfg.env() {
            cmd.env(k, v);
        }
        cmd.current_dir(&cfg.state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| SupervisorError::Spawn(e.to_string()))?;
        Ok(Self { child: Some(child) })
    }

    /// Spawn only a binary whose SHA-256 matches what the caller pinned
    /// (INV-19).
    ///
    /// The pin is the caller's, taken before the spawn, so a binary replaced
    /// between install and launch is refused rather than run.
    pub fn spawn_pinned(
        binary: &Path,
        expected_sha256: [u8; 32],
        cfg: &SpawnConfig,
    ) -> Result<Self, SupervisorError> {
        if !binary.exists() {
            return Err(SupervisorError::BinaryMissing(binary.to_path_buf()));
        }
        if binary_digest(binary)? != expected_sha256 {
            return Err(SupervisorError::BinaryHashMismatch);
        }
        Self::spawn(binary, cfg)
    }

    /// Heartbeat. Stopping this is itself a soft kill.
    pub async fn heartbeat(&mut self) -> Result<(), SupervisorError> {
        let child = self.child.as_mut().ok_or(SupervisorError::NotRunning)?;
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(CMD_BEAT.as_bytes()).await;
            let _ = stdin.flush().await;
        }
        Ok(())
    }

    /// Kill switch. Sends `halt`, waits for the sidecar's final line, then
    /// escalates to a signal — all bounded by [`KILL_DEADLINE`].
    pub async fn halt(&mut self) -> Result<HaltReceipt, SupervisorError> {
        let started = Instant::now();
        let stdout = {
            let child = self.child.as_mut().ok_or(SupervisorError::NotRunning)?;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(CMD_HALT.as_bytes()).await;
                let _ = stdin.flush().await;
            }
            // Closing stdin is itself the halt signal for a sidecar that has
            // stopped reading commands: EOF on the control plane is a halt.
            child.stdin.take();
            child.stdout.take()
        };

        // Read the SIDECAR'S OWN census figure out of its final event line.
        // A timed-out read and a stream that ended without the line are the
        // same answer: nothing was observed.
        let line: Option<String> = match stdout {
            Some(s) => tokio::time::timeout(KILL_DEADLINE, read_halt_line(s))
                .await
                .unwrap_or_default(),
            None => None,
        };
        let open_sockets_after = SocketsAfter::from_halt_line(line.as_deref());

        let child = self.child.as_mut().ok_or(SupervisorError::NotRunning)?;
        let remaining = KILL_DEADLINE.saturating_sub(started.elapsed());
        if tokio::time::timeout(remaining, child.wait()).await.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.child = None;

        Ok(HaltReceipt {
            elapsed_ms: started.elapsed().as_millis() as u64,
            open_sockets_after,
        })
    }

    /// Whether a child is still held. `false` after a halt.
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}

/// Read the child's stdout until the halt line arrives or the stream ends.
async fn read_halt_line(stdout: tokio::process::ChildStdout) -> Option<String> {
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.contains(HALT_LINE_KIND) {
            return Some(line);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg(dir: &Path) -> SpawnConfig {
        SpawnConfig {
            allowlist_path: dir.join("allowlist.json"),
            consent_path: dir.join("consent.json"),
            state_dir: dir.join("state"),
            policy_text_hash_hex: hex::encode([1u8; 32]),
            daily_ceiling_bytes: 1_000_000,
            throttle_bytes_per_sec: 262_144,
            operator_wallet: "0x1111111111111111111111111111111111111111".into(),
        }
    }

    /// INV-19.
    ///
    /// Mutations this detects: dropping `env_clear()`, which hands the sidecar
    /// the parent's proxy variables and key paths; adding an eighth variable
    /// without declaring it in `config::DECLARED_ENV`.
    #[test]
    fn spawn_passes_only_the_seven_declared_env_vars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = cfg(dir.path()).env();
        assert_eq!(env.len(), 7);

        let mut keys: Vec<&str> = env.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut declared: Vec<&str> = crate::config::DECLARED_ENV.to_vec();
        declared.sort_unstable();
        assert_eq!(keys, declared);

        // NEGATIVE CONTROL: nothing inherited reaches the map.
        for forbidden in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "PATH",
            "HOME",
            "USERPROFILE",
            "RUST_LOG",
        ] {
            assert!(
                !env.contains_key(forbidden),
                "{forbidden} reached the sidecar's environment"
            );
        }

        // POSITIVE CONTROL: the map really is populated, so the absence
        // assertions above are about a map that has entries.
        assert_eq!(
            env.get(crate::config::ENV_OPERATOR_WALLET)
                .map(String::as_str),
            Some("0x1111111111111111111111111111111111111111")
        );

        // The production source clears the environment. A sweep, because
        // `env()` alone cannot show what `spawn` does with it.
        let src = include_str!("supervisor.rs");
        let prod = src
            .rfind("\n#[cfg(test)]\nmod tests {")
            .map(|i| &src[..i])
            .unwrap_or(src);
        let clear = format!("{}{}", "env_", "clear()");
        assert!(
            prod.contains(clear.as_str()),
            "spawn no longer clears the parent environment"
        );
    }

    /// §4.1's kill-deadline row and the one exit code, both pinned.
    ///
    /// Mutations this detects: the deadline redeclared here with a different
    /// value; `EXIT_CONFIG` changed to `1`, which makes "this configuration
    /// will never work" indistinguishable from "this run failed".
    #[test]
    fn kill_deadline_is_five_seconds_and_exit_code_is_ex_config() {
        assert_eq!(KILL_DEADLINE_MS, 5_000);
        assert_eq!(KILL_DEADLINE, Duration::from_millis(KILL_DEADLINE_MS));
        assert_eq!(EXIT_CONFIG, 78);
        // The value is the tunnel's, not a second copy that agrees today.
        assert_eq!(
            KILL_DEADLINE_MS,
            goat_proxy_tunnel::lifecycle::KILL_DEADLINE_MS
        );
    }

    /// Mutations this detects: `spawn` reaching `Command::spawn` for a path
    /// that does not exist, which reports an opaque OS error instead of the
    /// operator's actual problem.
    #[tokio::test]
    async fn spawn_refuses_a_missing_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = ProxySupervisor::spawn(&dir.path().join("nope.exe"), &cfg(dir.path()));
        assert!(matches!(r, Err(SupervisorError::BinaryMissing(_))));
    }

    /// INV-19's launch half: the sidecar is launched only from a binary whose
    /// hash the supervisor pinned.
    ///
    /// Mutations this detects: the comparison written as `!=` on the wrong
    /// side, or dropped entirely so any binary at that path is run; the digest
    /// taken over the path string rather than the file's bytes.
    #[test]
    fn the_supervisor_refuses_a_sidecar_whose_hash_is_unpinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("sidecar.bin");
        std::fs::write(&bin, b"the real sidecar").expect("write");

        // POSITIVE CONTROL: the digest function answers, and answers stably.
        let pinned = binary_digest(&bin).expect("digest");
        assert_eq!(pinned, binary_digest(&bin).expect("digest"));
        assert_ne!(pinned, [0u8; 32], "the digest is a constant, not a hash");

        // A DIFFERENT pin over the same file is refused.
        let mut wrong = pinned;
        wrong[0] ^= 0xFF;
        assert!(matches!(
            ProxySupervisor::spawn_pinned(&bin, wrong, &cfg(dir.path())),
            Err(SupervisorError::BinaryHashMismatch)
        ));

        // ...and the digest tracks the FILE, not the path: rewriting the same
        // path with different bytes changes the answer.
        std::fs::write(&bin, b"a swapped sidecar").expect("write");
        assert_ne!(
            binary_digest(&bin).expect("digest"),
            pinned,
            "the digest is not taken over the file's bytes"
        );
        assert!(matches!(
            ProxySupervisor::spawn_pinned(&bin, pinned, &cfg(dir.path())),
            Err(SupervisorError::BinaryHashMismatch)
        ));

        // An absent binary is refused before any hashing happens.
        assert!(matches!(
            ProxySupervisor::spawn_pinned(&dir.path().join("gone"), pinned, &cfg(dir.path())),
            Err(SupervisorError::BinaryMissing(_))
        ));
    }

    /// INV-10's honesty half, and the single most important assertion in this
    /// module.
    ///
    /// Mutations this detects: `from_halt_line(None)` returning `Census(0)`;
    /// the timeout arm folded into the success arm; a line of the wrong kind
    /// accepted, so an ordinary heartbeat's `open_sockets` is reported as the
    /// halt evidence; `is_verified_clean` returning true for `Unverified`.
    #[test]
    fn a_halt_receipt_with_no_sidecar_line_reports_unverified_not_zero() {
        // POSITIVE CONTROL FIRST: a real halt line is read, and the number in
        // it is the number reported. Without this the assertions below also
        // pass against a parser that answers `Unverified` to everything.
        let good = r#"{"seq":9,"kind":"halt_completed","open_sockets":0,"elapsed_ms":12}"#;
        assert_eq!(
            SocketsAfter::from_halt_line(Some(good)),
            SocketsAfter::Census(0)
        );
        let dirty = r#"{"seq":9,"kind":"halt_completed","open_sockets":3,"elapsed_ms":12}"#;
        assert_eq!(
            SocketsAfter::from_halt_line(Some(dirty)),
            SocketsAfter::Census(3),
            "the receipt did not carry the sidecar's own figure"
        );

        // NO LINE AT ALL — the timeout case.
        assert_eq!(SocketsAfter::from_halt_line(None), SocketsAfter::Unverified);
        // A line that is not the halt line.
        for other in [
            r#"{"seq":1,"kind":"indicator_heartbeat","open_sockets":0,"live":true}"#,
            r#"{"seq":2,"kind":"halt_census_unavailable","elapsed_ms":40}"#,
            r#"{"seq":3,"kind":"halt_completed","elapsed_ms":40}"#,
            "not json at all",
            "",
        ] {
            assert_eq!(
                SocketsAfter::from_halt_line(Some(other)),
                SocketsAfter::Unverified,
                "{other:?} was accepted as halt evidence"
            );
        }

        // And `Unverified` is never a success.
        let unverified = HaltReceipt {
            elapsed_ms: 10,
            open_sockets_after: SocketsAfter::Unverified,
        };
        assert!(
            !unverified.is_verified_clean(),
            "an unobserved halt reported success"
        );
        let dirty_receipt = HaltReceipt {
            elapsed_ms: 10,
            open_sockets_after: SocketsAfter::Census(1),
        };
        assert!(!dirty_receipt.is_verified_clean());
        let late = HaltReceipt {
            elapsed_ms: KILL_DEADLINE_MS + 1,
            open_sockets_after: SocketsAfter::Census(0),
        };
        assert!(
            !late.is_verified_clean(),
            "a halt past the deadline reported success"
        );
        // POSITIVE CONTROL: the only shape that IS a success.
        assert!(HaltReceipt {
            elapsed_ms: 10,
            open_sockets_after: SocketsAfter::Census(0)
        }
        .is_verified_clean());
    }

    /// INV-10's provenance half: the number is the census's, and this module
    /// has no other way to produce one.
    ///
    /// Mutations this detects: a literal `SocketsAfter::Census(0)` written into
    /// the halt path so the receipt always reads clean; the in-process
    /// registry's own count substituted for the operating system's.
    #[test]
    fn the_halt_receipt_socket_count_comes_from_the_os_census() {
        let src = include_str!("supervisor.rs");
        let prod = src
            .rfind("\n#[cfg(test)]\nmod tests {")
            .map(|i| &src[..i])
            .unwrap_or(src);
        assert!(
            prod.len() > 4_000,
            "vacuity guard: the production part did not parse"
        );

        // The halt function's OWN body, so a `Census(..)` that legitimately
        // appears elsewhere -- `is_verified_clean` READS one, it does not
        // construct one -- is not confused with the halt path inventing a
        // number.
        let halt_body = prod
            .split("pub async fn halt(")
            .nth(1)
            .expect("the halt path must be findable")
            .split("\n    }")
            .next()
            .expect("the halt path must terminate");
        assert!(
            halt_body.len() > 300,
            "vacuity guard: the halt path did not parse"
        );

        // The ONLY construction of a census figure in the halt path is
        // `from_halt_line`. A literal would be a number this process chose.
        let ctor = format!("{}{}", "SocketsAfter::from_halt", "_line");
        assert!(
            halt_body.contains(ctor.as_str()),
            "the halt path no longer reads the sidecar's own line"
        );
        let invented = format!("{}{}", "Census", "(");
        // POSITIVE CONTROL: the scanner can see such a form when it is present
        // -- and it does see one in `is_verified_clean`, which is why the scope
        // above is the function body and not the whole file.
        assert!(
            prod.contains(invented.as_str()),
            "the scanner cannot see the form it forbids anywhere in this module"
        );
        assert!(
            !halt_body.contains(invented.as_str()),
            "the halt path constructs a census figure itself instead of reading the sidecar's"
        );
    }

    /// Mutations this detects: `halt` on a supervisor holding no child
    /// answering `Ok` with a clean receipt — a halt of nothing reported as a
    /// verified halt.
    #[tokio::test]
    async fn halting_a_supervisor_that_never_spawned_is_an_error_not_a_clean_receipt() {
        let mut s = ProxySupervisor { child: None };
        assert!(!s.is_running());
        assert!(matches!(s.halt().await, Err(SupervisorError::NotRunning)));
        assert!(matches!(
            s.heartbeat().await,
            Err(SupervisorError::NotRunning)
        ));
    }

    /// The two control words are line-terminated and distinct.
    ///
    /// Mutations this detects: a trailing newline dropped, which makes the
    /// child's line reader block forever on a command that was sent.
    #[test]
    fn the_control_words_are_line_terminated_and_distinct() {
        assert_eq!(CMD_HALT, "halt\n");
        assert_eq!(CMD_BEAT, "beat\n");
        assert_ne!(CMD_HALT, CMD_BEAT);
        for c in [CMD_HALT, CMD_BEAT] {
            assert!(c.ends_with('\n'), "{c:?} is not line-terminated");
            assert_eq!(c.lines().count(), 1, "{c:?} is more than one command");
        }
    }
}
