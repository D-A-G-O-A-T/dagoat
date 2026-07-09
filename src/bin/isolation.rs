//! Host-edge execution isolation supervisor (execution-isolation / Vector 1.1).
//!
//! Spawns `goat-worker` as a **separate OS process**, never runs payload code in-process.
//! Device-agnostic: no device-type branches. Fail-closed when isolation is unavailable.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Default wall-clock timeout for a worker probe/task (Phase-0).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default memory hint (bytes) — enforced cooperatively in Phase-0; OS Job/rlimit in production backends.
pub const DEFAULT_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;

/// Framed line protocol version tag.
const PROTO: &str = "GOAT_ISO/1";

/// Whether the host can provide the isolation contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsolationStatus {
    /// Worker binary found; out-of-process execution allowed under policy.
    Available { worker_path: PathBuf },
    /// Must not execute payloads.
    Unavailable { reason: String },
}

/// Policy for a single execution (device-agnostic).
#[derive(Clone, Debug)]
pub struct ExecPolicy {
    pub timeout: Duration,
    pub memory_limit_bytes: u64,
    /// If true, allow only when status is Available (always required for real exec).
    pub require_isolation: bool,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT,
            require_isolation: true,
        }
    }
}

/// Outcome of a supervised worker run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerReport {
    Ok { detail: String },
    Denied { detail: String },
    Crashed { exit_code: Option<i32> },
    TimedOut,
    ProtocolError { detail: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsolationError {
    Unavailable(String),
    Spawn(String),
    Io(String),
}

fn worker_bin_name() -> &'static str {
    if cfg!(windows) {
        "goat-worker.exe"
    } else {
        "goat-worker"
    }
}

/// Locate the worker binary: `GOAT_WORKER_PATH` (exclusive if set), next to the current exe,
/// parent of exe (`target/debug/deps` → `target/debug`), or `target/{debug,release}/` under the crate root.
pub fn check_isolation() -> IsolationStatus {
    let name = worker_bin_name();

    // Exclusive override — fail-closed when the operator points at a missing path.
    if let Ok(p) = std::env::var("GOAT_WORKER_PATH") {
        let path = PathBuf::from(&p);
        return if path.is_file() {
            IsolationStatus::Available { worker_path: path }
        } else {
            IsolationStatus::Unavailable {
                reason: format!("GOAT_WORKER_PATH not a file: {p}"),
            }
        };
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(name));
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join(name));
            }
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["debug", "release"] {
        candidates.push(manifest.join("target").join(profile).join(name));
    }

    for path in &candidates {
        if path.is_file() {
            return IsolationStatus::Available {
                worker_path: path.clone(),
            };
        }
    }
    IsolationStatus::Unavailable {
        reason: format!(
            "goat-worker binary not found (set GOAT_WORKER_PATH or `cargo build --bin goat-worker`); tried {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Fail-closed gate: may we execute payloads?
pub fn may_execute(status: &IsolationStatus, policy: &ExecPolicy) -> Result<(), IsolationError> {
    if !policy.require_isolation {
        return Err(IsolationError::Unavailable(
            "require_isolation=false is not permitted on the production path".into(),
        ));
    }
    match status {
        IsolationStatus::Available { .. } => Ok(()),
        IsolationStatus::Unavailable { reason } => Err(IsolationError::Unavailable(reason.clone())),
    }
}

/// Run an opaque probe operation in the worker (Phase-0 containment harness).
pub fn run_probe(
    worker_path: &Path,
    scratch: &Path,
    op: &str,
    arg: &str,
    policy: &ExecPolicy,
) -> Result<WorkerReport, IsolationError> {
    let mut child = Command::new(worker_path)
        .current_dir(scratch)
        .env("GOAT_SCRATCH", scratch.as_os_str())
        .env("GOAT_MEMORY_LIMIT", policy.memory_limit_bytes.to_string())
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| IsolationError::Spawn(e.to_string()))?;

    let req = format!("{PROTO} {op} {arg}\n");
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(req.as_bytes())
            .map_err(|e| IsolationError::Io(e.to_string()))?;
        // drop stdin → EOF
    }

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                return Ok(interpret_exit(status.code(), stdout.trim()));
            }
            Ok(None) => {
                if start.elapsed() > policy.timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(WorkerReport::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(IsolationError::Io(e.to_string())),
        }
    }
}

fn interpret_exit(code: Option<i32>, stdout: &str) -> WorkerReport {
    // Worker conventions: exit 0 = ok/denied structured; 2 = denied; 3 = crash probe done via abort
    if code == Some(101) || code == Some(3) {
        return WorkerReport::Crashed { exit_code: code };
    }
    if let Some(detail) = stdout.strip_prefix("OK ") {
        return WorkerReport::Ok {
            detail: detail.to_string(),
        };
    }
    if let Some(detail) = stdout.strip_prefix("DENIED ") {
        return WorkerReport::Denied {
            detail: detail.to_string(),
        };
    }
    if code != Some(0) {
        return WorkerReport::Crashed { exit_code: code };
    }
    WorkerReport::ProtocolError {
        detail: format!("code={code:?} stdout={stdout}"),
    }
}

/// Create a private scratch directory for one task.
pub fn make_scratch(prefix: &str) -> Result<PathBuf, IsolationError> {
    let base = std::env::temp_dir().join("goat_iso");
    std::fs::create_dir_all(&base).map_err(|e| IsolationError::Io(e.to_string()))?;
    let dir = base.join(format!(
        "{prefix}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| IsolationError::Io(e.to_string()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that might touch process-global env / worker discovery.
    static ISO_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn worker() -> PathBuf {
        let _g = ISO_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure we don't inherit a bad override from another test.
        std::env::remove_var("GOAT_WORKER_PATH");
        match check_isolation() {
            IsolationStatus::Available { worker_path } => worker_path,
            IsolationStatus::Unavailable { reason } => {
                panic!("goat-worker required for isolation tests: {reason}");
            }
        }
    }

    #[test]
    fn fail_closed_when_isolation_unavailable() {
        let st = IsolationStatus::Unavailable {
            reason: "simulated-missing".into(),
        };
        assert!(may_execute(&st, &ExecPolicy::default()).is_err());
    }

    #[test]
    fn check_isolation_exclusive_override_missing_path() {
        let _g = ISO_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GOAT_WORKER_PATH", "/nonexistent/goat-worker-not-real");
        let st = check_isolation();
        std::env::remove_var("GOAT_WORKER_PATH");
        assert!(matches!(st, IsolationStatus::Unavailable { .. }));
    }

    #[test]
    fn benign_probe_ok() {
        let w = worker();
        let scratch = make_scratch("benign").unwrap();
        let pol = ExecPolicy::default();
        let r = run_probe(&w, &scratch, "benign", "-", &pol).unwrap();
        assert!(matches!(r, WorkerReport::Ok { .. }), "{r:?}");
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[test]
    fn host_fs_write_denied() {
        let w = worker();
        let scratch = make_scratch("fs").unwrap();
        let pol = ExecPolicy::default();
        // Attempt to write outside scratch (parent of scratch).
        let outside = scratch
            .parent()
            .unwrap()
            .join("goat_iso_should_not_exist.txt");
        let arg = outside.to_string_lossy();
        let r = run_probe(&w, &scratch, "fs_write", &arg, &pol).unwrap();
        assert!(
            matches!(r, WorkerReport::Denied { .. }),
            "expected Denied, got {r:?}"
        );
        assert!(!outside.exists(), "host file must not be created");
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[test]
    fn network_connect_denied() {
        let w = worker();
        let scratch = make_scratch("net").unwrap();
        let pol = ExecPolicy::default();
        let r = run_probe(&w, &scratch, "net_connect", "1.1.1.1:80", &pol).unwrap();
        assert!(
            matches!(r, WorkerReport::Denied { .. }),
            "expected Denied, got {r:?}"
        );
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[test]
    fn spawn_escalation_denied() {
        let w = worker();
        let scratch = make_scratch("spawn").unwrap();
        let pol = ExecPolicy::default();
        let r = run_probe(&w, &scratch, "spawn", "echo", &pol).unwrap();
        assert!(
            matches!(r, WorkerReport::Denied { .. }),
            "expected Denied, got {r:?}"
        );
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[test]
    fn crash_contained_parent_lives() {
        let w = worker();
        let scratch = make_scratch("crash").unwrap();
        let pol = ExecPolicy::default();
        let r = run_probe(&w, &scratch, "crash", "-", &pol).unwrap();
        assert!(
            matches!(r, WorkerReport::Crashed { .. }),
            "expected Crashed, got {r:?}"
        );
        // Parent (test process) still running if we reach here.
        let r2 = run_probe(&w, &scratch, "benign", "-", &pol).unwrap();
        assert!(matches!(r2, WorkerReport::Ok { .. }));
        let _ = std::fs::remove_dir_all(scratch);
    }
}
