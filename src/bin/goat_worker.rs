//! `goat-worker` — short-lived, network-less payload executor (execution-isolation).
//!
//! Runs as a **separate process** under the isolation supervisor. Enforces scratch-only
//! filesystem policy and denies network/spawn probes. Not a full OS sandbox by itself;
//! production Linux backend adds namespaces/seccomp (see `GoatHAL_Isolation_Design.md`).
//!
//! Protocol (stdin line): `GOAT_ISO/1 <op> <arg>`
//! Response (stdout line): `OK <detail>` | `DENIED <detail>`
//! Exit: 0 normal; 3 intentional crash probe; non-zero other failure.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

fn main() {
    let scratch = std::env::var_os("GOAT_SCRATCH")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        std::process::exit(1);
    }
    let line = line.trim();
    let mut parts = line.splitn(3, ' ');
    let ver = parts.next().unwrap_or("");
    let op = parts.next().unwrap_or("");
    let arg = parts.next().unwrap_or("-");
    if ver != "GOAT_ISO/1" {
        let _ = writeln!(io::stdout(), "DENIED bad-protocol");
        std::process::exit(2);
    }

    match op {
        "benign" => {
            let marker = scratch.join("ok.txt");
            if std::fs::write(&marker, b"ok").is_ok() {
                let _ = writeln!(io::stdout(), "OK benign");
                std::process::exit(0);
            }
            let _ = writeln!(io::stdout(), "DENIED scratch-write");
            std::process::exit(2);
        }
        "fs_write" => {
            let path = Path::new(arg);
            if !is_under_scratch(path, &scratch) {
                let _ = writeln!(io::stdout(), "DENIED path-outside-scratch");
                std::process::exit(2);
            }
            // Even under scratch, this op is only for tests; still write only under scratch.
            match std::fs::write(path, b"x") {
                Ok(()) => {
                    let _ = writeln!(io::stdout(), "OK wrote");
                    std::process::exit(0);
                }
                Err(_) => {
                    let _ = writeln!(io::stdout(), "DENIED fs");
                    std::process::exit(2);
                }
            }
        }
        "fs_read" => {
            let path = Path::new(arg);
            if !is_under_scratch(path, &scratch) {
                let _ = writeln!(io::stdout(), "DENIED path-outside-scratch");
                std::process::exit(2);
            }
            match std::fs::read(path) {
                Ok(_) => {
                    let _ = writeln!(io::stdout(), "OK read");
                    std::process::exit(0);
                }
                Err(_) => {
                    let _ = writeln!(io::stdout(), "DENIED fs");
                    std::process::exit(2);
                }
            }
        }
        "net_connect" => {
            // Phase-0: hard policy deny (no sockets). Production Linux: network namespace empty.
            let _ = writeln!(io::stdout(), "DENIED network-disabled");
            std::process::exit(2);
        }
        "spawn" => {
            let _ = writeln!(io::stdout(), "DENIED spawn-disabled");
            std::process::exit(2);
        }
        "crash" => {
            // Contained abort — supervisor must survive.
            std::process::exit(3);
        }
        _ => {
            let _ = writeln!(io::stdout(), "DENIED unknown-op");
            std::process::exit(2);
        }
    }
}

/// Return true only if `path` resolves inside `scratch` (after canonicalize when possible).
fn is_under_scratch(path: &Path, scratch: &Path) -> bool {
    let scratch_canon = scratch
        .canonicalize()
        .unwrap_or_else(|_| scratch.to_path_buf());
    // Absolute path that is not under scratch → deny.
    if path.is_absolute() {
        if let Ok(p) = path.canonicalize() {
            return p.starts_with(&scratch_canon);
        }
        // Non-existent absolute path: check prefix string after normalize.
        return path.starts_with(&scratch_canon) || path.starts_with(scratch);
    }
    // Relative: join with scratch and ensure result stays under scratch (no `..` escape).
    let joined = scratch.join(path);
    let mut depth = 0i32;
    for c in joined.components() {
        use std::path::Component;
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
        }
        if depth < 0 {
            return false;
        }
    }
    // If path contains parent components that escape scratch root:
    let stripped = path
        .components()
        .all(|c| !matches!(c, std::path::Component::ParentDir));
    if !stripped {
        // Allow only if canonicalize stays inside
        if let (Ok(j), Ok(s)) = (joined.canonicalize(), scratch.canonicalize()) {
            return j.starts_with(s);
        }
        return false;
    }
    true
}
