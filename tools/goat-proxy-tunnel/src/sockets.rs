//! The operating-system socket census.
//!
//! # Why this is not a comment
//!
//! "The daemon opens no inbound port" is the whole NAT story and a named
//! invariant (INV-5). An invariant asserted by a comment is an invariant
//! nobody has tested. This module asks the operating system how many sockets
//! a process is listening on, so the assertion is made against real kernel
//! state.
//!
//! # It fails loudly, on purpose
//!
//! A census that cannot enumerate returns `Err`. It never returns `Ok(0)` for
//! "I could not look". A permanently clean machine is the single most
//! dangerous answer this function could give: every test that depends on it
//! would pass, forever, against a process listening on every interface. So an
//! absent enumerator is [`SocketsError::EnumeratorMissing`], an unknown
//! platform is [`SocketsError::UnsupportedPlatform`], and callers are expected
//! to treat both as failures rather than as zeroes.
//!
//! # What counts
//!
//! TCP sockets in the listening state owned by `pid`. Outbound connections do
//! not count — dialling out is the entire design — and neither do sockets
//! owned by other processes.
//!
//! Design authority: the "Residential Proxy Network (P3) Implementation Plan",
//! §2 (INV-5, INV-10).

use std::process::Command;

/// Why the census could not answer.
///
/// Every variant is a loud failure. There is deliberately no "assume none"
/// variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketsError {
    /// The platform's enumerator program is not installed or not on `PATH`.
    EnumeratorMissing { command: String, detail: String },
    /// The enumerator ran and failed.
    EnumeratorFailed {
        command: String,
        status: Option<i32>,
        detail: String,
    },
    /// This build has no enumerator for the target platform.
    UnsupportedPlatform(&'static str),
    /// The enumerator's output was not valid text.
    Unreadable(String),
}

/// How many TCP sockets `pid` is listening on, according to the operating
/// system.
///
/// Returns `Err` rather than `Ok(0)` whenever the answer is unknown.
pub fn listening_socket_census(pid: u32) -> Result<usize, SocketsError> {
    #[cfg(target_os = "windows")]
    {
        census_windows(pid)
    }
    #[cfg(target_os = "linux")]
    {
        census_linux(pid)
    }
    #[cfg(target_os = "macos")]
    {
        census_macos(pid)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err(SocketsError::UnsupportedPlatform(std::env::consts::OS))
    }
}

/// Run `program args…` and return its stdout, mapping "not installed" to
/// [`SocketsError::EnumeratorMissing`] so an absent enumerator is
/// distinguishable from an empty answer.
///
/// `tolerate_empty_failure` exists for `lsof`, which exits non-zero when it
/// simply matched nothing.
fn run(program: &str, args: &[&str], tolerate_empty_failure: bool) -> Result<String, SocketsError> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SocketsError::EnumeratorMissing {
                command: program.to_string(),
                detail: e.to_string(),
            }
        } else {
            SocketsError::EnumeratorFailed {
                command: program.to_string(),
                status: None,
                detail: e.to_string(),
            }
        }
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let matched_nothing = tolerate_empty_failure && stdout.trim().is_empty();
        if !matched_nothing {
            return Err(SocketsError::EnumeratorFailed {
                command: program.to_string(),
                status: output.status.code(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
    }
    Ok(stdout)
}

/// `netstat -ano`, counting TCP rows in the listening state owned by `pid`.
///
/// The state word is localised on non-English Windows installs, so a row also
/// counts when its foreign endpoint is the wildcard `…:0` — which is what a
/// socket with no peer looks like in every locale. Over-counting is not a
/// hazard here: the invariant is `== 0`, and the control below measures a
/// delta.
#[cfg(target_os = "windows")]
fn census_windows(pid: u32) -> Result<usize, SocketsError> {
    let text = run("netstat", &["-ano"], false)?;
    let want = pid.to_string();
    let mut n = 0usize;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || !f[0].to_ascii_uppercase().starts_with("TCP") || f[4] != want {
            continue;
        }
        let state_is_listen = f[3].eq_ignore_ascii_case("LISTENING");
        let peer_is_wildcard = f[2].rsplit(':').next() == Some("0");
        if state_is_listen || peer_is_wildcard {
            n += 1;
        }
    }
    Ok(n)
}

/// `ss -Hltnp`, counting rows whose `users:(…)` field names `pid`.
#[cfg(target_os = "linux")]
fn census_linux(pid: u32) -> Result<usize, SocketsError> {
    let text = run("ss", &["-H", "-l", "-t", "-n", "-p"], false)?;
    let want = format!("pid={pid},");
    Ok(text.lines().filter(|l| l.contains(&want)).count())
}

/// `lsof`, restricted to `pid` and to TCP sockets in the listening state.
#[cfg(target_os = "macos")]
fn census_macos(pid: u32) -> Result<usize, SocketsError> {
    let pid_arg = pid.to_string();
    let text = run(
        "lsof",
        &["-nP", "-a", "-p", &pid_arg, "-iTCP", "-sTCP:LISTEN"],
        true,
    )?;
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("COMMAND"))
        .count())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Mutations this detects:** turning any failure into `Ok(0)`, which
    /// would make every zero-socket assertion in this crate pass vacuously
    /// forever.
    #[test]
    fn the_census_has_no_assume_none_path() {
        // A pid that cannot exist is still a *successful* enumeration on every
        // supported platform: the process simply owns nothing. That is `Ok(0)`
        // legitimately, and it is the only way this function may return zero.
        let answer = listening_socket_census(u32::MAX - 1);
        match answer {
            Ok(n) => assert_eq!(n, 0, "an impossible pid owns no listening socket"),
            Err(e) => panic!("the census failed on this platform: {e:?}"),
        }

        // And an enumerator that is not installed is an error, not a zero.
        let missing = run("goat-no-such-enumerator-exists", &["--version"], false);
        assert!(
            matches!(missing, Err(SocketsError::EnumeratorMissing { .. })),
            "an absent enumerator did not read as EnumeratorMissing: {missing:?}"
        );
    }

    /// **Mutations this detects:** collapsing the four failure causes onto
    /// one, so "not installed" and "unsupported platform" become
    /// indistinguishable to a caller that must fail loudly on both.
    #[test]
    fn every_census_failure_cause_is_distinguishable() {
        let a = SocketsError::EnumeratorMissing {
            command: "ss".into(),
            detail: "not found".into(),
        };
        let b = SocketsError::EnumeratorFailed {
            command: "ss".into(),
            status: Some(1),
            detail: String::new(),
        };
        let c = SocketsError::UnsupportedPlatform("plan9");
        let d = SocketsError::Unreadable("bad utf8".into());
        assert_eq!(a, a.clone());
        for (i, x) in [&a, &b, &c, &d].iter().enumerate() {
            for (j, y) in [&a, &b, &c, &d].iter().enumerate() {
                if i != j {
                    assert_ne!(x, y);
                }
            }
        }
    }
}
