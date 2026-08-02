//! The OS socket census.
//!
//! # Why this exists at all
//!
//! INV-10's halt evidence is "how many egress sockets does the operating system
//! still attribute to this process", and it is deliberately **not** an
//! in-process counter. A counter is a field the reporter assigns to itself: a
//! sidecar that leaked a socket would report zero with complete sincerity. So
//! the number in a halt receipt is read back out of the OS.
//!
//! # It must fail LOUDLY when it cannot answer
//!
//! [`CensusError::Unsupported`] is the dangerous case, because a census that
//! silently answers `0` on an unrecognised platform reports a permanently clean
//! machine and makes every zero-socket assertion in this crate vacuous. The
//! function therefore never invents a zero, and
//! `socket_census_positive_and_negative_control` panics rather than skips when
//! the platform is unsupported.
//!
//! # Established egress only
//!
//! A listener is not egress, and this crate has none — but the census must not
//! count one even if some other part of the process did. The predicate is
//! structural rather than textual: an entry is counted when the OS attributes it
//! to this process **and** its remote endpoint has a non-zero port. A passive
//! socket's remote endpoint is the wildcard `0.0.0.0:0` / `[::]:0`, so it is
//! excluded without ever reading a connection-state word — which matters on
//! Windows, where that word is localised and an English-only string comparison
//! would silently count nothing on a German or Japanese machine.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 32 and its Security invariants section (INV-10).

use thiserror::Error;

/// Why the census could not answer. **Never** folded into a `0`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CensusError {
    #[error("no socket census on {0}; every zero-socket assertion would be vacuous here")]
    Unsupported(&'static str),
    #[error("the socket census failed: {0}")]
    Io(String),
}

/// Established egress sockets the operating system attributes to `pid`.
pub fn egress_socket_census(pid: u32) -> Result<usize, CensusError> {
    platform::census(pid)
}

#[cfg(target_os = "windows")]
mod platform {
    use super::CensusError;
    use std::process::Command;

    /// `netstat -ano` rows, parsed structurally.
    ///
    /// The row shape for TCP is five whitespace-separated fields:
    /// `Proto  Local  Remote  State  PID`. UDP rows have four and are skipped by
    /// the `TCP` test. The state word is **not** compared: it is localised, and
    /// an `== "ESTABLISHED"` check would report zero on every non-English
    /// Windows — a check that cannot fail.
    pub fn census(pid: u32) -> Result<usize, CensusError> {
        let out = Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .map_err(|e| CensusError::Io(format!("netstat did not run: {}", e.kind())))?;
        if !out.status.success() {
            return Err(CensusError::Io(format!(
                "netstat exited with {:?}",
                out.status.code()
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let want = pid.to_string();
        let mut n = 0usize;
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 || !f[0].eq_ignore_ascii_case("TCP") {
                continue;
            }
            if f[4] != want {
                continue;
            }
            if remote_port(f[2]).is_some_and(|p| p != 0) {
                n += 1;
            }
        }
        Ok(n)
    }

    /// The port out of `1.2.3.4:443` or `[::1]:443`.
    fn remote_port(endpoint: &str) -> Option<u16> {
        endpoint.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::CensusError;
    use std::fs;

    /// `/proc/<pid>/net/tcp{,6}`.
    ///
    /// Established is state `01`; a listener is `0A`. Both the state word and
    /// the remote-port test are applied, because on Linux the state field is a
    /// stable hex integer rather than a localised word.
    pub fn census(pid: u32) -> Result<usize, CensusError> {
        let mut total = 0usize;
        let mut read_any = false;
        for name in ["tcp", "tcp6"] {
            let path = format!("/proc/{pid}/net/{name}");
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                // tcp6 is absent on a v4-only kernel; tcp is not, and its
                // absence is a real failure rather than an empty answer.
                Err(_) if name == "tcp6" => continue,
                Err(e) => return Err(CensusError::Io(format!("{path}: {}", e.kind()))),
            };
            read_any = true;
            for line in text.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 4 {
                    continue;
                }
                if f[3] != "01" {
                    continue;
                }
                if remote_port(f[2]).is_some_and(|p| p != 0) {
                    total += 1;
                }
            }
        }
        if !read_any {
            return Err(CensusError::Io("no /proc/<pid>/net/tcp".into()));
        }
        Ok(total)
    }

    /// `0100007F:01BB` -> `0x01BB`.
    fn remote_port(endpoint: &str) -> Option<u16> {
        endpoint
            .rsplit_once(':')
            .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::CensusError;
    use std::process::Command;

    /// `lsof -nP -p <pid> -iTCP -sTCP:ESTABLISHED`.
    ///
    /// The state selector is `lsof`'s own, not a localised display string.
    pub fn census(pid: u32) -> Result<usize, CensusError> {
        let out = Command::new("lsof")
            .args([
                "-nP",
                "-p",
                &pid.to_string(),
                "-iTCP",
                "-sTCP:ESTABLISHED",
                "-Fn",
            ])
            .output()
            .map_err(|e| CensusError::Io(format!("lsof did not run: {}", e.kind())))?;
        // `lsof` exits non-zero when it finds nothing, which is a legitimate
        // zero rather than a failure.
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text
            .lines()
            .filter(|l| l.starts_with('n') && l.contains("->"))
            .count())
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod platform {
    use super::CensusError;

    pub fn census(_pid: u32) -> Result<usize, CensusError> {
        Err(CensusError::Unsupported(std::env::consts::OS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRITICAL: `egress_socket_census` returning 0 is only meaningful if the
    /// same function has been shown, in the same run, to return >0 for a
    /// connection we opened ourselves. A census that is silently `Unsupported`
    /// on this platform would otherwise report a permanently clean machine --
    /// the exact "check that cannot fail" this repository's verification
    /// standard forbids.
    ///
    /// Mutations this detects: `Unsupported` mapped to `Ok(0)`; the remote-port
    /// test dropped, which counts listeners; a localised state-word comparison,
    /// which returns 0 on every non-English Windows.
    ///
    /// **The signal is deliberately large.** The census reads a
    /// process-global table, and the rest of this crate's suite opens and closes
    /// loopback sockets while it runs, so a one-socket delta would be a coin
    /// flip under the default `cargo test` threading. Sixteen simultaneous pairs
    /// is thirty-two sockets held open at once — far above that churn — and the
    /// tolerances below say how much noise each direction absorbs. Running the
    /// suite with `--test-threads=1` removes the noise entirely and is the
    /// recommended invocation.
    #[test]
    fn socket_census_positive_and_negative_control() {
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        /// Simultaneous connections held open, each contributing two sockets to
        /// this process (our client end and our server end).
        const PAIRS: usize = 16;
        /// How much concurrent churn each assertion tolerates.
        const NOISE: usize = 12;

        let pid = std::process::id();
        let base = match egress_socket_census(pid) {
            Ok(n) => n,
            Err(CensusError::Unsupported(p)) => panic!(
                "socket census is unsupported on {p}; every kill-switch assertion in this crate \
                 would be vacuous"
            ),
            Err(e) => panic!("census failed: {e:?}"),
        };

        // LISTENERS ALONE MUST NOT MOVE THE COUNT. This is the half that catches
        // a census counting passive sockets.
        let listeners: Vec<TcpListener> = (0..PAIRS)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("loopback listener"))
            .collect();
        let with_listeners = egress_socket_census(pid).expect("census");
        assert!(
            with_listeners < base + NOISE,
            "the census counted {PAIRS} listening sockets (base={base}, \
             with_listeners={with_listeners})"
        );

        // POSITIVE CONTROL: the census must SEE connections we open.
        let mut held = Vec::with_capacity(PAIRS * 2);
        for l in &listeners {
            let addr = l.local_addr().unwrap();
            let client = TcpStream::connect(addr).expect("loopback connect");
            let (server, _) = l.accept().expect("accept");
            held.push(client);
            held.push(server);
        }
        let with_conn = egress_socket_census(pid).expect("census");
        assert!(
            with_conn >= base + (PAIRS * 2 - NOISE),
            "census cannot see {} open connections (base={base}, with_conn={with_conn}); every \
             zero-socket assertion in this crate would be meaningless",
            PAIRS * 2
        );

        // NEGATIVE CONTROL: it must drop back once the connections are gone.
        drop(held);
        drop(listeners);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut after = with_conn;
        while Instant::now() < deadline {
            after = egress_socket_census(pid).expect("census");
            if after < base + NOISE {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            after < base + NOISE,
            "census did not drop after close (base={base}, after={after})"
        );
    }

    /// Mutations this detects: the census reading the whole machine's socket
    /// table rather than one process's, which would make a halt receipt report
    /// somebody else's connections — and would report a non-zero count forever
    /// on any machine that has a browser open.
    #[test]
    fn the_census_is_scoped_to_one_process() {
        use std::net::{TcpListener, TcpStream};

        // POSITIVE CONTROL: our own pid sees our own connection.
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let mine = egress_socket_census(std::process::id()).expect("census");
        assert!(mine > 0, "the census cannot see our own connection");

        // A pid no process can hold. A census scoped to it must be zero or an
        // error, and must NOT report the connection we just opened -- which a
        // machine-wide reader would.
        match egress_socket_census(u32::MAX) {
            Ok(n) => assert_eq!(
                n, 0,
                "a census scoped to an impossible pid saw {n} sockets; it is reading the whole \
                 machine"
            ),
            Err(CensusError::Unsupported(p)) => panic!("unsupported on {p}"),
            Err(CensusError::Io(_)) => {}
        }

        drop(client);
        drop(server);
    }
}
