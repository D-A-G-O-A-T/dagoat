//! `goat-proxy-worker`: the sidecar daemon.
//!
//! # Startup order is the whole security argument
//!
//! Nothing that can dial is constructed until configuration, the destination
//! allowlist and consent have all verified, and the byte ledger has proved it
//! can be read. Every failure exits [`EXIT_CONFIG`] with a single
//! `StartupRefused` event and leaves no partial state behind. **There is no
//! "started with reduced capability" state**: the refusal set has no variant
//! meaning "running anyway".
//!
//! # Two descriptors, two formats
//!
//! Human-readable logging goes to **stderr**; the machine-readable JSON-lines
//! stream the desktop supervisor parses goes to **stdout**. Those are two
//! different formats, and putting them on one descriptor is how a supervisor's
//! ring buffer, its `last_seq` and its counters stay permanently empty while
//! the daemon looks like it is reporting.
//!
//! # The control plane is the parent's stdin
//!
//! No listening socket, no control port, no local console API — a local console
//! API is precisely the design this avoids. Losing stdin means the shell is
//! gone, and that is a halt.
//!
//! # The halt's socket count is the OPERATING SYSTEM'S
//!
//! On the way out the daemon reads `census::egress_socket_census(pid)` and
//! carries that number in its final line. It never writes a zero it did not
//! measure: a census that cannot answer produces a `HaltCensusUnavailable`
//! line with **no** count, and the supervisor reports `Unverified` rather than
//! `0` (INV-10).
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 34 and its Security invariants section (INV-1, INV-8, INV-9,
//! INV-10, INV-11, INV-19, INV-20).

use std::collections::HashMap;
use std::sync::Arc;

use goat_proxy_worker::census::{egress_socket_census, CensusError};
use goat_proxy_worker::config::{now_unix, ProxyConfig, DECLARED_ENV};
use goat_proxy_worker::fetch::HttpRobotsFetcher;
use goat_proxy_worker::logging::{
    emit, emit_both, install_stderr_subscriber, OperatorLogRing, RefusalReason, SafeEvent,
};
use goat_proxy_worker::net::{SocketRegistry, KILL_DEADLINE};
use goat_proxy_worker::policy::SystemClock;
use goat_proxy_worker::resolve::SystemResolver;
use goat_proxy_worker::robots::RobotsCache;
use goat_proxy_worker::start_gate_with;
use goat_proxy_worker::supervisor::{CMD_BEAT, CMD_HALT, EXIT_CONFIG};

/// The one exit path for a refusal. One event, one code, no partial state.
fn refuse(reason: RefusalReason) -> ! {
    emit(&SafeEvent::StartupRefused { reason });
    std::process::exit(EXIT_CONFIG)
}

/// What the daemon says on the way out, and what it exits with.
///
/// A **pure function of the census result**, deliberately: this is the single
/// place INV-10's "never a field the reporter assigns to itself" rule could be
/// broken, and a pure function is a thing a test can drive directly. The
/// mutation "report `0` instead of the census figure" edits exactly this.
fn halt_event(elapsed_ms: u64, census: &Result<usize, CensusError>) -> SafeEvent {
    match census {
        Ok(n) => SafeEvent::HaltCompleted {
            elapsed_ms,
            open_sockets_after: *n,
        },
        // NOT `open_sockets_after: 0`. There is no number that honestly means
        // "we did not find out", and `0` is the one that reads as "clean".
        Err(_) => SafeEvent::HaltCensusUnavailable { elapsed_ms },
    }
}

/// A clean halt is the only zero exit.
///
/// A census that could not answer is a LOUD failure — an `Unsupported`
/// platform would otherwise report a permanently clean machine and make every
/// zero-socket assertion in this crate vacuous.
fn halt_exit_code(census: &Result<usize, CensusError>) -> i32 {
    match census {
        Ok(0) => 0,
        Ok(_) => 1,
        Err(_) => EXIT_CONFIG,
    }
}

#[tokio::main]
async fn main() {
    // Human logs to STDERR. STDOUT carries the line-delimited JSON event
    // stream and nothing else.
    install_stderr_subscriber();
    let ring = OperatorLogRing::new();

    // 1. Configuration — only the seven declared variables are read.
    let mut map: HashMap<String, String> = HashMap::new();
    for k in DECLARED_ENV {
        if let Ok(v) = std::env::var(k) {
            map.insert(k.to_string(), v);
        }
    }
    let cfg = match ProxyConfig::load_from_map(&map) {
        Ok(c) => c,
        Err(_) => refuse(RefusalReason::ConfigInvalid),
    };

    // 2. A registry exists before the gate because the real robots fetcher
    //    needs one. It holds a counter and a notification handle and NOTHING
    //    else: no socket, no descriptor, no thread. The first socket cannot
    //    exist until `EgressPolicy::evaluate` admits a request, and nothing can
    //    call that until the gate below has returned.
    let registry = Arc::new(SocketRegistry::new());
    let registry_for_robots = Arc::clone(&registry);

    // 3. THE GATE, in order: allowlist, then consent re-verified from the file
    //    against the wallet the supervisor named, then the byte ledger. Every
    //    failure is a refusal.
    //
    //    The robots fetcher is built inside the gate because it takes the
    //    ledger: robots bytes are the operator's bytes and are debited like any
    //    other, and an undebited fetch path is an uncapped one.
    let (policy, _record) = match start_gate_with(
        &cfg,
        now_unix(),
        Arc::new(SystemResolver),
        move |budget| {
            Arc::new(RobotsCache::new(Box::new(HttpRobotsFetcher::new(
                registry_for_robots,
                Arc::clone(budget),
            ))))
        },
        Arc::new(SystemClock),
    ) {
        Ok(v) => v,
        Err(e) => refuse(RefusalReason::from(&e)),
    };

    // 4. The ledger must be READABLE, not merely present: a daemon that cannot
    //    prove it is under the operator's ceiling does not run.
    if policy.budget().spent_today(now_unix()).is_err() {
        refuse(RefusalReason::BudgetUnavailable);
    }

    emit_both(
        &ring,
        &SafeEvent::StartupAccepted {
            entry_count: policy.entries().len(),
            daily_ceiling_bytes: policy.budget().ceiling_bytes(),
        },
    );

    // 5. Control plane: the parent's stdin. Losing it is a halt.
    let reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = tokio::io::AsyncBufReadExt::lines(reader);
    policy.indicator().set_live(true, now_unix());
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => {
                    let l = format!("{l}\n");
                    if l == CMD_BEAT {
                        policy.indicator().set_live(true, now_unix());
                        emit_both(&ring, &SafeEvent::IndicatorHeartbeat {
                            live: true,
                            open_sockets: registry.open(),
                        });
                    } else if l == CMD_HALT {
                        break;
                    }
                }
                // EOF, or a broken pipe: the shell is gone. Halt.
                Ok(None) | Err(_) => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    // 6. The halt. The indicator closes first, so no request admitted during
    //    the drain can start a new dial.
    emit_both(
        &ring,
        &SafeEvent::KillSwitchEngaged {
            open_sockets: registry.open(),
        },
    );
    policy.indicator().engage_kill_switch();
    let report = registry.halt_and_wait(KILL_DEADLINE).await;

    // 7. THE census, read from the operating system on the way out and carried
    //    in the final line, so the supervisor reports a measured number rather
    //    than a literal this process assigned itself.
    let census = egress_socket_census(std::process::id());
    let event = halt_event(report.elapsed_ms, &census);
    emit_both(&ring, &event);
    std::process::exit(halt_exit_code(&census));
}

#[cfg(test)]
mod tests {
    use super::*;
    use goat_proxy_worker::logging::EgressLine;
    use goat_proxy_worker::supervisor::SocketsAfter;
    use goat_proxy_worker::StartupRefusal;

    /// INV-10, at the one seam where the halt receipt's number is chosen.
    ///
    /// Mutations this detects: `halt_event` returning
    /// `HaltCompleted { open_sockets_after: 0 }` on the error arm, which is the
    /// literal zero a surface then renders under "Stopped. Open sockets:" as if
    /// it were evidence; the census result discarded and the in-process
    /// registry count substituted; the two arms swapped.
    #[test]
    fn the_halt_receipt_socket_count_comes_from_the_os_census() {
        // POSITIVE CONTROL: a measured non-zero count is carried through
        // unchanged, so the assertions below are about a function that reports
        // what it was given.
        assert_eq!(
            halt_event(42, &Ok(3)),
            SafeEvent::HaltCompleted {
                elapsed_ms: 42,
                open_sockets_after: 3
            }
        );
        assert_eq!(
            halt_event(42, &Ok(0)),
            SafeEvent::HaltCompleted {
                elapsed_ms: 42,
                open_sockets_after: 0
            }
        );

        // THE assertion: a census that could not answer produces no count at
        // all — never a zero.
        for err in [
            CensusError::Unsupported("plan9"),
            CensusError::Io("netstat did not run: NotFound".into()),
        ] {
            let ev = halt_event(42, &Err(err.clone()));
            assert_eq!(
                ev,
                SafeEvent::HaltCensusUnavailable { elapsed_ms: 42 },
                "an unanswerable census produced a socket count"
            );
            // ...and the line the supervisor reads carries no count, so the
            // supervisor's own parser answers `Unverified`.
            let line = EgressLine::with_seq(1, &ev);
            assert!(
                line.open_sockets.is_none(),
                "the unverified halt line carries a socket count"
            );
            let text = serde_json::to_string(&line).expect("render");
            assert_eq!(
                SocketsAfter::from_halt_line(Some(&text)),
                SocketsAfter::Unverified
            );
        }

        // And the round trip for the verified case: what the census said is
        // what the supervisor reads back.
        let line = EgressLine::with_seq(1, &halt_event(42, &Ok(3)));
        let text = serde_json::to_string(&line).expect("render");
        assert_eq!(
            SocketsAfter::from_halt_line(Some(&text)),
            SocketsAfter::Census(3),
            "the supervisor did not read back the sidecar's own census figure"
        );
    }

    /// A halt is a zero exit only when the operating system was asked and
    /// answered zero.
    ///
    /// Mutations this detects: `Err` folded onto `0`, which lets an
    /// unsupported platform exit clean forever; a non-zero count exiting zero.
    #[test]
    fn only_a_measured_clean_halt_exits_zero() {
        assert_eq!(halt_exit_code(&Ok(0)), 0);
        assert_eq!(halt_exit_code(&Ok(1)), 1);
        assert_eq!(halt_exit_code(&Ok(99)), 1);
        assert_eq!(
            halt_exit_code(&Err(CensusError::Unsupported("plan9"))),
            EXIT_CONFIG
        );
        assert_eq!(
            halt_exit_code(&Err(CensusError::Io("no".into()))),
            EXIT_CONFIG
        );
        assert_ne!(EXIT_CONFIG, 0, "the loud failure must not be a clean exit");
    }

    /// Every startup failure is a refusal, and they map onto the closed set.
    ///
    /// Mutations this detects: a gate failure logged and then ignored, which is
    /// the "started with reduced capability" state this daemon does not have.
    #[test]
    fn every_gate_failure_is_a_refusal_on_the_closed_set() {
        use goat_proxy_worker::{ConsentError, PolicyError};
        assert_eq!(
            RefusalReason::from(&StartupRefusal::Allowlist(PolicyError::AllowlistEmpty)),
            RefusalReason::PolicyUnavailable
        );
        assert_eq!(
            RefusalReason::from(&StartupRefusal::Consent(ConsentError::Absent)),
            RefusalReason::ConsentMissing
        );
        assert_eq!(
            RefusalReason::from(&StartupRefusal::Consent(ConsentError::BadSignature)),
            RefusalReason::ConsentInvalid
        );
        // POSITIVE CONTROL: the closed set is not a single value.
        let mut slugs: Vec<&str> = RefusalReason::ALL.iter().map(|r| r.slug()).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), 5);
    }
}
