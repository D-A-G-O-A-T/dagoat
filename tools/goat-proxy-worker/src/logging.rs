//! The only place in this crate that calls a `tracing` macro.
//!
//! # Zero content logging is a property of the type system here, not a habit
//!
//! Every field of every [`SafeEvent`] variant is a byte count, an integer
//! identifier, a `bool`, a closed enum, or the resolved address. There is no
//! variant with a field capable of holding a URL, a path, a query string, a
//! header name, a header value or a body byte — which is why the claim is
//! provable rather than promised. Formatting nine clean events and grepping the
//! strings proves the *sample* is clean and nothing else: a
//! `StartupRefused { reason: <free text> }` accepts any literal, including a
//! URL. So [`RefusalReason`] is a **closed set**, and a structural test reads
//! this file's own enum declaration and refuses a free-text or destination
//! shaped field.
//!
//! # INV-11 is split, and the split is deliberate
//!
//! * **Receipts and on-chain evidence** carry a byte count, an integer
//!   identifier or a fixed constant, and the destination is an allowlist
//!   **entry id** and nothing else. That half lives in `meter.rs` and in the
//!   attestor.
//! * **The operator's own live log** additionally discloses the allowlist entry
//!   id and the address the allowlisted name resolved to — facts the operator
//!   read on screen and signed. It lives in a
//!   [`OPERATOR_LOG_RING_CAPACITY`]-entry in-memory ring and is **never written
//!   to disk**.
//!
//! Stating this as one global invariant would have been false, because the
//! desktop's egress feed carries the resolved address and the shipped
//! disclosure text promises exactly that.
//!
//! # Two formats, two descriptors
//!
//! Human-readable logging goes to **stderr**; the machine-readable
//! [`EgressLine`] JSON-lines stream the desktop supervisor reads goes to
//! **stdout**. Mixing them on one descriptor is how a supervisor's ring buffer,
//! its `last_seq` and its counters stay permanently empty while the daemon
//! looks like it is reporting.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 34 and its Security invariants section (INV-10, INV-11, INV-20).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::policy::DenyReason;

/// Why the sidecar refused to start.
///
/// A **CLOSED set**. An earlier shape took free text, which accepted any
/// literal — including a URL — and made "no variant can carry content" untrue
/// at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The seven declared environment variables did not produce a usable
    /// configuration.
    ConfigInvalid,
    /// The destination allowlist is absent, empty or corrupt.
    PolicyUnavailable,
    /// No consent record could be read.
    ConsentMissing,
    /// A consent record was read and did not verify.
    ConsentInvalid,
    /// The byte ledger could not be read, so this process cannot prove it is
    /// under the operator's ceiling.
    BudgetUnavailable,
}

impl RefusalReason {
    /// Every variant, so a test can enumerate the set without reflection.
    pub const ALL: [RefusalReason; 5] = [
        RefusalReason::ConfigInvalid,
        RefusalReason::PolicyUnavailable,
        RefusalReason::ConsentMissing,
        RefusalReason::ConsentInvalid,
        RefusalReason::BudgetUnavailable,
    ];

    /// A stable lower-case slug for the machine stream. Closed by construction:
    /// the match is exhaustive and every arm is a literal.
    pub fn slug(self) -> &'static str {
        match self {
            RefusalReason::ConfigInvalid => "config_invalid",
            RefusalReason::PolicyUnavailable => "policy_unavailable",
            RefusalReason::ConsentMissing => "consent_missing",
            RefusalReason::ConsentInvalid => "consent_invalid",
            RefusalReason::BudgetUnavailable => "budget_unavailable",
        }
    }
}

impl From<&crate::StartupRefusal> for RefusalReason {
    /// The startup gate's refusal, narrowed to the closed set the log speaks.
    ///
    /// `ConsentError::Absent` is the only one that means "there is nothing to
    /// check"; every other consent failure means "there was something and it
    /// did not hold", and the operator is told which.
    fn from(r: &crate::StartupRefusal) -> Self {
        match r {
            crate::StartupRefusal::Allowlist(_) => RefusalReason::PolicyUnavailable,
            crate::StartupRefusal::Consent(crate::ConsentError::Absent) => {
                RefusalReason::ConsentMissing
            }
            crate::StartupRefusal::Consent(_) => RefusalReason::ConsentInvalid,
        }
    }
}

/// Everything this crate is permitted to say out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeEvent {
    StartupRefused {
        reason: RefusalReason,
    },
    StartupAccepted {
        entry_count: usize,
        daily_ceiling_bytes: u64,
    },
    /// `resolved_ip` is one of the destination facts the operator read and
    /// signed (INV-11, operator-log half). It reaches the live log and nothing
    /// else: never a receipt, never the schema, never disk.
    EgressAllowed {
        entry_id: u32,
        port: u16,
        resolved_ip: IpAddr,
    },
    EgressDenied {
        entry_id: Option<u32>,
        reason: DenyReason,
        resolved_ip: Option<IpAddr>,
    },
    ChunkSealed {
        entry_id: u32,
        chunk_index: u32,
        bytes: u64,
        partial: bool,
    },
    SessionEnded {
        entry_id: u32,
        total_bytes: u64,
    },
    KillSwitchEngaged {
        open_sockets: usize,
    },
    /// `open_sockets_after` is the **operating system's** answer, read on the
    /// way out. It is never a literal this process chose.
    HaltCompleted {
        elapsed_ms: u64,
        open_sockets_after: usize,
    },
    /// The census could not answer. There is no number that honestly means
    /// "we did not find out", so none is carried — and `0` is the one that
    /// would read as "clean".
    HaltCensusUnavailable {
        elapsed_ms: u64,
    },
    IndicatorHeartbeat {
        live: bool,
        open_sockets: usize,
    },
}

impl SafeEvent {
    /// The event's kind, as a closed lower-case slug shared with the machine
    /// stream. Exhaustive, so a new variant is a compile error here.
    pub fn kind(&self) -> &'static str {
        match self {
            SafeEvent::StartupRefused { .. } => "startup_refused",
            SafeEvent::StartupAccepted { .. } => "startup_accepted",
            SafeEvent::EgressAllowed { .. } => "egress_allowed",
            SafeEvent::EgressDenied { .. } => "egress_denied",
            SafeEvent::ChunkSealed { .. } => "chunk_sealed",
            SafeEvent::SessionEnded { .. } => "session_ended",
            SafeEvent::KillSwitchEngaged { .. } => "kill_switch_engaged",
            SafeEvent::HaltCompleted { .. } => "halt_completed",
            SafeEvent::HaltCensusUnavailable { .. } => "halt_census_unavailable",
            SafeEvent::IndicatorHeartbeat { .. } => "indicator_heartbeat",
        }
    }
}

/// Install the human-readable subscriber on **stderr**.
///
/// Kept here rather than in `main.rs` so that the `tracing` name appears in
/// exactly one production file and the sweep below can say so without a
/// carve-out.
pub fn install_stderr_subscriber() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .try_init();
}

/// Write one event to the human-readable log.
pub fn emit(ev: &SafeEvent) {
    match ev {
        SafeEvent::StartupRefused { reason } => {
            tracing::error!(
                reason = reason.slug(),
                "proxy: refusing to start (fail-closed)"
            )
        }
        SafeEvent::StartupAccepted {
            entry_count,
            daily_ceiling_bytes,
        } => {
            tracing::info!(entry_count, daily_ceiling_bytes, "proxy: started")
        }
        SafeEvent::EgressAllowed {
            entry_id,
            port,
            resolved_ip,
        } => {
            tracing::info!(entry_id, port, ip = %resolved_ip, "proxy: egress allowed")
        }
        SafeEvent::EgressDenied {
            entry_id,
            reason,
            resolved_ip,
        } => {
            tracing::warn!(entry_id = ?entry_id, reason = ?reason, ip = ?resolved_ip, "proxy: egress denied")
        }
        SafeEvent::ChunkSealed {
            entry_id,
            chunk_index,
            bytes,
            partial,
        } => {
            tracing::info!(entry_id, chunk_index, bytes, partial, "proxy: chunk sealed")
        }
        SafeEvent::SessionEnded {
            entry_id,
            total_bytes,
        } => {
            tracing::info!(entry_id, total_bytes, "proxy: session ended")
        }
        SafeEvent::KillSwitchEngaged { open_sockets } => {
            tracing::warn!(open_sockets, "proxy: kill switch engaged")
        }
        SafeEvent::HaltCompleted {
            elapsed_ms,
            open_sockets_after,
        } => {
            tracing::warn!(elapsed_ms, open_sockets_after, "proxy: halt complete")
        }
        SafeEvent::HaltCensusUnavailable { elapsed_ms } => {
            tracing::error!(
                elapsed_ms,
                "proxy: halt complete but the socket census could not answer; the count is unverified"
            )
        }
        SafeEvent::IndicatorHeartbeat { live, open_sockets } => {
            tracing::debug!(live, open_sockets, "proxy: indicator")
        }
    }
}

// ---------------------------------------------------------------------------
// The operator's live log ring
// ---------------------------------------------------------------------------

/// How many events the operator's live log holds. Bounded, in memory, and
/// never written anywhere.
pub const OPERATOR_LOG_RING_CAPACITY: usize = 512;

/// The operator's live log: the newest [`OPERATOR_LOG_RING_CAPACITY`] events,
/// in memory.
///
/// There is deliberately no `flush`, no `path`, no `persist` and no file handle
/// on this type. INV-11's operator-log half is allowed to name the resolved
/// address precisely **because** it never outlives the process.
#[derive(Debug, Default)]
pub struct OperatorLogRing {
    inner: Mutex<VecDeque<SafeEvent>>,
}

impl OperatorLogRing {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// Record an event, evicting the oldest once the ring is full.
    pub fn record(&self, ev: SafeEvent) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() == OPERATOR_LOG_RING_CAPACITY {
            q.pop_front();
        }
        q.push_back(ev);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A copy of what the ring currently holds, oldest first.
    pub fn snapshot(&self) -> Vec<SafeEvent> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The machine-readable stream
// ---------------------------------------------------------------------------

/// The monotonic sequence number the desktop reconciles against. Starts at 1;
/// `0` is reserved for "nothing has been seen yet".
static NEXT_SEQ: AtomicU64 = AtomicU64::new(0);

/// The next sequence number. Increments by exactly one per call.
pub fn next_seq() -> u64 {
    NEXT_SEQ.fetch_add(1, Ordering::SeqCst) + 1
}

/// One line of the JSON stream on stdout.
///
/// Every field is a byte count, an integer identifier, a `bool`, a closed slug
/// or the resolved address. `reason` is populated **only** from a
/// [`DenyReason`], every variant of which is a unit variant, so the value set
/// is closed and a test asserts it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EgressLine {
    pub seq: u64,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_ceiling_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_sockets: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
}

/// Every key that may ever appear in a line of the machine stream.
///
/// An allowed-key list rather than a forbidden-key list: the forbidden set is
/// unbounded and the permitted set is thirteen names long.
pub const EGRESS_LINE_ALLOWED_KEYS: [&str; 14] = [
    "seq",
    "kind",
    "entry_id",
    "port",
    "resolved_ip",
    "reason",
    "chunk_index",
    "bytes",
    "partial",
    "entry_count",
    "daily_ceiling_bytes",
    "open_sockets",
    "elapsed_ms",
    "live",
];

impl EgressLine {
    /// An empty line of the given kind.
    fn bare(seq: u64, kind: &'static str) -> Self {
        Self {
            seq,
            kind,
            entry_id: None,
            port: None,
            resolved_ip: None,
            reason: None,
            chunk_index: None,
            bytes: None,
            partial: None,
            entry_count: None,
            daily_ceiling_bytes: None,
            open_sockets: None,
            elapsed_ms: None,
            live: None,
        }
    }

    /// Render an event at a caller-chosen sequence number. Deterministic, so a
    /// test does not have to reason about a process-global counter.
    pub fn with_seq(seq: u64, ev: &SafeEvent) -> Self {
        let mut l = Self::bare(seq, ev.kind());
        match ev {
            SafeEvent::StartupRefused { reason } => {
                l.reason = Some(reason.slug().to_string());
            }
            SafeEvent::StartupAccepted {
                entry_count,
                daily_ceiling_bytes,
            } => {
                l.entry_count = Some(*entry_count);
                l.daily_ceiling_bytes = Some(*daily_ceiling_bytes);
            }
            SafeEvent::EgressAllowed {
                entry_id,
                port,
                resolved_ip,
            } => {
                l.entry_id = Some(*entry_id);
                l.port = Some(*port);
                l.resolved_ip = Some(*resolved_ip);
            }
            SafeEvent::EgressDenied {
                entry_id,
                reason,
                resolved_ip,
            } => {
                l.entry_id = *entry_id;
                // A unit variant's `Debug` rendering is its bare name, and
                // `DenyReason` is asserted to be all-unit both here and in
                // `policy.rs`. So this is a closed value set, not free text.
                l.reason = Some(format!("{reason:?}"));
                l.resolved_ip = *resolved_ip;
            }
            SafeEvent::ChunkSealed {
                entry_id,
                chunk_index,
                bytes,
                partial,
            } => {
                l.entry_id = Some(*entry_id);
                l.chunk_index = Some(*chunk_index);
                l.bytes = Some(*bytes);
                l.partial = Some(*partial);
            }
            SafeEvent::SessionEnded {
                entry_id,
                total_bytes,
            } => {
                l.entry_id = Some(*entry_id);
                l.bytes = Some(*total_bytes);
            }
            SafeEvent::KillSwitchEngaged { open_sockets } => {
                l.open_sockets = Some(*open_sockets);
            }
            SafeEvent::HaltCompleted {
                elapsed_ms,
                open_sockets_after,
            } => {
                l.elapsed_ms = Some(*elapsed_ms);
                l.open_sockets = Some(*open_sockets_after);
            }
            SafeEvent::HaltCensusUnavailable { elapsed_ms } => {
                l.elapsed_ms = Some(*elapsed_ms);
                // `open_sockets` is deliberately absent, not zero.
            }
            SafeEvent::IndicatorHeartbeat { live, open_sockets } => {
                l.live = Some(*live);
                l.open_sockets = Some(*open_sockets);
            }
        }
        l
    }

    /// Render an event at the next process sequence number.
    pub fn next(ev: &SafeEvent) -> Self {
        Self::with_seq(next_seq(), ev)
    }
}

/// Write one line of the machine stream to **stdout**.
pub fn emit_egress_line(line: &EgressLine) {
    use std::io::Write;
    if let Ok(json) = serde_json::to_string(line) {
        let out = std::io::stdout();
        let mut handle = out.lock();
        let _ = handle.write_all(json.as_bytes());
        let _ = handle.write_all(b"\n");
        let _ = handle.flush();
    }
}

/// Emit an event on **both** descriptors: the human log on stderr and the
/// machine line on stdout, recording it in the operator's ring on the way.
pub fn emit_both(ring: &OperatorLogRing, ev: &SafeEvent) {
    emit(ev);
    ring.record(ev.clone());
    emit_egress_line(&EgressLine::next(ev));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate's `src/*.rs` count AT THIS TASK, an exact assertion rather
    /// than a `>=`: a floor written for the finished crate is unsatisfiable in
    /// the task that introduces the sweep, and an implementer who meets a red
    /// floor by lowering it has deleted the guard.
    ///
    /// Raised 15 -> 16 by Task 35, which adds `meter.rs`; 16 -> 17 by the
    /// canonical slug <-> id table, which adds `destinations.rs`.
    pub(crate) const WORKER_SRC_FILES_AT_THIS_TASK: usize = 17;
    /// A floor on BYTES as well as on files, so a truncating pre-filter cannot
    /// blank most of the corpus while the file count stays right. Measured
    /// 224_788 after Tasks 34-35.
    ///
    /// **It is not sufficient on its own** — see
    /// [`SURVIVES_ONLY_A_TRAILING_STRIP`], which is the guard that actually
    /// catches a first-match truncation.
    pub(crate) const MIN_SWEPT_BYTES: usize = 190_000;

    fn src_files() -> Vec<(std::path::PathBuf, String)> {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).expect("src/ must be readable") {
            let p = e.expect("dir entry").path();
            if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                let body = std::fs::read_to_string(&p).expect("read source");
                out.push((p, body));
            }
        }
        out
    }

    /// Strip ONLY the trailing `#[cfg(test)] mod tests` block.
    ///
    /// Matching the FIRST `#[cfg(test)]` occurrence silently blanks everything
    /// after an early test helper — `fetch.rs`'s `tests_support` module is
    /// exactly that shape — leaving most of a file unswept while every
    /// file-count vacuity guard stays green.
    fn production_part(body: &str) -> &str {
        match body.rfind("\n#[cfg(test)]\nmod tests {") {
            Some(i) => &body[..i],
            None => body,
        }
    }

    /// A marker that survives a TRAILING-block strip and does not survive a
    /// first-match truncation.
    ///
    /// `fetch.rs` declares `#[cfg(test)] mod tests_support` at column zero,
    /// roughly a hundred lines above its trailing test module. A pre-filter
    /// that cut at the first `#[cfg(test)]` would blank everything from there
    /// on — several thousand bytes of production source — while the file count
    /// stayed right and the byte floor stayed met, because the loss is a small
    /// fraction of a 200 kB corpus. So the byte floor is not the only guard:
    /// this marker is.
    const SURVIVES_ONLY_A_TRAILING_STRIP: &str = "mod tests_support";

    /// Mutations this detects: a `tracing::info!` naming a path or a query
    /// string added anywhere for debugging; the discipline relaxed so a second
    /// module may log; `production_part` regressing to a first-match
    /// truncation, which the byte floor catches.
    #[test]
    fn only_logging_module_calls_tracing_macros() {
        let files = src_files();
        assert_eq!(
            files.len(),
            WORKER_SRC_FILES_AT_THIS_TASK,
            "the crate's source-file count moved; raise WORKER_SRC_FILES_AT_THIS_TASK in the \
             same commit"
        );
        let swept_bytes: usize = files.iter().map(|(_, b)| production_part(b).len()).sum();
        assert!(
            swept_bytes >= MIN_SWEPT_BYTES,
            "swept only {swept_bytes} bytes of production source; the pre-filter is eating the \
             corpus"
        );

        // NEGATIVE CONTROL ON THE PRE-FILTER ITSELF, and it is load-bearing.
        // The byte floor alone does NOT catch a first-match truncation: the
        // one file it would blank is a few thousand bytes out of two hundred
        // thousand, so the floor stays met and the sweep silently stops reading
        // most of that file. This marker is what says so.
        let (fetch_path, fetch_body) = files
            .iter()
            .find(|(p, _)| p.ends_with("fetch.rs"))
            .expect("fetch.rs must be in the swept set");
        assert!(
            fetch_body.contains(SURVIVES_ONLY_A_TRAILING_STRIP),
            "the marker is gone from {}; this control proves nothing",
            fetch_path.display()
        );
        assert!(
            production_part(fetch_body).contains(SURVIVES_ONLY_A_TRAILING_STRIP),
            "the pre-filter truncated at the FIRST #[cfg(test)] instead of the trailing test \
             block; everything after {SURVIVES_ONLY_A_TRAILING_STRIP:?} is no longer swept"
        );

        // Assembled at runtime so the assertion below reads its own tokens out
        // of data rather than out of this file's literal text.
        let macros = [
            format!("{}{}", "tracing::", "info!"),
            format!("{}{}", "tracing::", "warn!"),
            format!("{}{}", "tracing::", "error!"),
            format!("{}{}", "tracing::", "debug!"),
            format!("{}{}", "tracing::", "trace!"),
        ];
        // POSITIVE CONTROL: the scanner can see every token in a string that
        // has them. A scanner with too small an alphabet reports a clean sweep.
        let control = macros.join(" ");
        for m in &macros {
            assert!(control.contains(m.as_str()), "the scanner cannot see {m}");
        }

        let mut hits = 0usize;
        for (p, body) in &files {
            let prod = production_part(body);
            for m in &macros {
                let n = prod.matches(m.as_str()).count();
                if n > 0 {
                    hits += n;
                    assert!(
                        p.ends_with("logging.rs"),
                        "{m} appears in {} -- route it through logging::emit",
                        p.display()
                    );
                }
            }
        }
        assert!(
            hits >= 8,
            "found only {hits} logging call sites; the scanner is broken"
        );
    }

    /// Zero-content logging, asserted on the TYPES rather than on a hand-built
    /// sample.
    ///
    /// Formatting ten clean events and grepping the strings proves the
    /// *sample* is clean and nothing more. What has to be true is that no
    /// variant has a field capable of holding free text or a destination.
    ///
    /// Mutations this detects: adding a free-text or path-shaped field to any
    /// variant; widening `reason` from the closed [`RefusalReason`] enum.
    #[test]
    fn no_safe_event_can_carry_a_url_path_or_header() {
        let all_reasons = RefusalReason::ALL;
        assert!(
            all_reasons.len() >= 5,
            "vacuity guard: the refusal set looks empty"
        );

        let events = sample_events();
        assert_eq!(events.len(), 10, "vacuity guard: no events to inspect");
        for ev in &events {
            let s = format!("{ev:?}");
            for poison in [
                "http",
                "://",
                "?",
                "Authorization",
                "Cookie",
                "/abs/",
                "SECRET",
            ] {
                assert!(!s.contains(poison), "{poison} in {s}");
            }
        }

        // The structural half: the enum's own source declares no free-text or
        // destination-shaped field.
        let src = include_str!("logging.rs");
        let decl = src
            .split("pub enum SafeEvent")
            .nth(1)
            .expect("the enum must be findable")
            .split("\n}")
            .next()
            .expect("the enum body must terminate");
        assert!(
            decl.len() > 200,
            "vacuity guard: the enum body did not parse"
        );
        for banned_ty in [
            ": String",
            ": &str",
            ": &'static str",
            ": Vec<u8>",
            ": PathBuf",
            ": Url",
            ": Uri",
        ] {
            assert!(
                !decl.contains(banned_ty),
                "SafeEvent has a {banned_ty} field"
            );
        }
        // POSITIVE CONTROL for the structural scanner: it fires on a
        // declaration that does carry one.
        assert!(
            "    EgressAllowed { path: String },".contains(": String"),
            "the structural scanner cannot see the field shape it forbids"
        );
    }

    /// One sample of every variant, so the two content tests and the key test
    /// all read the same closed set.
    fn sample_events() -> Vec<SafeEvent> {
        vec![
            SafeEvent::StartupRefused {
                reason: RefusalReason::ConsentMissing,
            },
            SafeEvent::StartupAccepted {
                entry_count: 2,
                daily_ceiling_bytes: 1,
            },
            SafeEvent::EgressAllowed {
                entry_id: 1,
                port: 443,
                resolved_ip: "93.184.216.34".parse().expect("literal"),
            },
            SafeEvent::EgressDenied {
                entry_id: Some(1),
                reason: DenyReason::RobotsDisallowed,
                resolved_ip: None,
            },
            SafeEvent::ChunkSealed {
                entry_id: 1,
                chunk_index: 0,
                bytes: 1,
                partial: false,
            },
            SafeEvent::SessionEnded {
                entry_id: 1,
                total_bytes: 1,
            },
            SafeEvent::KillSwitchEngaged { open_sockets: 0 },
            SafeEvent::HaltCompleted {
                elapsed_ms: 1,
                open_sockets_after: 0,
            },
            SafeEvent::HaltCensusUnavailable { elapsed_ms: 1 },
            SafeEvent::IndicatorHeartbeat {
                live: true,
                open_sockets: 0,
            },
        ]
    }

    /// INV-11, on the wire format the desktop actually parses.
    ///
    /// An allowed-KEY list, not a forbidden-key list: the forbidden set is
    /// unbounded. A `host`, `path`, `url`, `query` or `header` key added to
    /// this struct fails here before it can reach a desktop that renders it.
    ///
    /// Mutations this detects: a new field on `EgressLine` that is not in
    /// `EGRESS_LINE_ALLOWED_KEYS`; a key in the list that nothing ever emits,
    /// which is a list that has stopped describing the type.
    #[test]
    fn the_machine_stream_carries_only_allowed_keys() {
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (i, ev) in sample_events().iter().enumerate() {
            let line = EgressLine::with_seq(i as u64 + 1, ev);
            let json = serde_json::to_value(&line).expect("serialise");
            let obj = json.as_object().expect("an object");
            for k in obj.keys() {
                assert!(
                    EGRESS_LINE_ALLOWED_KEYS.contains(&k.as_str()),
                    "the machine stream carries an unlisted key {k:?}"
                );
                seen.insert(k.clone());
            }
            // The rendered line carries no destination beyond the entry id and
            // the resolved address.
            let text = serde_json::to_string(&line).expect("render");
            for poison in ["http", "://", "path", "query", "header", "cookie", "host"] {
                assert!(
                    !text.contains(poison),
                    "the machine stream leaked {poison:?}: {text}"
                );
            }
        }
        // POSITIVE CONTROL: every allowed key is actually emitted by something.
        // A list nothing populates is a list that has stopped describing the
        // type.
        for k in EGRESS_LINE_ALLOWED_KEYS {
            assert!(
                seen.contains(k),
                "no event ever emits {k:?}; the allowed-key list has drifted from the type"
            );
        }
    }

    /// The refusal slug and the deny slug are both drawn from closed sets.
    ///
    /// Mutations this detects: `reason` populated from anything but a
    /// `DenyReason`; a data-carrying `DenyReason` variant, whose `Debug`
    /// rendering would carry its payload straight into the machine stream.
    #[test]
    fn the_reason_field_is_a_closed_set_of_bare_identifiers() {
        let reasons = [
            DenyReason::RedirectHopLimit,
            DenyReason::MalformedHost,
            DenyReason::NonCanonicalIpLiteral,
            DenyReason::HostNotAllowlisted,
            DenyReason::PortNotAllowed,
            DenyReason::SchemeNotAllowed,
            DenyReason::MethodNotAllowed,
            DenyReason::RequestBodyNotPermitted,
            DenyReason::PathOutOfScope,
            DenyReason::NoResolvedAddress,
            DenyReason::ResolutionFailed,
            DenyReason::DeniedNetwork,
            DenyReason::RobotsDisallowed,
            DenyReason::RobotsUnavailable,
            DenyReason::EntryRateExceeded,
            DenyReason::DailyCeilingExceeded,
            DenyReason::BudgetUnavailable,
            DenyReason::ScheduleClosed,
            DenyReason::IndicatorStale,
            DenyReason::ConsentWithdrawn,
            DenyReason::KillSwitchEngaged,
            DenyReason::ConcurrencyLimit,
            DenyReason::MalformedRedirectLocation,
            DenyReason::RedirectSchemeNotAllowed,
            DenyReason::ResponseTooLarge,
        ];
        assert_eq!(reasons.len(), 25, "the refusal set moved; see policy.rs");
        for r in reasons {
            let line = EgressLine::with_seq(
                1,
                &SafeEvent::EgressDenied {
                    entry_id: None,
                    reason: r,
                    resolved_ip: None,
                },
            );
            let slug = line.reason.expect("a denial names its reason");
            assert!(
                slug.chars().all(|c| c.is_ascii_alphanumeric()),
                "DenyReason::{slug} is not a bare identifier; it can carry data into the stream"
            );
        }
        // POSITIVE CONTROL: the identifier test can fail. A rendering carrying
        // a payload is rejected.
        assert!(!"HostNotAllowlisted(\"example.com\")"
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));

        // Every startup refusal slug is likewise closed and distinct.
        let mut slugs: Vec<&str> = RefusalReason::ALL.iter().map(|r| r.slug()).collect();
        let before = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), before, "two refusal reasons share a slug");
    }

    /// The sequence number the desktop reconciles against starts at 1 and
    /// increments by exactly one.
    ///
    /// Mutations this detects: `fetch_add` returning the pre-increment value
    /// straight out, which starts the stream at 0 — the value reserved for
    /// "nothing seen yet", so the first real event would be indistinguishable
    /// from an empty feed.
    #[test]
    fn the_machine_stream_sequence_starts_at_one_and_never_repeats() {
        let a = next_seq();
        let b = next_seq();
        let c = next_seq();
        assert!(a >= 1, "the sequence must start at 1, not 0");
        assert_eq!(b, a + 1);
        assert_eq!(c, b + 1);
    }

    /// INV-11's operator-log half: bounded, in memory, never on disk.
    ///
    /// Mutations this detects: the ring given a file handle or a path; the
    /// eviction dropped, which makes the "bounded" claim false and lets the
    /// log grow without limit; `pop_back` in place of `pop_front`, which
    /// evicts the newest event instead of the oldest.
    #[test]
    fn the_operator_log_ring_is_never_written_to_disk() {
        let ring = OperatorLogRing::new();
        assert!(ring.is_empty());

        // POSITIVE CONTROL first: the ring really does hold what it is given.
        ring.record(SafeEvent::KillSwitchEngaged { open_sockets: 7 });
        assert_eq!(ring.len(), 1);
        assert_eq!(
            ring.snapshot()[0],
            SafeEvent::KillSwitchEngaged { open_sockets: 7 }
        );

        for i in 0..OPERATOR_LOG_RING_CAPACITY as u64 + 10 {
            ring.record(SafeEvent::SessionEnded {
                entry_id: 1,
                total_bytes: i,
            });
        }
        assert_eq!(
            ring.len(),
            OPERATOR_LOG_RING_CAPACITY,
            "the ring is unbounded; a 512-entry promise that grows forever is not a promise"
        );
        // The OLDEST went, not the newest.
        let snap = ring.snapshot();
        assert_eq!(
            snap.last().expect("non-empty"),
            &SafeEvent::SessionEnded {
                entry_id: 1,
                total_bytes: OPERATOR_LOG_RING_CAPACITY as u64 + 9
            },
            "the ring evicted the newest event instead of the oldest"
        );

        // The structural half: this module names no file-writing API in its
        // production part. `emit_egress_line` writes to a descriptor the parent
        // handed it, which is not a file this process opened.
        let src = include_str!("logging.rs");
        let prod = production_part(src);
        let banned = [
            format!("{}{}", "File::", "create"),
            format!("{}{}", "OpenOptions", "::new"),
            format!("{}{}", "fs::", "write"),
            format!("{}{}", "create_dir", "_all"),
        ];
        // POSITIVE CONTROL: the scanner sees its own tokens.
        let control = banned.join(" ");
        for b in &banned {
            assert!(control.contains(b.as_str()), "the scanner cannot see {b}");
        }
        assert!(
            prod.len() > 5_000,
            "vacuity guard: the module's production part did not parse"
        );
        for b in &banned {
            assert!(
                !prod.contains(b.as_str()),
                "the operator log module names {b}; this log never reaches disk"
            );
        }
    }

    /// The startup gate's refusal narrows onto the closed set correctly.
    ///
    /// Mutations this detects: every consent failure collapsed onto
    /// `ConsentMissing`, which tells an operator whose record was tampered with
    /// that there is no record at all.
    #[test]
    fn a_startup_refusal_narrows_onto_the_closed_reason_set() {
        use crate::{ConsentError, PolicyError, StartupRefusal};
        assert_eq!(
            RefusalReason::from(&StartupRefusal::Allowlist(PolicyError::AllowlistAbsent)),
            RefusalReason::PolicyUnavailable
        );
        assert_eq!(
            RefusalReason::from(&StartupRefusal::Consent(ConsentError::Absent)),
            RefusalReason::ConsentMissing
        );
        // The distinguishing half: a record that EXISTS and failed is not
        // reported as a record that is missing.
        for e in [
            ConsentError::BadSignature,
            ConsentError::ForeignSigner,
            ConsentError::Expired,
            ConsentError::AllowlistDigestMismatch,
        ] {
            assert_eq!(
                RefusalReason::from(&StartupRefusal::Consent(e.clone())),
                RefusalReason::ConsentInvalid,
                "{e:?} was reported as a missing record"
            );
        }
    }
}
