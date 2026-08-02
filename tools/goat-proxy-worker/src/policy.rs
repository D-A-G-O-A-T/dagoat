//! The egress policy: a destination allowlist decided on the resolved,
//! pinned IP address.
//!
//! # Why this is an allowlist and not a filter
//!
//! Port-gating to 80/443 plus filtering on the TLS server name **does not
//! work**, and the design does not pretend otherwise:
//!
//! * Encrypted ClientHello hides the real server name from the node.
//! * Domain fronting splits the TLS server name from the `Host` header, so the
//!   two name different origins.
//! * The server name is asserted by the client and authenticated by nobody.
//! * A request to a bare IP literal carries no server name at all.
//! * A request that asks a proxy for an opaque bidirectional tunnel on 443
//!   carries any protocol whatsoever through the port gate.
//!
//! Every abuse class this feature exists to prevent — credential stuffing, ad
//! fraud, layer-7 flooding, malware command-and-control, forbidden scraping,
//! illegal-content retrieval — fits entirely inside ordinary HTTPS on 443. So
//! the control that actually bounds abuse is the **allowlist**, and it is
//! decided on the address the node itself resolved.
//!
//! # Fail closed by construction
//!
//! [`EgressPolicy::load_entries`] has no success path that yields zero entries.
//! Absent, empty, unreadable and corrupt are four distinct refusals and none of
//! them degrades to "permit everything" or to "permit nothing but keep
//! running". A daemon that cannot load a list does not start.
//!
//! # Order of evaluation
//!
//! [`EgressPolicy::evaluate`] runs, in this order, and **no socket is opened
//! until every step before the pin has passed**:
//!
//! 1. hop bound
//! 2. canonical host-literal check
//! 3. allowlist host match
//! 4. port gate
//! 5. scheme
//! 6. method
//! 7. path scope
//! 8. resolve and pin, with the deny-net applied to every resolved address
//! 9. per-entry request rate
//!
//! Two further steps — `robots.txt` and the byte budget/indicator liveness —
//! are named in the design between 8 and 9 and after 9 respectively, and land
//! with the modules that own them. Their insertion points are marked in
//! `evaluate` so that adding them is an edit at a named line rather than a
//! guess about ordering.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 29 and its Security invariants section (INV-1, INV-4, INV-5,
//! INV-6, INV-7); and the "Residential Proxy Network (P3) Implementation Plan",
//! §2 and §3.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::caps::{CapError, EgressLedger};
use crate::destinations::{self, RegistryError};
use crate::indicator::Indicator;
use crate::resolve::{is_denied_net, parse_canonical_ip_literal, resolve_and_pin, Resolver};
use crate::robots::{RobotsCache, RobotsVerdict};

/// Ports 80 and 443, and nothing else.
///
/// This gate is NECESSARY AND GROSSLY INSUFFICIENT, and saying so here is part
/// of the design. Every abuse class that matters -- credential stuffing, ad
/// fraud, CAPTCHA relaying, scalping, layer-7 flooding, forbidden scraping,
/// illegal-content retrieval, command-and-control -- fits entirely inside
/// HTTPS on 443. The gate removes only the trivially-wrong cases (mail, remote
/// desktop, torrents, DNS). The control that actually bounds abuse is the
/// ALLOWLIST below, decided on the resolved IP; the port check exists so that a
/// bug in the allowlist does not also hand out an SMTP relay.
pub const ALLOWED_PORTS: [u16; 2] = [80, 443];

/// How many redirects may be followed.
///
/// The counting convention, written out because it is the kind of thing that
/// gets read backwards: `ProxyRequest::hop` is the number of redirects already
/// followed, so the original request has `hop == 0`. `evaluate` refuses at
/// `hop >= MAX_REDIRECT_HOPS`, which means hops 0, 1 and 2 are evaluated and
/// the request that would be the fourth is refused.
pub const MAX_REDIRECT_HOPS: u8 = 3;

/// The sliding window the per-entry request ceiling is measured over.
const RATE_WINDOW_MS: u64 = 60_000;

/// The schema tag the allowlist file must carry.
const ALLOWLIST_SCHEMA_ID: &str = "GOAT_PROXY_ALLOWLIST_V1";

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

/// The two schemes this node speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// The one port this scheme is permitted on.
    ///
    /// Coupling the two is a real check, not bookkeeping: a request that names
    /// one scheme and the other's port is either a confused client or an
    /// attempt to have the port gate and the scheme handler disagree about what
    /// is on the wire.
    pub fn required_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// The methods this node will speak.
///
/// **There is deliberately no variant for the method that asks a proxy to open
/// an opaque bidirectional tunnel.** Its name does not appear anywhere in this
/// crate's production source, and `the_tunnelling_method_does_not_exist_in_the_enum`
/// asserts that absence by assembling the token at runtime. The node terminates
/// as an HTTP client and parses a response body; it is never a relay forwarding
/// bytes it has not read. Such a request arrives as [`Method::Other`] and is
/// refused with 405, having opened no socket.
///
/// `Clone` is required and is not decoration: `Method` owns a `String`, so it
/// is not `Copy`, and the redirect loop moves `req.method` out of `req` on the
/// first iteration while still borrowing the rest of `req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Other(String),
}

/// One request, as the policy sees it.
///
/// Note what the consumer does **not** get to supply: an IP address. There is
/// no address field anywhere in this struct, so there is no path by which a
/// consumer-chosen destination reaches a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub scheme: Scheme,
    pub method: Method,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    /// Redirects already followed. The original request is `0`.
    pub hop: u8,
}

// ---------------------------------------------------------------------------
// The allowlist
// ---------------------------------------------------------------------------

/// How an entry's `host` is compared against a request's host.
///
/// **One variant in v1.** The `match_mode` field is matched exhaustively at
/// every use site, so adding a suffix or wildcard mode is a compile error in
/// several places at once — which is the point. A suffix mode would have to
/// answer, first, what it does about a host carrying userinfo and about the
/// FQDN root dot, both of which defeat naive suffix comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchMode {
    Exact,
}

/// How an entry's `path_prefixes` list is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathScope {
    /// The request path must begin with one of the entry's prefixes. The list
    /// may not be empty: an entry declaring this scope with no prefixes refuses
    /// to load, because an empty prefix list read as "matches everything" is
    /// the fail-open shape this crate exists to avoid.
    Prefixes,
    /// The entry's whole origin is in scope. Spelled out as its own deliberate
    /// declaration so that "no path restriction" can never be arrived at by
    /// omission — a missing `path_prefixes` key is a load refusal, not a silent
    /// widening to this.
    WholeOrigin,
}

/// One allowed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// The only destination identifier that may ever reach a receipt. Never
    /// zero, so an uninitialised integer names no entry.
    pub id: u32,
    /// Lower-case, no trailing dot, never an IP literal.
    pub host: String,
    pub match_mode: MatchMode,
    pub path_scope: PathScope,
    /// Sorted and deduplicated at load time, so one prefix set has one
    /// in-memory spelling however the file wrote it.
    ///
    /// **Not part of the consent digest.** It was, under the retired
    /// operational-manifest hash; the founder ruling recorded on
    /// [`operator_allowlist_preimage`] took it back out, because a path
    /// adjustment is daemon operation and the operator was never shown these
    /// prefixes.
    pub path_prefixes: Vec<String>,
    pub max_requests_per_minute: u32,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a request was refused.
///
/// Every variant is a **unit** variant. A refusal reason that carried data
/// would be a field that starts as a port number and grows into a hostname, and
/// this type is read by the operator log and, indirectly, by the receipt path.
/// The refused port, path and host are known to the caller that built the
/// request; they do not need to travel inside the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    // -- request shape ------------------------------------------------------
    /// `hop >= MAX_REDIRECT_HOPS`.
    RedirectHopLimit,
    /// The host is not a syntactically valid name or address.
    MalformedHost,
    /// The host is an address written in some encoding other than the canonical
    /// one: decimal, hex, octal, leading-zero octets, a short form, bracketed,
    /// or carrying the FQDN root dot.
    NonCanonicalIpLiteral,
    /// No allowlist entry matches this host.
    HostNotAllowlisted,
    /// The port is not in [`ALLOWED_PORTS`].
    PortNotAllowed,
    /// The scheme is not permitted, or does not match the port.
    SchemeNotAllowed,
    /// The method is not one this node speaks. The opaque-tunnel method lands
    /// here.
    MethodNotAllowed,
    /// The method would carry a request body. v1 is a read-only fetcher.
    RequestBodyNotPermitted,
    /// The path is not well formed, or is outside the entry's declared
    /// prefixes.
    PathOutOfScope,

    // -- resolution ---------------------------------------------------------
    /// The name resolved to nothing.
    NoResolvedAddress,
    /// The resolver failed.
    ResolutionFailed,
    /// At least one resolved address is not public unicast.
    DeniedNetwork,

    // -- origin policy (robots; the module that fetches it lands later) -----
    /// The origin's `robots.txt` disallows this path for this agent.
    RobotsDisallowed,
    /// `robots.txt` could not be read, which RFC 9309 §2.3.1 makes a complete
    /// disallow rather than a permission.
    RobotsUnavailable,

    // -- budgets and liveness ----------------------------------------------
    /// The entry's per-minute request ceiling is spent.
    EntryRateExceeded,
    /// The operator's daily byte ceiling is spent.
    DailyCeilingExceeded,
    /// The byte ledger could not be read, so this process cannot prove it is
    /// under the ceiling.
    ///
    /// **Distinct from [`DenyReason::DailyCeilingExceeded`] on purpose.** The
    /// two refuse identically — an unprovable ceiling and a spent one both stop
    /// the request — but they are different operational problems: one clears at
    /// UTC midnight and the other needs somebody to look at a file. Folding them
    /// together is the "silently merges two refusals into one" mutation the
    /// variant-count test exists to catch.
    BudgetUnavailable,
    /// The current time is outside every consented schedule window.
    ScheduleClosed,
    /// The operator-visible liveness indicator is not fresh.
    IndicatorStale,
    /// Consent has been withdrawn.
    ConsentWithdrawn,
    /// The kill switch is engaged.
    KillSwitchEngaged,
    /// Too many sessions are already in flight.
    ConcurrencyLimit,

    // -- redirects ----------------------------------------------------------
    /// A `Location` value in neither of the two accepted shapes.
    MalformedRedirectLocation,
    /// A `Location` naming a scheme this node does not speak.
    RedirectSchemeNotAllowed,

    // -- response -----------------------------------------------------------
    /// The response exceeded the size this node will carry.
    ResponseTooLarge,
}

/// Why the policy itself could not be brought up, or why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("the allowlist file is absent; the daemon does not start without one")]
    AllowlistAbsent,
    #[error("the allowlist is empty; an empty list is a refusal to start, never allow-all")]
    AllowlistEmpty,
    #[error("the allowlist is unreadable or malformed: {0}")]
    AllowlistCorrupt(String),
    #[error("refused: {0:?}")]
    Denied(DenyReason),
}

/// The outcome of evaluating one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow {
        /// The allowlist entry that authorised this.
        entry_id: u32,
        /// The address that was validated, and the only address that may be
        /// dialled. Carried by value so the dial cannot re-resolve.
        pinned_ip: IpAddr,
        port: u16,
    },
    Deny(DenyReason),
}

impl PolicyDecision {
    /// The dial target for an allowed request.
    ///
    /// This is how the pin travels from validation to connect: a `SocketAddr`,
    /// built from the address that passed the deny-net, with no name in it.
    pub fn pinned_socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            PolicyDecision::Allow {
                pinned_ip, port, ..
            } => Some(std::net::SocketAddr::new(*pinned_ip, *port)),
            PolicyDecision::Deny(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Clock and rate limiter
// ---------------------------------------------------------------------------

/// Time, behind a seam, so a rate ceiling can be tested without sleeping.
pub trait Clock: Send + Sync {
    fn now_unix_millis(&self) -> u64;
}

/// The wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// A sliding one-minute request ceiling, per allowlist entry.
///
/// The mutex is a `tokio::sync::Mutex` because `evaluate` is `async` and this
/// lock is taken inside it; a `std` mutex held across an await blocks the
/// worker thread it is running on.
#[derive(Default)]
pub struct EntryRateLimiter {
    windows: Mutex<HashMap<u32, Vec<u64>>>,
}

impl EntryRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request against `entry_id` if the ceiling permits it.
    ///
    /// Returns `false` without recording anything when the window is full, so a
    /// refused request does not itself extend the refusal.
    pub async fn try_admit(&self, entry_id: u32, limit: u32, now_ms: u64) -> bool {
        let mut windows = self.windows.lock().await;
        let stamps = windows.entry(entry_id).or_default();
        let floor = now_ms.saturating_sub(RATE_WINDOW_MS);
        stamps.retain(|t| *t > floor);
        if stamps.len() as u64 >= u64::from(limit) {
            return false;
        }
        stamps.push(now_ms);
        true
    }
}

// ---------------------------------------------------------------------------
// The allowlist file
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAllowlist {
    schema_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    entries: Vec<WireEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    id: u32,
    host: String,
    match_mode: String,
    path_scope: String,
    path_prefixes: Vec<String>,
    max_requests_per_minute: u32,
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// The loaded, digested allowlist plus the seams `evaluate` needs.
///
/// The three seams that were marked absent when this struct was introduced —
/// `robots`, `budget` and `indicator` — are now filled by the modules that own
/// them. Each is a **required** constructor argument rather than an `Option`
/// with a default, for the reason the absent version recorded: a field holding
/// an allow-everything default is a control that reads as present and is not.
pub struct EgressPolicy {
    pub(crate) entries: Vec<AllowlistEntry>,
    pub(crate) allowlist_digest: [u8; 32],
    pub(crate) resolver: Arc<dyn Resolver>,
    /// `robots.txt`, fetched over the pinned address with RFC 9309 §2.3.1
    /// semantics.
    pub(crate) robots: Arc<RobotsCache>,
    /// The durable UTC-daily byte ledger. Read here as a **precheck**; the
    /// debits happen as the body flows, in `fetch::BudgetSink`.
    pub(crate) budget: Arc<EgressLedger>,
    /// The operator-visible liveness gate. Stale closes egress.
    pub(crate) indicator: Arc<Indicator>,
    pub(crate) rate: EntryRateLimiter,
    pub(crate) clock: Arc<dyn Clock>,
}

impl EgressPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entries: Vec<AllowlistEntry>,
        allowlist_digest: [u8; 32],
        resolver: Arc<dyn Resolver>,
        robots: Arc<RobotsCache>,
        budget: Arc<EgressLedger>,
        indicator: Arc<Indicator>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            entries,
            allowlist_digest,
            resolver,
            robots,
            budget,
            indicator,
            rate: EntryRateLimiter::new(),
            clock,
        }
    }

    /// Load the allowlist from disk and build a policy around it.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        path: &Path,
        resolver: Arc<dyn Resolver>,
        robots: Arc<RobotsCache>,
        budget: Arc<EgressLedger>,
        indicator: Arc<Indicator>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PolicyError> {
        let (entries, digest) = Self::load_entries(path)?;
        Ok(Self::new(
            entries, digest, resolver, robots, budget, indicator, clock,
        ))
    }

    /// The byte ledger this policy debits. `fetch` reaches it through here so
    /// that one policy owns one ledger and a second ledger over the same file
    /// cannot be constructed by accident.
    pub fn budget(&self) -> &Arc<EgressLedger> {
        &self.budget
    }

    /// The liveness gate, for whoever owns the operator surface.
    pub fn indicator(&self) -> &Arc<Indicator> {
        &self.indicator
    }

    /// Read, validate and digest the allowlist.
    ///
    /// There is **no** success path that returns zero entries. Absent, empty,
    /// unreadable and schema-wrong are four separate refusals.
    pub fn load_entries(path: &Path) -> Result<(Vec<AllowlistEntry>, [u8; 32]), PolicyError> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(PolicyError::AllowlistAbsent),
            // Unreadable is corrupt, not absent: a file that exists and cannot
            // be read is a different operational problem, and conflating the
            // two would let a permissions mistake read as "no list configured".
            Err(e) => return Err(PolicyError::AllowlistCorrupt(e.kind().to_string())),
        };

        // Typed deserialisation with unknown fields refused. A
        // `from_str::<Value>` check would accept `{"entries": "yes"}` and every
        // other valid-JSON-wrong-schema shape.
        let wire: WireAllowlist = serde_json::from_str(&text)
            .map_err(|e| PolicyError::AllowlistCorrupt(format!("schema: {e}")))?;

        if wire.schema_id != ALLOWLIST_SCHEMA_ID {
            return Err(PolicyError::AllowlistCorrupt(format!(
                "schema_id is {:?}, expected {ALLOWLIST_SCHEMA_ID:?}",
                wire.schema_id
            )));
        }
        if wire.entries.is_empty() {
            return Err(PolicyError::AllowlistEmpty);
        }

        let mut entries = Vec::with_capacity(wire.entries.len());
        for w in wire.entries {
            entries.push(validate_entry(w)?);
        }

        for (i, a) in entries.iter().enumerate() {
            for b in &entries[i + 1..] {
                if a.id == b.id {
                    return Err(PolicyError::AllowlistCorrupt(format!(
                        "duplicate entry id {}",
                        a.id
                    )));
                }
                if a.host == b.host {
                    return Err(PolicyError::AllowlistCorrupt(format!(
                        "duplicate host {:?} under ids {} and {}",
                        a.host, a.id, b.id
                    )));
                }
            }
        }

        // THE CANONICAL DIGEST, OR NO LIST AT ALL. An entry naming a `u32` the
        // canonical registry does not carry cannot be serialised the way the
        // desktop serialises it, so the daemon refuses to load rather than
        // starting with a digest only it can reproduce.
        let digest = allowlist_digest(&entries).map_err(|e| {
            PolicyError::AllowlistCorrupt(format!(
                "the list cannot be named canonically, so it cannot be consented to: {e}"
            ))
        })?;
        Ok((entries, digest))
    }

    /// The 32-byte digest of the loaded list. This is what a receipt names, so
    /// an entry id can be resolved back to the list it indexes, and it is what
    /// the consent record's `allowlist_digest` is compared against.
    ///
    /// It is the **operator-facing** digest — SHA-256 over
    /// `(id, registered slug, host)`, the desktop's construction byte for byte,
    /// with both sides resolving their own identifier through
    /// [`crate::destinations`]. See [`operator_allowlist_preimage`] for the two
    /// founder rulings that decided this and for what they deliberately leave
    /// outside the binding.
    pub fn allowlist_digest(&self) -> [u8; 32] {
        self.allowlist_digest
    }

    pub fn entries(&self) -> &[AllowlistEntry] {
        &self.entries
    }

    /// The entry an [`PolicyDecision::Allow`] refers to.
    ///
    /// This is where the `Host` header and the TLS server name come from: the
    /// **allowlisted** name that the policy matched, never a string the
    /// consumer supplied.
    pub fn entry(&self, id: u32) -> Option<&AllowlistEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Decide one request. No socket is opened on any refusal path.
    pub async fn evaluate(&self, req: &ProxyRequest) -> PolicyDecision {
        // 1. HOP BOUND, first, inside `evaluate`.
        //
        // First because a redirect is a new request that has not been approved
        // yet, and inside `evaluate` because a loop counter in the caller is a
        // bound the caller can forget. A single allowlisted origin answering
        // `302 Location: /next` forever spins on near-zero bytes, so a byte
        // budget never stops it either.
        if req.hop >= MAX_REDIRECT_HOPS {
            return PolicyDecision::Deny(DenyReason::RedirectHopLimit);
        }

        // 2. CANONICAL HOST-LITERAL CHECK.
        //
        // Run on `req.host`, and again on every redirect host, before the
        // allowlist is consulted. A permissive parser that normalised octal,
        // decimal or hex into an address would hand that address to the deny-net
        // only AFTER the allowlist had already matched the string as a name.
        let literal = match parse_canonical_ip_literal(&req.host) {
            Ok(v) => v,
            Err(PolicyError::Denied(r)) => return PolicyDecision::Deny(r),
            Err(_) => return PolicyDecision::Deny(DenyReason::MalformedHost),
        };
        // A canonical literal still faces the deny-net, before anything else
        // looks at it. It will then fail the allowlist match as well, because
        // entries are names; both refusals are wanted.
        if let Some(ip) = literal {
            if is_denied_net(ip) {
                return PolicyDecision::Deny(DenyReason::DeniedNetwork);
            }
        }

        // 3. ALLOWLIST HOST MATCH.
        let host = req.host.to_ascii_lowercase();
        let entry = match self.entries.iter().find(|e| match e.match_mode {
            MatchMode::Exact => e.host == host,
        }) {
            Some(e) => e,
            None => return PolicyDecision::Deny(DenyReason::HostNotAllowlisted),
        };

        // 4. PORT GATE. Necessary and grossly insufficient; see ALLOWED_PORTS.
        if !ALLOWED_PORTS.contains(&req.port) {
            return PolicyDecision::Deny(DenyReason::PortNotAllowed);
        }

        // 5. SCHEME, coupled to the port.
        if req.scheme.required_port() != req.port {
            return PolicyDecision::Deny(DenyReason::SchemeNotAllowed);
        }

        // 6. METHOD.
        match req.method {
            Method::Get | Method::Head => {}
            // v1 is a read-only fetcher. A request body is the credential-
            // stuffing and form-abuse primitive, and `Post` is a named variant
            // rather than an `Other` so that permitting it later is a
            // deliberate edit here and not a widening nobody notices.
            Method::Post => return PolicyDecision::Deny(DenyReason::RequestBodyNotPermitted),
            Method::Other(_) => return PolicyDecision::Deny(DenyReason::MethodNotAllowed),
        }

        // 7. PATH SCOPE.
        if !path_in_scope(entry, &req.path_and_query) {
            return PolicyDecision::Deny(DenyReason::PathOutOfScope);
        }

        // 8. RESOLVE AND PIN, deny-net applied to every resolved address.
        //
        // The name resolved is the ALLOWLIST ENTRY's host, not the request's.
        // Under `MatchMode::Exact` they are equal, and resolving the entry's
        // copy is the stronger statement: the address is derived from the list,
        // not from anything that arrived over the wire.
        //
        // `spawn_blocking` because name resolution is a blocking syscall and
        // this is an async context.
        let resolver = Arc::clone(&self.resolver);
        let entry_host = entry.host.clone();
        let entry_id = entry.id;
        let port = req.port;
        let pinned = match tokio::task::spawn_blocking(move || {
            resolve_and_pin(&*resolver, &entry_host, port, entry_id)
        })
        .await
        {
            Ok(Ok(t)) => t,
            Ok(Err(PolicyError::Denied(r))) => return PolicyDecision::Deny(r),
            Ok(Err(_)) | Err(_) => return PolicyDecision::Deny(DenyReason::ResolutionFailed),
        };

        // 9. ROBOTS. Fetched over THIS pinned address, with the SAME name, with
        //    no redirects, and with its bytes debited through the same ledger as
        //    every other byte. RFC 9309 §2.3.1: 4xx is unrestricted; 5xx, a
        //    transport failure, a timeout, an oversize body or a refused debit
        //    is a COMPLETE DISALLOW.
        //
        //    Placed after the pin and before the rate limiter because it is a
        //    property of the ORIGIN, and the origin is not known until the
        //    address is. A robots check made before the pin would be a check
        //    against a name, which is the thing this policy refuses to trust.
        match self
            .robots
            .allows(
                req.scheme,
                &pinned,
                &req.path_and_query,
                self.clock.now_unix_millis() / 1_000,
            )
            .await
        {
            RobotsVerdict::Allowed => {}
            RobotsVerdict::Disallowed => return PolicyDecision::Deny(DenyReason::RobotsDisallowed),
            RobotsVerdict::Unavailable => {
                return PolicyDecision::Deny(DenyReason::RobotsUnavailable)
            }
        }

        // 10. PER-ENTRY REQUEST RATE.
        if !self
            .rate
            .try_admit(
                entry.id,
                entry.max_requests_per_minute,
                self.clock.now_unix_millis(),
            )
            .await
        {
            return PolicyDecision::Deny(DenyReason::EntryRateExceeded);
        }

        // 11. BUDGET PRECHECK.
        //
        // A PRECHECK, not the debit: the debit happens byte by byte as the body
        // flows (`fetch::BudgetSink`), because a check made only at admission
        // lets one large response blow through a spent operator's cap. What this
        // step buys is that a request which cannot possibly fit opens no socket
        // at all — and, more importantly, that an UNAVAILABLE ledger refuses
        // here rather than being discovered mid-transfer.
        let now_secs = self.clock.now_unix_millis() / 1_000;
        match self.budget.remaining_today(now_secs) {
            Ok(0) => return PolicyDecision::Deny(DenyReason::DailyCeilingExceeded),
            Ok(_) => {}
            Err(CapError::DailyCeilingReached) => {
                return PolicyDecision::Deny(DenyReason::DailyCeilingExceeded)
            }
            Err(CapError::OutsideSchedule) => {
                return PolicyDecision::Deny(DenyReason::ScheduleClosed)
            }
            // A ledger this process cannot read is a ceiling it cannot prove it
            // is under, and an unprovable ceiling is a refusal.
            Err(CapError::Unavailable(_)) => {
                return PolicyDecision::Deny(DenyReason::BudgetUnavailable)
            }
        }

        // 12. INDICATOR LIVENESS. Every egress is visible to the operator, so an
        // indicator nobody has refreshed inside its TTL closes egress rather
        // than letting traffic run unobserved.
        if !self.indicator.is_fresh(now_secs) {
            return PolicyDecision::Deny(DenyReason::IndicatorStale);
        }

        PolicyDecision::Allow {
            entry_id: pinned.entry_id,
            pinned_ip: pinned.ip,
            port: pinned.port,
        }
    }
}

/// Build the next request from a `Location` value.
///
/// A redirect is **not** a continuation of an approved request. This function
/// only parses; the result must be handed back to [`EgressPolicy::evaluate`],
/// which re-runs every check on it, including the allowlist.
///
/// Exactly two shapes are accepted, and anything else is a refusal rather than
/// a best-effort guess:
///
/// * an absolute `http`/`https` URL whose authority carries no `@`, no
///   whitespace and no control byte;
/// * a path beginning with **exactly one** `/`.
///
/// The "exactly one" is load-bearing: `//evil.example/x` is a protocol-relative
/// URL naming a different origin, and a parser that treats it as a path
/// silently rewrites the destination.
pub fn next_request(prev: &ProxyRequest, location: &str) -> Result<ProxyRequest, DenyReason> {
    if location.is_empty() || !location.is_ascii() {
        return Err(DenyReason::MalformedRedirectLocation);
    }
    if location.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(DenyReason::MalformedRedirectLocation);
    }

    let lowered = location.to_ascii_lowercase();

    // Origin-form path: exactly one leading slash.
    if location.starts_with('/') {
        if location.starts_with("//") {
            return Err(DenyReason::MalformedRedirectLocation);
        }
        return Ok(ProxyRequest {
            scheme: prev.scheme,
            method: prev.method.clone(),
            host: prev.host.clone(),
            port: prev.port,
            path_and_query: location.to_string(),
            hop: prev.hop.saturating_add(1),
        });
    }

    let (scheme, rest) = if let Some(r) = lowered.strip_prefix("https://") {
        (Scheme::Https, &location[location.len() - r.len()..])
    } else if let Some(r) = lowered.strip_prefix("http://") {
        (Scheme::Http, &location[location.len() - r.len()..])
    } else {
        // A recognisable scheme that is not one this node speaks gets its own
        // refusal, so `mailto:`/`file:`/`gopher:` do not read as "malformed".
        return Err(if has_uri_scheme(location) {
            DenyReason::RedirectSchemeNotAllowed
        } else {
            DenyReason::MalformedRedirectLocation
        });
    };

    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(DenyReason::MalformedRedirectLocation);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let parsed: u16 = p
                .parse()
                .map_err(|_| DenyReason::MalformedRedirectLocation)?;
            (h.to_string(), parsed)
        }
        None => (authority.to_string(), scheme.required_port()),
    };
    if host.is_empty() {
        return Err(DenyReason::MalformedRedirectLocation);
    }

    Ok(ProxyRequest {
        scheme,
        method: prev.method.clone(),
        host,
        port,
        path_and_query,
        hop: prev.hop.saturating_add(1),
    })
}

/// Does this string begin with a URI scheme (`scheme:`)?
fn has_uri_scheme(s: &str) -> bool {
    let Some(colon) = s.find(':') else {
        return false;
    };
    let scheme = &s[..colon];
    !scheme.is_empty()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// Is this path well formed **and** inside the entry's declared scope?
///
/// Prefix matching is not substring matching, and it is not matching against a
/// path anyone normalised. Any traversal segment — literal or percent-encoded —
/// is a refusal before the prefix is even considered, because the whole point of
/// a prefix is that what follows it cannot climb back out.
fn path_in_scope(entry: &AllowlistEntry, path_and_query: &str) -> bool {
    if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
        return false;
    }
    if !path_and_query.is_ascii()
        || path_and_query
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
    {
        return false;
    }

    let path = match path_and_query.find(['?', '#']) {
        Some(i) => &path_and_query[..i],
        None => path_and_query,
    };

    // Percent-encoded dot, slash and backslash: the same traversal, spelled so
    // a segment split cannot see it.
    let lowered = path.to_ascii_lowercase();
    for encoded in ["%2e", "%2f", "%5c"] {
        if lowered.contains(encoded) {
            return false;
        }
    }
    // Dot and dot-dot segments, and the empty segment an internal `//` makes.
    if path.contains("//") {
        return false;
    }
    for segment in path.split('/').skip(1) {
        if segment == "." || segment == ".." {
            return false;
        }
    }

    match entry.path_scope {
        PathScope::WholeOrigin => true,
        PathScope::Prefixes => entry.path_prefixes.iter().any(|p| {
            // `p` is guaranteed by `validate_entry` to start and end with `/`
            // and to be at least two bytes, so `/api/` matches `/api/v1` and
            // the directory itself, and never matches `/apifoo`.
            path.starts_with(p.as_str()) || path == p.trim_end_matches('/')
        }),
    }
}

fn validate_entry(w: WireEntry) -> Result<AllowlistEntry, PolicyError> {
    let corrupt = PolicyError::AllowlistCorrupt;

    if w.id == 0 {
        return Err(corrupt(
            "entry id 0 is reserved so that an uninitialised integer names no entry".into(),
        ));
    }

    let match_mode = match w.match_mode.as_str() {
        "exact" => MatchMode::Exact,
        other => return Err(corrupt(format!("unknown match_mode {other:?}"))),
    };

    // The host must be a name, not an address in any encoding, and not a name
    // carrying the FQDN root dot or upper case -- one spelling only, so the
    // exact match cannot be sidestepped by a second spelling that resolves the
    // same way.
    if w.host != w.host.to_ascii_lowercase() {
        return Err(corrupt(format!("host {:?} is not lower case", w.host)));
    }
    match parse_canonical_ip_literal(&w.host) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(corrupt(format!(
                "host {:?} is an IP literal; entries name hosts, and an address entry would \
                 bypass the resolve-and-pin step entirely",
                w.host
            )))
        }
        Err(e) => return Err(corrupt(format!("host {:?}: {e}", w.host))),
    }

    let path_scope = match w.path_scope.as_str() {
        "prefixes" => PathScope::Prefixes,
        "whole_origin" => PathScope::WholeOrigin,
        other => return Err(corrupt(format!("unknown path_scope {other:?}"))),
    };

    let mut path_prefixes = w.path_prefixes;
    for p in &path_prefixes {
        if !p.starts_with('/') || !p.ends_with('/') || p.len() < 2 {
            return Err(corrupt(format!(
                "path prefix {p:?} must start and end with '/' and be at least two bytes; \
                 a bare \"/\" is `whole_origin` spelled ambiguously"
            )));
        }
        if p.contains("//") || p.contains("..") || !p.is_ascii() {
            return Err(corrupt(format!("path prefix {p:?} is not a plain path")));
        }
    }
    if matches!(path_scope, PathScope::Prefixes) && path_prefixes.is_empty() {
        return Err(corrupt(format!(
            "entry {} declares prefix scope with no prefixes; an empty prefix list read as \
             \"matches everything\" is the fail-open shape this loader exists to refuse",
            w.id
        )));
    }
    // Sorted and deduplicated, so the digest does not depend on the order the
    // prefixes were written in.
    path_prefixes.sort();
    path_prefixes.dedup();

    if w.max_requests_per_minute == 0 {
        return Err(corrupt(format!(
            "entry {} has a zero request ceiling, which is a missing field read as a value",
            w.id
        )));
    }

    Ok(AllowlistEntry {
        id: w.id,
        host: w.host,
        match_mode,
        path_scope,
        path_prefixes,
        max_requests_per_minute: w.max_requests_per_minute,
    })
}

/// The exact bytes the OPERATOR-FACING allowlist digest is taken over.
///
/// # Founder ruling: the summary the human read is what the signature covers
///
/// This crate previously digested its own OPERATIONAL manifest — `id`, `host`,
/// `match_mode`, `path_scope`, `path_prefixes` and `max_requests_per_minute`,
/// under Keccak-256. The desktop, which is where the operator actually reads the
/// disclosure and signs, digested the summary it had shown them: `id` and `host`
/// only, under SHA-256. Two digests, one field in the signed record, and a
/// consent gate that refused every record the surface produced.
///
/// The founder ruled the **operator-facing summary digest authoritative on both
/// sides**, and the reasoning is recorded here because it decides what may be
/// changed without re-consenting every operator:
///
/// * A signature must cover **what the human read**. `match_mode`, `path_scope`,
///   `path_prefixes` and the per-entry rate appear nowhere in the disclosure, so
///   binding a signature to them binds it to text nobody was shown.
/// * Internal tuning must not silently invalidate signed consent. Raising a
///   per-entry rate ceiling or narrowing a path prefix is daemon operation, not
///   a change of scope the operator agreed to, and under the old digest each one
///   halted every node until every operator re-signed.
///
/// The trade this ruling accepts, stated plainly rather than hidden: the
/// operational fields are now **outside** the signed binding, so an edit to
/// `path_scope` or `path_prefixes` no longer refuses startup. What the operator
/// signed — and what the digest still binds exactly — is the set of
/// **destinations**, which is what the disclosure names.
///
/// # Second founder ruling: one static slug <-> id table, and both sides
/// serialise through it
///
/// The ruling above settled which digest is authoritative and left the two sides
/// still disagreeing about the DATA. The desktop names a destination by a
/// **slug**; [`AllowlistEntry::id`] is a **`u32`** that cannot become a string
/// without breaking every receipt, pinned target, robots cache key and log line
/// that carries it. The founder ruled that a canonical, static, one-to-one
/// mapping between the two exists in exactly one place — [`crate::destinations`]
/// — and that both sides serialise the destination list through it before
/// hashing.
///
/// So the construction is now, exactly:
///
/// [`destinations::CANONICAL_DIGEST_DOMAIN`], a newline, then for each
/// destination **sorted by the numeric id ascending**: the id in base ten,
/// `\u{1f}`, the **registered slug**, `\u{1f}`, the host, `\u{1e}`. No trailing
/// newline, no length prefixes.
///
/// Three things follow, and each is a test rather than a claim:
///
/// * **Neither side can skip the table.** This crate holds integers and must
///   look up a slug to produce the bytes; the desktop holds slugs and must look
///   up an integer. A mutation that dropped either lookup cannot reproduce the
///   pin.
/// * **An unresolvable identifier is a refusal.** These functions return
///   `Result`, and there is no path that hashes a zero id or an empty slug.
/// * **The sort is numeric.** A sort on the rendered id would order `10` before
///   `2` the moment the registry passes nine rows.
///
/// The separators still carry the weight that length prefixes would, and that is
/// safe only because no field can spell one: `validate_entry` refuses a host
/// that is not a well-formed ASCII name, the registry's slug charset is
/// `[a-z0-9-]`, an id renders as decimal digits, and
/// [`crate::destinations`]`::render` refuses a host carrying either separator
/// even when it arrives from the desktop's document rather than from this
/// loader.
pub fn operator_allowlist_preimage(entries: &[(&str, &str)]) -> Result<String, RegistryError> {
    destinations::canonical_preimage_by_slug(entries)
}

/// SHA-256 of [`operator_allowlist_preimage`]. **This is what consent binds.**
///
/// Taken over `(slug, host)` pairs rather than over [`AllowlistEntry`] values on
/// purpose: it is the seam the cross-language parity test drives with the
/// DESKTOP's own entries, whose ids are slugs. A digest function that could only
/// be handed this crate's own structs could only ever be compared against
/// itself.
pub fn operator_allowlist_digest(entries: &[(&str, &str)]) -> Result<[u8; 32], RegistryError> {
    destinations::canonical_digest_by_slug(entries)
}

/// The same digest over a loaded list, whose destinations are named by the
/// `u32` this daemon actually carries.
///
/// Fallible, and that is the point: an id the canonical registry does not know
/// produces **no digest at all**, so it cannot be loaded, rather than being
/// hashed under a zero or an empty slug and quietly disagreeing with the
/// desktop.
fn allowlist_digest(entries: &[AllowlistEntry]) -> Result<[u8; 32], RegistryError> {
    let pairs: Vec<(u32, &str)> = entries.iter().map(|e| (e.id, e.host.as_str())).collect();
    destinations::canonical_digest_by_id(&pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destinations::{RECORD_SEPARATOR, UNIT_SEPARATOR};
    use crate::resolve::{FixedResolver, SequencedResolver};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // -- helpers -----------------------------------------------------------

    /// A clock a test moves by hand.
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn new(ms: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(ms)))
        }
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_unix_millis(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn shipped_allowlist() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("allowlist.json")
    }

    fn public_resolver() -> Arc<dyn Resolver> {
        Arc::new(FixedResolver::new(vec!["93.184.216.34".parse().unwrap()]))
    }

    /// A robots fetcher that permits everything.
    ///
    /// A STUB, and named so. It is used only by the tests whose subject is not
    /// robots; INV-7's own control drives the real `HttpRobotsFetcher` against a
    /// fixture origin in `fetch.rs`, because a fail-closed argument asserted
    /// only against an allow-everything stub is not an argument.
    struct AllowAllRobots;

    #[async_trait::async_trait]
    impl crate::robots::RobotsFetcher for AllowAllRobots {
        async fn fetch(
            &self,
            _s: Scheme,
            _t: &crate::resolve::PinnedTarget,
        ) -> crate::robots::RobotsFetchOutcome {
            crate::robots::RobotsFetchOutcome::AllowAll
        }
    }

    /// One state directory for the whole test binary, removed when the process
    /// exits.
    ///
    /// Shared rather than per-test because nothing in this module DEBITS the
    /// ledger — `evaluate` only prechecks — so there is no cross-test
    /// interference to isolate, and a per-test `TempDir` would have to be leaked
    /// to outlive the policy that holds its path.
    fn state_dir() -> &'static Path {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"))
            .path()
    }

    /// The three seams, wired for a test that is not about any of them.
    ///
    /// The indicator is stamped with **this policy's own clock**, not with the
    /// wall clock: several tests below drive a `ManualClock` starting near zero,
    /// and a wall-clock stamp would read as a stamp from the future and close
    /// egress in every one of them.
    fn seams(clock: &dyn Clock) -> (Arc<RobotsCache>, Arc<EgressLedger>, Arc<Indicator>) {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let budget = Arc::new(EgressLedger::new(
            state_dir().join(format!("egress-{n}.json")),
            crate::caps::DEFAULT_DAILY_BYTE_CAP,
            crate::caps::TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        ));
        let indicator = Arc::new(Indicator::new());
        indicator.set_live(true, clock.now_unix_millis() / 1_000);
        (
            Arc::new(RobotsCache::new(Box::new(AllowAllRobots))),
            budget,
            indicator,
        )
    }

    fn shipped_policy() -> EgressPolicy {
        policy_with(public_resolver(), Arc::new(SystemClock))
    }

    fn policy_with(resolver: Arc<dyn Resolver>, clock: Arc<dyn Clock>) -> EgressPolicy {
        let (entries, digest) =
            EgressPolicy::load_entries(&shipped_allowlist()).expect("shipped list loads");
        let (robots, budget, indicator) = seams(&*clock);
        EgressPolicy::new(entries, digest, resolver, robots, budget, indicator, clock)
    }

    fn get(host: &str, port: u16, path: &str) -> ProxyRequest {
        ProxyRequest {
            scheme: if port == 80 {
                Scheme::Http
            } else {
                Scheme::Https
            },
            method: Method::Get,
            host: host.to_string(),
            port,
            path_and_query: path.to_string(),
            hop: 0,
        }
    }

    /// A request the shipped list allows, used as the positive control
    /// everywhere a refusal is asserted.
    fn allowed_request() -> ProxyRequest {
        get("example.com", 443, "/data/report.json")
    }

    fn write_temp(name: &str, body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        fs::write(&path, body).expect("write fixture");
        (dir, path)
    }

    fn valid_list_body() -> String {
        r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes",
             "path_prefixes":["/data/"],"max_requests_per_minute":5}]}"#
            .to_string()
    }

    // -- source sweep ------------------------------------------------------

    fn production_sources() -> Vec<(String, String)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths = Vec::new();
        collect_rs(&dir, &mut paths);
        paths.sort();
        paths
            .into_iter()
            .map(|p| {
                let text = fs::read_to_string(&p).expect("read source");
                let name = p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string();
                // Strip only the TRAILING test module. Stripping from the first
                // `#[cfg(test)]` would blank most of a file whose helpers sit
                // near the top while leaving the file count unchanged.
                let marker = "\n#[cfg(test)]\nmod tests {";
                let prod = match text.rfind(marker) {
                    Some(i) => text[..i].to_string(),
                    None => text,
                };
                (name, prod)
            })
            .collect()
    }

    fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// Raised in the same commit as the task that adds the next source file.
    /// An exact assertion, not a `>=`: a `>=` floor written for the finished
    /// crate is unsatisfiable in the task that introduces the sweep, and an
    /// implementer who meets a red floor by lowering it has deleted the guard.
    ///
    /// 11 -> 16 across Tasks 34-35: `logging.rs`, `supervisor.rs`,
    /// `vocabulary_audit.rs` and `main.rs` land in Task 34 and `meter.rs` in
    /// Task 35. 16 -> 17 with `destinations.rs`, which carries the canonical
    /// slug <-> id table the second founder ruling requires.
    const WORKER_SRC_FILES_AT_THIS_TASK: usize = 17;
    /// Measured 224_788 bytes of production text across those sixteen files
    /// after Tasks 34-35. The floor sits below that measurement and **above the
    /// largest single file** (policy.rs, 39_422), so a truncating pre-filter
    /// that blanked even the biggest one is caught here rather than reported as
    /// a clean sweep. Raise it with the crate.
    const MIN_SWEPT_PRODUCTION_BYTES: usize = 170_000;

    // -- INV-1: fail closed by construction --------------------------------

    /// Mutations this detects: `read_to_string(..).unwrap_or_default()`, which
    /// turns an absent list into an empty one; or mapping `NotFound` onto
    /// `AllowlistEmpty`, which loses the operator's actual problem.
    #[test]
    fn absent_allowlist_refuses_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("not-here.json");
        assert_eq!(
            EgressPolicy::load_entries(&missing).expect_err("absent must refuse"),
            PolicyError::AllowlistAbsent
        );
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let (robots, budget, indicator) = seams(&*clock);
        assert!(EgressPolicy::load(
            &missing,
            public_resolver(),
            robots,
            budget,
            indicator,
            clock
        )
        .is_err());

        // POSITIVE CONTROL: the same loader, given a real file, succeeds.
        let (_g, ok) = write_temp("allowlist.json", &valid_list_body());
        assert!(EgressPolicy::load_entries(&ok).is_ok());
    }

    /// Mutations this detects: `Ok((vec![], digest))` for an empty `entries`
    /// array. An empty-but-running policy is the failure mode this whole crate
    /// is built to refuse -- it reads as "configured" and permits nothing while
    /// looking like it permits by rule.
    #[test]
    fn empty_allowlist_refuses_to_load() {
        for body in [
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","note":"none","entries":[]}"#,
        ] {
            let (_g, path) = write_temp("allowlist.json", body);
            assert_eq!(
                EgressPolicy::load_entries(&path).expect_err("empty must refuse"),
                PolicyError::AllowlistEmpty,
                "body {body}"
            );
        }

        // POSITIVE CONTROL: one entry is enough to load.
        let (_g, ok) = write_temp("allowlist.json", &valid_list_body());
        assert_eq!(EgressPolicy::load_entries(&ok).expect("loads").0.len(), 1);
    }

    /// Both corruption shapes, separately.
    ///
    /// Mutations this detects: a `serde_json::from_str::<Value>` check in place
    /// of typed deserialisation, which accepts every valid-JSON-wrong-schema
    /// document; `#[serde(default)]` on `entries`, which turns a missing key
    /// into an empty list; dropping `deny_unknown_fields`, under which
    /// `"path_prefix"` (singular) is silently ignored and the entry loads with
    /// no scope.
    #[test]
    fn corrupt_allowlist_refuses_startup() {
        let truncated = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"#;
        let wrong_schema = [
            // Valid JSON, wrong shape -- the class a `Value` check misses.
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":"everything"}"#,
            r#"[{"id":1,"host":"example.com"}]"#,
            r#"{"entries":[]}"#,
            r#"{"schema_id":"SOMETHING_ELSE_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1}]}"#,
            // An unknown key, which is how a typo widens an entry silently.
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1,"allow_everything":true}]}"#,
            // Entry-level refusals.
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":0,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"169.254.169.254","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"EXAMPLE.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"suffix","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":[],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/../b/"],"max_requests_per_minute":1}]}"#,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/a/"],"max_requests_per_minute":0}]}"#,
        ];

        let (_g, path) = write_temp("allowlist.json", truncated);
        assert!(
            matches!(
                EgressPolicy::load_entries(&path),
                Err(PolicyError::AllowlistCorrupt(_))
            ),
            "truncated JSON must refuse as corrupt"
        );

        for body in wrong_schema {
            let (_g, path) = write_temp("allowlist.json", body);
            assert!(
                matches!(
                    EgressPolicy::load_entries(&path),
                    Err(PolicyError::AllowlistCorrupt(_))
                ),
                "must refuse as corrupt: {body}"
            );
        }

        // POSITIVE CONTROL: the loader is not simply refusing everything.
        let (_g, ok) = write_temp("allowlist.json", &valid_list_body());
        assert!(EgressPolicy::load_entries(&ok).is_ok());
    }

    /// Mutations this detects: the id collision check written as a `HashSet`
    /// insert whose return value is discarded, so the later entry silently wins
    /// and every receipt naming that id is ambiguous.
    #[test]
    fn duplicate_entry_ids_refuse_to_load() {
        let body = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":4,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":1},
            {"id":4,"host":"b.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/y/"],"max_requests_per_minute":1}]}"#;
        let (_g, path) = write_temp("allowlist.json", body);
        assert!(matches!(
            EgressPolicy::load_entries(&path),
            Err(PolicyError::AllowlistCorrupt(m)) if m.contains("duplicate entry id 4")
        ));

        // The same, for a duplicated host under two ids: two entries naming one
        // destination make the entry id in a receipt non-deterministic.
        let dup_host = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":4,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":1},
            {"id":5,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/y/"],"max_requests_per_minute":1}]}"#;
        let (_g, path) = write_temp("allowlist.json", dup_host);
        assert!(matches!(
            EgressPolicy::load_entries(&path),
            Err(PolicyError::AllowlistCorrupt(_))
        ));

        // POSITIVE CONTROL: distinct ids and hosts load.
        let (_g, ok) = write_temp(
            "allowlist.json",
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":4,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":1},
            {"id":5,"host":"b.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/y/"],"max_requests_per_minute":1}]}"#,
        );
        assert_eq!(EgressPolicy::load_entries(&ok).expect("loads").0.len(), 2);
    }

    /// INV-1's runtime half.
    ///
    /// Mutations this detects: an `evaluate` that returns `Allow` when the entry
    /// list is empty -- the "degrade to allow-all" failure this design refuses
    /// to have a code path for.
    #[tokio::test]
    async fn empty_allowlist_refuses_every_request_and_opens_zero_sockets() {
        // The loader cannot produce this state, so it is built by hand: the
        // property must hold even if some future path constructs one.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let (robots, budget, indicator) = seams(&*clock);
        let policy = EgressPolicy::new(
            Vec::new(),
            [0u8; 32],
            public_resolver(),
            robots,
            budget,
            indicator,
            clock,
        );

        for req in [
            allowed_request(),
            get("example.org", 443, "/api/v1/x"),
            get("research.example.net", 80, "/open-data/y"),
        ] {
            assert_eq!(
                policy.evaluate(&req).await,
                PolicyDecision::Deny(DenyReason::HostNotAllowlisted),
                "an empty allowlist permitted {}",
                req.host
            );
        }

        // POSITIVE CONTROL: the SAME request against the shipped list is
        // allowed, so the loop above is not passing against a policy that
        // refuses unconditionally.
        assert!(matches!(
            policy_with(public_resolver(), Arc::new(SystemClock))
                .evaluate(&allowed_request())
                .await,
            PolicyDecision::Allow { .. }
        ));
    }

    // -- INV-6: the port gate ---------------------------------------------

    /// Mutations this detects: 8080 or 8443 added "for convenience"; the array
    /// widened to a range.
    #[test]
    fn allowed_ports_is_exactly_eighty_and_four_four_three() {
        assert_eq!(ALLOWED_PORTS, [80u16, 443u16]);
        assert_eq!(ALLOWED_PORTS.len(), 2, "port gate must not grow silently");
    }

    /// Mutations this detects: the port check inverted, or moved after the
    /// resolve step so a socket is opened before the port is judged.
    #[tokio::test]
    async fn non_web_ports_refused() {
        let policy = shipped_policy();
        for port in [22u16, 25, 53, 465, 587, 3389, 6881, 6889, 8080, 9050] {
            let mut req = allowed_request();
            req.port = port;
            assert_eq!(
                policy.evaluate(&req).await,
                PolicyDecision::Deny(DenyReason::PortNotAllowed),
                "port {port} was not refused"
            );
        }

        // NEGATIVE CONTROL: 80 and 443 pass. Without this the loop above also
        // passes against a policy that refuses every port.
        for (port, scheme) in [(80u16, Scheme::Http), (443u16, Scheme::Https)] {
            let mut req = allowed_request();
            req.port = port;
            req.scheme = scheme;
            assert!(
                matches!(policy.evaluate(&req).await, PolicyDecision::Allow { .. }),
                "port {port} must pass the gate"
            );
        }
    }

    /// Mutations this detects: the scheme/port coupling deleted, so a request
    /// naming one scheme and the other's port is handled by whichever half
    /// reads the field last.
    #[tokio::test]
    async fn a_scheme_that_disagrees_with_its_port_is_refused() {
        let policy = shipped_policy();
        for (scheme, port) in [(Scheme::Http, 443u16), (Scheme::Https, 80u16)] {
            let mut req = allowed_request();
            req.scheme = scheme;
            req.port = port;
            assert_eq!(
                policy.evaluate(&req).await,
                PolicyDecision::Deny(DenyReason::SchemeNotAllowed)
            );
        }
        // POSITIVE CONTROL: the agreeing pairs pass.
        assert_eq!(Scheme::Http.required_port(), 80);
        assert_eq!(Scheme::Https.required_port(), 443);
    }

    // -- INV-5: no opaque relay -------------------------------------------

    /// INV-5's source and type halves.
    ///
    /// Mutations this detects: a variant for the opaque-tunnel method added to
    /// `Method`; a bidirectional copy or a listening socket introduced into
    /// production code; the method name appearing in a string literal that some
    /// dispatcher could match on.
    #[test]
    fn the_tunnelling_method_does_not_exist_in_the_enum() {
        // Assembled at runtime so this file does not itself contain the tokens
        // it forbids in production text.
        //
        // The METHOD NAME is matched as a WHOLE WORD and the API names as
        // substrings, and the split is deliberate rather than a loosening. The
        // TLS dialler type in `fetch.rs` is spelled `TlsConn` + `ector`, which
        // contains the method name as a prefix and has nothing to do with
        // proxy tunnelling; a substring rule would either fail on it forever or
        // be "fixed" by carving `fetch.rs` out of the sweep — and a carve-out is
        // how a check stops checking the one file it exists for. A whole-word
        // rule still catches every way the method could actually be named: an
        // enum variant, a match arm, a string literal, a request line.
        let forbidden_words = [
            format!("{}{}", "CONN", "ECT"),
            format!("{}{}", "Conn", "ect"),
        ];
        let forbidden_substrings = [
            format!("{}{}", "copy_bi", "directional"),
            format!("{}{}", "Tcp", "Listener"),
            format!("{}{}", "Udp", "Socket"),
        ];

        /// A whole-word match: the token, not flanked by an identifier
        /// character on either side.
        fn names_word(text: &str, token: &str) -> bool {
            let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
            let mut from = 0usize;
            while let Some(i) = text[from..].find(token) {
                let at = from + i;
                let before_ok = text[..at].chars().next_back().is_none_or(|c| !ident(c));
                let after_ok = text[at + token.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !ident(c));
                if before_ok && after_ok {
                    return true;
                }
                from = at + token.len();
            }
            false
        }

        // POSITIVE CONTROL: the scanner sees every token in a string that has
        // them. A scanner with too small an alphabet reports a clean sweep.
        for token in &forbidden_words {
            let control = format!("let m = Method::{token}(x); \"{token}\" => 405,");
            assert!(
                names_word(&control, token),
                "the word scanner cannot see {token} in its own control string"
            );
        }
        let sub_control = forbidden_substrings.join(" ");
        for token in &forbidden_substrings {
            assert!(
                sub_control.contains(token.as_str()),
                "the substring scanner cannot see {token} in its own control string"
            );
        }
        // NEGATIVE CONTROL for the word scanner: it must NOT fire on the TLS
        // dialler type, and it must still fire on the bare word beside it.
        let dialler = format!("{}{}{}", "Tls", "Conn", "ector::from(config)");
        for token in &forbidden_words {
            assert!(
                !names_word(&dialler, token),
                "the word scanner fires on {dialler}, which is not the tunnelling method"
            );
        }
        assert!(names_word(
            &format!("{} {}", dialler, forbidden_words[1]),
            &forbidden_words[1]
        ));

        let sources = production_sources();
        assert_eq!(
            sources.len(),
            WORKER_SRC_FILES_AT_THIS_TASK,
            "swept {} file(s); raise WORKER_SRC_FILES_AT_THIS_TASK in the commit that adds one",
            sources.len()
        );
        let total: usize = sources.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total >= MIN_SWEPT_PRODUCTION_BYTES,
            "swept only {total} byte(s) of production text; the sweep is reading almost nothing"
        );

        for (name, text) in &sources {
            for token in &forbidden_words {
                assert!(
                    !names_word(text, token),
                    "{name} names {token} in production code; this node terminates as an HTTP \
                     client and is never an opaque relay"
                );
            }
            for token in &forbidden_substrings {
                assert!(
                    !text.contains(token.as_str()),
                    "{name} names {token} in production code; this node terminates as an HTTP \
                     client and is never an opaque relay"
                );
            }
        }

        // The type-level fact: four variants, exhaustively matched.
        fn index(m: &Method) -> usize {
            match m {
                Method::Get => 0,
                Method::Head => 1,
                Method::Post => 2,
                Method::Other(_) => 3,
            }
        }
        let all = [
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Other("X".into()),
        ];
        let mut seen: Vec<usize> = all.iter().map(index).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen,
            vec![0, 1, 2, 3],
            "Method must have exactly four variants"
        );
    }

    /// The runtime half: such a request is refused, and nothing was dialled.
    ///
    /// Mutations this detects: `Method::Other(_)` falling through to `Allow`;
    /// the method check moved after the resolve step, which would resolve and
    /// pin a destination for a request that is refused anyway.
    #[tokio::test]
    async fn the_tunnelling_method_is_refused_and_relays_zero_bytes() {
        // A resolver with NO answers queued: if evaluation reached the resolve
        // step it would consume one and this assertion at the end would fail.
        let resolver = Arc::new(SequencedResolver::new(vec![vec!["93.184.216.34"
            .parse()
            .unwrap()]]));
        let policy = policy_with(resolver.clone(), Arc::new(SystemClock));

        let mut req = allowed_request();
        req.method = Method::Other(format!("{}{}", "CONN", "ECT"));
        let decision = policy.evaluate(&req).await;

        assert_eq!(decision, PolicyDecision::Deny(DenyReason::MethodNotAllowed));
        assert_eq!(
            decision.pinned_socket_addr(),
            None,
            "a refusal must carry no dial target, so no byte can be relayed"
        );
        assert_eq!(
            resolver.remaining(),
            1,
            "the request was refused BEFORE resolution; nothing was looked up and nothing dialled"
        );

        // A body-bearing method is refused too, with its own reason.
        let mut post = allowed_request();
        post.method = Method::Post;
        assert_eq!(
            policy.evaluate(&post).await,
            PolicyDecision::Deny(DenyReason::RequestBodyNotPermitted)
        );

        // POSITIVE CONTROL: GET and HEAD are admitted, and the queued answer is
        // then consumed -- proving the resolver seam works and the assertion
        // above measured a real absence.
        let mut head = allowed_request();
        head.method = Method::Head;
        assert!(matches!(
            policy.evaluate(&head).await,
            PolicyDecision::Allow { .. }
        ));
        assert_eq!(resolver.remaining(), 0);
    }

    // -- INV-7: path scope --------------------------------------------------

    /// Mutations this detects: `path.contains(prefix)` in place of
    /// `starts_with`; any normalisation of `..` before matching; the
    /// percent-encoded traversal forms not being considered.
    #[tokio::test]
    async fn path_scope_prefix_match_is_not_substring_match() {
        let policy = shipped_policy();
        for path in [
            "/x/../admin",
            "//admin",
            "/api/v1/../../admin",
            "/data/../admin",
            "/data/%2e%2e/admin",
            "/data/./admin",
            "/admin/data/",    // the prefix as a substring, not a prefix
            "/datafoo/report", // the prefix without its trailing slash
            "/admin",
            "/data\\admin",
        ] {
            let req = get("example.com", 443, path);
            assert_eq!(
                policy.evaluate(&req).await,
                PolicyDecision::Deny(DenyReason::PathOutOfScope),
                "path {path:?} must be out of scope"
            );
        }

        // POSITIVE CONTROL: paths inside the declared prefix are allowed,
        // including the directory itself and a query string.
        for path in ["/data/", "/data", "/data/report.json", "/data/a/b?q=1"] {
            let req = get("example.com", 443, path);
            assert!(
                matches!(policy.evaluate(&req).await, PolicyDecision::Allow { .. }),
                "path {path:?} must be in scope"
            );
        }
    }

    // -- the digest --------------------------------------------------------

    /// The founder ruling, expressed as the two things the digest must do: move
    /// when a DESTINATION moves, and hold still when only daemon operation
    /// changes.
    ///
    /// Both halves are asserted, and the second half is the new one — under the
    /// retired operational-manifest hash a path-prefix edit moved the digest and
    /// halted every node until every operator re-signed.
    ///
    /// Mutations this detects: a digest computed over the file bytes (which
    /// changes with whitespace and key order and is therefore not a digest of
    /// the *list*); the operational fields folded back into the preimage, which
    /// re-breaks signed consent on a rate-limit edit; the host or the id dropped
    /// from the preimage, which is the far worse direction — a swapped
    /// destination would then verify against a record naming the old one.
    #[test]
    fn the_allowlist_digest_binds_the_destinations_and_not_the_daemon_tuning() {
        let base = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":1,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":5},
            {"id":2,"host":"b.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/y/"],"max_requests_per_minute":7}]}"#;
        let (_g, p) = write_temp("allowlist.json", base);
        let (_e, d0) = EgressPolicy::load_entries(&p).expect("loads");

        // ORDER INDEPENDENCE: the same two entries, written the other way
        // round, digest identically.
        let reordered = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":2,"host":"b.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/y/"],"max_requests_per_minute":7},
            {"id":1,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":5}]}"#;
        let (_g, p) = write_temp("allowlist.json", reordered);
        let (_e, d_reordered) = EgressPolicy::load_entries(&p).expect("loads");
        assert_eq!(d0, d_reordered, "the digest must not depend on entry order");

        // Whitespace and key order in the FILE must not move it either.
        let respaced = base.replace('\n', "").replace("            ", " ");
        let (_g, p) = write_temp("allowlist.json", &respaced);
        let (_e, d_respaced) = EgressPolicy::load_entries(&p).expect("loads");
        assert_eq!(d0, d_respaced);

        // WHAT THE OPERATOR READ. Each mutation changes exactly one of the two
        // fields the disclosure shows, and each must move the digest.
        let destination_edits = [
            base.replace("\"id\":2", "\"id\":3"),
            base.replace("b.example.com", "c.example.com"),
            // An added destination.
            base.replace(
                "\"max_requests_per_minute\":7}]",
                "\"max_requests_per_minute\":7},{\"id\":9,\"host\":\"d.example.com\",\"match_mode\":\"exact\",\"path_scope\":\"prefixes\",\"path_prefixes\":[\"/w/\"],\"max_requests_per_minute\":1}]",
            ),
            // A removed destination.
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
            {"id":1,"host":"a.example.com","match_mode":"exact","path_scope":"prefixes","path_prefixes":["/x/"],"max_requests_per_minute":5}]}"#
                .to_string(),
        ];
        for (i, body) in destination_edits.iter().enumerate() {
            assert_ne!(body.as_str(), base, "edit {i} did not change the source");
            let (_g, p) = write_temp("allowlist.json", body);
            let (_e, d) = EgressPolicy::load_entries(&p).expect("edit loads");
            assert_ne!(d, d0, "destination edit {i} did not move the digest");
        }

        // WHAT THE OPERATOR WAS NEVER SHOWN. Each of these is daemon operation,
        // and none of them may invalidate a signature.
        let operational_edits = [
            base.replace("\"/y/\"", "\"/z/\""),
            base.replace(
                "\"max_requests_per_minute\":7",
                "\"max_requests_per_minute\":8",
            ),
            base.replace(
                "\"path_scope\":\"prefixes\",\"path_prefixes\":[\"/y/\"]",
                "\"path_scope\":\"whole_origin\",\"path_prefixes\":[\"/y/\"]",
            ),
            // Two prefixes written in the other order: the same scope, and the
            // loader's sort is what makes it the same bytes.
            base.replace(
                "\"path_prefixes\":[\"/y/\"]",
                "\"path_prefixes\":[\"/q/\",\"/y/\"]",
            ),
        ];
        for (i, body) in operational_edits.iter().enumerate() {
            assert_ne!(body.as_str(), base, "edit {i} did not change the source");
            let (_g, p) = write_temp("allowlist.json", body);
            let (entries, d) = EgressPolicy::load_entries(&p).expect("edit loads");
            assert_eq!(
                d, d0,
                "operational edit {i} moved the digest and would invalidate signed consent"
            );
            // POSITIVE CONTROL on the edit itself: the LOADED LIST really did
            // change, so the equality above is not two identical inputs
            // agreeing.
            let (_g2, p2) = write_temp("allowlist.json", base);
            let (base_entries, _) = EgressPolicy::load_entries(&p2).expect("base loads");
            assert_ne!(
                entries, base_entries,
                "operational edit {i} did not change the loaded list at all"
            );
        }

        // A digest is 32 bytes and is not all zeroes.
        assert_eq!(d0.len(), 32);
        assert_ne!(d0, [0u8; 32]);
    }

    /// THE cross-language pin, and the whole point of the ruling.
    ///
    /// It reads the DESKTOP's own policy document and the DESKTOP's own pinned
    /// fixture, hands this crate's [`operator_allowlist_digest`] the entries out
    /// of the first, and asserts it reproduces the second. Neither input is
    /// produced by this crate, so nothing here can drift into agreeing with
    /// itself: a test that recomputed the expected value with the same function
    /// would pass against any algorithm at all, including a wrong one adopted on
    /// both sides.
    ///
    /// `include_str!` rather than a runtime read, so a moved or renamed pin is a
    /// compile error in this crate rather than a test that quietly skips.
    ///
    /// Mutations this detects: any edit to the domain string, either separator,
    /// the sort, the field set, or the hash function; the digest switched back to
    /// Keccak-256; the id or the host dropped; a trailing newline added to the
    /// preimage.
    #[test]
    fn the_allowlist_digest_reproduces_the_desktop_pin() {
        const DESKTOP_POLICY: &str = include_str!("../../../desktop/src/proxy/policy.v1.json");
        const DESKTOP_FIXTURE: &str =
            include_str!("../../../desktop/src/proxy/fixtures/policy-digest.json");

        let doc: serde_json::Value =
            serde_json::from_str(DESKTOP_POLICY).expect("the desktop policy document is malformed");
        let fixture: serde_json::Value =
            serde_json::from_str(DESKTOP_FIXTURE).expect("the desktop fixture is malformed");

        let list = doc["allowlist"]
            .as_array()
            .expect("the desktop document must carry an allowlist array");
        assert_eq!(
            list.len(),
            5,
            "the desktop list changed shape; read this test before re-pinning anything"
        );
        let owned: Vec<(String, String)> = list
            .iter()
            .map(|e| {
                (
                    e["id"].as_str().expect("entry id").to_string(),
                    e["host"].as_str().expect("entry host").to_string(),
                )
            })
            .collect();
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();

        let pinned = fixture["allowlist_digest"]
            .as_str()
            .expect("the fixture must pin an allowlist digest");
        assert_eq!(
            pinned.len(),
            64,
            "the pin is not a 32-byte digest in hex: {pinned}"
        );
        assert_eq!(
            hex::encode(operator_allowlist_digest(&pairs).expect("the desktop's slugs resolve")),
            pinned,
            "this crate's operator-facing digest disagrees with the desktop's pin"
        );

        // THE SAME PIN, REACHED FROM THE OTHER END OF THE TABLE. This is the
        // second founder ruling's whole claim: the sidecar holds `u32` ids, the
        // desktop holds slugs, and both land on one digest. The ids here come
        // from the canonical registry, so a table edit that renumbered a slug
        // moves this line and the line above together — and neither of them is
        // this crate recomputing its own answer, because the pin is the
        // desktop's file.
        let by_id: Vec<(u32, &str)> = owned
            .iter()
            .map(|(slug, host)| {
                (
                    crate::destinations::id_for_slug(slug).expect("a desktop slug is registered"),
                    host.as_str(),
                )
            })
            .collect();
        assert_eq!(
            hex::encode(
                crate::destinations::canonical_digest_by_id(&by_id).expect("the ids resolve")
            ),
            pinned,
            "naming the desktop's destinations by their registered u32 did not reproduce the pin"
        );

        // ORDER INDEPENDENCE, proved against the PIN rather than against a
        // second call to this function.
        let mut backwards = pairs.clone();
        backwards.reverse();
        assert_eq!(
            hex::encode(operator_allowlist_digest(&backwards).expect("resolves")),
            pinned
        );

        // NEGATIVE CONTROL: one edited host and the pin no longer holds. Without
        // it, a digest function that returned a constant would pass everything
        // above.
        let mut swapped = owned.clone();
        swapped[0].1 = "elsewhere.example".to_string();
        let swapped_pairs: Vec<(&str, &str)> = swapped
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_ne!(
            hex::encode(operator_allowlist_digest(&swapped_pairs).expect("resolves")),
            pinned,
            "a swapped destination reproduced the desktop's pin"
        );
        // ...and an edited SLUG is now a REFUSAL rather than a different digest,
        // which is the stronger answer: a destination the canonical table does
        // not name cannot be hashed at all.
        let mut renamed = owned.clone();
        renamed[0].0 = format!("{}-2", renamed[0].0);
        let renamed_pairs: Vec<(&str, &str)> = renamed
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert!(
            matches!(
                operator_allowlist_digest(&renamed_pairs),
                Err(RegistryError::UnknownSlug(_))
            ),
            "an unregistered slug produced a digest instead of a refusal"
        );
        // ...and so is a destination renumbered to an id nobody registered.
        let past_the_end = crate::destinations::registry()
            .expect("registry")
            .rows()
            .len() as u32
            + 1;
        let mut renumbered = by_id.clone();
        renumbered[0].0 = past_the_end;
        assert!(matches!(
            crate::destinations::canonical_digest_by_id(&renumbered),
            Err(RegistryError::UnknownId(_))
        ));

        // The preimage's shape, so a reader can see what was hashed without
        // running a hash: domain, newline, then one THREE-FIELD record per
        // entry — the id, the registered slug, and the host.
        let pre = operator_allowlist_preimage(&pairs).expect("resolves");
        assert!(pre.starts_with("GOAT-PROXY-ALLOWLIST-v2\n"));
        assert_eq!(pre.matches(RECORD_SEPARATOR).count(), list.len());
        assert_eq!(pre.matches(UNIT_SEPARATOR).count(), 2 * list.len());
        assert!(pre.ends_with(RECORD_SEPARATOR));
        for (slug, host) in &owned {
            let id = crate::destinations::id_for_slug(slug).expect("registered");
            assert!(
                pre.contains(&format!(
                    "{id}{UNIT_SEPARATOR}{slug}{UNIT_SEPARATOR}{host}{RECORD_SEPARATOR}"
                )),
                "the preimage does not carry {slug} as an id/slug/host record"
            );
        }
    }

    /// An allowlist naming a destination the canonical registry does not carry
    /// refuses to load. It does not load with a zero, an empty slug, or a digest
    /// only this daemon can reproduce.
    ///
    /// This is the sidecar half of the founder ruling's fourth requirement; the
    /// desktop half — an unknown SLUG — is asserted in
    /// [`crate::destinations`]'s own tests and in the desktop's JavaScript
    /// mirror test.
    ///
    /// Mutations this detects: `allowlist_digest(..).unwrap_or([0u8; 32])`,
    /// which starts a daemon whose digest matches no consent record and whose
    /// operator is told nothing; the registry lookup skipped entirely so the
    /// preimage carries the integer twice; `load_entries` swallowing the
    /// registry error and returning the entries anyway.
    #[test]
    fn an_allowlist_naming_an_unregistered_destination_refuses_to_load() {
        let registered = destinations::registry().expect("registry").rows().len() as u32;
        let past_the_end = registered + 1;

        let body = format!(
            r#"{{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{{"id":{past_the_end},
               "host":"a.example.com","match_mode":"exact","path_scope":"whole_origin",
               "path_prefixes":[],"max_requests_per_minute":1}}]}}"#
        );
        let (_g, p) = write_temp("allowlist.json", &body);
        let err = EgressPolicy::load_entries(&p).expect_err("an unregistered id must refuse");
        match err {
            PolicyError::AllowlistCorrupt(m) => assert!(
                m.contains("canonical") && m.contains(&past_the_end.to_string()),
                "the refusal does not name the problem: {m}"
            ),
            other => panic!("expected a corrupt-list refusal, got {other:?}"),
        }

        // POSITIVE CONTROL: the same list under a REGISTERED id loads, so the
        // refusal above is about the registry and not about the body.
        let ok = body.replace(
            &format!(r#""id":{past_the_end}"#),
            &format!(r#""id":{registered}"#),
        );
        assert_ne!(ok, body, "the control edit changed nothing");
        let (_g, p) = write_temp("allowlist.json", &ok);
        let (entries, digest) = EgressPolicy::load_entries(&p).expect("a registered id must load");
        assert_eq!(entries.len(), 1);
        assert_ne!(digest, [0u8; 32]);

        // ...and the digest it loaded with is the CANONICAL one, reached from
        // the slug end of the table. If the loader had produced its own bytes,
        // this would not hold.
        let slug = destinations::slug_for_id(registered).expect("registered");
        assert_eq!(
            digest,
            destinations::canonical_digest_by_slug(&[(slug, "a.example.com")]).expect("resolves"),
            "the loaded digest is not the canonical one"
        );
    }

    /// Why the unprefixed preimage is safe: no field can contain either
    /// separator.
    ///
    /// The retired manifest digest length-prefixed every line, which made
    /// collisions impossible by construction. The desktop's preimage does not,
    /// and adopting it means the separator argument has to be an assertion
    /// rather than a hope.
    ///
    /// Mutations this detects: the host validator relaxed to permit control
    /// bytes, which would let one list be spelled two ways and two lists digest
    /// alike.
    #[test]
    fn separator_free_fields_are_what_makes_the_unprefixed_preimage_safe() {
        // A host carrying either separator refuses to LOAD, so it can never
        // reach the preimage.
        for escaped in ["a\\u001fb.example.com", "a\\u001eb.example.com"] {
            let body = format!(
                r#"{{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{{"id":1,"host":"{escaped}",
                   "match_mode":"exact","path_scope":"whole_origin","path_prefixes":[],
                   "max_requests_per_minute":1}}]}}"#
            );
            let (_g, p) = write_temp("allowlist.json", &body);
            assert!(
                matches!(
                    EgressPolicy::load_entries(&p),
                    Err(PolicyError::AllowlistCorrupt(_))
                ),
                "a host carrying a preimage separator loaded: {escaped}"
            );
        }
        // POSITIVE CONTROL: the same shape with an ordinary host does load, so
        // the refusals above are about the separator and not about the body.
        let ok = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,"host":"ab.example.com",
           "match_mode":"exact","path_scope":"whole_origin","path_prefixes":[],
           "max_requests_per_minute":1}]}"#;
        let (_g, p) = write_temp("allowlist.json", ok);
        let (entries, _) = EgressPolicy::load_entries(&p).expect("an ordinary host must load");

        // An id renders as decimal digits and nothing else.
        for e in &entries {
            let rendered = e.id.to_string();
            assert!(rendered.bytes().all(|b| b.is_ascii_digit()), "{rendered}");
        }

        // ...and the THIRD field, the registered slug, is drawn from a charset
        // that excludes both separators as well. Three fields now, not two.
        for d in destinations::registry().expect("registry").rows() {
            assert!(d
                .slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
        }

        // THE COLLISION IS REAL, and this is the assertion that says so out
        // loud rather than assuming it away: a two-record preimage and a
        // one-record preimage whose single host carries the separators are the
        // SAME BYTES, because the preimage has no length prefixes. What makes it
        // unreachable is the loader above and the render-time host check, not
        // the hash.
        //
        // Stated as an equality on purpose. An `assert_ne!` here would be a
        // claim the construction cannot support, and it would pass only until
        // somebody wrote the colliding pair correctly.
        let two = operator_allowlist_preimage(&[
            ("documentation-example-com", "a.example"),
            ("documentation-example-org", "b.example"),
        ])
        .expect("registered slugs");
        let one = format!(
            "{}\n1{UNIT_SEPARATOR}documentation-example-com{UNIT_SEPARATOR}a.example\
             {RECORD_SEPARATOR}2{UNIT_SEPARATOR}documentation-example-org{UNIT_SEPARATOR}\
             b.example{RECORD_SEPARATOR}",
            destinations::CANONICAL_DIGEST_DOMAIN
        );
        assert_eq!(
            two, one,
            "the preimage boundary moved; re-derive the separator argument"
        );
        // ...and that colliding host is refused before it is ever rendered, so
        // the collision cannot be reached from the desktop's document either.
        assert!(operator_allowlist_digest(&[(
            "documentation-example-com",
            "a.example\u{1e}2\u{1f}documentation-example-org\u{1f}b.example"
        )])
        .is_err());
        // ...and the colliding host is exactly what refuses to load.
        let colliding = r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":1,
           "host":"a.example\u001e2\u001fb.example","match_mode":"exact",
           "path_scope":"whole_origin","path_prefixes":[],"max_requests_per_minute":1}]}"#;
        let (_g, p) = write_temp("allowlist.json", colliding);
        assert!(matches!(
            EgressPolicy::load_entries(&p),
            Err(PolicyError::AllowlistCorrupt(_))
        ));
    }

    // -- INV-4: redirects ---------------------------------------------------

    /// Mutations this detects: the hop bound moved into the fetch loop, where a
    /// caller that forgets it has no bound at all; the comparison written `>`
    /// rather than `>=`, giving one free extra hop.
    #[tokio::test]
    async fn a_request_at_the_hop_limit_is_refused_by_evaluate_not_by_the_caller() {
        // A resolver with no answers at all: reaching the resolve step would
        // produce `ResolutionFailed`, not `RedirectHopLimit`, so this also
        // proves the hop bound runs FIRST.
        let policy = policy_with(
            Arc::new(SequencedResolver::new(vec![])),
            Arc::new(SystemClock),
        );

        let mut req = allowed_request();
        req.hop = MAX_REDIRECT_HOPS;
        assert_eq!(
            policy.evaluate(&req).await,
            PolicyDecision::Deny(DenyReason::RedirectHopLimit)
        );

        // It runs before EVERY other check: a request that is also wrong in
        // four other ways still reports the hop limit.
        let mut wrong_everywhere = ProxyRequest {
            scheme: Scheme::Http,
            method: Method::Other("X".into()),
            host: "169.254.169.254".into(),
            port: 9050,
            path_and_query: "/../admin".into(),
            hop: MAX_REDIRECT_HOPS,
        };
        assert_eq!(
            policy.evaluate(&wrong_everywhere).await,
            PolicyDecision::Deny(DenyReason::RedirectHopLimit)
        );

        // NEGATIVE CONTROL: one below the limit is NOT refused for this reason.
        wrong_everywhere.hop = MAX_REDIRECT_HOPS - 1;
        assert_ne!(
            policy.evaluate(&wrong_everywhere).await,
            PolicyDecision::Deny(DenyReason::RedirectHopLimit)
        );
    }

    /// Mutations this detects: a redirect treated as a continuation of an
    /// approved request, so the second hop inherits the first hop's approval.
    #[tokio::test]
    async fn redirect_to_non_allowlisted_host_is_denied() {
        let policy = shipped_policy();
        let first = allowed_request();
        assert!(matches!(
            policy.evaluate(&first).await,
            PolicyDecision::Allow { .. }
        ));

        for location in [
            "https://evil.example/data/x",
            "https://example.com.evil.example/data/x",
            // The same registrable name with the FQDN root dot, which defeats a
            // string-equality match while resolving identically.
            "https://example.com./data/x",
        ] {
            let next = next_request(&first, location).expect("shape is accepted");
            let decision = policy.evaluate(&next).await;
            assert!(
                matches!(
                    decision,
                    PolicyDecision::Deny(
                        DenyReason::HostNotAllowlisted | DenyReason::NonCanonicalIpLiteral
                    )
                ),
                "{location} was not refused; got {decision:?}"
            );
        }

        // A redirect into the deny-net, by address and by a name that resolves
        // there.
        let to_metadata = next_request(&first, "http://169.254.169.254/latest/meta-data/")
            .expect("shape is accepted");
        assert_eq!(
            policy.evaluate(&to_metadata).await,
            PolicyDecision::Deny(DenyReason::DeniedNetwork)
        );

        // POSITIVE CONTROL: a redirect that stays on the allowlist and in scope
        // is followed.
        let same_origin = next_request(&first, "/data/next.json").expect("shape is accepted");
        assert_eq!(same_origin.hop, 1);
        assert_eq!(same_origin.host, "example.com");
        assert!(matches!(
            policy.evaluate(&same_origin).await,
            PolicyDecision::Allow { .. }
        ));
    }

    /// Mutations this detects: `//host/path` reinterpreted as a path, which
    /// silently rewrites the destination to a host nobody checked; a `Location`
    /// parser that strips userinfo instead of refusing it.
    #[test]
    fn a_protocol_relative_or_userinfo_location_is_refused_not_reinterpreted() {
        let prev = allowed_request();
        for bad in [
            "//evil.example/data/x",
            "///evil.example/data/x",
            "https://user@evil.example/data/x",
            "https://user:pw@evil.example/data/x",
            "https://example.com/data/\r\nX-Injected: 1",
            "https://example.com/data/ spaced",
            "",
            "https://@/x",
            "https://example.com:notaport/x",
        ] {
            assert!(
                matches!(
                    next_request(&prev, bad),
                    Err(DenyReason::MalformedRedirectLocation)
                ),
                "{bad:?} must be refused; got {:?}",
                next_request(&prev, bad)
            );
        }

        // A scheme this node does not speak gets its own refusal.
        for bad in ["file:///etc/passwd", "gopher://x/1", "mailto:a@b.example"] {
            assert!(
                matches!(
                    next_request(&prev, bad),
                    Err(DenyReason::RedirectSchemeNotAllowed)
                ),
                "{bad:?} must be refused as a scheme"
            );
        }

        // POSITIVE CONTROL: both accepted shapes parse, and carry the hop.
        let abs = next_request(&prev, "https://example.org/api/v1/x").expect("absolute");
        assert_eq!(
            (abs.host.as_str(), abs.port, abs.hop),
            ("example.org", 443, 1)
        );
        let rel = next_request(&prev, "/data/y").expect("origin-form path");
        assert_eq!(
            (rel.host.as_str(), rel.port, rel.hop),
            ("example.com", 443, 1)
        );
    }

    /// Mutations this detects: the hop counter not incremented by
    /// `next_request`, so a chain never reaches the bound; the bound compared
    /// against a constant other than `MAX_REDIRECT_HOPS`.
    #[tokio::test]
    async fn redirect_chain_bounded_at_three_and_every_hop_reruns_full_evaluate() {
        let policy = shipped_policy();
        let mut req = allowed_request();

        let mut evaluated = 0usize;
        loop {
            match policy.evaluate(&req).await {
                PolicyDecision::Allow { entry_id, .. } => {
                    evaluated += 1;
                    // Every hop got a full evaluation: it matched an entry, and
                    // the entry it matched is the one the host names.
                    assert_eq!(policy.entry(entry_id).expect("entry").host, req.host);
                }
                PolicyDecision::Deny(r) => {
                    assert_eq!(r, DenyReason::RedirectHopLimit);
                    assert_eq!(req.hop, MAX_REDIRECT_HOPS);
                    break;
                }
            }
            req = next_request(&req, "/data/next").expect("same-origin redirect");
            assert!(req.hop <= MAX_REDIRECT_HOPS, "the loop is unbounded");
        }
        assert_eq!(
            evaluated, MAX_REDIRECT_HOPS as usize,
            "hops 0..{MAX_REDIRECT_HOPS} must each be evaluated, and the next refused"
        );

        // Every hop re-runs the WHOLE evaluation, not just the hop check: a
        // mid-chain redirect off the allowlist is refused even though hop 1 is
        // well inside the bound.
        let first = allowed_request();
        let hop1 = next_request(&first, "https://evil.example/data/x").expect("shape");
        assert_eq!(hop1.hop, 1);
        assert_eq!(
            policy.evaluate(&hop1).await,
            PolicyDecision::Deny(DenyReason::HostNotAllowlisted)
        );
    }

    // -- INV-2: the pin -----------------------------------------------------

    /// Mutations this detects: `evaluate` returning the host name for the
    /// caller to resolve; a second resolution between the check and the dial.
    #[tokio::test]
    async fn evaluate_pins_the_resolved_address_and_resolves_exactly_once() {
        let resolver = Arc::new(SequencedResolver::new(vec![
            vec!["93.184.216.34".parse().unwrap()],
            // Queued and MUST NOT be consumed by a single evaluation.
            vec!["10.0.0.7".parse().unwrap()],
        ]));
        let policy = policy_with(resolver.clone(), Arc::new(SystemClock));

        let decision = policy.evaluate(&allowed_request()).await;
        assert_eq!(
            decision,
            PolicyDecision::Allow {
                entry_id: 1,
                pinned_ip: "93.184.216.34".parse().unwrap(),
                port: 443,
            }
        );
        assert_eq!(
            decision.pinned_socket_addr().expect("allowed"),
            "93.184.216.34:443".parse().unwrap()
        );
        assert_eq!(
            resolver.remaining(),
            1,
            "exactly one resolution per evaluation"
        );

        // The rebind: the SAME request, evaluated again, now resolves into the
        // deny-net and is refused. The first decision's pin is unaffected,
        // because it is an address and not a name.
        assert_eq!(
            policy.evaluate(&allowed_request()).await,
            PolicyDecision::Deny(DenyReason::DeniedNetwork)
        );
        assert_eq!(
            decision.pinned_socket_addr().expect("allowed"),
            "93.184.216.34:443".parse().unwrap()
        );
        assert_eq!(resolver.remaining(), 0);
    }

    /// Mutations this detects: the deny-net applied to `addrs[0]` only, or
    /// applied after the pin is taken.
    #[tokio::test]
    async fn allowlisted_host_resolving_to_denied_ip_is_refused() {
        for answer in [
            vec!["169.254.169.254".parse().unwrap()],
            vec!["10.0.0.7".parse().unwrap()],
            vec!["127.0.0.1".parse().unwrap()],
            vec!["64:ff9b::a9fe:a9fe".parse().unwrap()],
            // Public FIRST, poisoned second: the whole answer must fall.
            vec![
                "93.184.216.34".parse().unwrap(),
                "169.254.169.254".parse().unwrap(),
            ],
        ] {
            let policy = policy_with(
                Arc::new(FixedResolver::new(answer.clone())),
                Arc::new(SystemClock),
            );
            let decision = policy.evaluate(&allowed_request()).await;
            assert_eq!(
                decision,
                PolicyDecision::Deny(DenyReason::DeniedNetwork),
                "answer {answer:?} was not refused"
            );
            assert_eq!(decision.pinned_socket_addr(), None);
        }

        // POSITIVE CONTROL: an all-public answer for the same host is allowed.
        let policy = policy_with(public_resolver(), Arc::new(SystemClock));
        assert!(matches!(
            policy.evaluate(&allowed_request()).await,
            PolicyDecision::Allow { .. }
        ));
    }

    /// The threat brief's "an IP-literal request carries no server name at all"
    /// case, at the policy seam.
    ///
    /// Mutations this detects: an IP literal in the host field short-circuiting
    /// the allowlist because "the address is already known"; the deny-net check
    /// on a literal host moved after the allowlist match, where a list that ever
    /// gained an address entry would reach it.
    #[tokio::test]
    async fn an_ip_literal_host_is_refused_even_when_the_address_is_public() {
        // No answers queued: reaching resolution would report ResolutionFailed,
        // so each refusal below is proved to happen before any lookup.
        let resolver = Arc::new(SequencedResolver::new(vec![vec!["93.184.216.34"
            .parse()
            .unwrap()]]));
        let policy = policy_with(resolver.clone(), Arc::new(SystemClock));

        // A public literal: refused because entries name hosts, not addresses.
        assert_eq!(
            policy.evaluate(&get("93.184.216.34", 443, "/data/x")).await,
            PolicyDecision::Deny(DenyReason::HostNotAllowlisted)
        );
        // A deny-net literal: refused earlier still, on the address itself.
        for literal in ["169.254.169.254", "127.0.0.1", "10.0.0.7"] {
            assert_eq!(
                policy.evaluate(&get(literal, 443, "/data/x")).await,
                PolicyDecision::Deny(DenyReason::DeniedNetwork),
                "{literal} must be refused on the address"
            );
        }
        assert_eq!(
            resolver.remaining(),
            1,
            "every literal was refused before anything was looked up"
        );

        // POSITIVE CONTROL: the allowlisted NAME for the same address is
        // allowed, and consumes the queued answer -- so the assertion above
        // measured a real absence.
        assert!(matches!(
            policy.evaluate(&allowed_request()).await,
            PolicyDecision::Allow { .. }
        ));
        assert_eq!(resolver.remaining(), 0);
    }

    // -- rate ceiling -------------------------------------------------------

    /// Mutations this detects: a fixed window in place of a sliding one, which
    /// permits 2N requests across a boundary; the refused request still being
    /// recorded, which would extend the refusal indefinitely; `>` in place of
    /// `>=`, giving one free request.
    #[tokio::test]
    async fn per_entry_rate_ceiling_refuses_the_n_plus_first_request_in_a_minute() {
        let clock = ManualClock::new(1_000_000);
        let policy = policy_with(
            Arc::new(FixedResolver::new(vec!["93.184.216.34".parse().unwrap()])),
            clock.clone(),
        );
        // Entry 3 declares a ceiling of 10 in the shipped list.
        let entry = policy.entry(3).expect("entry 3").clone();
        assert_eq!(entry.max_requests_per_minute, 10);
        let req = get("research.example.net", 443, "/open-data/x");

        for i in 0..entry.max_requests_per_minute {
            assert!(
                matches!(policy.evaluate(&req).await, PolicyDecision::Allow { .. }),
                "request {i} was inside the ceiling and must be admitted"
            );
        }
        // The N+1st, at the same instant.
        assert_eq!(
            policy.evaluate(&req).await,
            PolicyDecision::Deny(DenyReason::EntryRateExceeded)
        );
        // And still refused a moment later: a refused request must not have
        // been recorded, but the window has not moved either.
        clock.advance(1_000);
        refresh_indicator(&policy, &*clock);
        assert_eq!(
            policy.evaluate(&req).await,
            PolicyDecision::Deny(DenyReason::EntryRateExceeded)
        );

        // A DIFFERENT entry is unaffected: the ceiling is per entry.
        assert!(matches!(
            policy.evaluate(&allowed_request()).await,
            PolicyDecision::Allow { .. }
        ));

        // POSITIVE CONTROL: once the window slides past, the ceiling reopens.
        //
        // The indicator is re-stamped alongside the clock because it is a
        // separate gate with its own (ten-second) TTL: a sixty-one-second jump
        // with no refresh would close egress on liveness and this test would
        // report a rate-limiter bug that is not there.
        clock.advance(60_001);
        refresh_indicator(&policy, &*clock);
        assert!(matches!(
            policy.evaluate(&req).await,
            PolicyDecision::Allow { .. }
        ));
    }

    /// Stamps the liveness gate at the policy's own current time, as the
    /// operator surface would.
    fn refresh_indicator(policy: &EgressPolicy, clock: &dyn Clock) {
        policy
            .indicator()
            .set_live(true, clock.now_unix_millis() / 1_000);
    }

    // -- pinned shapes ------------------------------------------------------

    /// Mutations this detects: a second `MatchMode` variant added without
    /// anyone reconsidering the userinfo and trailing-dot vectors; a shipped
    /// entry left on some other mode.
    #[test]
    fn match_mode_has_exactly_one_variant_in_v1() {
        // Exhaustive: adding a variant is a compile error here.
        let m = MatchMode::Exact;
        match m {
            MatchMode::Exact => (),
        }

        let (entries, _) = EgressPolicy::load_entries(&shipped_allowlist()).expect("loads");
        assert!(!entries.is_empty(), "the shipped fixture must not be empty");
        for e in &entries {
            assert_eq!(
                e.match_mode,
                MatchMode::Exact,
                "entry {} is not exact",
                e.id
            );
            assert_eq!(e.host, e.host.to_ascii_lowercase());
            assert!(!e.host.ends_with('.'));
            assert!(e.id > 0);
        }
    }

    /// Mutations this detects: a variant deleted and its call sites folded into
    /// a neighbour, which silently merges two refusals into one and makes an
    /// operator log unable to distinguish them.
    ///
    /// **The count was 24 when the byte ledger was still an insertion point.**
    /// Filling that seam added exactly one refusal — `BudgetUnavailable`, for a
    /// ledger this process cannot read — and raising the number here is the
    /// deliberate edit that records it. The property this test defends is that
    /// **every variant is a UNIT variant**: a reason that carried data would be
    /// a field that starts as a port number and grows into a hostname, and this
    /// type is read by the operator log and, indirectly, by the receipt path.
    /// That property is asserted below and does not depend on the count.
    #[test]
    fn deny_reason_has_exactly_twenty_five_unit_variants() {
        // Exhaustive: adding or removing a variant is a compile error here.
        fn index(r: DenyReason) -> usize {
            match r {
                DenyReason::RedirectHopLimit => 0,
                DenyReason::MalformedHost => 1,
                DenyReason::NonCanonicalIpLiteral => 2,
                DenyReason::HostNotAllowlisted => 3,
                DenyReason::PortNotAllowed => 4,
                DenyReason::SchemeNotAllowed => 5,
                DenyReason::MethodNotAllowed => 6,
                DenyReason::RequestBodyNotPermitted => 7,
                DenyReason::PathOutOfScope => 8,
                DenyReason::NoResolvedAddress => 9,
                DenyReason::ResolutionFailed => 10,
                DenyReason::DeniedNetwork => 11,
                DenyReason::RobotsDisallowed => 12,
                DenyReason::RobotsUnavailable => 13,
                DenyReason::EntryRateExceeded => 14,
                DenyReason::DailyCeilingExceeded => 15,
                DenyReason::BudgetUnavailable => 16,
                DenyReason::ScheduleClosed => 17,
                DenyReason::IndicatorStale => 18,
                DenyReason::ConsentWithdrawn => 19,
                DenyReason::KillSwitchEngaged => 20,
                DenyReason::ConcurrencyLimit => 21,
                DenyReason::MalformedRedirectLocation => 22,
                DenyReason::RedirectSchemeNotAllowed => 23,
                DenyReason::ResponseTooLarge => 24,
            }
        }
        let all = [
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
        let mut seen: Vec<usize> = all.iter().copied().map(index).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 25, "DenyReason must carry exactly 25 variants");
        assert_eq!(all.len(), 25);

        // THE PROPERTY, asserted independently of the count: every variant is a
        // unit variant, so no refusal can carry a port that later grows into a
        // hostname. `Copy` is only derivable when no variant owns data, and the
        // `Debug` rendering of each variant is its bare name -- a data-carrying
        // variant would render as `Name(..)`.
        fn assert_copy<T: Copy>(_: &T) {}
        for r in all {
            assert_copy(&r);
            let rendered = format!("{r:?}");
            assert!(
                !rendered.contains('(') && !rendered.contains('{'),
                "DenyReason::{rendered} carries data; every refusal reason must be a unit variant"
            );
        }
    }

    /// INV-11's shape, at this seam.
    ///
    /// Mutations this detects: a host, path or URL added to `PolicyDecision`,
    /// which is the value the receipt and the log are built from.
    #[tokio::test]
    async fn an_allow_decision_names_an_entry_id_and_an_address_and_nothing_else() {
        let policy = shipped_policy();
        let req = get("example.com", 443, "/data/secret-report.json?token=abc");
        let decision = policy.evaluate(&req).await;

        let rendered = format!("{decision:?}");
        for leaked in ["secret-report", "token=abc", "/data/", "example.com"] {
            assert!(
                !rendered.contains(leaked),
                "the decision leaked {leaked:?}: {rendered}"
            );
        }
        // POSITIVE CONTROL: it does carry the two things it is allowed to.
        assert!(rendered.contains("entry_id: 1"), "{rendered}");
        assert!(rendered.contains("93.184.216.34"), "{rendered}");
    }
}
