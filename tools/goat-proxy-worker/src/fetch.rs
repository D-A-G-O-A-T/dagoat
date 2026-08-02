//! The HTTP client.
//!
//! This node **terminates as an HTTP client**. It never relays an opaque byte
//! stream, which is why `Method` has no variant for the tunnelling method and
//! why there is no bidirectional copy anywhere in this crate. Connection
//! establishment is ours: we connect to a **pinned address** and present a name
//! that came from the **allowlist match**, so a hostile `Host` header or a
//! rebinding DNS answer changes nothing about where the packets go.
//!
//! # How the pin travels from the decision to the dial
//!
//! [`EgressPolicy::evaluate`] resolves the allowlist entry's host, validates
//! every address in the answer, and returns one address **by value**. That value
//! becomes a [`PinnedTarget`], and `PinnedTarget::socket_addr()` is what
//! `SocketRegistry::connect` takes. There is no name left to look up: the dial
//! site cannot re-resolve because there is nothing there to re-resolve. A
//! mutation that passed `target.host` to the connect instead was what made this
//! comment necessary.
//!
//! # `Host` and SNI come from the allowlist, never from the consumer
//!
//! Both are `PinnedTarget::sni_name()`, which is the entry's host. A consumer
//! that supplies a different name reaches the allowlist matcher and is refused
//! there; it never reaches a header.
//!
//! # Every redirect hop re-enters `evaluate` in full
//!
//! A redirect is not a continuation of an approved request; it is a new request
//! that has not been approved yet. The hop bound lives **inside** `evaluate`, so
//! a redirect loop cannot spin on near-zero-byte 302s under a byte budget that
//! never trips.
//!
//! # The ceiling is enforced mid-stream, not at admission
//!
//! [`BudgetSink`] debits the durable ledger as the body flows and aborts the
//! transfer the moment the ceiling is reached — and aborting means the socket is
//! **dropped**, not merely left unread.
//!
//! # Nothing here is logged
//!
//! There is no logging macro in this crate's production source and a sweep in
//! this module asserts it. [`FetchOutcome::location`] holds a URL and is used to
//! build the next hop; it is never rendered, never persisted, and never
//! forwarded to the consumer.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 33 and its Security invariants section (INV-2, INV-4, INV-5,
//! INV-7, INV-9, INV-11, INV-17).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::caps::CapError;
use crate::net::{MeteredStream, SocketRegistry, TrackedStream};
use crate::policy::{
    next_request, DenyReason, EgressPolicy, Method, PolicyDecision, ProxyRequest, Scheme,
};
use crate::resolve::PinnedTarget;
use crate::robots::{RobotsFetchOutcome, RobotsFetcher};

/// Where a response body goes.
///
/// There is deliberately **no file-backed implementation of this trait in this
/// crate**: the body is forwarded to the consumer and never lands on the
/// operator's disk.
pub trait BodySink: Send {
    fn write(&mut self, chunk: &[u8]) -> Result<(), FetchError>;
}

/// The inner post-quantum channel to the gateway.
///
/// Defined here so this crate compiles and tests standalone, and so the
/// dependency direction stays sidecar → tunnel: the adapter that drives a tunnel
/// session belongs on **this** side, because the sidecar drives the carriage. An
/// implementation living in the tunnel crate would need a dependency back on
/// this one and Cargo would refuse the cycle.
pub trait GatewayLink: Send {
    fn next_request(&mut self) -> Option<ProxyRequest>;
    fn body_sink(&mut self) -> &mut dyn BodySink;
    fn deny(&mut self, reason: DenyReason);
    fn complete(&mut self, status: u16, bytes: u64);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    pub status: u16,
    /// The `Location` header, when the status is a redirect. Used to build the
    /// next hop's request; **never logged, never persisted, never forwarded**.
    pub location: Option<String>,
    /// Bytes observed on the SOCKET. This is the byte budget's debit source and
    /// a transport diagnostic. It is **not** the payout quantity: for HTTPS it
    /// includes TLS records, MACs, the handshake and the outbound request.
    pub socket_bytes: u64,
    /// THE metered quantity (§4.1, INV-17): response body bytes after HTTP
    /// framing is stripped and chunked transfer-encoding is decoded. The gateway
    /// counts the same number as `TunnelMeterRecord.to_consumer`, and the
    /// strict-equality challenger compares these and nothing else.
    pub body_bytes_to_consumer: u64,
}

/// Why a fetch did not complete.
///
/// Every variant is a **unit** variant except `Denied`, whose payload is itself
/// a unit-variant enum. Nothing in this type can carry a URL, a path, a query
/// string, a header name or a header value, which is what makes
/// `a_refusal_carries_no_path_query_or_header_in_any_rendering` an assertion
/// about the type rather than about one code path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    Denied(DenyReason),
    Transport,
    MalformedResponse,
    ResponseTooLarge,
    Halted,
}

/// Per-request wall-clock ceiling. A stalled origin must not hold a socket open
/// past the kill deadline's ability to reason about it.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest single response this node will move: 256 MiB.
pub const MAX_RESPONSE_BYTES: u64 = 268_435_456;

/// Matches `MAX_FRAME_PAYLOAD` in the tunnel crate, so a read never produces
/// more body than one frame can carry.
const READ_BUF: usize = 65_536;

/// The largest response head this node will accumulate before refusing. An
/// origin that has not finished its headers in 256 KiB is not sending headers.
const MAX_HEAD_BYTES: usize = READ_BUF * 4;

enum Wire {
    Plain(MeteredStream<TrackedStream>),
    Tls(Box<tokio_rustls::client::TlsStream<MeteredStream<TrackedStream>>>),
}

impl Wire {
    async fn write_all(&mut self, b: &[u8]) -> Result<(), FetchError> {
        let r = match self {
            Wire::Plain(s) => s.write_all(b).await,
            Wire::Tls(s) => s.write_all(b).await,
        };
        r.map_err(|_| FetchError::Transport)
    }

    async fn read(&mut self, b: &mut [u8]) -> Result<usize, FetchError> {
        let r = match self {
            Wire::Plain(s) => s.read(b).await,
            Wire::Tls(s) => s.read(b).await,
        };
        r.map_err(|_| FetchError::Transport)
    }
}

/// The web PKI roots, built once.
///
/// `ring` is the provider, named explicitly for the reason the tunnel crate
/// names it: rustls 0.23 refuses to pick a default when zero or two providers
/// are compiled in.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }))
}

async fn open_wire(
    target: &PinnedTarget,
    scheme: Scheme,
    registry: Arc<SocketRegistry>,
    counter: Arc<AtomicU64>,
) -> Result<Wire, FetchError> {
    if registry.is_halted() {
        return Err(FetchError::Halted);
    }
    // THE PIN: a `SocketAddr`, never a name. There is no second lookup, because
    // there is no name here to look up.
    let tcp = registry
        .connect(target.socket_addr())
        .await
        .map_err(|_| FetchError::Transport)?;
    let metered = MeteredStream::new(tcp, counter);
    match scheme {
        Scheme::Http => Ok(Wire::Plain(metered)),
        Scheme::Https => {
            // The SNI name is the ALLOWLISTED name, never the pinned address and
            // never anything the consumer supplied.
            let name = rustls_pki_types::ServerName::try_from(target.sni_name().to_string())
                .map_err(|_| FetchError::Denied(DenyReason::MalformedHost))?;
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            let tls = connector
                .connect(name, metered)
                .await
                .map_err(|_| FetchError::Transport)?;
            Ok(Wire::Tls(Box::new(tls)))
        }
    }
}

/// How the body is framed. The response says which; we do not guess, and we
/// refuse a response that declares **both** — that combination is a
/// request-smuggling shape and has no legitimate reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    Length(u64),
    Chunked,
    /// No declared framing: read to EOF, which HTTP/1.1 permits with
    /// `Connection: close`.
    ToEof,
}

struct Head {
    status: u16,
    location: Option<String>,
    framing: BodyFraming,
}

fn parse_head(head: &str) -> Result<Head, FetchError> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(FetchError::MalformedResponse)?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .ok_or(FetchError::MalformedResponse)?
        .parse()
        .map_err(|_| FetchError::MalformedResponse)?;

    let mut location = None;
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "location" => location = Some(v.trim().to_string()),
            "content-length" => {
                let n = v
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| FetchError::MalformedResponse)?;
                // Two DIFFERENT `Content-Length` headers is the other smuggling
                // shape, and "last one wins" is how two intermediaries end up
                // reading two different messages out of one byte stream.
                if content_length.is_some_and(|prev| prev != n) {
                    return Err(FetchError::MalformedResponse);
                }
                content_length = Some(n);
            }
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }

    let framing = match (chunked, content_length) {
        // Both declared: refuse. This is the smuggling shape, not a preference.
        (true, Some(_)) => return Err(FetchError::MalformedResponse),
        (true, None) => BodyFraming::Chunked,
        (false, Some(n)) => BodyFraming::Length(n),
        (false, None) => BodyFraming::ToEof,
    };
    Ok(Head {
        status,
        location,
        framing,
    })
}

/// The chunked-transfer decoder's phase.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChunkPhase {
    /// Reading the hex size line (and any chunk extensions).
    Size(Vec<u8>),
    /// Reading `n` more data bytes.
    Data(u64),
    /// Consuming the CRLF that follows a chunk's data.
    AfterData(u8),
    /// Reading trailers until a blank line.
    Trailer(Vec<u8>),
    Done,
}

/// Decodes the body, whatever its framing, and emits **only** the decoded body
/// bytes to the sink.
///
/// The framing bytes — hex chunk-size lines, their CRLFs, the terminating
/// `0\r\n\r\n` and any trailers — are consumed and discarded. A decoder that
/// forwarded them would hand chunk-size lines to the consumer as content and,
/// because the operator is compensated per byte, would let a hostile origin
/// inflate a colluding operator's total with pure framing at no cost. It would
/// also make a truncated response indistinguishable from a complete one.
struct BodyReader {
    framing: BodyFraming,
    remaining: u64,
    phase: ChunkPhase,
    total: u64,
    complete: bool,
}

impl BodyReader {
    fn new(framing: BodyFraming) -> Self {
        let remaining = match framing {
            BodyFraming::Length(n) => n,
            _ => 0,
        };
        Self {
            framing,
            remaining,
            phase: ChunkPhase::Size(Vec::new()),
            total: 0,
            complete: matches!(framing, BodyFraming::Length(0)),
        }
    }

    fn feed(&mut self, bytes: &[u8], sink: &mut dyn BodySink) -> Result<(), FetchError> {
        match self.framing {
            BodyFraming::Length(_) => {
                if bytes.len() as u64 > self.remaining {
                    // More body than was declared: the length was a lie, and a
                    // lying length is the shape a smuggled second message takes.
                    return Err(FetchError::MalformedResponse);
                }
                self.emit(bytes, sink)?;
                self.remaining -= bytes.len() as u64;
                if self.remaining == 0 {
                    self.complete = true;
                }
                Ok(())
            }
            BodyFraming::ToEof => self.emit(bytes, sink),
            BodyFraming::Chunked => self.feed_chunked(bytes, sink),
        }
    }

    fn emit(&mut self, bytes: &[u8], sink: &mut dyn BodySink) -> Result<(), FetchError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.total = self.total.saturating_add(bytes.len() as u64);
        if self.total > MAX_RESPONSE_BYTES {
            return Err(FetchError::ResponseTooLarge);
        }
        sink.write(bytes)
    }

    fn feed_chunked(&mut self, bytes: &[u8], sink: &mut dyn BodySink) -> Result<(), FetchError> {
        let mut i = 0usize;
        while i < bytes.len() {
            match &mut self.phase {
                ChunkPhase::Done => return Ok(()),
                ChunkPhase::Size(line) => {
                    let b = bytes[i];
                    i += 1;
                    if b == b'\n' {
                        let text = String::from_utf8_lossy(line).to_string();
                        line.clear();
                        let head = text.trim_end_matches('\r');
                        // Chunk extensions after `;` are consumed and ignored.
                        let size_text = head.split(';').next().unwrap_or("").trim();
                        let size = u64::from_str_radix(size_text, 16)
                            .map_err(|_| FetchError::MalformedResponse)?;
                        self.phase = if size == 0 {
                            ChunkPhase::Trailer(Vec::new())
                        } else {
                            ChunkPhase::Data(size)
                        };
                    } else {
                        if line.len() > 64 {
                            return Err(FetchError::MalformedResponse);
                        }
                        line.push(b);
                    }
                }
                ChunkPhase::Data(left) => {
                    let take = (*left).min((bytes.len() - i) as u64) as usize;
                    let slice = &bytes[i..i + take];
                    i += take;
                    let now_left = *left - take as u64;
                    self.phase = if now_left == 0 {
                        ChunkPhase::AfterData(0)
                    } else {
                        ChunkPhase::Data(now_left)
                    };
                    self.emit(slice, sink)?;
                }
                ChunkPhase::AfterData(seen) => {
                    let b = bytes[i];
                    i += 1;
                    if b == b'\n' {
                        self.phase = ChunkPhase::Size(Vec::new());
                    } else if b == b'\r' && *seen == 0 {
                        *seen = 1;
                    } else {
                        return Err(FetchError::MalformedResponse);
                    }
                }
                ChunkPhase::Trailer(line) => {
                    let b = bytes[i];
                    i += 1;
                    if b == b'\n' {
                        let empty = line.iter().all(|c| *c == b'\r');
                        line.clear();
                        if empty {
                            self.phase = ChunkPhase::Done;
                            self.complete = true;
                            return Ok(());
                        }
                    } else {
                        if line.len() > 8_192 {
                            return Err(FetchError::MalformedResponse);
                        }
                        line.push(b);
                    }
                }
            }
        }
        Ok(())
    }

    /// A declared length the body did not honour is a **truncation**, and a
    /// truncated response must not be indistinguishable from a complete one.
    fn finish(&self) -> Result<(), FetchError> {
        match self.framing {
            BodyFraming::Length(n) if n != self.total => Err(FetchError::MalformedResponse),
            BodyFraming::Chunked if !self.complete => Err(FetchError::MalformedResponse),
            _ => Ok(()),
        }
    }
}

/// One hop. The caller has already run `evaluate` and holds the pinned target.
///
/// `method` is taken **by reference**. `Method::Other(String)` owns a `String`,
/// so `Method` is not `Copy`; passing it by value would move `req.method` out of
/// `req` on the first iteration of `fetch_with_redirects`'s loop while
/// `&req.path_and_query` in the same call and `next_request(&req, ..)`
/// immediately after both borrow the partially-moved value.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_once(
    target: &PinnedTarget,
    scheme: Scheme,
    method: &Method,
    path_and_query: &str,
    sink: &mut dyn BodySink,
    registry: Arc<SocketRegistry>,
    counter: Arc<AtomicU64>,
) -> Result<FetchOutcome, FetchError> {
    let cancel = registry.cancelled();
    let work = fetch_once_inner(
        target,
        scheme,
        method,
        path_and_query,
        sink,
        registry,
        counter,
    );

    tokio::select! {
        r = tokio::time::timeout(REQUEST_TIMEOUT, work) => match r {
            Ok(v) => v,
            Err(_) => Err(FetchError::Transport),
        },
        // The kill switch. Selecting on it DROPS `work`, which drops the wire,
        // which drops the `TrackedStream` and closes the socket. Stopping the
        // read alone would leave the transfer running at the origin's pace.
        _ = cancel.notified() => Err(FetchError::Halted),
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_once_inner(
    target: &PinnedTarget,
    scheme: Scheme,
    method: &Method,
    path_and_query: &str,
    sink: &mut dyn BodySink,
    registry: Arc<SocketRegistry>,
    counter: Arc<AtomicU64>,
) -> Result<FetchOutcome, FetchError> {
    // THE METHOD TOKEN IS A CLOSED SET, and it is built here rather than taken
    // from the request.
    //
    // This is a second gate, independent of `evaluate`'s method check, and it is
    // the one that matters: `Method::Other(String)` owns a consumer-supplied
    // string, and a `method.as_str()` that handed that string to the request
    // line would let the consumer name **any** method — including the one that
    // asks a proxy to open an opaque bidirectional tunnel, which is the single
    // thing this node must never do. No consumer-supplied byte reaches the
    // request line's first token, so the tunnelling method cannot be spelled
    // here even by a caller that skipped the policy.
    let method_token = match method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => return Err(FetchError::Denied(DenyReason::RequestBodyNotPermitted)),
        Method::Other(_) => return Err(FetchError::Denied(DenyReason::MethodNotAllowed)),
    };

    let mut wire = open_wire(target, scheme, registry, Arc::clone(&counter)).await?;

    // `Host` is the ALLOWLISTED name. `Accept-Encoding: identity` because a
    // compressed body would be metered after decompression by one counter and
    // before it by the other, and INV-17's strict equality has no tolerance to
    // absorb the difference.
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        method_token,
        path_and_query,
        target.sni_name(),
        crate::robots::ROBOTS_UA
    );
    wire.write_all(req.as_bytes()).await?;

    let mut acc: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut head: Option<Head> = None;
    let mut body: Option<BodyReader> = None;
    let mut discard = DiscardSink;
    // Set once the head is parsed. A redirect's body goes to `discard`.
    let mut redirecting = false;
    let mut buf = vec![0u8; READ_BUF];

    loop {
        let n = wire.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let fresh: &[u8] = &buf[..n];

        if head.is_none() {
            acc.extend_from_slice(fresh);
            if acc.len() > MAX_HEAD_BYTES {
                return Err(FetchError::MalformedResponse);
            }
            let Some(p) = find_head_end(&acc) else {
                continue;
            };
            let parsed = parse_head(&String::from_utf8_lossy(&acc[..p + 4]))?;
            redirecting = is_redirect_status(parsed.status) && parsed.location.is_some();
            let mut reader = BodyReader::new(parsed.framing);
            head = Some(parsed);
            // Everything after the blank line is body.
            let leftover: Vec<u8> = acc.split_off(p + 4);
            acc.clear();
            let out: &mut dyn BodySink = if redirecting { &mut discard } else { sink };
            reader.feed(&leftover, out)?;
            let done = reader.complete;
            body = Some(reader);
            if done {
                break;
            }
            continue;
        }

        let reader = body
            .as_mut()
            .expect("the body reader exists once the head does");
        let out: &mut dyn BodySink = if redirecting { &mut discard } else { sink };
        reader.feed(fresh, out)?;
        if reader.complete {
            break;
        }
    }

    let head = head.ok_or(FetchError::MalformedResponse)?;
    let body = body.ok_or(FetchError::MalformedResponse)?;
    body.finish()?;

    Ok(FetchOutcome {
        status: head.status,
        location: head.location,
        socket_bytes: counter.load(Ordering::SeqCst),
        // Zero on a redirect hop, because zero bytes reached the consumer. The
        // operator's LINE still carried them, which is why `socket_bytes` is a
        // different number and why the ledger debits that one.
        body_bytes_to_consumer: if redirecting { 0 } else { body.total },
    })
}

/// The five statuses this node treats as a redirect.
fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn find_head_end(acc: &[u8]) -> Option<usize> {
    acc.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The full hop loop. **Every hop re-runs `evaluate` in full** — allowlist,
/// port, path scope, deny-net, robots, the byte budget and liveness.
///
/// The hop bound lives inside `evaluate`, not here: a bound the caller applies
/// is a bound a second caller forgets, and a redirect loop on near-zero-byte
/// 302s is never stopped by a byte budget.
pub async fn fetch_with_redirects(
    policy: &EgressPolicy,
    initial: ProxyRequest,
    sink: &mut dyn BodySink,
    registry: Arc<SocketRegistry>,
) -> Result<FetchOutcome, FetchError> {
    let mut req = initial;
    loop {
        let (entry_id, ip, port) = match policy.evaluate(&req).await {
            PolicyDecision::Allow {
                entry_id,
                pinned_ip,
                port,
            } => (entry_id, pinned_ip, port),
            PolicyDecision::Deny(r) => return Err(FetchError::Denied(r)),
        };
        // The name in the target is the ENTRY's, read back out of the policy —
        // not `req.host`, which is a string that arrived over the wire and
        // merely compared equal to it.
        let host = policy
            .entry(entry_id)
            .map(|e| e.host.clone())
            .ok_or(FetchError::Denied(DenyReason::HostNotAllowlisted))?;
        let target = PinnedTarget {
            entry_id,
            host,
            port,
            ip,
        };

        let counter = Arc::new(AtomicU64::new(0));
        let mut guard = BudgetSink {
            inner: sink,
            policy,
            counter: Arc::clone(&counter),
            spent: 0,
        };
        let out = fetch_once(
            &target,
            req.scheme,
            &req.method, // by reference: `Method` owns a `String` and is not `Copy`
            &req.path_and_query,
            &mut guard,
            Arc::clone(&registry),
            Arc::clone(&counter),
        )
        .await;
        let already_debited = guard.spent;
        drop(guard);

        // THE RESIDUAL DEBIT, and it is not bookkeeping.
        //
        // `BudgetSink` charges as the body flows, but it is only called for
        // bytes that reach the consumer: a redirect hop's body is discarded, a
        // refused hop may carry a full head, and the request line and response
        // head are never body at all. Every one of those crossed the operator's
        // line. Without this step a redirect chain would be an UNCHARGED path,
        // and an uncharged path under a hop bound of three is a free multiplier
        // on every request.
        let observed = counter.load(Ordering::SeqCst);
        if observed > already_debited {
            match policy
                .budget()
                .spend(observed - already_debited, crate::now_unix())
            {
                Ok(_wait) => {}
                Err(CapError::DailyCeilingReached) => {
                    return Err(FetchError::Denied(DenyReason::DailyCeilingExceeded))
                }
                Err(CapError::Unavailable(_)) => {
                    return Err(FetchError::Denied(DenyReason::BudgetUnavailable))
                }
                Err(CapError::OutsideSchedule) => {
                    return Err(FetchError::Denied(DenyReason::ScheduleClosed))
                }
            }
        }
        let out = out?;

        if !is_redirect_status(out.status) {
            return Ok(out);
        }
        let loc = out.location.clone().ok_or(FetchError::MalformedResponse)?;
        req = next_request(&req, &loc).map_err(FetchError::Denied)?;
    }
}

/// Debits the durable byte budget as the body flows and aborts the transfer the
/// moment the daily ceiling is reached.
///
/// Enforcing only at admission would let a single large response blow through
/// the operator's cap: the precheck in `evaluate` cannot know how big the
/// response will be, and by the time it does the bytes are already on the line.
struct BudgetSink<'a> {
    inner: &'a mut dyn BodySink,
    policy: &'a EgressPolicy,
    /// The SOCKET counter — the operator's line carries framing and TLS
    /// overhead, so that is what their ceiling is charged.
    counter: Arc<AtomicU64>,
    spent: u64,
}

impl BodySink for BudgetSink<'_> {
    fn write(&mut self, chunk: &[u8]) -> Result<(), FetchError> {
        let observed = self.counter.load(Ordering::SeqCst);
        let delta = observed.saturating_sub(self.spent);
        if delta > 0 {
            self.spent = observed;
            match self.policy.budget().spend(delta, crate::now_unix()) {
                Ok(_wait) => {}
                Err(CapError::DailyCeilingReached) => {
                    return Err(FetchError::Denied(DenyReason::DailyCeilingExceeded))
                }
                Err(CapError::Unavailable(_)) => {
                    return Err(FetchError::Denied(DenyReason::BudgetUnavailable))
                }
                Err(CapError::OutsideSchedule) => {
                    return Err(FetchError::Denied(DenyReason::ScheduleClosed))
                }
            }
        }
        self.inner.write(chunk)
    }
}

/// The real robots fetcher: same pinned address, same TLS name, no redirects,
/// and its bytes debited through the operator's own ledger.
///
/// It is **async** and holds no runtime handle. A *synchronous*
/// `RobotsFetcher::fetch` implemented by calling `Handle::block_on` would panic
/// whenever it was invoked from within a runtime context — and it is invoked
/// from `EgressPolicy::evaluate`, called from `fetch_with_redirects`, running on
/// a tokio worker.
pub struct HttpRobotsFetcher {
    registry: Arc<SocketRegistry>,
    budget: Arc<crate::caps::EgressLedger>,
}

impl HttpRobotsFetcher {
    pub fn new(registry: Arc<SocketRegistry>, budget: Arc<crate::caps::EgressLedger>) -> Self {
        Self { registry, budget }
    }
}

/// Consumes body bytes without forwarding them.
///
/// Used for **redirect** responses. A 3xx's body is the origin's "click here"
/// page: it is not the content the consumer asked for, it never becomes part of
/// the answer, and forwarding it would let an origin deliver arbitrary bytes to
/// a consumer under the guise of a redirect the node then refuses to follow. It
/// is still read off the socket — the framing has to be validated and the
/// operator's line carried it — but it reaches nobody.
struct DiscardSink;

impl BodySink for DiscardSink {
    fn write(&mut self, _chunk: &[u8]) -> Result<(), FetchError> {
        Ok(())
    }
}

/// Accumulates a bounded `robots.txt` body in memory.
struct StringSink(Vec<u8>);

impl BodySink for StringSink {
    fn write(&mut self, chunk: &[u8]) -> Result<(), FetchError> {
        if self.0.len() + chunk.len() > crate::robots::MAX_ROBOTS_BYTES {
            return Err(FetchError::ResponseTooLarge);
        }
        self.0.extend_from_slice(chunk);
        Ok(())
    }
}

#[async_trait::async_trait]
impl RobotsFetcher for HttpRobotsFetcher {
    async fn fetch(&self, scheme: Scheme, target: &PinnedTarget) -> RobotsFetchOutcome {
        let counter = Arc::new(AtomicU64::new(0));
        let mut sink = StringSink(Vec::new());
        let out = fetch_once(
            target,
            scheme,
            &Method::Get,
            "/robots.txt",
            &mut sink,
            Arc::clone(&self.registry),
            Arc::clone(&counter),
        )
        .await;

        // Robots bytes are the operator's bytes. Debiting them here is what
        // keeps the consented ceiling a ceiling: an undebited fetch path is an
        // uncapped one, and the cache's TTL refetches make it a recurring one. A
        // ledger refusal turns into `Unavailable`, which RFC 9309 §2.3.1 makes a
        // COMPLETE DISALLOW — so running out of budget closes egress rather than
        // opening it.
        let spent = counter.load(Ordering::SeqCst);
        if spent > 0 && self.budget.spend(spent, crate::now_unix()).is_err() {
            return RobotsFetchOutcome::Unavailable;
        }

        match (out, sink.0) {
            (Ok(o), body) if (200..300).contains(&o.status) => {
                RobotsFetchOutcome::Body(String::from_utf8_lossy(&body).to_string())
            }
            // RFC 9309 §2.3.1: "unavailable" (4xx) means unrestricted.
            (Ok(o), _) if (400..500).contains(&o.status) => RobotsFetchOutcome::AllowAll,
            // 5xx, transport failure, timeout, oversize: complete disallow.
            _ => RobotsFetchOutcome::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;
    use crate::caps::{EgressLedger, TokenBucket};
    use crate::indicator::Indicator;
    use crate::policy::SystemClock;
    use crate::resolve::FixedResolver;
    use crate::robots::{RobotsCache, RobotsFetchOutcome, RobotsFetcher};

    /// A stub, used ONLY by the tests whose subject is not robots. INV-7's own
    /// control drives `HttpRobotsFetcher` against the fixture origin — a
    /// fail-closed argument asserted only against an allow-everything stub is
    /// not an argument.
    pub struct AllowAllRobots;

    #[async_trait::async_trait]
    impl RobotsFetcher for AllowAllRobots {
        async fn fetch(&self, _s: Scheme, _t: &PinnedTarget) -> RobotsFetchOutcome {
            RobotsFetchOutcome::AllowAll
        }
    }

    pub fn allowlist_body(host: &str) -> String {
        format!(
            r#"{{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{{"id":1,"host":"{host}",
             "match_mode":"exact","path_scope":"whole_origin","path_prefixes":[],
             "max_requests_per_minute":1000}}]}}"#
        )
    }

    /// The address every fixture policy resolves to.
    ///
    /// A **public** address (RFC 5737 documentation space is denied, so this is
    /// the documented address of the IANA example domain, which the rest of the
    /// crate already uses). Deliberately public rather than loopback, so the
    /// deny-net runs for real on the fetch path instead of being bypassed: a
    /// private answer here would be refused by `resolve_and_pin` exactly as it
    /// is in production.
    pub const FIXTURE_PUBLIC_IP: &str = "93.184.216.34";

    /// The address a request the policy admits will pin to — the public fixture
    /// address on the only plaintext port the gate allows.
    pub fn admitted_dial() -> std::net::SocketAddr {
        std::net::SocketAddr::new(FIXTURE_PUBLIC_IP.parse().unwrap(), 80)
    }

    /// A registry whose dial lands on the fixture origin.
    ///
    /// **The seam is the DIAL, and it is compiled out of production.** The port
    /// gate is `[80, 443]` and a fixture binds an ephemeral port, so a request
    /// the policy would admit cannot reach it. Rather than widen the gate for
    /// tests — which would delete the control — the policy is left to admit an
    /// ordinary public address on port 80, and only the socket is redirected.
    /// Every refusal asserted below is therefore a refusal the production policy
    /// makes on production inputs.
    pub fn registry_for(addr: std::net::SocketAddr) -> Arc<SocketRegistry> {
        let reg = Arc::new(SocketRegistry::new());
        reg.map_dial(admitted_dial(), addr);
        reg
    }

    /// A policy over a fixture origin, with a named ceiling and a chosen robots
    /// fetcher.
    pub fn policy_with(
        host: &str,
        ceiling: u64,
        robots: Box<dyn RobotsFetcher>,
    ) -> (EgressPolicy, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let al = dir.path().join("allowlist.json");
        std::fs::write(&al, allowlist_body(host)).unwrap();
        let (entries, digest) = EgressPolicy::load_entries(&al).unwrap();

        let indicator = Arc::new(Indicator::new());
        indicator.set_live(true, crate::now_unix());

        (
            EgressPolicy::new(
                entries,
                digest,
                Arc::new(FixedResolver::new(vec![FIXTURE_PUBLIC_IP.parse().unwrap()])),
                Arc::new(RobotsCache::new(robots)),
                Arc::new(EgressLedger::new(
                    dir.path().join("egress.json"),
                    ceiling,
                    TokenBucket {
                        rate_bytes_per_sec: 1_000_000_000,
                        capacity_bytes: 1_000_000_000,
                    },
                )),
                indicator,
                Arc::new(SystemClock),
            ),
            dir,
        )
    }

    pub fn policy_with_ceiling(host: &str, ceiling: u64) -> (EgressPolicy, tempfile::TempDir) {
        policy_with(host, ceiling, Box::new(AllowAllRobots))
    }

    pub fn policy_for(host: &str) -> (EgressPolicy, tempfile::TempDir) {
        policy_with_ceiling(host, 2_000_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{
        policy_for, policy_with, policy_with_ceiling, registry_for, AllowAllRobots,
    };
    use super::*;
    use crate::caps::{EgressLedger, TokenBucket};
    use crate::robots::{RobotsCache, RobotsVerdict};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// A fixture origin. Returns its address and a hit counter, so "how many
    /// times did we really go out" is observable rather than inferred.
    async fn origin(
        h: impl Fn(&str) -> (u16, Option<String>, Vec<u8>) + Send + Sync + 'static,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicU32>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let hits2 = Arc::clone(&hits);
        let h = Arc::new(h);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&hits2);
                let h = Arc::clone(&h);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                    hits.fetch_add(1, Ordering::SeqCst);
                    let (status, location, body) = h(&target);
                    let mut head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    );
                    if let Some(l) = location {
                        head.push_str(&format!("Location: {l}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, hits)
    }

    /// An origin that answers with chunked transfer-encoding, splitting `body`
    /// at the given chunk sizes.
    async fn chunked_origin(body: &'static [u8], sizes: &'static [usize]) -> std::net::SocketAddr {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut wire = Vec::new();
                wire.extend_from_slice(
                    b"HTTP/1.1 200 X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                );
                let mut at = 0usize;
                for s in sizes {
                    let end = (at + *s).min(body.len());
                    let piece = &body[at..end];
                    at = end;
                    wire.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                    wire.extend_from_slice(piece);
                    wire.extend_from_slice(b"\r\n");
                }
                wire.extend_from_slice(b"0\r\n\r\n");
                let _ = sock.write_all(&wire).await;
                let _ = sock.shutdown().await;
            }
        });
        addr
    }

    /// An origin that declares `Content-Length: declared` and sends `body`.
    async fn lying_length_origin(body: &'static [u8], declared: usize) -> std::net::SocketAddr {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let head = format!(
                    "HTTP/1.1 200 X\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            }
        });
        addr
    }

    /// An origin that accepts the connection and never answers.
    async fn silent_origin() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        addr
    }

    struct CountingSink {
        bytes: u64,
    }

    impl BodySink for CountingSink {
        fn write(&mut self, chunk: &[u8]) -> Result<(), FetchError> {
            self.bytes += chunk.len() as u64;
            Ok(())
        }
    }

    fn pinned(addr: std::net::SocketAddr, entry_id: u32, host: &str) -> PinnedTarget {
        PinnedTarget {
            entry_id,
            host: host.to_string(),
            port: addr.port(),
            ip: addr.ip(),
        }
    }

    /// A request the port gate admits: `http` on 80, which is where the dial map
    /// puts the fixture.
    fn get(host: &str, path: &str) -> ProxyRequest {
        ProxyRequest {
            scheme: Scheme::Http,
            method: Method::Get,
            host: host.to_string(),
            port: 80,
            path_and_query: path.to_string(),
            hop: 0,
        }
    }

    // -- INV-2: the pin reaches the dial -----------------------------------

    /// Mutations this detects: passing `target.host` to the connect, which would
    /// re-resolve and discard the pin.
    #[tokio::test]
    async fn connect_uses_the_pinned_ip_not_a_second_lookup() {
        let (addr, hits) = origin(|_p| (200, None, b"body-bytes".to_vec())).await;
        let reg = Arc::new(SocketRegistry::new());
        let mut sink = CountingSink { bytes: 0 };
        // The pinned NAME does not resolve anywhere; only the pinned ADDRESS can
        // work. A dial that looked the name up would fail outright.
        let t = pinned(addr, 1, "nonexistent.invalid");
        let counter = Arc::new(AtomicU64::new(0));
        let out = fetch_once(
            &t,
            Scheme::Http,
            &Method::Get,
            "/x",
            &mut sink,
            Arc::clone(&reg),
            Arc::clone(&counter),
        )
        .await
        .expect("the pinned address must connect");

        assert_eq!(out.status, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(sink.bytes, 10);
        assert_eq!(out.body_bytes_to_consumer, 10);
        assert!(counter.load(Ordering::SeqCst) >= 10, "socket bytes counted");
        // POSITIVE CONTROL: the socket count exceeds the body count, so the two
        // numbers are genuinely different quantities and not one field read
        // twice.
        assert!(out.socket_bytes > out.body_bytes_to_consumer);
        assert_eq!(reg.open(), 0, "the socket was not released");
    }

    /// INV-2. The `Host` header is the ALLOWLISTED name, never the pinned
    /// address and never anything the consumer supplied.
    ///
    /// Mutations this detects: `Host` built from `target.ip` or from
    /// `req.host`; the header omitted entirely, which makes every virtual host
    /// answer with its default site.
    #[tokio::test]
    async fn host_header_is_the_allowlisted_name() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = Arc::clone(&seen);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            *seen2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = sock
                .write_all(b"HTTP/1.1 200 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
        });

        let reg = Arc::new(SocketRegistry::new());
        let mut sink = CountingSink { bytes: 0 };
        let t = pinned(addr, 1, "arxiv.org");
        fetch_once(
            &t,
            Scheme::Http,
            &Method::Get,
            "/abs/x",
            &mut sink,
            reg,
            Arc::new(AtomicU64::new(0)),
        )
        .await
        .expect("fetch");

        let req = seen.lock().unwrap().clone();
        assert!(
            req.contains("host: arxiv.org") || req.contains("Host: arxiv.org"),
            "{req}"
        );
        assert!(
            !req.contains("127.0.0.1"),
            "the pinned address leaked into the request: {req}"
        );
    }

    // -- INV-4: every hop is a new request ---------------------------------

    /// The 302 carries a NON-EMPTY body. With an empty one, `sink.bytes == 0`
    /// would be true whether or not the redirect body was forwarded, so the
    /// assertion below could not catch the bug it exists for.
    ///
    /// Mutations this detects: the redirect followed without re-entering
    /// `evaluate`; the redirect's own body forwarded to the consumer.
    #[tokio::test]
    async fn redirect_to_non_allowlisted_host_is_denied() {
        let (addr, _h) = origin(|p| {
            if p == "/abs/start" {
                (
                    302,
                    Some("http://evil.example/loot".into()),
                    b"redirect-body-must-not-reach-the-sink".to_vec(),
                )
            } else {
                (200, None, b"never".to_vec())
            }
        })
        .await;
        let (policy, _d) = policy_for("arxiv.org");
        let mut sink = CountingSink { bytes: 0 };

        let err = fetch_with_redirects(
            &policy,
            get("arxiv.org", "/abs/start"),
            &mut sink,
            registry_for(addr),
        )
        .await
        .expect_err("a redirect off the allowlist must refuse");

        assert_eq!(err, FetchError::Denied(DenyReason::HostNotAllowlisted));
        assert_eq!(
            sink.bytes, 0,
            "no body from the redirect chain may reach the sink"
        );

        // POSITIVE CONTROL: the same fixture without the redirect delivers a
        // body, so the zero above distinguishes two outcomes.
        let (addr2, _h2) = origin(|_p| (200, None, b"delivered".to_vec())).await;
        let (policy2, _d2) = policy_for("arxiv.org");
        let mut sink2 = CountingSink { bytes: 0 };
        fetch_with_redirects(
            &policy2,
            get("arxiv.org", "/abs/start"),
            &mut sink2,
            registry_for(addr2),
        )
        .await
        .expect("the control fetch must succeed");
        assert_eq!(sink2.bytes, 9);
    }

    /// Mutations this detects: the hop counter kept by this loop instead of
    /// inside `evaluate`; `hop` not incremented, which makes the chain endless.
    #[tokio::test]
    async fn every_redirect_hop_reruns_full_evaluate() {
        // A self-redirect chain longer than the hop budget, on an allowlisted
        // host, with a near-zero-byte body — so nothing but the hop bound can
        // stop it.
        let (addr, hits) = origin(|_p| (302, Some("/abs/next".into()), Vec::new())).await;
        let (policy, _d) = policy_for("arxiv.org");
        let mut sink = CountingSink { bytes: 0 };

        let err = fetch_with_redirects(
            &policy,
            get("arxiv.org", "/abs/start"),
            &mut sink,
            registry_for(addr),
        )
        .await
        .expect_err("an endless redirect chain must refuse");

        assert_eq!(err, FetchError::Denied(DenyReason::RedirectHopLimit));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            u32::from(crate::policy::MAX_REDIRECT_HOPS),
            "exactly MAX_REDIRECT_HOPS origin requests, then refusal"
        );
    }

    /// Mutations this detects: a permissive `Location` parser. Each of these is
    /// a silent reinterpretation of attacker-controlled input.
    #[test]
    fn location_parsing_refuses_protocol_relative_userinfo_and_control_bytes() {
        let base = ProxyRequest {
            scheme: Scheme::Https,
            method: Method::Get,
            host: "arxiv.org".into(),
            port: 443,
            path_and_query: "/abs/x".into(),
            hop: 0,
        };
        for bad in [
            "//evil.example/loot",            // protocol-relative: NOT a path
            "http://a@b/",                    // userinfo
            "http://a:b@c/",                  // userinfo with a colon
            "http://arxiv.org@evil.example/", // the allowlisted name as userinfo
            "http://evil.example@arxiv.org/", // the allowlisted name as host, attacker as userinfo
            "http://x\r\nX: y/",              // control bytes
            "http://ev il.example/",          // whitespace in the authority
            "///triple",                      // more than one leading slash
        ] {
            assert!(
                next_request(&base, bad).is_err(),
                "{bad} must be refused, not reinterpreted"
            );
        }
        // POSITIVE CONTROL: the two accepted shapes still parse.
        assert!(next_request(&base, "/next").is_ok());
        assert!(next_request(&base, "https://arxiv.org/next").is_ok());
    }

    // -- INV-9: the ceiling binds mid-stream -------------------------------

    /// The daily ceiling enforced mid-stream, not just at admission.
    ///
    /// Mutations this detects: the budget checked only in `evaluate`, so a
    /// single large response blows through the cap; the abort implemented by
    /// ceasing to READ rather than by dropping the socket, which leaves the
    /// transfer running at the origin's pace.
    #[tokio::test]
    async fn daily_ceiling_aborts_an_in_flight_transfer() {
        let (addr, _h) = origin(|_p| (200, None, vec![b'x'; 2_000_000])).await;
        // The band's floor is 1 GB, so the ledger is spent down to a small
        // remainder rather than constructed with a small ceiling.
        let (policy, _d) = policy_with_ceiling("arxiv.org", crate::caps::MIN_DAILY_BYTE_CAP);
        policy
            .budget()
            .spend(crate::caps::MIN_DAILY_BYTE_CAP - 50_000, crate::now_unix())
            .expect("pre-spend");

        let reg = registry_for(addr);
        let mut sink = CountingSink { bytes: 0 };
        let err = fetch_with_redirects(
            &policy,
            get("arxiv.org", "/abs/big"),
            &mut sink,
            Arc::clone(&reg),
        )
        .await
        .expect_err("the transfer must be aborted");

        assert_eq!(err, FetchError::Denied(DenyReason::DailyCeilingExceeded));
        assert!(
            sink.bytes < 2_000_000,
            "the transfer completed anyway: {} bytes reached the sink",
            sink.bytes
        );
        assert_eq!(reg.open(), 0, "the aborted connection must be closed");

        // POSITIVE CONTROL: the same origin, with budget left, delivers the
        // whole body — so the assertion above distinguishes two outcomes.
        let (policy2, _d2) = policy_with_ceiling("arxiv.org", 2_000_000_000);
        let mut sink2 = CountingSink { bytes: 0 };
        let out = fetch_with_redirects(
            &policy2,
            get("arxiv.org", "/abs/big"),
            &mut sink2,
            registry_for(addr),
        )
        .await
        .expect("the control fetch must complete");
        assert_eq!(out.body_bytes_to_consumer, 2_000_000);
        assert_eq!(sink2.bytes, 2_000_000);
    }

    /// INV-9's other half: a ledger this process cannot read refuses, and it
    /// refuses with its own reason rather than as a spent ceiling.
    ///
    /// Mutations this detects: `CapError::Unavailable` folded into
    /// `DailyCeilingExceeded`, which tells the operator to wait for UTC midnight
    /// for a problem that midnight will not fix.
    #[tokio::test]
    async fn a_corrupt_budget_refuses_service_rather_than_granting_it() {
        let (addr, hits) = origin(|_p| (200, None, b"never".to_vec())).await;
        let (policy, _d) = policy_with_ceiling("arxiv.org", 2_000_000_000);
        std::fs::write(policy.budget().path(), "{ truncated").expect("corrupt the ledger");

        let err = fetch_with_redirects(
            &policy,
            get("arxiv.org", "/abs/x"),
            &mut CountingSink { bytes: 0 },
            registry_for(addr),
        )
        .await
        .expect_err("a corrupt ledger must refuse");
        assert_eq!(err, FetchError::Denied(DenyReason::BudgetUnavailable));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a corrupt ledger must open ZERO sockets"
        );

        // POSITIVE CONTROL: removing the corruption lets the same request
        // through, so the refusal is the ledger's and not the fixture's.
        std::fs::remove_file(policy.budget().path()).expect("clear the ledger");
        assert!(fetch_with_redirects(
            &policy,
            get("arxiv.org", "/abs/x"),
            &mut CountingSink { bytes: 0 },
            registry_for(addr),
        )
        .await
        .is_ok());
    }

    // -- INV-17: the metered quantity --------------------------------------

    /// Mutations this detects: `parse_head` ignoring `Transfer-Encoding`, so hex
    /// chunk-size lines and CRLF terminators are forwarded to the consumer AS
    /// CONTENT and counted as paid bytes — which a hostile or colluding origin
    /// inflates for free, and which makes a truncated response indistinguishable
    /// from a complete one.
    #[tokio::test]
    async fn chunked_framing_bytes_are_never_metered() {
        const BODY: &[u8] = b"hello, world";
        let addr = chunked_origin(BODY, &[5, 7]).await;
        let reg = Arc::new(SocketRegistry::new());
        let mut sink = CountingSink { bytes: 0 };
        let t = pinned(addr, 1, "arxiv.org");
        let counter = Arc::new(AtomicU64::new(0));

        let out = fetch_once(
            &t,
            Scheme::Http,
            &Method::Get,
            "/x",
            &mut sink,
            reg,
            Arc::clone(&counter),
        )
        .await
        .expect("fetch");

        assert_eq!(out.status, 200);
        assert_eq!(
            sink.bytes,
            BODY.len() as u64,
            "only DECODED body bytes may be metered"
        );
        assert_eq!(out.body_bytes_to_consumer, BODY.len() as u64);
        // POSITIVE CONTROL: the socket really did carry more than the body, so
        // the assertion above is distinguishing two different numbers.
        assert!(
            counter.load(Ordering::SeqCst) > BODY.len() as u64,
            "the fixture did not actually send chunk framing"
        );
    }

    /// Step 4b's cross-process pin.
    ///
    /// Mutations this detects: the node's meter drifting onto the socket seam,
    /// which `fixtures/metered-quantity.json` records as the WRONG seam by
    /// name — the gateway compares at exact equality with no tolerance, so a
    /// seam change is a forfeited bond rather than a red test unless this file
    /// pins it.
    #[tokio::test]
    async fn node_and_gateway_pin_the_same_metered_quantity_for_a_known_payload() {
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures")
                    .join("metered-quantity.json"),
            )
            .expect("the metered-quantity fixture must exist"),
        )
        .expect("fixture parses");

        assert_eq!(
            fixture["metered_quantity"].as_str().unwrap(),
            "body_bytes_to_consumer"
        );
        let want: u64 = fixture["body_bytes_to_consumer"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let sizes: Vec<usize> = fixture["chunk_sizes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(sizes.iter().sum::<usize>() as u64, want);

        // The same payload, over the wire, through the real decoder.
        const PAYLOAD: [u8; 9_529] = [b'g'; 9_529];
        static SIZES: [usize; 3] = [4096, 4096, 1337];
        assert_eq!(PAYLOAD.len() as u64, want);
        assert_eq!(SIZES.to_vec(), sizes);

        let addr = chunked_origin(&PAYLOAD, &SIZES).await;
        let mut sink = CountingSink { bytes: 0 };
        let counter = Arc::new(AtomicU64::new(0));
        let out = fetch_once(
            &pinned(addr, 1, "arxiv.org"),
            Scheme::Http,
            &Method::Get,
            "/x",
            &mut sink,
            Arc::new(SocketRegistry::new()),
            Arc::clone(&counter),
        )
        .await
        .expect("fetch");

        assert_eq!(out.body_bytes_to_consumer, want);
        assert_eq!(
            out.body_bytes_to_consumer,
            fixture["gateway_to_consumer"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            "the node and the gateway must pin ONE number"
        );
        // NEGATIVE CONTROL: the socket seam is a DIFFERENT number, which is why
        // the fixture records it as the wrong seam.
        assert!(counter.load(Ordering::SeqCst) > want);
        assert_ne!(out.socket_bytes, out.body_bytes_to_consumer);
    }

    /// Mutations this detects: `Content-Length` parsed and discarded, so a
    /// truncated response is accepted as complete and paid for; and a response
    /// declaring BOTH framings being accepted, which is a request-smuggling
    /// shape.
    #[tokio::test]
    async fn a_response_whose_length_disagrees_with_its_body_is_refused() {
        let addr = lying_length_origin(b"short", 500).await;
        let mut sink = CountingSink { bytes: 0 };
        let err = fetch_once(
            &pinned(addr, 1, "arxiv.org"),
            Scheme::Http,
            &Method::Get,
            "/x",
            &mut sink,
            Arc::new(SocketRegistry::new()),
            Arc::new(AtomicU64::new(0)),
        )
        .await
        .expect_err("a truncated body must not read as complete");
        assert_eq!(err, FetchError::MalformedResponse);

        // The over-long direction too: more body than was declared.
        let addr2 = lying_length_origin(b"far too much body", 3).await;
        assert_eq!(
            fetch_once(
                &pinned(addr2, 1, "arxiv.org"),
                Scheme::Http,
                &Method::Get,
                "/x",
                &mut CountingSink { bytes: 0 },
                Arc::new(SocketRegistry::new()),
                Arc::new(AtomicU64::new(0)),
            )
            .await
            .expect_err("an over-long body must refuse"),
            FetchError::MalformedResponse
        );

        // And a response declaring BOTH framings.
        let both =
            parse_head("HTTP/1.1 200 X\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert!(matches!(both, Err(FetchError::MalformedResponse)));

        // POSITIVE CONTROL: an honest length is accepted, so the parser is not
        // simply refusing everything.
        let addr3 = lying_length_origin(b"exact", 5).await;
        let out = fetch_once(
            &pinned(addr3, 1, "arxiv.org"),
            Scheme::Http,
            &Method::Get,
            "/x",
            &mut CountingSink { bytes: 0 },
            Arc::new(SocketRegistry::new()),
            Arc::new(AtomicU64::new(0)),
        )
        .await
        .expect("an honest length must be accepted");
        assert_eq!(out.body_bytes_to_consumer, 5);
    }

    // -- INV-7: the REAL robots fetcher ------------------------------------

    /// INV-7's own control, driven through `HttpRobotsFetcher` rather than a
    /// stub. Every other robots test injects a component that allows
    /// everything, so without this the whole fail-closed argument would be
    /// asserted against something that never fetched.
    ///
    /// Mutations this detects: 5xx mapped to `AllowAll`; the oversize guard
    /// dropped; a synchronous `fetch` that panics inside a runtime.
    #[tokio::test]
    async fn the_real_http_robots_fetcher_honours_rfc9309_against_a_live_fixture_origin() {
        let reg = Arc::new(SocketRegistry::new());
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(EgressLedger::new(
            dir.path().join("egress.json"),
            2_000_000_000,
            TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        ));
        let fetcher = HttpRobotsFetcher::new(Arc::clone(&reg), Arc::clone(&ledger));

        // 200 with a Disallow.
        let (a200, _) =
            origin(|_p| (200, None, b"User-agent: *\nDisallow: /private/\n".to_vec())).await;
        assert_eq!(
            fetcher
                .fetch(Scheme::Http, &pinned(a200, 1, "arxiv.org"))
                .await,
            RobotsFetchOutcome::Body("User-agent: *\nDisallow: /private/\n".into())
        );

        // 4xx => unrestricted.
        let (a404, _) = origin(|_p| (404, None, b"nope".to_vec())).await;
        assert_eq!(
            fetcher
                .fetch(Scheme::Http, &pinned(a404, 1, "arxiv.org"))
                .await,
            RobotsFetchOutcome::AllowAll
        );

        // 5xx => complete disallow.
        let (a503, _) = origin(|_p| (503, None, b"down".to_vec())).await;
        assert_eq!(
            fetcher
                .fetch(Scheme::Http, &pinned(a503, 1, "arxiv.org"))
                .await,
            RobotsFetchOutcome::Unavailable
        );

        // Transport failure => complete disallow. Port 1 on loopback refuses.
        assert_eq!(
            fetcher
                .fetch(
                    Scheme::Http,
                    &PinnedTarget {
                        entry_id: 1,
                        host: "arxiv.org".into(),
                        port: 1,
                        ip: "127.0.0.1".parse().unwrap(),
                    }
                )
                .await,
            RobotsFetchOutcome::Unavailable
        );

        // Oversize => complete disallow.
        let (big, _) =
            origin(|_p| (200, None, vec![b'#'; crate::robots::MAX_ROBOTS_BYTES + 1])).await;
        assert_eq!(
            fetcher
                .fetch(Scheme::Http, &pinned(big, 1, "arxiv.org"))
                .await,
            RobotsFetchOutcome::Unavailable
        );

        // And the whole thing wired through a cache, over the real fetcher: the
        // disallowed prefix is refused and the rest is allowed.
        let cache = RobotsCache::new(Box::new(HttpRobotsFetcher::new(reg, ledger)));
        let t = pinned(a200, 1, "arxiv.org");
        assert_eq!(
            cache
                .allows(Scheme::Http, &t, "/private/x", crate::now_unix())
                .await,
            RobotsVerdict::Disallowed
        );
        assert_eq!(
            cache
                .allows(Scheme::Http, &t, "/public/x", crate::now_unix())
                .await,
            RobotsVerdict::Allowed
        );
    }

    /// INV-7's budget half.
    ///
    /// Mutations this detects: the robots fetch left undebited, which makes it
    /// an uncapped path — and, because the cache refetches on a TTL, a
    /// recurring one.
    #[tokio::test]
    async fn robots_bytes_are_debited_against_the_daily_ceiling() {
        let (addr, _) = origin(|_p| (200, None, vec![b'#'; 100_000])).await;
        let reg = Arc::new(SocketRegistry::new());
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(EgressLedger::new(
            dir.path().join("egress.json"),
            crate::caps::MIN_DAILY_BYTE_CAP,
            TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        ));
        // Spend the ceiling down to fewer bytes than the robots body needs.
        let now = crate::now_unix();
        ledger
            .spend(crate::caps::MIN_DAILY_BYTE_CAP - 10_000, now)
            .expect("pre-spend");
        let before = ledger.spent_today(now).expect("read");

        let fetcher = HttpRobotsFetcher::new(reg, Arc::clone(&ledger));
        let outcome = fetcher
            .fetch(Scheme::Http, &pinned(addr, 1, "arxiv.org"))
            .await;

        // The debit was refused, so RFC 9309 §2.3.1's unreachable branch fires:
        // running out of budget CLOSES egress rather than opening it.
        assert_eq!(outcome, RobotsFetchOutcome::Unavailable);
        // And the ledger is now closed for the day, so the next request refuses.
        assert_eq!(
            ledger.spend(1, now),
            Err(CapError::DailyCeilingReached),
            "the robots fetch did not close the day it overran"
        );
        assert!(
            ledger.spent_today(now).expect("read") > before,
            "the robots bytes went undebited"
        );

        // POSITIVE CONTROL: with budget available, the same fetch succeeds and
        // the ledger moves by roughly the body size.
        let dir2 = tempfile::tempdir().unwrap();
        let ledger2 = Arc::new(EgressLedger::new(
            dir2.path().join("egress.json"),
            2_000_000_000,
            TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        ));
        let ok = HttpRobotsFetcher::new(Arc::new(SocketRegistry::new()), Arc::clone(&ledger2));
        assert!(matches!(
            ok.fetch(Scheme::Http, &pinned(addr, 1, "arxiv.org")).await,
            RobotsFetchOutcome::Body(_)
        ));
        assert!(
            ledger2.spent_today(now).expect("read") >= 100_000,
            "the robots bytes were not charged on the success path either"
        );
    }

    /// INV-7 end to end through `evaluate`: a disallowed path is refused even
    /// though the entry's scope is the whole origin and the consumer asked for
    /// it explicitly.
    #[tokio::test]
    async fn disallowed_path_refused_regardless_of_consumer_instruction() {
        let (addr, _) = origin(|p| {
            if p == "/robots.txt" {
                (200, None, b"User-agent: *\nDisallow: /private/\n".to_vec())
            } else {
                (200, None, b"leaked".to_vec())
            }
        })
        .await;
        let reg = registry_for(addr);
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(EgressLedger::new(
            dir.path().join("robots-egress.json"),
            2_000_000_000,
            TokenBucket {
                rate_bytes_per_sec: 1_000_000_000,
                capacity_bytes: 1_000_000_000,
            },
        ));
        let (policy, _d) = policy_with(
            "arxiv.org",
            2_000_000_000,
            Box::new(HttpRobotsFetcher::new(Arc::clone(&reg), ledger)),
        );

        let mut sink = CountingSink { bytes: 0 };
        let err = fetch_with_redirects(
            &policy,
            get("arxiv.org", "/private/secret"),
            &mut sink,
            Arc::clone(&reg),
        )
        .await
        .expect_err("robots must refuse");
        assert_eq!(err, FetchError::Denied(DenyReason::RobotsDisallowed));
        assert_eq!(sink.bytes, 0);

        // POSITIVE CONTROL: a path outside the disallowed prefix is delivered,
        // so the refusal is the rule's and not a blanket one.
        let mut sink2 = CountingSink { bytes: 0 };
        fetch_with_redirects(&policy, get("arxiv.org", "/public/ok"), &mut sink2, reg)
            .await
            .expect("the allowed path must be delivered");
        assert_eq!(sink2.bytes, 6);
    }

    // -- INV-10: the kill switch stops a transfer --------------------------

    /// Mutations this detects: the halt implemented by ceasing to READ rather
    /// than by dropping the socket, which leaves the connection open and the
    /// origin sending.
    #[tokio::test]
    async fn a_halt_aborts_an_in_flight_fetch_and_closes_the_socket() {
        let addr = silent_origin().await;
        let reg = Arc::new(SocketRegistry::new());
        let reg2 = Arc::clone(&reg);

        let fetching = tokio::spawn(async move {
            fetch_once(
                &PinnedTarget {
                    entry_id: 1,
                    host: "arxiv.org".into(),
                    port: addr.port(),
                    ip: addr.ip(),
                },
                Scheme::Http,
                &Method::Get,
                "/never-answers",
                &mut CountingSink { bytes: 0 },
                Arc::clone(&reg2),
                Arc::new(AtomicU64::new(0)),
            )
            .await
        });

        // Let the dial land, then halt.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(reg.open(), 1, "the fixture did not hold a socket open");
        let report = reg.halt_and_wait(crate::net::KILL_DEADLINE).await;

        let out = tokio::time::timeout(Duration::from_secs(5), fetching)
            .await
            .expect("the fetch did not abort inside the deadline")
            .expect("join");
        assert_eq!(out, Err(FetchError::Halted));
        assert_eq!(report.open_sockets_after, 0, "the socket was not closed");
        assert!(report.within_deadline());
        assert_eq!(reg.open(), 0);
    }

    // -- INV-11: nothing here can carry content ---------------------------

    /// Mutations this detects: a `String` payload added to `FetchError` or to
    /// `DenyReason`; a refusal built with `format!("{path} was refused")`.
    #[tokio::test]
    async fn a_refusal_carries_no_path_query_or_header_in_any_rendering() {
        let (addr, _) = origin(|_p| (200, None, b"x".to_vec())).await;
        let (policy, _d) = policy_for("arxiv.org");

        // Markers that appear in the REQUEST, and one that appears only in the
        // attacker-controlled `Location` the redirect carries.
        const REQUEST_MARKERS: [&str; 3] = ["s3cr3t-path", "token=abcdef", "arxiv.org"];
        const LOCATION_MARKER: &str = "X-Private-Header";
        let req = get("arxiv.org", "/s3cr3t-path/x?token=abcdef");
        let _ = addr;

        // A refusal caused by a redirect off the allowlist, so the error is
        // produced deep inside the loop rather than at admission.
        let (addr2, _) = origin(|_p| {
            (
                302,
                Some("http://evil.example/X-Private-Header".into()),
                b"body".to_vec(),
            )
        })
        .await;
        let (policy2, _d2) = policy_for("arxiv.org");
        let err = fetch_with_redirects(
            &policy2,
            get("arxiv.org", "/s3cr3t-path/x?token=abcdef"),
            &mut CountingSink { bytes: 0 },
            registry_for(addr2),
        )
        .await
        .expect_err("refusal");

        let rendered = format!("{err:?}");
        for marker in REQUEST_MARKERS.iter().copied().chain([LOCATION_MARKER]) {
            assert!(
                !rendered.contains(marker),
                "the refusal leaked {marker:?}: {rendered}"
            );
        }

        // POSITIVE CONTROL: the markers really are in the values that produced
        // the refusal, and the scanner can see them when they are present.
        // Without this the assertions above also pass against a scanner looking
        // for strings nothing ever contained.
        let request_rendering = format!("{req:?}");
        for marker in REQUEST_MARKERS {
            assert!(
                request_rendering.contains(marker),
                "the control does not contain {marker:?}; this test proves nothing"
            );
        }
        assert!(format!("http://evil.example/{LOCATION_MARKER}").contains(LOCATION_MARKER));

        // And the policy's own decision is likewise clean.
        assert!(!format!("{:?}", policy.evaluate(&req).await).contains("s3cr3t-path"));
    }

    /// INV-11's source half, as a second independent sweep.
    ///
    /// Two rules, and the difference between them is the whole discipline:
    ///
    /// * **Nothing at all, anywhere.** A `println!`, an `eprintln!`, a `dbg!`
    ///   or a `log` macro is a place a URL reaches a terminal or a file with no
    ///   type between it and the string. Those are refused in every production
    ///   source without exception, `logging.rs` included.
    /// * **The facade, in one module.** The `tracing` macros are permitted only
    ///   in `logging.rs`, where every call site takes a `SafeEvent` field whose
    ///   type cannot hold free text. A second module reaching for the facade
    ///   directly is what this arm refuses.
    ///
    /// `logging.rs` carries the same rule from the other side
    /// (`only_logging_module_calls_tracing_macros`); two sweeps with two floors
    /// is two chances to notice a truncating pre-filter.
    ///
    /// Mutations this detects: a debug print added to production code; the
    /// facade called directly from `policy.rs` with a path in it; the
    /// `logging.rs` exemption widened to a prefix or to a second file.
    #[test]
    fn no_production_source_emits_a_log_line() {
        use std::path::PathBuf;

        // Assembled at runtime so this file does not itself contain the tokens
        // it forbids in production text.
        let forbidden_everywhere = [
            format!("{}{}", "print", "ln!"),
            format!("{}{}", "eprint", "ln!"),
            format!("{}{}", "db", "g!"),
            format!("{}{}", "log", "::warn"),
        ];
        // Permitted in exactly one module, and refused in every other.
        let facade = format!("{}{}", "tracing", "::");
        // POSITIVE CONTROL: the scanner can see every token in a string that has
        // them. A scanner with too small an alphabet reports a clean sweep.
        let control = format!("{} {facade}", forbidden_everywhere.join(" "));
        for t in forbidden_everywhere.iter().chain([&facade]) {
            assert!(control.contains(t.as_str()), "the scanner cannot see {t}");
        }
        // NEGATIVE CONTROL for the facade token: the subscriber's crate name is
        // NOT the facade, because `tracing_subscriber::` has no `::` after
        // `tracing`. Without this the exemption would have to be widened to a
        // second file for no reason.
        assert!(
            !format!("{}{}", "tracing_subscriber", "::fmt()").contains(facade.as_str()),
            "the facade scanner fires on the subscriber crate, which is not the facade"
        );

        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut swept_files = 0usize;
        let mut swept_bytes = 0usize;
        let mut facade_sites = 0usize;
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            // Strip only the TRAILING test module, never from the first
            // `#[cfg(test)]`: this file's own `tests_support` sits above the
            // tests and stripping from there would blank most of the file while
            // leaving the count unchanged.
            let marker = "\n#[cfg(test)]\nmod tests {";
            let prod = match text.rfind(marker) {
                Some(i) => &text[..i],
                None => &text[..],
            };
            swept_files += 1;
            swept_bytes += prod.len();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            for token in &forbidden_everywhere {
                assert!(
                    !prod.contains(token.as_str()),
                    "{name} emits {token} in production code; nothing in this crate may write a \
                     line that could carry a URL, a path, a query string or a header"
                );
            }
            let hits = prod.matches(facade.as_str()).count();
            if hits > 0 {
                facade_sites += hits;
                assert_eq!(
                    name, "logging.rs",
                    "{name} calls the logging facade directly; route it through logging::emit, \
                     whose field types cannot hold free text"
                );
            }
        }
        // POSITIVE CONTROL for the facade arm: the one permitted module really
        // does use it. Without this, deleting every call site would read as a
        // clean sweep.
        assert!(
            facade_sites >= 8,
            "found only {facade_sites} logging call sites; the scanner is broken or the facade \
             has been abandoned"
        );
        assert_eq!(
            swept_files, WORKER_SRC_FILES_AT_THIS_TASK,
            "swept {swept_files} file(s); raise WORKER_SRC_FILES_AT_THIS_TASK in the commit that \
             adds one"
        );
        assert!(
            swept_bytes >= MIN_SWEPT_PRODUCTION_BYTES,
            "swept only {swept_bytes} byte(s) of production text; the sweep is reading almost \
             nothing"
        );
    }

    /// Raised in the same commit as the task that adds the next source file.
    /// Kept beside `policy.rs`'s copy deliberately: two sweeps with two floors
    /// is two chances to notice a truncating pre-filter.
    ///
    /// 11 -> 16 across Tasks 34-35: `logging.rs`, `supervisor.rs`,
    /// `vocabulary_audit.rs` and `main.rs` land in Task 34 and `meter.rs` in
    /// Task 35. 16 -> 17 with `destinations.rs`, which carries the canonical
    /// slug <-> id table the second founder ruling requires.
    const WORKER_SRC_FILES_AT_THIS_TASK: usize = 17;
    /// Measured 224_788 bytes of production text across those sixteen files
    /// after Tasks 34-35. The floor sits below the measurement and above the
    /// largest single file (policy.rs, 39_422), so a pre-filter that blanked
    /// even the biggest one is caught here.
    const MIN_SWEPT_PRODUCTION_BYTES: usize = 170_000;

    /// The stub is used, and its use is confined to the tests whose subject is
    /// not robots.
    #[tokio::test]
    async fn the_allow_all_robots_stub_is_a_stub_and_says_so() {
        let s = AllowAllRobots;
        assert_eq!(
            s.fetch(
                Scheme::Http,
                &pinned("127.0.0.1:80".parse().unwrap(), 1, "h")
            )
            .await,
            RobotsFetchOutcome::AllowAll
        );
    }

    /// INV-5, at the request line.
    ///
    /// Mutations this detects: the method token taken from
    /// `Method::Other(String)`, which would let a consumer name the tunnelling
    /// method and have this node put it on the wire — the whole opaque-relay
    /// class, reachable past a policy that was never consulted.
    #[tokio::test]
    async fn a_method_this_node_does_not_speak_never_reaches_the_request_line() {
        let (addr, hits) = origin(|_p| (200, None, b"never".to_vec())).await;
        let t = pinned(addr, 1, "arxiv.org");

        // Assembled at runtime, so this file does not contain the token it
        // forbids.
        let tunnelling = format!("{}{}", "CONN", "ECT");
        for (m, want) in [
            (
                Method::Other(tunnelling.clone()),
                DenyReason::MethodNotAllowed,
            ),
            (Method::Other("TRACE".into()), DenyReason::MethodNotAllowed),
            (Method::Post, DenyReason::RequestBodyNotPermitted),
        ] {
            assert_eq!(
                fetch_once(
                    &t,
                    Scheme::Http,
                    &m,
                    "/x",
                    &mut CountingSink { bytes: 0 },
                    Arc::new(SocketRegistry::new()),
                    Arc::new(AtomicU64::new(0)),
                )
                .await,
                Err(FetchError::Denied(want)),
                "{m:?} was not refused"
            );
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a refused method opened a socket and reached the origin"
        );

        // POSITIVE CONTROL: the two methods this node does speak still work, so
        // the loop above is not passing against a client that refuses
        // everything.
        for m in [Method::Get, Method::Head] {
            assert!(fetch_once(
                &t,
                Scheme::Http,
                &m,
                "/x",
                &mut CountingSink { bytes: 0 },
                Arc::new(SocketRegistry::new()),
                Arc::new(AtomicU64::new(0)),
            )
            .await
            .is_ok());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
