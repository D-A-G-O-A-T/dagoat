//! The socket registry, the metered stream, and the kill switch's in-process
//! half.
//!
//! # Every socket this crate opens goes through here
//!
//! [`SocketRegistry::connect`] is the only place a socket is created, so
//! [`SocketRegistry::open`] is a count of what is actually outstanding rather
//! than an estimate maintained by whoever remembered to increment it. The
//! decrement is a `Drop` on [`TrackedStream`], which means it also fires on the
//! panic and early-return paths that a hand-written decrement misses.
//!
//! There is no accept half. The registry dials a [`SocketAddr`]; there is no
//! bind, no accept, and no name — the address arrived already validated and
//! pinned by the policy, and a name here would be a second lookup for a
//! rebinding answer to win.
//!
//! # The in-process count is NOT the halt evidence
//!
//! [`SocketRegistry::halt_and_wait`] returns what this process believes. The
//! number that goes into a halt receipt is the **operating system's** answer,
//! read by `census::egress_socket_census` — because a counter is a field the
//! reporter assigns to itself, and INV-10 exists precisely to refuse that. The
//! two are cross-checked in the census module's own control.
//!
//! # `KILL_DEADLINE_MS` is imported, not redeclared
//!
//! It is re-exported below from `goat_proxy_tunnel::lifecycle`, which declares
//! it once. Two crates that must halt together on one deadline cannot each own a
//! copy of the number: a five-second deadline that is 5 000 in one and 5 in the
//! other is not caught by any test either crate can write alone.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 32 and its Security invariants section (INV-5, INV-10); and the
//! "Residential Proxy Network (P3) Implementation Plan", §4.1 (the kill-deadline
//! row).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;

/// The one declaration of the kill deadline, imported. See the module header.
pub use goat_proxy_tunnel::lifecycle::{KILL_DEADLINE, KILL_DEADLINE_MS};

/// What a halt observed, from this process's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaltReport {
    pub elapsed_ms: u64,
    /// This process's own count. The receipt's number comes from the OS census;
    /// see the module header.
    pub open_sockets_after: usize,
}

impl HaltReport {
    /// Did the halt complete inside [`KILL_DEADLINE`]?
    pub fn within_deadline(&self) -> bool {
        self.elapsed_ms <= KILL_DEADLINE_MS && self.open_sockets_after == 0
    }
}

/// Counts open sockets and owns the halt signal.
#[derive(Debug, Default)]
pub struct SocketRegistry {
    open: AtomicUsize,
    halted: AtomicBool,
    cancel: Arc<Notify>,
    /// **Test-only, and compiled out of every production build.**
    ///
    /// The port gate is `[80, 443]` and a test origin binds an ephemeral port,
    /// so a fixture on `127.0.0.1:54321` cannot be reached by a request the
    /// policy would admit. This is the same class of problem as the deny-net's
    /// (`resolve_and_pin` correctly refuses loopback, so the resolver is the
    /// seam), and it gets the same class of answer: the **dial** is the seam,
    /// and it is replaced only under `cfg(test)`.
    ///
    /// It is a map on **this registry instance**, not a global, so two tests
    /// running concurrently cannot see each other's entries. It changes no
    /// policy decision: `evaluate` still admits or refuses exactly what it would
    /// in production, and only the socket lands somewhere else.
    #[cfg(test)]
    dial_map: std::sync::Mutex<std::collections::HashMap<SocketAddr, SocketAddr>>,
}

impl SocketRegistry {
    pub fn new() -> Self {
        Self {
            open: AtomicUsize::new(0),
            halted: AtomicBool::new(false),
            cancel: Arc::new(Notify::new()),
            #[cfg(test)]
            dial_map: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// See [`SocketRegistry::dial_map`]. Test-only.
    #[cfg(test)]
    pub(crate) fn map_dial(&self, from: SocketAddr, to: SocketAddr) {
        self.dial_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(from, to);
    }

    #[cfg(test)]
    fn dial_target(&self, addr: SocketAddr) -> SocketAddr {
        self.dial_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&addr)
            .copied()
            .unwrap_or(addr)
    }

    #[cfg(not(test))]
    #[inline]
    fn dial_target(&self, addr: SocketAddr) -> SocketAddr {
        addr
    }

    /// Dial a **pinned** address.
    ///
    /// Takes a `SocketAddr` and nothing else. There is no overload taking a
    /// name, deliberately: the policy already resolved and validated the
    /// address, and a name here would be a second lookup with nothing checking
    /// its answer.
    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> io::Result<TrackedStream> {
        if self.is_halted() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the kill switch is engaged",
            ));
        }
        let stream = TcpStream::connect(self.dial_target(addr)).await?;
        // Registered only after the connect succeeds, so a failed dial does not
        // leave a phantom socket in the count.
        self.open.fetch_add(1, Ordering::SeqCst);
        Ok(TrackedStream {
            inner: stream,
            registry: Arc::clone(self),
        })
    }

    /// How many sockets this process believes it has open.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// The halt signal. `cancelled().notified()` resolves when a halt begins.
    pub fn cancelled(&self) -> Arc<Notify> {
        Arc::clone(&self.cancel)
    }

    /// Sticky: once engaged, never cleared. A kill switch that can be
    /// un-engaged from inside the process it kills is not a kill switch.
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// Engage the kill switch and wait for the in-flight sockets to drain.
    ///
    /// Every waiter is woken, so an in-flight `fetch_once` returns
    /// `FetchError::Halted` rather than running to completion. The wait is
    /// bounded: past `deadline` the report carries whatever is still open, and
    /// the caller reports that rather than a zero it did not observe.
    pub async fn halt_and_wait(&self, deadline: Duration) -> HaltReport {
        let started = Instant::now();
        self.halted.store(true, Ordering::SeqCst);
        self.cancel.notify_waiters();

        while started.elapsed() < deadline {
            if self.open() == 0 {
                break;
            }
            // Re-notified on each pass: a task that began awaiting after the
            // first `notify_waiters` would otherwise never be woken.
            self.cancel.notify_waiters();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        HaltReport {
            elapsed_ms: started.elapsed().as_millis() as u64,
            open_sockets_after: self.open(),
        }
    }
}

/// A socket that decrements the registry when it is dropped.
#[derive(Debug)]
pub struct TrackedStream {
    inner: TcpStream,
    registry: Arc<SocketRegistry>,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.registry.open.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Counts every byte crossing a stream, in **both** directions.
///
/// This is the **socket** count: for HTTPS it includes TLS records, MACs, the
/// handshake and the outbound request. It is the byte budget's debit source and
/// a transport diagnostic, and it is explicitly **not** the payout quantity —
/// that is `body_bytes_to_consumer`, counted after framing is stripped (§4.1,
/// INV-17). Charging the operator's ceiling on socket bytes and paying on body
/// bytes is deliberate: the operator's line carries the former.
#[derive(Debug)]
pub struct MeteredStream<S> {
    inner: S,
    counter: Arc<AtomicU64>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, counter: Arc<AtomicU64>) -> Self {
        Self { inner, counter }
    }

    /// Total bytes observed in both directions.
    pub fn observed(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let read = buf.filled().len().saturating_sub(before);
            self.counter.fetch_add(read as u64, Ordering::SeqCst);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.counter.fetch_add(*n as u64, Ordering::SeqCst);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// §4.1's kill-deadline row, pinned in both spellings.
    ///
    /// Mutations this detects: the deadline redeclared in this crate with a
    /// different value; `Duration::from_secs(KILL_DEADLINE_MS)`, which is 5 000
    /// seconds; the retired `HALT_DEADLINE_MS` name reappearing.
    #[test]
    fn kill_deadline_is_five_seconds() {
        assert_eq!(KILL_DEADLINE_MS, 5_000);
        assert_eq!(KILL_DEADLINE, Duration::from_millis(KILL_DEADLINE_MS));
        assert_eq!(KILL_DEADLINE, Duration::from_millis(5_000));
        assert_eq!(KILL_DEADLINE.as_secs(), 5);

        // The value is the tunnel's, not a second copy that happens to agree
        // today. Re-imported here under its full path so a divergent local
        // declaration would be a compile error rather than a silent shadow.
        assert_eq!(
            KILL_DEADLINE_MS,
            goat_proxy_tunnel::lifecycle::KILL_DEADLINE_MS
        );
        assert_eq!(KILL_DEADLINE, goat_proxy_tunnel::lifecycle::KILL_DEADLINE);
    }

    /// Mutations this detects: the decrement written at the call site instead of
    /// in `Drop`, which misses every early return and every panic; the increment
    /// placed before the connect, which counts sockets a failed dial never
    /// opened.
    #[tokio::test]
    async fn the_registry_counts_what_it_opened_and_forgets_what_it_dropped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let reg = Arc::new(SocketRegistry::new());
        assert_eq!(reg.open(), 0);

        let a = reg.connect(addr).await.expect("dial");
        assert_eq!(reg.open(), 1);
        let b = reg.connect(addr).await.expect("dial");
        assert_eq!(reg.open(), 2);
        drop(a);
        assert_eq!(reg.open(), 1);
        drop(b);
        assert_eq!(reg.open(), 0);

        // NEGATIVE CONTROL: a dial that FAILS must not be counted. Port 1 on
        // loopback with nothing bound refuses immediately.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let _ = reg.connect(dead).await;
        assert_eq!(reg.open(), 0, "a failed dial was counted as an open socket");
    }

    /// INV-10's in-process half.
    ///
    /// Mutations this detects: `halt_and_wait` returning a hard-coded zero, or
    /// reporting `0` when the wait timed out with sockets still open — the
    /// "never a field the reporter assigns to itself" rule.
    #[tokio::test]
    async fn halt_report_counts_zero_open_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let reg = Arc::new(SocketRegistry::new());
        let report = reg.halt_and_wait(Duration::from_millis(200)).await;
        assert_eq!(report.open_sockets_after, 0);
        assert!(report.within_deadline());
        assert!(reg.is_halted());
        // Sticky: a halted registry refuses to dial.
        assert!(reg.connect(addr).await.is_err());

        // POSITIVE CONTROL: with a socket held open across the wait, the SAME
        // function reports a non-zero count instead of a clean zero. Without
        // this the assertion above also passes against a stub returning 0.
        let reg2 = Arc::new(SocketRegistry::new());
        let held = reg2.connect(addr).await.expect("dial");
        let stuck = reg2.halt_and_wait(Duration::from_millis(120)).await;
        assert_eq!(
            stuck.open_sockets_after, 1,
            "the halt report cannot see an open socket"
        );
        assert!(!stuck.within_deadline());
        drop(held);
        assert_eq!(reg2.open(), 0);
    }

    /// Mutations this detects: `cancelled()` returning a fresh `Notify` each
    /// call, so the waiter and the notifier hold different objects and the halt
    /// signal is never delivered.
    #[tokio::test]
    async fn a_halt_wakes_an_in_flight_waiter() {
        let reg = Arc::new(SocketRegistry::new());
        let cancel = reg.cancelled();
        let waiter = tokio::spawn(async move {
            cancel.notified().await;
            "woken"
        });
        // Let the waiter register before the halt fires.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = reg.halt_and_wait(Duration::from_millis(100)).await;
        let out = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("the waiter was never woken")
            .expect("join");
        assert_eq!(out, "woken");
    }

    /// INV-17's negative half: this counter is the SOCKET count, and the test
    /// says so by counting a payload plus its framing.
    ///
    /// Mutations this detects: the write side left uncounted, which halves the
    /// operator's debit; `poll_read` counting the buffer capacity rather than
    /// the bytes actually filled.
    #[tokio::test]
    async fn metered_stream_counts_every_byte_in_both_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(n, 5);
            sock.write_all(b"pong!!").await.unwrap();
            let _ = sock.shutdown().await;
        });

        let reg = Arc::new(SocketRegistry::new());
        let counter = Arc::new(AtomicU64::new(0));
        let tracked = reg.connect(addr).await.expect("dial");
        let mut metered = MeteredStream::new(tracked, counter.clone());

        metered.write_all(b"ping!").await.expect("write");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            5,
            "the write went uncounted"
        );

        let mut out = Vec::new();
        metered.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"pong!!");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            11,
            "both directions must be counted"
        );
        assert_eq!(metered.observed(), 11);

        // NEGATIVE CONTROL: a fresh counter over a fresh stream starts at zero,
        // so the number above is this transfer's and not a process-global.
        assert_eq!(Arc::new(AtomicU64::new(0)).load(Ordering::SeqCst), 0);
    }

    /// An origin that accepts connections and then never answers, holding each
    /// socket open until the CLIENT closes it.
    ///
    /// The per-connection reader is load-bearing, not tidiness. An accepted
    /// socket parked in a `Vec` outlives the client's close and keeps appearing
    /// in the operating system's table with a non-zero remote port — on Windows
    /// as `CLOSE_WAIT`, still attributed to this process — so a census-based
    /// drain assertion would be unsatisfiable for a reason that has nothing to
    /// do with the kill switch. Reading to EOF and dropping makes the server
    /// end follow the client end down.
    async fn holding_origin() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1];
                    let _ = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await;
                });
            }
        });
        addr
    }

    /// INV-10, in process. The assertion is a SOCKET COUNT, not a log line: a
    /// halt that logs "stopped" while a stream is still draining is exactly the
    /// failure this test exists to catch.
    ///
    /// Mutations this detects: `halt_and_wait` dropping the `notify_waiters()`
    /// inside the loop, so a task that began awaiting after the first
    /// notification is never woken and its socket outlives the deadline; the
    /// drain implemented as "stop accepting new dials" without cancelling the
    /// in-flight ones; the deadline loop exiting on the first pass regardless
    /// of what is still open.
    #[tokio::test]
    async fn kill_switch_halts_in_flight_egress_within_five_seconds() {
        let addr = holding_origin().await;
        let reg = Arc::new(SocketRegistry::new());
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let reg = reg.clone();
            tasks.push(tokio::spawn(async move {
                let cancel = reg.cancelled();
                let Ok(stream) = reg.connect(addr).await else {
                    return;
                };
                tokio::select! {
                    _ = cancel.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
                drop(stream);
            }));
        }

        // POSITIVE CONTROL: all three are established before anything is
        // halted. Without it, `open_sockets_after == 0` also passes against a
        // registry that never opened anything.
        for _ in 0..500 {
            if reg.open() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            reg.open(),
            3,
            "the three egress sockets must be established first"
        );

        let report = reg.halt_and_wait(KILL_DEADLINE).await;
        assert_eq!(
            report.open_sockets_after, 0,
            "sockets were still open {} ms after the halt",
            report.elapsed_ms
        );
        // Measured locally 2026-07-31: 15-16 ms for three sockets, against a
        // 5 000 ms deadline. The assertion is against the DEADLINE, not against
        // the measurement: a tight bound would turn a slow runner into a red
        // gate, and the property is "inside five seconds", not "in fifteen
        // milliseconds".
        assert!(
            report.elapsed_ms < KILL_DEADLINE_MS,
            "halt took {} ms, the deadline is {KILL_DEADLINE_MS} ms",
            report.elapsed_ms
        );
        assert!(report.within_deadline());
        for t in tasks {
            let _ = t.await;
        }
    }

    /// INV-10's evidence rule: the halt is verified against the **operating
    /// system's** socket table, not against the registry's own flag.
    ///
    /// The census reads a process-global table, so the signal is deliberately
    /// large and the tolerance is named. Run the suite with `--test-threads=1`
    /// — which is what CI does — and the concurrent churn is zero.
    ///
    /// Mutations this detects: `is_halted()` flipped without any socket being
    /// closed, which leaves the OS count where it was; the drain replaced by a
    /// flag the reporter reads back to itself; a census that answers a constant.
    #[tokio::test]
    async fn the_halt_is_verified_by_an_os_socket_census_not_by_a_flag() {
        use crate::census::{egress_socket_census, CensusError};

        /// Held connections. Each contributes at least one socket the census
        /// can see (our client end; the fixture origin's accepted end is in
        /// this process too).
        const HELD: usize = 8;
        /// How much concurrent churn the assertions tolerate.
        const NOISE: usize = 6;

        let pid = std::process::id();
        let base = match egress_socket_census(pid) {
            Ok(n) => n,
            Err(CensusError::Unsupported(p)) => panic!(
                "socket census is unsupported on {p}; every kill-switch assertion in this crate \
                 would be vacuous"
            ),
            Err(e) => panic!("census failed: {e:?}"),
        };

        let addr = holding_origin().await;
        let reg = Arc::new(SocketRegistry::new());
        let mut tasks = Vec::new();
        for _ in 0..HELD {
            let reg = reg.clone();
            tasks.push(tokio::spawn(async move {
                let cancel = reg.cancelled();
                let Ok(stream) = reg.connect(addr).await else {
                    return;
                };
                tokio::select! {
                    _ = cancel.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
                drop(stream);
            }));
        }
        for _ in 0..500 {
            if reg.open() == HELD {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reg.open(), HELD, "the harness did not open {HELD} sockets");

        // POSITIVE CONTROL: the OPERATING SYSTEM can see them. Without this,
        // the post-halt census below is a number nothing ever moved.
        let busy = egress_socket_census(pid).expect("census");
        assert!(
            busy >= base + HELD,
            "the census cannot see {HELD} open egress sockets (base={base}, busy={busy}); the \
             halt assertion below would be vacuous"
        );

        let report = reg.halt_and_wait(KILL_DEADLINE).await;
        assert_eq!(report.open_sockets_after, 0);
        assert!(report.elapsed_ms < KILL_DEADLINE_MS);

        // THE assertion: the operating system agrees, inside the deadline.
        let deadline = Instant::now() + KILL_DEADLINE;
        let mut after = busy;
        while Instant::now() < deadline {
            after = egress_socket_census(pid).expect("census");
            if after < base + NOISE {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            after < base + NOISE,
            "the registry reported a clean halt while the operating system still attributed \
             sockets to this process (base={base}, busy={busy}, after={after})"
        );
        for t in tasks {
            let _ = t.await;
        }
    }
}
