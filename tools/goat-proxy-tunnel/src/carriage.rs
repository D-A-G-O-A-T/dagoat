//! The outer carriage — outbound only, port 443, never a trust boundary.
//!
//! # R6, in the source rather than in a plan nobody reads at 2am
//!
//! An outbound WebSocket-over-TLS connection to port 443 traverses NAT, CGNAT
//! and residential firewalls **everywhere**, with **no inbound port** on the
//! operator's machine. That is the entire reason this layer exists. QUIC/UDP
//! is frequently blocked on exactly the networks this has to work on, and
//! would add a second stack to harden for no traversal benefit.
//!
//! # The outer TLS is dumb carriage
//!
//! Whoever terminates it — a corporate middlebox, a CDN, a captive portal —
//! sees a WebSocket carrying opaque binary datagrams and nothing structural.
//! The trust boundary is the inner post-quantum channel: ML-KEM-768 key
//! establishment, ML-DSA-65 node identity, AES-256-GCM framing, with the frame
//! header inside the AEAD plaintext. Re-keying or resuming the outer TLS
//! cannot move the inner session key, because the inner key derives from the
//! KEM shared secret and from nothing the outer TLS contributes.
//!
//! # Zero listening sockets
//!
//! This module dials. It never accepts. There is no accept path, no inbound
//! port and no relay in it, and that is asserted against real kernel state by
//! [`crate::sockets::listening_socket_census`] rather than by this sentence.
//!
//! Design authority: the "Residential Proxy Network (P3) Implementation Plan",
//! §2 (INV-5) and §3 (the CONNECT-tunnelling and AV/EDR rows).

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::{TargetRefusal, TunnelError};
use crate::frame::MAX_FRAME_WIRE;

/// The only port the carriage dials.
pub const CARRIAGE_PORT: u16 = 443;

/// The largest datagram the carriage will hand to the wire — one full wire
/// frame. Anything larger is a refusal before any socket work happens.
pub const MAX_DATAGRAM_BYTES: usize = MAX_FRAME_WIRE;

/// Why a carriage was closed.
///
/// Two of these are recoverable and two are not, and the distinction is
/// load-bearing: a supervisor that redials after a kill switch has defeated
/// the kill switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The session ended cleanly. A new session may be dialled.
    Normal,
    /// The operator's kill switch fired. **Not recoverable**: nothing in this
    /// process may dial again.
    KillSwitch,
    /// A policy check refused. **Not recoverable** by redialling — the refusal
    /// would simply repeat.
    PolicyRefusal,
    /// The peer went away. A new session may be dialled.
    PeerGone,
}

impl CloseReason {
    /// Whether a carriage closed for this reason may be dialled again.
    #[inline]
    pub fn is_recoverable(self) -> bool {
        match self {
            CloseReason::Normal | CloseReason::PeerGone => true,
            CloseReason::KillSwitch | CloseReason::PolicyRefusal => false,
        }
    }
}

/// The carriage seam: opaque datagrams in, opaque datagrams out.
///
/// It knows nothing about frames, streams, metering or identity. That is the
/// point — the carriage is replaceable (an in-process
/// [`crate::loopback::LoopbackCarriage`] is a full implementation of it) and
/// nothing above it may depend on which carriage it has.
#[async_trait]
pub trait Carriage: Send {
    /// Hand one datagram to the wire.
    async fn send_datagram(&mut self, datagram: &[u8]) -> Result<(), TunnelError>;

    /// Take the next datagram off the wire.
    async fn recv_datagram(&mut self) -> Result<Vec<u8>, TunnelError>;

    /// Close, recording why.
    async fn close(&mut self, reason: CloseReason) -> Result<(), TunnelError>;
}

/// A validated outbound dial target.
///
/// Validation happens **before** any socket work, and each refusal has its own
/// cause, because a test that asserts "some refusal" also passes against a
/// component that refuses everything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WssTarget {
    host: String,
    path: String,
}

impl WssTarget {
    /// Parse and validate a gateway URL.
    ///
    /// Accepted: `wss://host[/path]` and `wss://host:443[/path]`. Refused:
    /// any other scheme, any other port, a missing host, and any authority
    /// carrying userinfo.
    pub fn parse(raw: &str) -> Result<Self, TunnelError> {
        let refuse = |r: TargetRefusal| Err(TunnelError::CarriageRefusedTarget(r));
        let url = match url::Url::parse(raw) {
            Ok(u) => u,
            // `wss` is a special scheme, so an empty authority is rejected by
            // the parser rather than reaching the host check below. It is
            // still a *missing host*, not an unreadable URL, and the caller is
            // entitled to know which.
            Err(url::ParseError::EmptyHost) => return refuse(TargetRefusal::HostMissing),
            Err(_) => return refuse(TargetRefusal::Unparsable),
        };
        if url.scheme() != "wss" {
            return refuse(TargetRefusal::NotWssScheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return refuse(TargetRefusal::AuthorityCarriesUserinfo);
        }
        let host = match url.host_str() {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => return refuse(TargetRefusal::HostMissing),
        };
        if url.port_or_known_default() != Some(CARRIAGE_PORT) {
            return refuse(TargetRefusal::NotPortFourFourThree);
        }
        let mut path = url.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        Ok(Self { host, path })
    }

    /// The host this target dials.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port this target dials. Always [`CARRIAGE_PORT`].
    pub fn port(&self) -> u16 {
        CARRIAGE_PORT
    }

    /// The dial URL, with the port written out explicitly.
    pub fn url(&self) -> String {
        format!("wss://{}:{}{}", self.host, CARRIAGE_PORT, self.path)
    }
}

/// The shipped carriage: one outbound WebSocket-over-TLS connection.
pub struct WssCarriage {
    target: WssTarget,
    stream: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    closed: Option<CloseReason>,
}

impl WssCarriage {
    /// A carriage that has not dialled yet.
    ///
    /// Construction opens nothing. Separating construction from the dial is
    /// what lets the refusal paths — closed, not open, oversize, bad target —
    /// be tested without a network, which is the only way they get tested at
    /// all.
    pub fn new(target: WssTarget) -> Self {
        Self {
            target,
            stream: None,
            closed: None,
        }
    }

    /// The validated target.
    pub fn target(&self) -> &WssTarget {
        &self.target
    }

    /// Whether a session is currently carried.
    pub fn is_open(&self) -> bool {
        self.stream.is_some() && self.closed.is_none()
    }

    /// Why this carriage closed, if it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.closed
    }

    /// Dial out.
    ///
    /// **[TARGET].** There is no deployed gateway to dial, so this path has
    /// never carried a byte in production. Refuses outright once closed for a
    /// non-recoverable reason.
    pub async fn connect(&mut self) -> Result<(), TunnelError> {
        if let Some(reason) = self.closed {
            if !reason.is_recoverable() {
                return Err(TunnelError::CarriageClosed(reason));
            }
        }
        let (stream, _response) = connect_async(self.target.url())
            .await
            .map_err(|e| TunnelError::CarriageIo(e.to_string()))?;
        self.stream = Some(stream);
        self.closed = None;
        Ok(())
    }

    fn guard(&self) -> Result<(), TunnelError> {
        if let Some(reason) = self.closed {
            return Err(TunnelError::CarriageClosed(reason));
        }
        if self.stream.is_none() {
            return Err(TunnelError::CarriageNotOpen);
        }
        Ok(())
    }
}

#[async_trait]
impl Carriage for WssCarriage {
    async fn send_datagram(&mut self, datagram: &[u8]) -> Result<(), TunnelError> {
        self.guard()?;
        if datagram.len() > MAX_DATAGRAM_BYTES {
            return Err(TunnelError::FrameTooLarge {
                len: datagram.len(),
                max: MAX_DATAGRAM_BYTES,
            });
        }
        let stream = self.stream.as_mut().ok_or(TunnelError::CarriageNotOpen)?;
        stream
            .send(Message::binary(datagram.to_vec()))
            .await
            .map_err(|e| TunnelError::CarriageIo(e.to_string()))
    }

    async fn recv_datagram(&mut self) -> Result<Vec<u8>, TunnelError> {
        self.guard()?;
        let stream = self.stream.as_mut().ok_or(TunnelError::CarriageNotOpen)?;
        loop {
            match stream.next().await {
                Some(Ok(Message::Binary(b))) => {
                    if b.len() > MAX_DATAGRAM_BYTES {
                        return Err(TunnelError::FrameTooLarge {
                            len: b.len(),
                            max: MAX_DATAGRAM_BYTES,
                        });
                    }
                    return Ok(b.to_vec());
                }
                // Ping/pong/text are carriage housekeeping, not tunnel
                // payload. Text especially: nothing in this protocol is text,
                // so a text message is noise from a middlebox.
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(TunnelError::CarriageIo(e.to_string())),
                None => {
                    self.closed = Some(CloseReason::PeerGone);
                    return Err(TunnelError::CarriageClosed(CloseReason::PeerGone));
                }
            }
        }
    }

    async fn close(&mut self, reason: CloseReason) -> Result<(), TunnelError> {
        // The reason is recorded first. A close that fails at the socket layer
        // must still leave the carriage closed, or a kill switch would be
        // undone by a broken pipe. And a non-recoverable reason is sticky: a
        // later `close(Normal)` must not downgrade a kill switch.
        match self.closed {
            Some(existing) if !existing.is_recoverable() => {}
            _ => self.closed = Some(reason),
        }
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.close(None).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::LoopbackCarriage;
    use crate::sockets::listening_socket_census;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Serialises every test that measures OS socket state, so one test's
    /// control socket cannot be counted by another test's census.
    static CENSUS_LOCK: Mutex<()> = Mutex::new(());

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
    const TUNNEL_SRC_FILES_AT_THIS_TASK: usize = 14;
    /// See the same constant in `channel.rs` for the measurement and for why
    /// the floor sits where it does.
    const MIN_SWEPT_PRODUCTION_BYTES: usize = 120_000;

    /// INV-5's socket half, measured against the operating system.
    ///
    /// The negative control is the whole test: bind one loopback listener,
    /// assert the census sees it, drop it, assert the census drops back. A
    /// census that cannot enumerate **panics** here rather than passing — an
    /// `Unsupported` platform reporting a permanently clean machine is the
    /// failure mode this control exists to catch.
    ///
    /// **Mutations this detects:** opening any inbound port in this crate;
    /// and any change that makes the census unable to see a socket that is
    /// demonstrably there.
    #[test]
    fn node_process_opens_zero_listening_sockets() {
        let _guard = CENSUS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pid = std::process::id();

        let before = listening_socket_census(pid)
            .expect("the socket census must answer; an unenumerable platform fails loudly");

        // Negative control, ascending: a socket that IS there must be seen.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("control socket");
        let with_control = listening_socket_census(pid).expect("census");
        assert!(
            with_control > before,
            "the census reported {with_control} with a control socket open and {before} without \
             — it cannot see a socket that is demonstrably there, so its zeroes mean nothing"
        );

        // Negative control, descending: and it must stop seeing it.
        drop(listener);
        let after = listening_socket_census(pid).expect("census");
        assert_eq!(
            after, before,
            "the census did not drop back after the control socket closed"
        );

        // The invariant itself: constructing and exercising the tunnel's own
        // carriages opens nothing inbound.
        let target = WssTarget::parse("wss://gateway.example/tunnel").unwrap();
        let carriage = WssCarriage::new(target);
        assert!(!carriage.is_open());
        let (_a, _b) = LoopbackCarriage::pair(4);
        assert_eq!(
            listening_socket_census(pid).expect("census"),
            0,
            "this process is listening on a port; the tunnel dials out and never accepts"
        );
    }

    /// **Mutations this detects:** accepting `ws://` (no TLS), accepting an
    /// alternate port, accepting a credential-bearing authority, or dropping
    /// validation entirely so the dial is attempted first and judged after.
    #[test]
    fn the_carriage_connects_outbound_only_to_port_443() {
        assert_eq!(CARRIAGE_PORT, 443);

        // Positive control: the two accepted shapes.
        for ok in [
            "wss://gateway.example/tunnel",
            "wss://gateway.example:443/tunnel",
            "wss://gateway.example",
        ] {
            let t = WssTarget::parse(ok).unwrap_or_else(|e| panic!("{ok} was refused: {e:?}"));
            assert_eq!(t.port(), 443);
            assert!(t.url().starts_with("wss://gateway.example:443"));
        }

        let cases = [
            ("ws://gateway.example/tunnel", TargetRefusal::NotWssScheme),
            ("https://gateway.example/", TargetRefusal::NotWssScheme),
            (
                "wss://gateway.example:8443/",
                TargetRefusal::NotPortFourFourThree,
            ),
            (
                "wss://gateway.example:80/",
                TargetRefusal::NotPortFourFourThree,
            ),
            (
                "wss://user:pw@gateway.example/",
                TargetRefusal::AuthorityCarriesUserinfo,
            ),
            ("not a url", TargetRefusal::Unparsable),
            ("wss://", TargetRefusal::HostMissing),
            ("wss://:443/tunnel", TargetRefusal::HostMissing),
        ];
        for (raw, want) in cases {
            assert_eq!(
                WssTarget::parse(raw),
                Err(TunnelError::CarriageRefusedTarget(want)),
                "{raw} was not refused as {want:?}"
            );
        }
    }

    /// **Mutations this detects:** clearing the closed flag on send, or
    /// letting a closed carriage fall through to the "not open" path, which
    /// loses the reason and lets a supervisor redial after a kill switch.
    #[tokio::test]
    async fn a_closed_carriage_refuses_every_subsequent_send() {
        let (mut a, mut b) = LoopbackCarriage::pair(4);

        // Positive control: open, it carries.
        a.send_datagram(b"before").await.unwrap();
        assert_eq!(b.recv_datagram().await.unwrap(), b"before");

        a.close(CloseReason::KillSwitch).await.unwrap();
        for _ in 0..3 {
            assert_eq!(
                a.send_datagram(b"after").await,
                Err(TunnelError::CarriageClosed(CloseReason::KillSwitch))
            );
            assert_eq!(
                a.recv_datagram().await,
                Err(TunnelError::CarriageClosed(CloseReason::KillSwitch))
            );
        }

        // Same for the WSS carriage, which never dialled: closing it first
        // must beat "not open", because the reason is the thing that matters.
        let mut w = WssCarriage::new(WssTarget::parse("wss://gateway.example/t").unwrap());
        assert_eq!(
            w.send_datagram(b"x").await,
            Err(TunnelError::CarriageNotOpen)
        );
        w.close(CloseReason::KillSwitch).await.unwrap();
        assert_eq!(
            w.send_datagram(b"x").await,
            Err(TunnelError::CarriageClosed(CloseReason::KillSwitch))
        );
        assert_eq!(w.close_reason(), Some(CloseReason::KillSwitch));
    }

    /// **Mutations this detects:** marking the kill switch recoverable, or
    /// letting a later `close(Normal)` overwrite it — either of which turns
    /// the kill switch into a pause button.
    #[tokio::test]
    async fn close_reason_kill_switch_is_not_recoverable() {
        assert!(!CloseReason::KillSwitch.is_recoverable());
        assert!(!CloseReason::PolicyRefusal.is_recoverable());
        // Positive control: the other two are.
        assert!(CloseReason::Normal.is_recoverable());
        assert!(CloseReason::PeerGone.is_recoverable());

        let mut w = WssCarriage::new(WssTarget::parse("wss://gateway.example/t").unwrap());
        w.close(CloseReason::KillSwitch).await.unwrap();
        w.close(CloseReason::Normal).await.unwrap();
        assert_eq!(
            w.close_reason(),
            Some(CloseReason::KillSwitch),
            "a later normal close overwrote the kill switch"
        );
        assert_eq!(
            w.connect().await,
            Err(TunnelError::CarriageClosed(CloseReason::KillSwitch)),
            "a kill-switched carriage redialled"
        );
    }

    /// INV-5's source half.
    ///
    /// **Mutations this detects:** introducing an inbound socket, a datagram
    /// socket or a bidirectional relay into production code — the three
    /// shapes that turn this from a dialler into a proxy anyone can point at.
    #[test]
    fn the_carriage_source_contains_no_listener_or_bind_api() {
        // Assembled at runtime, so this file does not itself contain the
        // tokens it forbids in production code.
        let forbidden = [
            format!("{}{}", "Tcp", "Listener"),
            format!("{}{}", "Udp", "Socket"),
            format!("{}{}", "copy_bi", "directional"),
            format!("{}{}", ".bi", "nd("),
            format!("{}{}", "::bi", "nd("),
        ];

        let sources = production_sources();
        assert_eq!(sources.len(), TUNNEL_SRC_FILES_AT_THIS_TASK);
        let total: usize = sources.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total >= MIN_SWEPT_PRODUCTION_BYTES,
            "swept only {total} byte(s) of production text"
        );

        // Positive control: the matcher fires on text that has the tokens.
        // This crate's own test code uses the first and fourth, so a scanner
        // that could not see them would be silently reading nothing.
        let control = format!(
            "std::net::{}::{}\"127.0.0.1:0\" {} {} {}",
            forbidden[0], "bind(", forbidden[1], forbidden[2], forbidden[3]
        );
        for token in &forbidden {
            assert!(
                control.contains(token.as_str()),
                "the scanner cannot see {token} in its own control string"
            );
        }

        for (name, text) in &sources {
            for token in &forbidden {
                assert!(
                    !text.contains(token.as_str()),
                    "{name} names {token} in production code; this crate dials out and never \
                     accepts"
                );
            }
        }
    }

    /// **Mutations this detects:** dropping the datagram bound, so an
    /// oversize buffer is copied and handed to the wire before anyone
    /// objects.
    #[tokio::test]
    async fn an_oversize_datagram_is_refused_before_the_carriage_sends_it() {
        assert_eq!(MAX_DATAGRAM_BYTES, MAX_FRAME_WIRE);
        let (mut a, mut b) = LoopbackCarriage::pair(4);

        // Positive control: exactly at the bound, it is carried.
        let at_bound = vec![0xABu8; MAX_DATAGRAM_BYTES];
        a.send_datagram(&at_bound).await.unwrap();
        assert_eq!(b.recv_datagram().await.unwrap().len(), MAX_DATAGRAM_BYTES);

        let over = vec![0xABu8; MAX_DATAGRAM_BYTES + 1];
        assert_eq!(
            a.send_datagram(&over).await,
            Err(TunnelError::FrameTooLarge {
                len: MAX_DATAGRAM_BYTES + 1,
                max: MAX_DATAGRAM_BYTES,
            })
        );
        assert_eq!(a.sent_datagrams(), 1, "the oversize datagram was queued");
    }

    /// **Mutations this detects:** a loopback pair that shares one queue, so
    /// an endpoint reads back its own writes and every round-trip test above
    /// passes without a peer.
    #[tokio::test]
    async fn a_loopback_pair_round_trips_a_datagram_in_both_directions() {
        let (mut a, mut b) = LoopbackCarriage::pair(4);
        a.send_datagram(b"up").await.unwrap();
        b.send_datagram(b"down").await.unwrap();
        assert_eq!(b.recv_datagram().await.unwrap(), b"up");
        assert_eq!(a.recv_datagram().await.unwrap(), b"down");

        b.close(CloseReason::Normal).await.unwrap();
        assert_eq!(
            a.recv_datagram().await,
            Err(TunnelError::CarriageClosed(CloseReason::PeerGone)),
            "a closed peer did not surface as PeerGone"
        );
    }
}
