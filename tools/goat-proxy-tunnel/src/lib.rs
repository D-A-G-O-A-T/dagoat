//! `goat-proxy-tunnel` — the residential-proxy tunnel's transport and crypto core.
//!
//! # This is greenfield. There was no network code to extend.
//!
//! Before this crate there was no socket, no QUIC, no WebSocket, no NAT logic
//! and no relay anywhere in either Rust tree. The closest thing was an
//! in-process `HashMap` bus whose own doc comment says it stands in for
//! sockets (`goatcoin-rs/crates/goat-net/src/transport.rs:209-234`:
//! `Network { queues: HashMap<String, Vec<Frame>> }`, with `send` pushing a
//! frame and `drain` popping it). Nothing here is a refactor of that. Every
//! byte of the carriage, the handshake, the framing and the socket census is
//! new code, and every invariant below is therefore a property that had never
//! been tested against anything.
//!
//! # The distinction this repository had never written down
//!
//! There are **two** layers of encryption on the node↔gateway path and they do
//! **not** have equal standing:
//!
//! * **Outer: WSS on 443 — dumb carriage, NOT the trust boundary.** An
//!   outbound WebSocket-over-TLS connection to port 443 traverses NAT, CGNAT
//!   and residential firewalls everywhere, with **no inbound port** on the
//!   operator's machine. That is its entire job. QUIC/UDP is frequently
//!   blocked on exactly those networks and would add a second stack to harden.
//!   Whoever terminates the outer TLS — a corporate middlebox, a CDN, a
//!   transparent proxy — sees a WebSocket carrying opaque datagrams and
//!   nothing structural: the frame header is inside the AEAD plaintext, not in
//!   the clear.
//! * **Inner: ML-KEM-768 + ML-DSA-65 + AES-256-GCM — this IS the trust
//!   boundary.** The session key derives from the ML-KEM-768 shared secret
//!   under a KDF label of this crate's own, and from **nothing the outer TLS
//!   contributes**. Re-keying, resuming or terminating the outer TLS cannot
//!   move it. A peer that offers a classical key exchange only is refused
//!   before any key is derived. This is the "no classical-only fallback on the
//!   load-bearing crypto path" rule of the "D.A. G.O.A.T. — Core Principles
//!   and Invariants" document, §post-quantum, applied to a transport for the
//!   first time.
//!
//! **A future reader will get this backwards, so it is stated flatly:** the
//! outer TLS is carriage. Deleting it would cost NAT traversal and nothing
//! else. Deleting the inner channel would cost everything.
//!
//! **Classical TLS to a scraped origin is a third thing and is out of scope of
//! that invariant.** On the origin leg the node is an ordinary HTTPS client
//! talking to an ordinary public website; the cipher suite is the *origin's*
//! choice, the node cannot change it, and that leg carries no GOAT
//! authentication and no GOAT key material. Requiring post-quantum crypto
//! there would mean requiring it of the public web, which is not a property
//! this project can hold.
//!
//! # `SecureChannel` is a FRAMING seam, not a transport seam
//!
//! [`goat_core::transport::SecureChannel`] is frozen: byte slice in, byte slice
//! out, `no_std`, allocation-free, synchronous, with no address, connect,
//! accept or stream concept anywhere in it. "No change to the frozen trait
//! surfaces" is a standing non-goal of the convergence architecture, so this
//! crate defines its **own** trait, [`channel::TunnelChannel`], and **wraps**
//! the frozen one through [`channel::TunnelSeam`]. The frozen trait is
//! imported and implemented; it is never edited and never re-implemented from
//! scratch.
//!
//! # Zero listening sockets, ever
//!
//! The tunnel dials **out**. It never accepts. That is the whole NAT story and
//! it is a named invariant, so it is asserted against real operating-system
//! socket state by [`sockets::listening_socket_census`] rather than asserted by
//! a comment. The census carries its own positive control: a platform it
//! cannot enumerate returns `Err` and fails loudly, because a census that
//! silently reports a permanently clean machine is worse than no census.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Tasks 18-21 and its Global Constraints; the "Residential Proxy
//! Network (P3) Implementation Plan", §2 (INV-5, INV-12) and §4.1; and the
//! "The No-Ponzi Invariant — GoatCoin's load-bearing economic rule" spec, §1
//! and §8.
//!
//! # Honesty tagging
//!
//! Every capability in this crate is **[TARGET]**. Nothing here is [NOW]:
//! there is no deployed gateway, no pilot traffic and no settlement path
//! reachable from this code. The refusal paths are the only thing that runs
//! today, and refusing is not a capability.

#![forbid(unsafe_code)]

pub mod capacity;
pub mod carriage;
pub mod channel;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod lifecycle;
pub mod loopback;
pub mod meter;
pub mod mux;
pub mod session;
pub mod sockets;
pub mod state;

#[cfg(feature = "gateway")]
pub use capacity::GatewayScheduler;
pub use capacity::{CapacityReport, DeScheduleReason, NodeId, MAX_CONCURRENT_NODES};
pub use carriage::{
    Carriage, CloseReason, WssCarriage, WssTarget, CARRIAGE_PORT, MAX_DATAGRAM_BYTES,
};
pub use channel::{
    tunnel_seam, Aes256GcmTunnelChannel, ChannelRole, TunnelChannel, TunnelSeam, TUNNEL_NONCE_LEN,
};
pub use error::{TargetRefusal, TunnelError};
pub use frame::{
    open_frame, seal_frame, FrameHeader, FrameKind, MAX_FRAME_PAYLOAD, MAX_FRAME_PLAINTEXT,
    MAX_FRAME_WIRE, TUNNEL_FRAME_HEADER_LEN, TUNNEL_FRAME_VERSION,
};
pub use handshake::{
    derive_session_key, initiate, respond, verify_confirm, GatewayPolicy, HelloBinding,
    HelloReplayCache, KemSuite, MlKem768MlDsa65, PeerKemOffer, TunnelConfirm, TunnelHello,
    TunnelPqBackend, MAX_TRACKED_HELLOES, TUNNEL_KDF_LABEL, TUNNEL_PROTOCOL_VERSION,
};
pub use lifecycle::{
    ControlOrigin, HaltOutcome, HaltRecord, TunnelLifecycle, HEARTBEAT_TTL_MS, KILL_DEADLINE,
    KILL_DEADLINE_MS,
};
pub use loopback::LoopbackCarriage;
pub use meter::{
    gateway_signing_key_from_seed, meter_preimage, sign_meter_record, verify_meter_record,
    GatewaySessionMeter, SignedTunnelMeterRecord, TunnelMeterRecord, BODY_OVERRUN_ALLOWANCE_BYTES,
    METERED_QUANTITY, METER_RECORD_CONTEXT, METER_RECORD_FIELDS,
};
pub use mux::{Mux, MAX_CONCURRENT_STREAMS};
pub use session::TunnelSession;
pub use sockets::{listening_socket_census, SocketsError};
pub use state::{seam_for_endpoint, step, TunnelEndpoint, TunnelEvent, TunnelState};
