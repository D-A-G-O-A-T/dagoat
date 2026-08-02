//! One session, end to end, over the in-process carriage.
//!
//! Every test here drives the **public** API only: two [`TunnelSession`]s, a
//! [`LoopbackCarriage`] pair, and the frozen `SecureChannel` implementation the
//! session wraps. Nothing reaches inside, and nothing opens a socket.
//!
//! Design authority: the "Residential Proxy Network — Worker & Tunnel Spec
//! (Tasks 18-36, 44, 45, 47)", Task 26; the "Residential Proxy Network (P3)
//! Implementation Plan", §2 (INV-12).

use goat_core::transport::TransportError;

use goat_proxy_tunnel::carriage::{Carriage, CloseReason};
use goat_proxy_tunnel::channel::{Aes256GcmTunnelChannel, ChannelRole};
use goat_proxy_tunnel::error::TunnelError;
use goat_proxy_tunnel::frame::{
    FrameHeader, FrameKind, MAX_FRAME_PAYLOAD, TUNNEL_FRAME_HEADER_LEN,
};
use goat_proxy_tunnel::loopback::LoopbackCarriage;
use goat_proxy_tunnel::session::TunnelSession;
use goat_proxy_tunnel::state::{TunnelEvent, TunnelState};

fn pair() -> (
    TunnelSession<Aes256GcmTunnelChannel>,
    TunnelSession<Aes256GcmTunnelChannel>,
) {
    let key = [0x42u8; 32];
    let (a, b) = LoopbackCarriage::pair(16);
    (
        TunnelSession::new(
            Aes256GcmTunnelChannel::new(key, ChannelRole::Initiator),
            Box::new(a),
            TunnelState::Ready,
        ),
        TunnelSession::new(
            Aes256GcmTunnelChannel::new(key, ChannelRole::Responder),
            Box::new(b),
            TunnelState::Ready,
        ),
    )
}

/// **Mutations this detects:** mis-slicing the payload by the header width,
/// losing the header on the way through, or sealing the payload without it.
#[tokio::test]
async fn a_data_frame_round_trips_through_the_wrapped_secure_channel() {
    let (mut node, mut gw) = pair();
    let payload = vec![0xABu8; 1_024];
    node.send_frame(FrameHeader::data(1, 1_024), &payload)
        .await
        .unwrap();
    let (h, got) = gw.recv_frame().await.unwrap();
    assert_eq!(h.kind, FrameKind::StreamData);
    assert_eq!(h.stream_id, 1);
    assert_eq!(h.length, 1_024);
    assert_eq!(got, payload);

    // And back the other way, so the two nonce spaces are both exercised.
    let down = vec![0x0Fu8; 7];
    gw.send_frame(FrameHeader::session(FrameKind::MeterTick, 7), &down)
        .await
        .unwrap();
    let (h, got) = node.recv_frame().await.unwrap();
    assert_eq!(h.kind, FrameKind::MeterTick);
    assert_eq!(h.stream_id, 0);
    assert_eq!(got, down);
}

/// Nothing structural leaks to whoever terminates the outer TLS.
///
/// **Mutations this detects:** moving the header outside the AEAD, and — the
/// blunter failure — bypassing the cipher entirely and shipping the plaintext,
/// which every round-trip test above would still pass.
#[tokio::test]
async fn header_is_inside_the_aead_plaintext_not_in_the_clear() {
    let key = [0x42u8; 32];
    let (a, mut b) = LoopbackCarriage::pair(4);
    let mut node = TunnelSession::new(
        Aes256GcmTunnelChannel::new(key, ChannelRole::Initiator),
        Box::new(a),
        TunnelState::Ready,
    );
    // stream_id 0x01020305 would appear verbatim at wire offset 4..8 if the
    // header were in the clear.
    let h = FrameHeader::data(0x0102_0305, 4);
    let encoded = h.encode().unwrap();
    assert_eq!(encoded.len(), TUNNEL_FRAME_HEADER_LEN);

    node.send_frame(h, b"abcd").await.unwrap();
    let wire = b.recv_datagram().await.unwrap();

    // Positive control: the needles ARE findable in the plaintext they came
    // from, so "not found on the wire" is a statement about the AEAD and not
    // about a broken search.
    let plaintext: Vec<u8> = encoded
        .iter()
        .copied()
        .chain(b"abcd".iter().copied())
        .collect();
    assert!(plaintext
        .windows(TUNNEL_FRAME_HEADER_LEN)
        .any(|w| w == encoded));
    assert!(plaintext.windows(4).any(|w| w == [0x01, 0x02, 0x03, 0x05]));
    assert!(plaintext.windows(4).any(|w| w == b"abcd"));

    assert!(
        !wire.windows(4).any(|w| w == [0x01, 0x02, 0x03, 0x05]),
        "the stream id is visible in the clear on the wire"
    );
    // The WHOLE encoded header, not a guess about one byte. An earlier draft
    // asserted `!wire.starts_with(&[1u8])`, which with a fixed key and nonce is
    // deterministic but arbitrary — it would pass or fail for reasons unrelated
    // to whether the header is confidential.
    assert!(
        !wire.windows(TUNNEL_FRAME_HEADER_LEN).any(|w| w == encoded),
        "the encoded header appears verbatim on the wire"
    );
    assert!(
        !wire.starts_with(&encoded[..4]),
        "the header prefix is in the clear"
    );
    assert!(
        !wire.windows(4).any(|w| w == b"abcd"),
        "the payload appears verbatim on the wire"
    );
    assert_ne!(&wire[..4], b"abcd", "the payload prefix is in the clear");
    assert_eq!(
        wire.len(),
        TUNNEL_FRAME_HEADER_LEN + 4 + 16,
        "the wire frame is not plaintext plus one AEAD tag"
    );
}

/// **Mutations this detects:** resetting or sharing the nonce counter, which
/// makes two frames with the same plaintext produce the same wire bytes under
/// the same key — the one catastrophic misuse of AES-GCM.
#[tokio::test]
async fn frame_counter_is_the_nonce_counter_and_never_repeats() {
    let (mut node, mut gw) = pair();
    for i in 0..8u8 {
        node.send_frame(FrameHeader::data(1, 1), &[i])
            .await
            .unwrap();
    }
    let mut seen = Vec::new();
    for _ in 0..8 {
        let (_h, p) = gw.recv_frame().await.unwrap();
        seen.push(p[0]);
    }
    assert_eq!(seen, (0..8u8).collect::<Vec<_>>());

    // Positive control on the observation: identical plaintext across the eight
    // frames would still have produced eight DIFFERENT wire frames, which is
    // what the counter is for. Assert it on the wire.
    let key = [0x42u8; 32];
    let (c, mut raw) = LoopbackCarriage::pair(8);
    let mut sender = TunnelSession::new(
        Aes256GcmTunnelChannel::new(key, ChannelRole::Initiator),
        Box::new(c),
        TunnelState::Ready,
    );
    for _ in 0..4 {
        sender
            .send_frame(FrameHeader::data(1, 4), b"same")
            .await
            .unwrap();
    }
    let mut wires = Vec::new();
    for _ in 0..4 {
        wires.push(raw.recv_datagram().await.unwrap());
    }
    let mut deduped = wires.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        wires.len(),
        "identical plaintext produced a repeated wire frame, so the counter is not advancing"
    );
}

/// The carriage MUST be ordered: the frame counter is the nonce, so a reordered
/// frame fails the tag rather than being silently accepted out of order. This
/// is a property, not an accident.
///
/// **Mutations this detects:** carrying an explicit nonce on the wire (which
/// would make reordering silently succeed), or deriving the inbound nonce from
/// anything but the peer's counter.
#[tokio::test]
async fn a_reordered_frame_fails_the_aead_tag() {
    let key = [0x42u8; 32];
    let (a, mut raw) = LoopbackCarriage::pair(8);
    let mut node = TunnelSession::new(
        Aes256GcmTunnelChannel::new(key, ChannelRole::Initiator),
        Box::new(a),
        TunnelState::Ready,
    );
    node.send_frame(FrameHeader::data(1, 1), b"1")
        .await
        .unwrap();
    node.send_frame(FrameHeader::data(1, 1), b"2")
        .await
        .unwrap();
    let first = raw.recv_datagram().await.unwrap();
    let second = raw.recv_datagram().await.unwrap();

    // Positive control: in order, the same two frames open.
    let (mut ordered_feeder, ordered_b) = LoopbackCarriage::pair(8);
    let mut ordered_gw = TunnelSession::new(
        Aes256GcmTunnelChannel::new(key, ChannelRole::Responder),
        Box::new(ordered_b),
        TunnelState::Ready,
    );
    ordered_feeder.send_datagram(&first).await.unwrap();
    ordered_feeder.send_datagram(&second).await.unwrap();
    assert_eq!(ordered_gw.recv_frame().await.unwrap().1, b"1");
    assert_eq!(ordered_gw.recv_frame().await.unwrap().1, b"2");

    let (mut feeder, replay_b) = LoopbackCarriage::pair(8);
    let mut gw = TunnelSession::new(
        Aes256GcmTunnelChannel::new(key, ChannelRole::Responder),
        Box::new(replay_b),
        TunnelState::Ready,
    );
    feeder.send_datagram(&second).await.unwrap(); // out of order
    feeder.send_datagram(&first).await.unwrap();
    assert_eq!(
        gw.recv_frame().await.unwrap_err(),
        TunnelError::Aead(TransportError::DecryptionFailed)
    );
}

/// **Mutations this detects:** dropping the payload bound from the send path,
/// so an oversize frame is sealed and handed to the carriage before anyone
/// objects.
#[tokio::test]
async fn a_frame_over_max_payload_is_refused_before_it_reaches_the_carriage() {
    let (mut node, _gw) = pair();

    // Positive control: exactly at the bound, it is carried.
    let at_bound = vec![0u8; MAX_FRAME_PAYLOAD];
    node.send_frame(FrameHeader::data(1, MAX_FRAME_PAYLOAD as u32), &at_bound)
        .await
        .unwrap();

    let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let h = FrameHeader::data(1, (MAX_FRAME_PAYLOAD + 1) as u32);
    assert_eq!(
        node.send_frame(h, &payload).await,
        Err(TunnelError::FrameTooLarge {
            len: MAX_FRAME_PAYLOAD + 1,
            max: MAX_FRAME_PAYLOAD,
        })
    );
}

/// **Mutations this detects:** adding a `ConfirmSent + StreamOpened` edge to
/// the transition table, or making `may_carry_stream_data` true for any state
/// but `Ready`.
#[tokio::test]
async fn no_stream_data_flows_before_ready() {
    let (mut node, _gw) = pair();

    // Positive control: in `Ready`, both are permitted.
    assert!(node.state.may_carry_stream_data());
    node.apply(TunnelEvent::StreamOpened).unwrap();

    node.state = TunnelState::ConfirmSent;
    assert!(!node.state.may_carry_stream_data());
    assert_eq!(
        node.apply(TunnelEvent::StreamOpened).unwrap_err(),
        TunnelError::IllegalTransition {
            from: "ConfirmSent",
            event: "StreamOpened"
        }
    );
}

/// **Mutations this detects:** clearing the closed flag on send, or letting a
/// closed carriage fall through to the "not open" path — which loses the reason
/// and lets a supervisor redial after a kill switch.
#[tokio::test]
async fn closing_the_carriage_stops_every_subsequent_send() {
    let (mut node, _gw) = pair();

    // Positive control: before the close, it carries.
    node.send_frame(FrameHeader::data(1, 1), b"x")
        .await
        .unwrap();

    node.close(CloseReason::KillSwitch).await.unwrap();
    for _ in 0..3 {
        assert_eq!(
            node.send_frame(FrameHeader::data(1, 1), b"x").await,
            Err(TunnelError::CarriageClosed(CloseReason::KillSwitch))
        );
    }
}
