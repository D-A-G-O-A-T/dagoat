//! One tunnel session = one carriage + one `SecureChannel` + one `Mux` + one
//! state machine.
//!
//! # This is where the wrap is visible
//!
//! [`TunnelSession::send_frame`] calls the frozen
//! [`goat_core::transport::SecureChannel::encrypt_frame`] **exactly once**, on
//! `header ‖ payload`, and hands the result to the carriage. Nothing else in
//! this file touches the cipher, and nothing in this file re-implements it. The
//! session is generic over `C: SecureChannel`, so it cannot know or depend on
//! which implementation it holds.
//!
//! The header is inside that one plaintext, which is the whole confidentiality
//! claim: whoever terminates the outer TLS sees an opaque blob with no kind, no
//! stream id and no length.
//!
//! # Why the buffers are fields
//!
//! `plain` and `wire` were stack arrays
//! (`let mut plain = [0u8; MAX_FRAME_PLAINTEXT];`) inside both `send_frame` and
//! `recv_frame`. An array declared in an `async fn` lives in the generated
//! future, not on the caller's stack frame, so two of them per method across
//! two methods is 4 × `MAX_FRAME_PLAINTEXT` carried in every future that awaits
//! a session — and tokio's default worker stack is 2 MiB, which any nesting
//! then overflows. Owning them here allocates once per session instead.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 26; the "Residential Proxy Network (P3) Implementation Plan", §2
//! (INV-12) and §4.1.
//!
//! Honesty tagging: **[TARGET]**. No session has ever been driven over anything
//! but the in-process carriage.

use goat_core::transport::SecureChannel;

use crate::carriage::{Carriage, CloseReason};
use crate::error::TunnelError;
use crate::frame::{
    FrameHeader, MAX_FRAME_PAYLOAD, MAX_FRAME_PLAINTEXT, MAX_FRAME_WIRE, TUNNEL_FRAME_HEADER_LEN,
};
use crate::mux::Mux;
use crate::state::{step, TunnelEvent, TunnelState};

/// A live tunnel session over one carriage.
pub struct TunnelSession<C: SecureChannel + Send> {
    channel: C,
    carriage: Box<dyn Carriage>,
    /// Where the session is in its lifecycle. Only [`TunnelState::Ready`] may
    /// carry stream data.
    pub state: TunnelState,
    /// The per-session stream table.
    pub mux: Mux,
    /// Reusable, session-owned, HEAP buffers. See the module doc comment.
    plain: Vec<u8>,
    wire: Vec<u8>,
}

impl<C: SecureChannel + Send> TunnelSession<C> {
    /// A session over an already-derived channel and an already-dialled
    /// carriage.
    pub fn new(channel: C, carriage: Box<dyn Carriage>, state: TunnelState) -> Self {
        Self {
            channel,
            carriage,
            state,
            mux: Mux::new(),
            plain: vec![0u8; MAX_FRAME_PLAINTEXT],
            wire: vec![0u8; MAX_FRAME_WIRE],
        }
    }

    /// Drive the state machine. A refused transition leaves the state
    /// unchanged.
    pub fn apply(&mut self, ev: TunnelEvent) -> Result<(), TunnelError> {
        self.state = step(self.state, ev)?;
        Ok(())
    }

    /// The wrap, in six lines: build the plaintext, hand it to the FROZEN
    /// trait, ship the bytes.
    ///
    /// The bounds are checked before the AEAD is touched, so an oversize frame
    /// is a refusal rather than an allocation followed by an apology.
    pub async fn send_frame(
        &mut self,
        header: FrameHeader,
        payload: &[u8],
    ) -> Result<(), TunnelError> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(TunnelError::FrameTooLarge {
                len: payload.len(),
                max: MAX_FRAME_PAYLOAD,
            });
        }
        if header.length as usize != payload.len() {
            return Err(TunnelError::LengthMismatch {
                declared: header.length,
                actual: payload.len(),
            });
        }
        // `encode` validates every field bound, so a malformed header never
        // reaches the cipher.
        let encoded = header.encode()?;
        self.plain[..TUNNEL_FRAME_HEADER_LEN].copy_from_slice(&encoded);
        let plain_len = TUNNEL_FRAME_HEADER_LEN + payload.len();
        self.plain[TUNNEL_FRAME_HEADER_LEN..plain_len].copy_from_slice(payload);
        let n = self
            .channel
            .encrypt_frame(&self.plain[..plain_len], &mut self.wire)?;
        self.carriage.send_datagram(&self.wire[..n]).await
    }

    /// Take one frame off the carriage and open it.
    pub async fn recv_frame(&mut self) -> Result<(FrameHeader, Vec<u8>), TunnelError> {
        let wire = self.carriage.recv_datagram().await?;
        if wire.len() > MAX_FRAME_WIRE {
            return Err(TunnelError::FrameTooLarge {
                len: wire.len(),
                max: MAX_FRAME_WIRE,
            });
        }
        let n = self.channel.decrypt_frame(&wire, &mut self.plain)?;
        if n < TUNNEL_FRAME_HEADER_LEN {
            return Err(TunnelError::MalformedHeader);
        }
        // `decode` validates, so a header that survived the AEAD but names an
        // undefined kind or an out-of-range length is still refused.
        let header = FrameHeader::decode(&self.plain[..TUNNEL_FRAME_HEADER_LEN])?;
        let payload = self.plain[TUNNEL_FRAME_HEADER_LEN..n].to_vec();
        if header.length as usize != payload.len() {
            return Err(TunnelError::LengthMismatch {
                declared: header.length,
                actual: payload.len(),
            });
        }
        Ok((header, payload))
    }

    /// Close the carriage, recording why.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), TunnelError> {
        self.carriage.close(reason).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Aes256GcmTunnelChannel, ChannelRole};
    use crate::frame::{FrameKind, TUNNEL_FRAME_VERSION};
    use crate::loopback::LoopbackCarriage;

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

    /// **Mutations this detects:** trusting the header's declared length
    /// instead of checking it against the payload actually supplied — a parser
    /// bug with a buffer behind it, and the one the frame layer already refuses
    /// at its own seam.
    #[tokio::test]
    async fn a_length_that_disagrees_with_the_payload_is_refused_by_the_session_too() {
        let (mut node, mut gw) = pair();

        // Positive control: an agreeing length crosses.
        node.send_frame(FrameHeader::data(1, 4), b"abcd")
            .await
            .unwrap();
        assert_eq!(gw.recv_frame().await.unwrap().1, b"abcd");

        assert_eq!(
            node.send_frame(FrameHeader::data(1, 5), b"abcd").await,
            Err(TunnelError::LengthMismatch {
                declared: 5,
                actual: 4
            })
        );
    }

    /// **Mutations this detects:** dropping `encode`'s validation from the send
    /// path, so a header naming stream 0 on a per-stream kind, or an
    /// unsupported version, reaches the cipher and the peer.
    #[tokio::test]
    async fn a_malformed_header_is_refused_before_the_cipher() {
        let (mut node, _gw) = pair();

        let zero_stream = FrameHeader {
            version: TUNNEL_FRAME_VERSION,
            kind: FrameKind::StreamData,
            stream_id: 0,
            length: 1,
        };
        assert_eq!(
            node.send_frame(zero_stream, b"x").await,
            Err(TunnelError::ZeroStreamId(FrameKind::StreamData))
        );

        let bad_version = FrameHeader {
            version: TUNNEL_FRAME_VERSION + 1,
            kind: FrameKind::StreamData,
            stream_id: 1,
            length: 1,
        };
        assert_eq!(
            node.send_frame(bad_version, b"x").await,
            Err(TunnelError::UnsupportedFrameVersion {
                expected: TUNNEL_FRAME_VERSION,
                got: TUNNEL_FRAME_VERSION + 1,
            })
        );

        // Positive control: the same session still carries a good frame, so the
        // refusals above are about the headers and not about a dead session.
        node.send_frame(FrameHeader::data(1, 1), b"x")
            .await
            .unwrap();
    }

    /// The session owns its buffers on the heap, not in the future.
    ///
    /// **Mutations this detects:** moving `plain` or `wire` back into
    /// `send_frame`/`recv_frame` as stack arrays — which is invisible to every
    /// behavioural test and shows up only as a stack overflow under nesting.
    #[tokio::test]
    async fn the_session_buffers_are_session_owned_and_full_width() {
        let (node, _gw) = pair();
        assert_eq!(node.plain.len(), MAX_FRAME_PLAINTEXT);
        assert_eq!(node.wire.len(), MAX_FRAME_WIRE);

        // The whole future must be small: a session future carrying four
        // 64 KiB arrays is what this design exists to prevent. The bound is
        // deliberately loose — it fails on kilobytes, not on bytes.
        let (mut a, _b) = pair();
        let fut = a.send_frame(FrameHeader::data(1, 1), b"x");
        assert!(
            std::mem::size_of_val(&fut) < 8_192,
            "the send future is {} bytes; a frame buffer is living inside it",
            std::mem::size_of_val(&fut)
        );
        fut.await.unwrap();
    }

    /// **Mutations this detects:** letting `apply` advance the state on a
    /// refused transition, so an illegal event still moves the session.
    #[tokio::test]
    async fn a_refused_transition_leaves_the_state_where_it_was() {
        let (mut node, _gw) = pair();
        node.state = TunnelState::ConfirmSent;
        assert_eq!(
            node.apply(TunnelEvent::StreamOpened).unwrap_err(),
            TunnelError::IllegalTransition {
                from: "ConfirmSent",
                event: "StreamOpened",
            }
        );
        assert_eq!(node.state, TunnelState::ConfirmSent);

        // Positive control: a legal transition does move it.
        node.apply(TunnelEvent::PeerConfirmed).unwrap();
        assert_eq!(node.state, TunnelState::Ready);
        assert!(node.state.may_carry_stream_data());
    }
}
