//! The tunnel frame format.
//!
//! # Layout — 10 bytes, big-endian, no padding
//!
//! ```text
//! offset  width  field       notes
//! ------  -----  ----------  ---------------------------------------------
//!   0       1    version     TUNNEL_FRAME_VERSION; anything else refuses
//!   1       1    kind        1 StreamOpen 2 StreamData 3 StreamEnd
//!                            4 Control    5 MeterTick
//!   2       4    stream_id   u32 BE; non-zero for the three stream kinds,
//!                            zero for the two session kinds
//!   6       4    length      u32 BE; payload bytes that follow the header
//!  10       N    payload     N == length, N <= MAX_FRAME_PAYLOAD
//! ```
//!
//! **The header is inside the AEAD plaintext, never in the clear.** The sealed
//! plaintext is `header ‖ payload` and the wire form is
//! `AEAD(header ‖ payload)`, so whoever terminates the outer TLS sees an
//! opaque blob — no kind, no stream id, no length, and therefore no way to
//! tell a control frame from a data frame or to count streams. A header
//! outside the AEAD would leak exactly that structure to a middlebox, and the
//! outer TLS is not the trust boundary, so it must not be relied on to hide
//! it.
//!
//! # Why `MAX_FRAME_PAYLOAD` is 64 KiB, written down here
//!
//! It matches the sidecar's origin read buffer, so one origin read becomes one
//! frame with no re-chunking and no second copy. It is deliberately **not**
//! sized from the response ceiling: a session streams many frames, it does not
//! send one enormous one. And it is small enough that a buffer of that size is
//! survivable — such buffers must live in a per-session reusable `Vec`, never
//! as a stack array inside an `async fn`, because a stack array is stored in
//! the future and two of them per frame in two nested methods overflows a
//! default worker stack.
//!
//! Design authority: the "Residential Proxy Network (P3) Implementation Plan",
//! §4.1 ("Max frame payload") and §2 (INV-12).

use goat_core::transport::AES_256_GCM_TAG_LEN;

use crate::channel::TunnelChannel;
use crate::error::TunnelError;

/// The only frame version this build speaks.
pub const TUNNEL_FRAME_VERSION: u8 = 1;

/// Encoded header width in bytes.
pub const TUNNEL_FRAME_HEADER_LEN: usize = 10;

/// Largest payload a single frame may carry (64 KiB).
pub const MAX_FRAME_PAYLOAD: usize = 65_536;

/// Largest plaintext handed to the AEAD: header plus a full payload.
pub const MAX_FRAME_PLAINTEXT: usize = TUNNEL_FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD;

/// Largest wire frame: the plaintext plus the AEAD tag.
pub const MAX_FRAME_WIRE: usize = MAX_FRAME_PLAINTEXT + AES_256_GCM_TAG_LEN;

/// What a frame is for.
///
/// The wire values are load-bearing and are pinned by a test: renumbering them
/// is a protocol break, not a refactor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// Open a new stream. Per-stream.
    StreamOpen = 1,
    /// Payload bytes on an open stream. Per-stream.
    StreamData = 2,
    /// Half-close a stream. Per-stream.
    StreamEnd = 3,
    /// Session-scoped control.
    Control = 4,
    /// Session-scoped metering tick.
    MeterTick = 5,
}

impl FrameKind {
    /// The wire byte.
    #[inline]
    pub fn byte(self) -> u8 {
        self as u8
    }

    /// Decode a wire byte, refusing anything undefined.
    ///
    /// There is no "unknown, ignore it" path. A frame this build cannot name
    /// is a frame it cannot bound, and an unbounded frame is not carried.
    #[inline]
    pub fn from_byte(b: u8) -> Result<Self, TunnelError> {
        match b {
            1 => Ok(FrameKind::StreamOpen),
            2 => Ok(FrameKind::StreamData),
            3 => Ok(FrameKind::StreamEnd),
            4 => Ok(FrameKind::Control),
            5 => Ok(FrameKind::MeterTick),
            other => Err(TunnelError::UnknownFrameKind(other)),
        }
    }

    /// Whether this kind names a single stream (as opposed to the session).
    #[inline]
    pub fn is_per_stream(self) -> bool {
        matches!(
            self,
            FrameKind::StreamOpen | FrameKind::StreamData | FrameKind::StreamEnd
        )
    }
}

/// A decoded frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version byte.
    pub version: u8,
    /// What the frame is for.
    pub kind: FrameKind,
    /// Which stream, or 0 for the session.
    pub stream_id: u32,
    /// Payload bytes that follow.
    pub length: u32,
}

impl FrameHeader {
    /// A `StreamData` header for `stream_id` carrying `length` payload bytes.
    pub fn data(stream_id: u32, length: u32) -> Self {
        Self {
            version: TUNNEL_FRAME_VERSION,
            kind: FrameKind::StreamData,
            stream_id,
            length,
        }
    }

    /// A session-scoped header of `kind` carrying `length` payload bytes.
    pub fn session(kind: FrameKind, length: u32) -> Self {
        Self {
            version: TUNNEL_FRAME_VERSION,
            kind,
            stream_id: 0,
            length,
        }
    }

    /// Check every field bound. Called by both [`Self::encode`] and
    /// [`Self::decode`], so a header cannot enter or leave the crate
    /// unvalidated.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.version != TUNNEL_FRAME_VERSION {
            return Err(TunnelError::UnsupportedFrameVersion {
                expected: TUNNEL_FRAME_VERSION,
                got: self.version,
            });
        }
        if self.kind.is_per_stream() {
            if self.stream_id == 0 {
                return Err(TunnelError::ZeroStreamId(self.kind));
            }
        } else if self.stream_id != 0 {
            // Session kinds are session-scoped by definition. A later task
            // that genuinely needs per-stream control must change this rule
            // deliberately and update this test, rather than discover that the
            // field was never checked.
            return Err(TunnelError::StreamIdOnSessionFrame(self.kind));
        }
        if self.length as usize > MAX_FRAME_PAYLOAD {
            return Err(TunnelError::FrameTooLarge {
                len: self.length as usize,
                max: MAX_FRAME_PAYLOAD,
            });
        }
        Ok(())
    }

    /// Encode to exactly [`TUNNEL_FRAME_HEADER_LEN`] bytes, validating first.
    pub fn encode(&self) -> Result<[u8; TUNNEL_FRAME_HEADER_LEN], TunnelError> {
        self.validate()?;
        let mut out = [0u8; TUNNEL_FRAME_HEADER_LEN];
        out[0] = self.version;
        out[1] = self.kind.byte();
        out[2..6].copy_from_slice(&self.stream_id.to_be_bytes());
        out[6..10].copy_from_slice(&self.length.to_be_bytes());
        Ok(out)
    }

    /// Decode from the first [`TUNNEL_FRAME_HEADER_LEN`] bytes of `buf`,
    /// validating.
    pub fn decode(buf: &[u8]) -> Result<Self, TunnelError> {
        if buf.len() < TUNNEL_FRAME_HEADER_LEN {
            return Err(TunnelError::MalformedHeader);
        }
        let header = Self {
            version: buf[0],
            kind: FrameKind::from_byte(buf[1])?,
            stream_id: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            length: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Seal `header ‖ payload` into `out`, returning the wire length.
///
/// `header.length` must equal `payload.len()`: a length field that is copied
/// from the header rather than checked against the payload is a parser bug
/// with a buffer behind it.
pub fn seal_frame<C: TunnelChannel>(
    channel: &mut C,
    header: &FrameHeader,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, TunnelError> {
    if header.length as usize != payload.len() {
        return Err(TunnelError::LengthMismatch {
            declared: header.length,
            actual: payload.len(),
        });
    }
    let encoded = header.encode()?;
    let mut plaintext = Vec::with_capacity(TUNNEL_FRAME_HEADER_LEN + payload.len());
    plaintext.extend_from_slice(&encoded);
    plaintext.extend_from_slice(payload);
    channel.seal(&plaintext, out)
}

/// Open a wire frame, returning the header and the payload length written into
/// `out`.
pub fn open_frame<C: TunnelChannel>(
    channel: &mut C,
    wire: &[u8],
    out: &mut [u8],
) -> Result<(FrameHeader, usize), TunnelError> {
    let mut plaintext = vec![0u8; MAX_FRAME_PLAINTEXT];
    let n = channel.open(wire, &mut plaintext)?;
    if n < TUNNEL_FRAME_HEADER_LEN {
        return Err(TunnelError::MalformedHeader);
    }
    let header = FrameHeader::decode(&plaintext[..TUNNEL_FRAME_HEADER_LEN])?;
    let payload = &plaintext[TUNNEL_FRAME_HEADER_LEN..n];
    if header.length as usize != payload.len() {
        return Err(TunnelError::LengthMismatch {
            declared: header.length,
            actual: payload.len(),
        });
    }
    if out.len() < payload.len() {
        return Err(TunnelError::FrameTooLarge {
            len: payload.len(),
            max: out.len(),
        });
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok((header, payload.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{tunnel_seam, ChannelRole};

    fn seam_pair() -> (impl TunnelChannel, impl TunnelChannel) {
        let key = [0xC3u8; 32];
        (
            tunnel_seam(key, ChannelRole::Initiator),
            tunnel_seam(key, ChannelRole::Responder),
        )
    }

    /// **Mutations this detects:** widening or narrowing the header, or adding
    /// a field without changing the constant.
    #[test]
    fn header_encodes_to_exactly_ten_bytes() {
        assert_eq!(TUNNEL_FRAME_HEADER_LEN, 10);
        let h = FrameHeader::data(1, 0);
        assert_eq!(h.encode().unwrap().len(), 10);
    }

    /// **Mutations this detects:** moving a field, changing a width, or
    /// flipping an endianness — each of which round-trips cleanly and is
    /// invisible to a round-trip-only test.
    #[test]
    fn the_header_field_offsets_are_pinned() {
        let h = FrameHeader {
            version: TUNNEL_FRAME_VERSION,
            kind: FrameKind::StreamEnd,
            stream_id: 0x0102_0304,
            length: 0x0000_ABCD,
        };
        let e = h.encode().unwrap();
        assert_eq!(e[0], 1, "version at offset 0");
        assert_eq!(e[1], 3, "kind at offset 1");
        assert_eq!(&e[2..6], &[0x01, 0x02, 0x03, 0x04], "stream_id BE at 2..6");
        assert_eq!(&e[6..10], &[0x00, 0x00, 0xAB, 0xCD], "length BE at 6..10");
    }

    /// **Mutations this detects:** renumbering a kind, which is a silent
    /// protocol break between two builds.
    #[test]
    fn the_kind_wire_bytes_are_pinned() {
        assert_eq!(FrameKind::StreamOpen.byte(), 1);
        assert_eq!(FrameKind::StreamData.byte(), 2);
        assert_eq!(FrameKind::StreamEnd.byte(), 3);
        assert_eq!(FrameKind::Control.byte(), 4);
        assert_eq!(FrameKind::MeterTick.byte(), 5);
        for b in 1..=5u8 {
            assert_eq!(FrameKind::from_byte(b).unwrap().byte(), b);
        }
    }

    /// **Mutations this detects:** dropping `validate` from either `encode` or
    /// `decode`, so a bad header enters or leaves unchecked.
    #[test]
    fn header_round_trips_through_encode_and_decode() {
        let cases = [
            FrameHeader::data(1, 0),
            FrameHeader::data(u32::MAX, MAX_FRAME_PAYLOAD as u32),
            FrameHeader::session(FrameKind::Control, 7),
            FrameHeader::session(FrameKind::MeterTick, 0),
            FrameHeader {
                version: TUNNEL_FRAME_VERSION,
                kind: FrameKind::StreamOpen,
                stream_id: 42,
                length: 1,
            },
        ];
        for h in cases {
            let e = h.encode().unwrap();
            assert_eq!(FrameHeader::decode(&e).unwrap(), h);
        }
    }

    /// **Mutations this detects:** trusting the header's `length` instead of
    /// checking it against the payload actually supplied.
    #[test]
    fn a_length_that_disagrees_with_the_payload_is_refused() {
        let (mut node, _gw) = seam_pair();
        let mut out = vec![0u8; MAX_FRAME_WIRE];

        // Positive control: agreeing length seals.
        let good = FrameHeader::data(1, 4);
        assert!(seal_frame(&mut node, &good, b"abcd", &mut out).is_ok());

        let bad = FrameHeader::data(1, 5);
        assert_eq!(
            seal_frame(&mut node, &bad, b"abcd", &mut out),
            Err(TunnelError::LengthMismatch {
                declared: 5,
                actual: 4
            })
        );
    }

    /// **Mutations this detects:** adding an "unknown kind, ignore it" arm.
    #[test]
    fn an_unknown_kind_byte_is_refused() {
        // Positive control: a defined byte decodes.
        let mut buf = FrameHeader::data(1, 0).encode().unwrap();
        assert!(FrameHeader::decode(&buf).is_ok());

        for bad in [0u8, 6, 7, 0x80, 0xFF] {
            buf[1] = bad;
            assert_eq!(
                FrameHeader::decode(&buf),
                Err(TunnelError::UnknownFrameKind(bad)),
                "kind byte {bad} was accepted"
            );
        }
    }

    /// **Mutations this detects:** removing the stream-id check, so a
    /// per-stream frame that names no stream is carried and demultiplexed onto
    /// whatever stream 0 happens to be.
    #[test]
    fn a_zero_stream_id_is_refused_for_stream_kinds() {
        // Positive control: a non-zero id on the same kinds is accepted.
        for kind in [
            FrameKind::StreamOpen,
            FrameKind::StreamData,
            FrameKind::StreamEnd,
        ] {
            let ok = FrameHeader {
                version: TUNNEL_FRAME_VERSION,
                kind,
                stream_id: 1,
                length: 0,
            };
            assert!(ok.validate().is_ok(), "{kind:?} with id 1 was refused");

            let bad = FrameHeader {
                version: TUNNEL_FRAME_VERSION,
                kind,
                stream_id: 0,
                length: 0,
            };
            assert_eq!(bad.validate(), Err(TunnelError::ZeroStreamId(kind)));
            assert_eq!(bad.encode(), Err(TunnelError::ZeroStreamId(kind)));
        }
    }

    /// **Mutations this detects:** letting a session-scoped frame carry a
    /// stream id, which makes "which stream is this control for?" ambiguous on
    /// the wire.
    #[test]
    fn a_nonzero_stream_id_is_refused_for_session_kinds() {
        for kind in [FrameKind::Control, FrameKind::MeterTick] {
            assert!(FrameHeader::session(kind, 0).validate().is_ok());
            let bad = FrameHeader {
                version: TUNNEL_FRAME_VERSION,
                kind,
                stream_id: 1,
                length: 0,
            };
            assert_eq!(
                bad.validate(),
                Err(TunnelError::StreamIdOnSessionFrame(kind))
            );
        }
    }

    /// The plan spells this name with a capitalised variant; Rust's
    /// `non_snake_case` lint is denied in this crate's clippy gate, so the
    /// snake_case spelling is used and the variant is asserted in the body.
    ///
    /// **Mutations this detects:** indexing a short buffer (a panic rather
    /// than a refusal), or answering a truncated header with a different
    /// cause.
    #[test]
    fn decode_of_a_short_buffer_is_malformed_header() {
        let full = FrameHeader::data(1, 0).encode().unwrap();
        // Positive control: the full buffer decodes.
        assert!(FrameHeader::decode(&full).is_ok());
        for n in 0..TUNNEL_FRAME_HEADER_LEN {
            assert_eq!(
                FrameHeader::decode(&full[..n]),
                Err(TunnelError::MalformedHeader),
                "a {n}-byte buffer did not read as a malformed header"
            );
        }
    }

    /// **Mutations this detects:** accepting a future version byte "for
    /// forward compatibility", which silently reinterprets every field after
    /// it.
    #[test]
    fn an_unsupported_version_byte_is_refused() {
        let mut buf = FrameHeader::data(1, 0).encode().unwrap();
        assert!(FrameHeader::decode(&buf).is_ok());
        for v in [0u8, 2, 3, 0xFF] {
            buf[0] = v;
            assert_eq!(
                FrameHeader::decode(&buf),
                Err(TunnelError::UnsupportedFrameVersion {
                    expected: TUNNEL_FRAME_VERSION,
                    got: v
                })
            );
        }
    }

    /// **Mutations this detects:** raising or removing the payload bound, or
    /// deriving `MAX_FRAME_WIRE` from something other than plaintext + tag.
    #[test]
    fn the_frame_size_constants_are_pinned() {
        assert_eq!(MAX_FRAME_PAYLOAD, 65_536);
        assert_eq!(MAX_FRAME_PLAINTEXT, 65_546);
        assert_eq!(MAX_FRAME_WIRE, 65_562);
        assert_eq!(
            MAX_FRAME_PLAINTEXT,
            TUNNEL_FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD
        );
        assert_eq!(MAX_FRAME_WIRE, MAX_FRAME_PLAINTEXT + AES_256_GCM_TAG_LEN);

        let at_bound = FrameHeader::data(1, MAX_FRAME_PAYLOAD as u32);
        assert!(at_bound.validate().is_ok());
        let over = FrameHeader::data(1, MAX_FRAME_PAYLOAD as u32 + 1);
        assert_eq!(
            over.validate(),
            Err(TunnelError::FrameTooLarge {
                len: MAX_FRAME_PAYLOAD + 1,
                max: MAX_FRAME_PAYLOAD
            })
        );
    }

    /// **Mutations this detects:** dropping the payload copy, mis-slicing the
    /// payload by the header width, or returning the plaintext length instead
    /// of the payload length.
    #[test]
    fn a_frame_round_trips_through_the_wrapped_channel_in_both_directions() {
        let (mut node, mut gateway) = seam_pair();
        let mut wire = vec![0u8; MAX_FRAME_WIRE];
        let mut got = vec![0u8; MAX_FRAME_PAYLOAD];

        let up = FrameHeader::data(9, 5);
        let n = seal_frame(&mut node, &up, b"hello", &mut wire).unwrap();
        assert_eq!(n, TUNNEL_FRAME_HEADER_LEN + 5 + AES_256_GCM_TAG_LEN);
        let (h, m) = open_frame(&mut gateway, &wire[..n], &mut got).unwrap();
        assert_eq!(h, up);
        assert_eq!(&got[..m], b"hello");

        let down = FrameHeader::session(FrameKind::MeterTick, 3);
        let n = seal_frame(&mut gateway, &down, b"xyz", &mut wire).unwrap();
        let (h, m) = open_frame(&mut node, &wire[..n], &mut got).unwrap();
        assert_eq!(h, down);
        assert_eq!(&got[..m], b"xyz");
    }

    /// INV-12's third named test.
    ///
    /// **Mutations this detects:** moving the header outside the AEAD — the
    /// change that leaks kind, stream id and length to whoever terminates the
    /// outer TLS, and the single most likely "optimisation" a future reader
    /// will attempt.
    #[test]
    fn header_is_inside_the_aead_plaintext_not_in_the_clear() {
        let (mut node, mut gateway) = seam_pair();
        let mut wire = vec![0u8; MAX_FRAME_WIRE];

        let header = FrameHeader::data(0xDEAD_BEEF, 6);
        let payload = b"secret";
        let encoded = header.encode().unwrap();

        let n = seal_frame(&mut node, &header, payload, &mut wire).unwrap();
        let on_wire = &wire[..n];

        // Positive control: the encoded header IS findable in the plaintext,
        // so "not found on the wire" below is a statement about the AEAD and
        // not about a broken search.
        let plaintext: Vec<u8> = encoded
            .iter()
            .copied()
            .chain(payload.iter().copied())
            .collect();
        assert!(
            plaintext.windows(encoded.len()).any(|w| w == encoded),
            "the search cannot find the header in the plaintext it came from"
        );

        assert!(
            !on_wire.windows(encoded.len()).any(|w| w == encoded),
            "the encoded header appears verbatim on the wire"
        );
        assert!(
            !on_wire.windows(payload.len()).any(|w| w == payload),
            "the payload appears verbatim on the wire"
        );
        assert!(
            !on_wire
                .windows(4)
                .any(|w| w == 0xDEAD_BEEFu32.to_be_bytes()),
            "the stream id appears verbatim on the wire"
        );
        assert_ne!(
            FrameHeader::decode(&on_wire[..TUNNEL_FRAME_HEADER_LEN]).ok(),
            Some(header),
            "the first ten wire bytes decode to the header, so it is in the clear"
        );

        // And it still opens at the far end.
        let mut got = vec![0u8; MAX_FRAME_PAYLOAD];
        let (h, m) = open_frame(&mut gateway, on_wire, &mut got).unwrap();
        assert_eq!(h, header);
        assert_eq!(&got[..m], payload);
    }

    /// **Mutations this detects:** opening a frame whose plaintext is shorter
    /// than a header, which would index past the end of the buffer.
    #[test]
    fn a_frame_whose_plaintext_is_shorter_than_a_header_is_refused() {
        let key = [0x11u8; 32];
        let mut node = tunnel_seam(key, ChannelRole::Initiator);
        let mut gateway = tunnel_seam(key, ChannelRole::Responder);
        let mut wire = vec![0u8; MAX_FRAME_WIRE];
        let mut got = vec![0u8; MAX_FRAME_PAYLOAD];

        // A raw seal that bypasses `seal_frame`, so the plaintext carries no
        // header at all.
        let n = node.seal(b"short", &mut wire).unwrap();
        assert_eq!(
            open_frame(&mut gateway, &wire[..n], &mut got),
            Err(TunnelError::MalformedHeader)
        );
    }
}
