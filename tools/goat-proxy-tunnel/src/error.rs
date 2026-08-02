//! The tunnel's refusal typology.
//!
//! Every variant is a *refusal*, never a clamp and never a best-effort guess.
//! Assertions in this crate are on variants and byte offsets, never on log
//! text, so the shape of this enum is part of the tested surface.
//!
//! [`TunnelError::Aead`] is the one variant that carries a foreign error type:
//! it wraps [`goat_core::transport::TransportError`] unchanged. That is
//! deliberate — the frozen trait's failure vocabulary is not re-spelled here,
//! because re-spelling it is how a wrapper starts to diverge from the thing it
//! wraps.

use goat_core::transport::TransportError;

use crate::carriage::CloseReason;
use crate::frame::FrameKind;
use crate::sockets::SocketsError;

/// Why the tunnel refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    /// The wrapped frozen [`goat_core::transport::SecureChannel`] failed. Tag
    /// mismatch, replay, exhausted nonce space or an undersized buffer.
    #[error("AEAD channel failure: {0:?}")]
    Aead(TransportError),

    /// The frame header declared a version this build does not speak.
    #[error("frame version {got} is not the supported version {expected}")]
    UnsupportedFrameVersion { expected: u8, got: u8 },

    /// The frame header's kind byte is not one of the five defined kinds.
    #[error("frame kind byte {0:#04x} is not defined")]
    UnknownFrameKind(u8),

    /// A header could not be read: the buffer was shorter than
    /// [`crate::frame::TUNNEL_FRAME_HEADER_LEN`].
    #[error("frame header is malformed or truncated")]
    MalformedHeader,

    /// A per-stream frame carried stream id 0, which names no stream.
    #[error("{0:?} frames must name a non-zero stream id")]
    ZeroStreamId(FrameKind),

    /// A session-scoped frame carried a non-zero stream id.
    #[error("{0:?} frames are session-scoped and must carry stream id 0")]
    StreamIdOnSessionFrame(FrameKind),

    /// The header's declared length is not the payload actually present. A
    /// length field that is trusted rather than checked is a parser bug with a
    /// buffer behind it.
    #[error("header declares {declared} payload byte(s) but {actual} were supplied")]
    LengthMismatch { declared: u32, actual: usize },

    /// A payload, plaintext or wire buffer exceeded its hard bound.
    #[error("{len} byte(s) exceeds the {max}-byte bound")]
    FrameTooLarge { len: usize, max: usize },

    /// The peer offered no post-quantum key encapsulation mechanism. There is
    /// no classical-only fallback on this path and no session key is derived.
    #[error("peer offered no post-quantum KEM; there is no classical-only fallback")]
    NoPostQuantumKem,

    /// The peer speaks a different tunnel protocol version.
    #[error("tunnel protocol version {got} is not the supported version {expected}")]
    ProtocolVersionMismatch { expected: u16, got: u16 },

    /// An ML-DSA-65 signature did not verify over its context-bound preimage.
    #[error("handshake signature did not verify")]
    HandshakeSignatureInvalid,

    /// The hello named an all-zero consent record hash — the "I did not fill
    /// this in" value, which must never read as a valid consent.
    #[error("hello carries an all-zero consent record hash")]
    ZeroConsentRecordHash,

    /// The hello named an all-zero policy text hash.
    #[error("hello carries an all-zero policy text hash")]
    ZeroPolicyTextHash,

    /// The hello named a destination allowlist digest the gateway has never
    /// published. The gateway serves the lists it published, not the lists a
    /// node claims.
    #[error("hello names an allowlist digest this gateway does not publish")]
    UnknownAllowlistDigest,

    /// This exact hello has already been accepted in this gateway session.
    #[error("hello replayed")]
    ReplayedHello,

    /// The gateway's replay cache is full and refuses to forget anything.
    ///
    /// Eviction is the wrong answer here and is deliberately not implemented:
    /// evicting an entry silently re-admits the hello it was tracking. Until
    /// the hello carries a freshness field there is no safe eviction order, so
    /// the cache fails closed instead.
    #[error("replay cache is full at {tracked} entries and does not evict")]
    ReplayCacheFull { tracked: usize },

    /// ML-KEM-768 encapsulation or decapsulation failed — a malformed key or
    /// ciphertext.
    #[error("ML-KEM-768 operation failed")]
    KemFailure,

    /// ML-DSA-65 signing failed, or this backend holds no signing key.
    #[error("ML-DSA-65 signing failed")]
    SigningFailure,

    /// The carriage has been closed and will not carry another byte. The
    /// reason is retained because [`CloseReason::KillSwitch`] and
    /// [`CloseReason::PolicyRefusal`] are not recoverable and the other two
    /// are.
    #[error("carriage closed: {0:?}")]
    CarriageClosed(CloseReason),

    /// A send or receive was attempted on a carriage that has not dialled yet.
    #[error("carriage is not open")]
    CarriageNotOpen,

    /// The dial target is not an outbound WSS-on-443 target.
    #[error("carriage target refused: {0:?}")]
    CarriageRefusedTarget(TargetRefusal),

    /// The outer carriage failed at the socket or WebSocket layer.
    #[error("carriage transport failure: {0}")]
    CarriageIo(String),

    /// The operating-system socket census could not answer.
    #[error("socket census failed: {0:?}")]
    Sockets(SocketsError),

    /// The tunnel state machine has no edge for this pair.
    ///
    /// Both fields are `&'static str` enum spellings rather than a `Debug`
    /// render, because this refusal is asserted on by name in tests and a
    /// derive is not a stable surface.
    #[error("{event} is not a legal event in state {from}")]
    IllegalTransition {
        from: &'static str,
        event: &'static str,
    },

    /// A stream id was opened twice. Two live streams under one id interleave
    /// their bytes into one consumer response.
    #[error("stream {0} is already open")]
    DuplicateStreamId(u32),

    /// A stream was closed that was never open. A driver that has lost track
    /// of its own streams must not be allowed to free a slot twice.
    #[error("stream {0} is not open")]
    UnknownStreamId(u32),

    /// The per-node concurrent-stream bound would be exceeded.
    #[error("{open} stream(s) already open; the bound is {max}")]
    TooManyStreams { open: usize, max: usize },

    /// The desktop shell asked to clear a halt. Clearing a halt is not a shell
    /// verb, in any state: the sidecar owns the kill switch.
    #[error("a halt cannot be cleared by the shell; the sidecar owns the kill switch")]
    HaltNotClearableByShell,

    /// A halt was engaged and nothing clears it for the life of the process.
    #[error("the halt is sticky; only a fresh process carries again")]
    HaltIsSticky,

    /// A stream was requested on a halted tunnel.
    #[error("the tunnel is halted")]
    TunnelHalted,

    /// A stream was requested with no fresh heartbeat. New streams stop; the
    /// carriage is not dropped.
    #[error("no heartbeat within the liveness window; new streams are stopped")]
    HeartbeatStale,

    /// The gateway witnessed more body bytes than the node declared, plus the
    /// one-frame allowance. A **refusal**: never a clamp to the declared
    /// length, which would make an over-sending session indistinguishable from
    /// an honest one.
    #[error(
        "witnessed {observed} body byte(s) against a declared {declared} plus a {allowance}-byte \
         allowance"
    )]
    MeteredBytesExceedDeclared {
        observed: u64,
        declared: u64,
        allowance: u64,
    },

    /// A meter counter could not count any further. Refused rather than
    /// wrapped or saturated: a counter that silently stops counting
    /// under-reports for the rest of the session.
    #[error("a meter counter would overflow")]
    MeterCounterOverflow,

    /// A second node was offered work while one is already scheduled.
    #[error("{max} node(s) may be scheduled at once and that many already are")]
    SchedulerAtCapacity { max: usize },

    /// The node cannot take work right now, for a stated reason.
    #[error("node is not schedulable: {0:?}")]
    NodeNotSchedulable(crate::capacity::DeScheduleReason),
}

impl From<TransportError> for TunnelError {
    #[inline]
    fn from(e: TransportError) -> Self {
        TunnelError::Aead(e)
    }
}

impl From<SocketsError> for TunnelError {
    #[inline]
    fn from(e: SocketsError) -> Self {
        TunnelError::Sockets(e)
    }
}

/// Why a dial target was refused before any socket work happened.
///
/// The carriage is **outbound only, to 443, over TLS**. Each of these is a
/// separate variant rather than one "bad url" because a test that asserts a
/// refusal without asserting *which* refusal passes against a component that
/// refuses everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetRefusal {
    /// The URL did not parse.
    Unparsable,
    /// The scheme was not `wss`. Plain `ws` is not carriage, it is exposure.
    NotWssScheme,
    /// An explicit port was present and it was not 443.
    NotPortFourFourThree,
    /// The URL named no host.
    HostMissing,
    /// The authority carried userinfo (`user@host`), which is a credential in
    /// a URL and is never accepted here.
    AuthorityCarriesUserinfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Mutations this detects:** collapsing two refusal causes onto one
    /// variant, or making `TunnelError` non-comparable so refusal tests can
    /// only assert "some error happened".
    #[test]
    fn every_refusal_cause_is_a_distinct_comparable_variant() {
        let all = [
            TunnelError::MalformedHeader,
            TunnelError::UnknownFrameKind(9),
            TunnelError::UnsupportedFrameVersion {
                expected: 1,
                got: 2,
            },
            TunnelError::NoPostQuantumKem,
            TunnelError::HandshakeSignatureInvalid,
            TunnelError::ZeroConsentRecordHash,
            TunnelError::ZeroPolicyTextHash,
            TunnelError::UnknownAllowlistDigest,
            TunnelError::ReplayedHello,
            TunnelError::CarriageNotOpen,
            TunnelError::CarriageClosed(CloseReason::KillSwitch),
            TunnelError::CarriageRefusedTarget(TargetRefusal::NotWssScheme),
        ];
        // Positive control: an item does equal itself, so an all-distinct
        // result below is not the artefact of a broken `PartialEq`.
        assert_eq!(all[0], all[0].clone());
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} compare equal");
                }
            }
        }
    }

    /// **Mutations this detects:** re-spelling the frozen crate's
    /// `TransportError` into local variants, which would let the wrapper drift
    /// from the thing it wraps without any test noticing.
    #[test]
    fn the_frozen_transport_error_is_carried_through_unchanged() {
        let wrapped: TunnelError = TransportError::DecryptionFailed.into();
        assert_eq!(wrapped, TunnelError::Aead(TransportError::DecryptionFailed));
        assert_ne!(wrapped, TunnelError::Aead(TransportError::BufferTooSmall));
    }

    /// **Mutations this detects:** dropping the `TargetRefusal` detail so that
    /// "wrong scheme" and "wrong port" become the same answer.
    #[test]
    fn target_refusals_do_not_collapse_into_one_cause() {
        assert_ne!(
            TunnelError::CarriageRefusedTarget(TargetRefusal::NotWssScheme),
            TunnelError::CarriageRefusedTarget(TargetRefusal::NotPortFourFourThree)
        );
    }
}
