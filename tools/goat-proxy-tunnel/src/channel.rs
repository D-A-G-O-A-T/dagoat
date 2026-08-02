//! The AEAD channel — and the new trait that wraps the frozen one.
//!
//! # What is frozen and what is new
//!
//! [`goat_core::transport::SecureChannel`] is frozen. Its shape is byte slice
//! in, byte slice out; it is `no_std`, allocation-free and synchronous; and it
//! has no address, connect, accept or stream concept. It is a **framing**
//! seam, not a transport seam. "No change to the frozen trait surfaces" is a
//! standing non-goal of the convergence architecture, so this module:
//!
//! * **implements** the frozen trait for [`Aes256GcmTunnelChannel`], and
//! * **defines a new trait**, [`TunnelChannel`], which adds the tunnel's own
//!   bounds and observability, and
//! * **wraps** any frozen implementation in [`TunnelSeam`], which is generic
//!   over `C: SecureChannel` and therefore cannot depend on which
//!   implementation it holds.
//!
//! Nothing here edits the frozen trait and nothing here re-implements it.
//!
//! # Two nonce prefixes per channel, not one
//!
//! The frozen trait's own doc comment says it manages "disjoint per-direction
//! nonce spaces" — *per direction*, which is **two** spaces per endpoint, not
//! one. A channel therefore holds `out_role = self.role` **and**
//! `in_role = self.role.peer()`, with separate counters.
//!
//! One role byte per channel does not work, and it fails silently in the
//! direction that matters: the responder would decrypt under
//! `role = Responder` while the initiator encrypted under `role = Initiator`,
//! so every inbound frame would fail its tag and no round trip would ever
//! complete.
//!
//! Nonce layout, 96 bits: `[ role ‖ 0x00 0x00 0x00 ‖ counter_be_u64 ]`. This
//! is byte-identical to the spine's host backend (`src/bin/host_crypto.rs`),
//! which is what makes the known-answer vectors below transferable between the
//! two.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use goat_core::transport::{SecureChannel, TransportError, AES_256_GCM_TAG_LEN};

use crate::error::TunnelError;
use crate::frame::{MAX_FRAME_PLAINTEXT, MAX_FRAME_WIRE};

/// AES-256-GCM nonce width in bytes (96-bit).
pub const TUNNEL_NONCE_LEN: usize = 12;

/// Which half of the bidirectional nonce space an endpoint owns.
///
/// The discriminants are load-bearing: they are the nonce's high byte, and the
/// spine's host backend uses the same two values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChannelRole {
    /// The node. Dials out, seals under nonce prefix `0`.
    Initiator = 0,
    /// The gateway. Seals under nonce prefix `1`.
    Responder = 1,
}

impl ChannelRole {
    /// The nonce's high byte for this role.
    #[inline]
    pub fn byte(self) -> u8 {
        self as u8
    }

    /// The other end's role — the space this endpoint *opens* from.
    #[inline]
    pub fn peer(self) -> Self {
        match self {
            ChannelRole::Initiator => ChannelRole::Responder,
            ChannelRole::Responder => ChannelRole::Initiator,
        }
    }
}

/// The tunnel's AES-256-GCM channel, behind the frozen
/// [`SecureChannel`] surface.
///
/// The wire form is `ciphertext ‖ tag` with no explicit nonce: both ends
/// advance their counters in lockstep, exactly as the spine's host backend
/// does. An out-of-order or dropped frame therefore fails its tag rather than
/// being silently accepted under the wrong nonce — which is the intended
/// behaviour for a carriage that guarantees ordering.
pub struct Aes256GcmTunnelChannel {
    cipher: Aes256Gcm,
    /// The direction this endpoint seals into.
    out_role: ChannelRole,
    /// The direction this endpoint opens from. Always `out_role.peer()`.
    in_role: ChannelRole,
    out_ctr: u64,
    in_ctr: u64,
}

impl Aes256GcmTunnelChannel {
    /// A channel over a 32-byte session key, for one role.
    pub fn new(key: [u8; 32], role: ChannelRole) -> Self {
        Self {
            cipher: Aes256Gcm::new((&key).into()),
            out_role: role,
            in_role: role.peer(),
            out_ctr: 0,
            in_ctr: 0,
        }
    }

    /// This endpoint's role.
    #[inline]
    pub fn role(&self) -> ChannelRole {
        self.out_role
    }

    /// Frames sealed so far — which is also the next outbound nonce counter.
    #[inline]
    pub fn frames_sealed(&self) -> u64 {
        self.out_ctr
    }

    /// Frames opened so far — which is also the next inbound nonce counter.
    #[inline]
    pub fn frames_opened(&self) -> u64 {
        self.in_ctr
    }

    /// The 96-bit nonce for `(role, counter)`.
    ///
    /// Exposed so tests can assert the two directions are disjoint on the
    /// value rather than on a comment.
    #[inline]
    pub fn nonce_bytes(role: ChannelRole, ctr: u64) -> [u8; TUNNEL_NONCE_LEN] {
        let mut n = [0u8; TUNNEL_NONCE_LEN];
        n[0] = role.byte();
        n[4..].copy_from_slice(&ctr.to_be_bytes());
        n
    }

    #[inline]
    fn nonce(role: ChannelRole, ctr: u64) -> Nonce<aes_gcm::aes::cipher::typenum::U12> {
        Self::nonce_bytes(role, ctr).into()
    }
}

impl SecureChannel for Aes256GcmTunnelChannel {
    fn encrypt_frame(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        let n = plaintext
            .len()
            .checked_add(AES_256_GCM_TAG_LEN)
            .ok_or(TransportError::BufferTooSmall)?;
        if out.len() < n {
            return Err(TransportError::BufferTooSmall);
        }
        let nonce = Self::nonce(self.out_role, self.out_ctr);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| TransportError::DecryptionFailed)?;
        if ct.len() != n {
            return Err(TransportError::DecryptionFailed);
        }
        out[..n].copy_from_slice(&ct);
        self.out_ctr = self
            .out_ctr
            .checked_add(1)
            .ok_or(TransportError::NonceExhausted)?;
        Ok(n)
    }

    fn decrypt_frame(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        if frame.len() < AES_256_GCM_TAG_LEN {
            return Err(TransportError::DecryptionFailed);
        }
        let pt_len = frame.len() - AES_256_GCM_TAG_LEN;
        if out.len() < pt_len {
            return Err(TransportError::BufferTooSmall);
        }
        let nonce = Self::nonce(self.in_role, self.in_ctr);
        let pt = self
            .cipher
            .decrypt(&nonce, frame)
            .map_err(|_| TransportError::DecryptionFailed)?;
        out[..pt.len()].copy_from_slice(&pt);
        self.in_ctr = self
            .in_ctr
            .checked_add(1)
            .ok_or(TransportError::NonceExhausted)?;
        Ok(pt.len())
    }
}

/// **The new trait.** The tunnel's own seam, defined in this crate.
///
/// It is not a replacement for [`SecureChannel`] and it does not widen it. It
/// adds the three things the tunnel needs and the frozen trait deliberately
/// does not have:
///
/// 1. **The tunnel's size bounds.** Refuse anything over
///    [`MAX_FRAME_PLAINTEXT`] / [`MAX_FRAME_WIRE`] *before* the AEAD is
///    touched, so an oversize buffer is a refusal rather than an allocation.
/// 2. **This crate's refusal typology.** [`TunnelError`] rather than
///    [`TransportError`], with the frozen error carried through unchanged
///    inside [`TunnelError::Aead`].
/// 3. **Frame counters as an observable.** The gateway's metering witness
///    needs to know how many frames crossed the seam; the frozen trait has no
///    opinion on that and should not be given one.
pub trait TunnelChannel {
    /// Seal `plaintext` into `out`, returning bytes written.
    fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, TunnelError>;

    /// Open `wire` into `out`, returning the plaintext length.
    fn open(&mut self, wire: &[u8], out: &mut [u8]) -> Result<usize, TunnelError>;

    /// Frames sealed by this endpoint so far.
    fn frames_sealed(&self) -> u64;

    /// Frames opened by this endpoint so far.
    fn frames_opened(&self) -> u64;
}

/// The wrapper. Generic over **any** frozen [`SecureChannel`].
///
/// This is the whole "wraps, never alters" claim made mechanical: the seam
/// cannot reach inside the channel it holds, cannot change its trait, and
/// cannot tell which implementation it has. Swapping
/// [`Aes256GcmTunnelChannel`] for a different frozen implementation is a type
/// parameter change and nothing else.
pub struct TunnelSeam<C: SecureChannel> {
    inner: C,
    sealed: u64,
    opened: u64,
}

impl<C: SecureChannel> TunnelSeam<C> {
    /// Wrap a frozen channel.
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            sealed: 0,
            opened: 0,
        }
    }

    /// Borrow the wrapped channel.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Unwrap, returning the frozen channel untouched.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: SecureChannel> TunnelChannel for TunnelSeam<C> {
    fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, TunnelError> {
        if plaintext.len() > MAX_FRAME_PLAINTEXT {
            return Err(TunnelError::FrameTooLarge {
                len: plaintext.len(),
                max: MAX_FRAME_PLAINTEXT,
            });
        }
        let n = self.inner.encrypt_frame(plaintext, out)?;
        self.sealed = self.sealed.saturating_add(1);
        Ok(n)
    }

    fn open(&mut self, wire: &[u8], out: &mut [u8]) -> Result<usize, TunnelError> {
        if wire.len() > MAX_FRAME_WIRE {
            return Err(TunnelError::FrameTooLarge {
                len: wire.len(),
                max: MAX_FRAME_WIRE,
            });
        }
        let n = self.inner.decrypt_frame(wire, out)?;
        self.opened = self.opened.saturating_add(1);
        Ok(n)
    }

    fn frames_sealed(&self) -> u64 {
        self.sealed
    }

    fn frames_opened(&self) -> u64 {
        self.opened
    }
}

/// A sealed-and-wrapped tunnel channel for one role, ready for
/// [`crate::frame::seal_frame`].
pub fn tunnel_seam(key: [u8; 32], role: ChannelRole) -> TunnelSeam<Aes256GcmTunnelChannel> {
    TunnelSeam::new(Aes256GcmTunnelChannel::new(key, role))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Compile-time proof that the wrapper did not alter the frozen trait's
    /// shape. If `encrypt_frame` ever grows an argument, changes its error
    /// type, stops taking `&mut self`, or starts returning an owned buffer,
    /// these coercions stop compiling.
    ///
    /// **Mutations this detects:** any edit to
    /// `goat_core::transport::SecureChannel`'s method signatures, and any
    /// attempt to "wrap" it by declaring a look-alike method with a different
    /// shape.
    /// The frozen trait's method shape, written out once: `&mut self`, a
    /// borrowed input slice, a borrowed output slice, and a byte count or a
    /// `TransportError`. Nothing owned, nothing async, nothing addressed.
    type FrozenFrameFn =
        fn(&mut Aes256GcmTunnelChannel, &[u8], &mut [u8]) -> Result<usize, TransportError>;

    const _ENCRYPT_SHAPE: FrozenFrameFn = <Aes256GcmTunnelChannel as SecureChannel>::encrypt_frame;
    const _DECRYPT_SHAPE: FrozenFrameFn = <Aes256GcmTunnelChannel as SecureChannel>::decrypt_frame;

    /// A deliberately non-cryptographic frozen-trait implementation, so
    /// [`TunnelSeam`]'s genericity is exercised against something that is not
    /// AES at all.
    struct MarkerChannel {
        encrypts: u32,
        decrypts: u32,
    }

    impl SecureChannel for MarkerChannel {
        fn encrypt_frame(
            &mut self,
            plaintext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, TransportError> {
            let n = plaintext.len() + AES_256_GCM_TAG_LEN;
            if out.len() < n {
                return Err(TransportError::BufferTooSmall);
            }
            out[..plaintext.len()].copy_from_slice(plaintext);
            out[plaintext.len()..n].fill(0x5A);
            self.encrypts += 1;
            Ok(n)
        }
        fn decrypt_frame(&mut self, frame: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
            if frame.len() < AES_256_GCM_TAG_LEN {
                return Err(TransportError::DecryptionFailed);
            }
            let pt = frame.len() - AES_256_GCM_TAG_LEN;
            if frame[pt..].iter().any(|&b| b != 0x5A) {
                return Err(TransportError::DecryptionFailed);
            }
            if out.len() < pt {
                return Err(TransportError::BufferTooSmall);
            }
            out[..pt].copy_from_slice(&frame[..pt]);
            self.decrypts += 1;
            Ok(pt)
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ------------------------------------------------------------------
    // Task 18 Step 1 tests
    // ------------------------------------------------------------------

    /// The two published AES-256-GCM vectors for an all-zero 256-bit key and
    /// an all-zero 96-bit IV, reproduced from `aes-gcm 0.11.0` through this
    /// channel rather than pasted in.
    ///
    /// `(role = Initiator, ctr = 0)` is the all-zero nonce by construction —
    /// high byte `0`, three zero pad bytes, counter `0` — which is what lets
    /// the standard vectors be checked through the real code path instead of
    /// through a bespoke test harness.
    ///
    /// The 16-byte empty-plaintext tag is `530f8afb…738b`; the 16-zero-byte
    /// case is `cea7403d…9d18` ‖ `d0d1c8a7…b919`. Both are byte-identical to
    /// what the spine's host backend produces for the same inputs, because
    /// that backend builds its nonce the same way and links the same crate —
    /// which is the cross-check the plan asks for.
    ///
    /// **Mutations this detects:** changing the nonce layout (role byte moved,
    /// counter endianness flipped, pad width changed), changing the key
    /// schedule, swapping the AEAD, or emitting `tag ‖ ciphertext` instead of
    /// `ciphertext ‖ tag`.
    #[test]
    fn aead_known_answer_vector_round_trips() {
        let mut ch = Aes256GcmTunnelChannel::new([0u8; 32], ChannelRole::Initiator);
        assert_eq!(
            Aes256GcmTunnelChannel::nonce_bytes(ChannelRole::Initiator, 0),
            [0u8; 12],
            "the first initiator nonce must be the all-zero IV, or the published vectors below \
             are being checked against a different input than the one they were computed for"
        );

        let mut out = [0u8; 64];
        let n = ch.encrypt_frame(&[], &mut out).expect("empty plaintext");
        assert_eq!(n, 16);
        assert_eq!(
            hex(&out[..16]),
            "530f8afbc74536b9a963b4f1c4cb738b",
            "AES-256-GCM(K=0^256, IV=0^96, P=<empty>, A=<empty>) tag"
        );

        let mut ch2 = Aes256GcmTunnelChannel::new([0u8; 32], ChannelRole::Initiator);
        let n2 = ch2.encrypt_frame(&[0u8; 16], &mut out).expect("16 zeroes");
        assert_eq!(n2, 32);
        assert_eq!(
            hex(&out[..16]),
            "cea7403d4d606b6e074ec5d3baf39d18",
            "AES-256-GCM(K=0^256, IV=0^96, P=0^128) ciphertext"
        );
        assert_eq!(
            hex(&out[16..32]),
            "d0d1c8a799996bf0265b98b5d48ab919",
            "AES-256-GCM(K=0^256, IV=0^96, P=0^128) tag"
        );

        // Round trip through the peer, so the vector is not merely reproduced
        // but is also openable.
        let mut peer = Aes256GcmTunnelChannel::new([0u8; 32], ChannelRole::Responder);
        let mut back = [0u8; 64];
        let m = peer.decrypt_frame(&out[..32], &mut back).expect("open");
        assert_eq!(&back[..m], &[0u8; 16]);
    }

    /// **Mutations this detects:** advancing the counter before use rather
    /// than after, sharing one counter between the two directions, resetting a
    /// counter on any event, or making `frames_sealed` a field the caller can
    /// set.
    #[test]
    fn frame_counter_is_the_nonce_counter_and_never_repeats() {
        let mut ch = Aes256GcmTunnelChannel::new([7u8; 32], ChannelRole::Initiator);
        let mut peer = Aes256GcmTunnelChannel::new([7u8; 32], ChannelRole::Responder);

        let mut seen: Vec<[u8; 12]> = Vec::new();
        let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
        for i in 0..64u64 {
            assert_eq!(ch.frames_sealed(), i, "counter is the frame index");
            seen.push(Aes256GcmTunnelChannel::nonce_bytes(ch.role(), i));
            let mut out = [0u8; 64];
            let n = ch.encrypt_frame(b"same plaintext", &mut out).unwrap();
            ciphertexts.push(out[..n].to_vec());
        }
        assert_eq!(ch.frames_sealed(), 64);

        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "a nonce repeated");

        // Positive control on the detector: identical plaintext under a
        // repeated counter WOULD produce identical ciphertext, so the
        // all-distinct result below is meaningful.
        let mut fixed_a = Aes256GcmTunnelChannel::new([7u8; 32], ChannelRole::Initiator);
        let mut fixed_b = Aes256GcmTunnelChannel::new([7u8; 32], ChannelRole::Initiator);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let na = fixed_a.encrypt_frame(b"same plaintext", &mut a).unwrap();
        let nb = fixed_b.encrypt_frame(b"same plaintext", &mut b).unwrap();
        assert_eq!(
            a[..na],
            b[..nb],
            "control: counter 0 twice repeats the frame"
        );

        let mut ct_sorted = ciphertexts.clone();
        ct_sorted.sort();
        ct_sorted.dedup();
        assert_eq!(
            ct_sorted.len(),
            ciphertexts.len(),
            "identical plaintext produced a repeated frame, so the counter is not advancing"
        );

        for (i, ct) in ciphertexts.iter().enumerate() {
            let mut back = [0u8; 64];
            let m = peer.decrypt_frame(ct, &mut back).unwrap();
            assert_eq!(&back[..m], b"same plaintext", "frame {i}");
            assert_eq!(peer.frames_opened(), i as u64 + 1);
        }
    }

    /// **Mutations this detects:** truncating the tag comparison, accepting a
    /// frame whose tag length is short, or mapping an AEAD failure onto `Ok`.
    #[test]
    fn a_tampered_tag_fails_decryption() {
        let mut ch = Aes256GcmTunnelChannel::new([3u8; 32], ChannelRole::Initiator);
        let mut wire = [0u8; 64];
        let n = ch.encrypt_frame(b"payload", &mut wire).unwrap();

        // Positive control: untouched, it opens.
        let mut peer = Aes256GcmTunnelChannel::new([3u8; 32], ChannelRole::Responder);
        let mut back = [0u8; 64];
        assert_eq!(peer.decrypt_frame(&wire[..n], &mut back).unwrap(), 7);

        for flip in 0..n {
            let mut tampered = wire[..n].to_vec();
            tampered[flip] ^= 0x01;
            let mut fresh = Aes256GcmTunnelChannel::new([3u8; 32], ChannelRole::Responder);
            let mut sink = [0u8; 64];
            assert_eq!(
                fresh.decrypt_frame(&tampered, &mut sink),
                Err(TransportError::DecryptionFailed),
                "a one-bit flip at byte {flip} was accepted"
            );
            assert_eq!(
                fresh.frames_opened(),
                0,
                "a rejected frame advanced the inbound counter"
            );
        }
    }

    /// **Mutations this detects:** collapsing the two nonce prefixes onto one
    /// role byte — the failure the plan calls out by name — or deriving the
    /// inbound prefix from anything other than `role.peer()`.
    #[test]
    fn initiator_and_responder_use_disjoint_nonce_spaces() {
        assert_eq!(ChannelRole::Initiator.byte(), 0);
        assert_eq!(ChannelRole::Responder.byte(), 1);
        assert_eq!(ChannelRole::Initiator.peer(), ChannelRole::Responder);
        assert_eq!(ChannelRole::Responder.peer(), ChannelRole::Initiator);

        for ctr in [0u64, 1, 2, 255, 65_536, u64::MAX - 1] {
            let i = Aes256GcmTunnelChannel::nonce_bytes(ChannelRole::Initiator, ctr);
            let r = Aes256GcmTunnelChannel::nonce_bytes(ChannelRole::Responder, ctr);
            assert_ne!(i, r, "the two directions share nonce {ctr}");
            assert_eq!(i[0], 0);
            assert_eq!(r[0], 1);
            assert_eq!(i[1..4], [0, 0, 0]);
            assert_eq!(i[4..], ctr.to_be_bytes());
        }

        // Two initiators cannot read each other: same space, same counter.
        let mut a = Aes256GcmTunnelChannel::new([9u8; 32], ChannelRole::Initiator);
        let mut b = Aes256GcmTunnelChannel::new([9u8; 32], ChannelRole::Initiator);
        let mut wire = [0u8; 64];
        let n = a.encrypt_frame(b"one way", &mut wire).unwrap();
        let mut sink = [0u8; 64];
        assert_eq!(
            b.decrypt_frame(&wire[..n], &mut sink),
            Err(TransportError::DecryptionFailed),
            "an initiator opened another initiator's frame, so the spaces are not disjoint"
        );
    }

    /// Both directions, in one test, because two tests for one property is how
    /// a property ends up asserted twice and fixed once.
    ///
    /// **Mutations this detects:** using `self.role` for both encrypt and
    /// decrypt, which passes a same-role test and fails only across the pair.
    #[test]
    fn an_initiator_encrypted_frame_decrypts_in_a_responder_and_vice_versa() {
        let key = [0x42u8; 32];
        let mut node = Aes256GcmTunnelChannel::new(key, ChannelRole::Initiator);
        let mut gateway = Aes256GcmTunnelChannel::new(key, ChannelRole::Responder);

        for round in 0..8u8 {
            let up = [round; 24];
            let mut wire = [0u8; 128];
            let n = node.encrypt_frame(&up, &mut wire).unwrap();
            let mut got = [0u8; 128];
            let m = gateway.decrypt_frame(&wire[..n], &mut got).unwrap();
            assert_eq!(&got[..m], &up[..], "node -> gateway, round {round}");

            let down = [round.wrapping_add(0x80); 31];
            let n = gateway.encrypt_frame(&down, &mut wire).unwrap();
            let m = node.decrypt_frame(&wire[..n], &mut got).unwrap();
            assert_eq!(&got[..m], &down[..], "gateway -> node, round {round}");
        }
        assert_eq!(node.frames_sealed(), 8);
        assert_eq!(node.frames_opened(), 8);
        assert_eq!(gateway.frames_sealed(), 8);
        assert_eq!(gateway.frames_opened(), 8);
    }

    /// **Mutations this detects:** replacing the wrap with a re-implementation
    /// — i.e. a channel that no longer satisfies the frozen trait at all, or a
    /// `TunnelSeam` that stops being generic over it.
    #[test]
    fn wrapping_does_not_alter_the_frozen_trait_signature() {
        fn accepts_any_frozen_channel<C: SecureChannel>(_c: &C) {}
        fn accepts_any_frozen_channel_dyn(_c: &mut dyn SecureChannel) {}

        let mut ch = Aes256GcmTunnelChannel::new([1u8; 32], ChannelRole::Initiator);
        accepts_any_frozen_channel(&ch);
        accepts_any_frozen_channel_dyn(&mut ch);

        // The two `const` shape coercions above are the real assertion; this
        // re-states them at runtime so the test body is not empty.
        let f: FrozenFrameFn = <Aes256GcmTunnelChannel as SecureChannel>::encrypt_frame;
        let mut out = [0u8; 32];
        assert_eq!(f(&mut ch, b"abc", &mut out).unwrap(), 19);

        // And the seam wraps something that is provably not this channel.
        let mut seam = TunnelSeam::new(MarkerChannel {
            encrypts: 0,
            decrypts: 0,
        });
        let mut wire = [0u8; 64];
        let n = seam.seal(b"through the seam", &mut wire).unwrap();
        let mut back = [0u8; 64];
        let m = seam.open(&wire[..n], &mut back).unwrap();
        assert_eq!(&back[..m], b"through the seam");
        assert_eq!(seam.frames_sealed(), 1);
        assert_eq!(seam.frames_opened(), 1);
        assert_eq!(seam.inner().encrypts, 1, "the seam did not delegate");
        assert_eq!(seam.inner().decrypts, 1, "the seam did not delegate");
    }

    /// **Mutations this detects:** dropping the seam's size bound so an
    /// oversize buffer reaches the AEAD and is allocated before it is refused.
    #[test]
    fn the_seam_refuses_an_oversize_plaintext_before_the_aead_sees_it() {
        let mut seam = TunnelSeam::new(MarkerChannel {
            encrypts: 0,
            decrypts: 0,
        });
        let mut out = vec![0u8; MAX_FRAME_WIRE + 64];

        // Positive control: exactly at the bound, it is accepted.
        let ok = vec![0u8; MAX_FRAME_PLAINTEXT];
        assert!(seam.seal(&ok, &mut out).is_ok());
        assert_eq!(seam.inner().encrypts, 1);

        let too_big = vec![0u8; MAX_FRAME_PLAINTEXT + 1];
        assert_eq!(
            seam.seal(&too_big, &mut out),
            Err(TunnelError::FrameTooLarge {
                len: MAX_FRAME_PLAINTEXT + 1,
                max: MAX_FRAME_PLAINTEXT,
            })
        );
        assert_eq!(
            seam.inner().encrypts,
            1,
            "the oversize plaintext reached the wrapped channel"
        );

        let over_wire = vec![0u8; MAX_FRAME_WIRE + 1];
        assert_eq!(
            seam.open(&over_wire, &mut out),
            Err(TunnelError::FrameTooLarge {
                len: MAX_FRAME_WIRE + 1,
                max: MAX_FRAME_WIRE,
            })
        );
        assert_eq!(seam.inner().decrypts, 0);
    }

    // ------------------------------------------------------------------
    // Source sweep
    // ------------------------------------------------------------------

    /// Every `.rs` file this crate ships, minus its trailing test module.
    ///
    /// Stripping the **trailing** `#[cfg(test)] mod tests` block and not the
    /// first `#[cfg(test)]` occurrence is deliberate: a sweep that truncates
    /// at the first occurrence can blank most of a file whose helpers sit near
    /// the top while reporting an unchanged file count.
    fn production_sources() -> Vec<(String, String)> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        collect_rs(&dir, &mut out);
        out.sort();
        out.into_iter()
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

    /// Exact file count at this task. Raised in the same commit as the task
    /// that adds the next source file — a `>=` floor written for the finished
    /// crate is unsatisfiable in the task that introduces the sweep, and an
    /// implementer who meets a red floor by lowering it has deleted the guard.
    const TUNNEL_SRC_FILES_AT_THIS_TASK: usize = 14;

    /// Byte floor on the swept production text. A file-count floor alone is
    /// defeated by a truncating pre-filter: a sweep that truncated at the
    /// FIRST `#[cfg(test)]` in each file would report the same twelve files
    /// while reading a fraction of them.
    ///
    /// Measured 122 013 bytes across twelve files at Task 24 and 144 054 bytes
    /// across fourteen at Task 26. 120 000 sits close enough that a pre-filter
    /// losing a sixth of the crate reds this, and far enough that ordinary
    /// editing does not.
    const MIN_SWEPT_PRODUCTION_BYTES: usize = 120_000;

    /// **Mutations this detects:** introducing either retired token in prose,
    /// an identifier, a string literal or a doc comment anywhere in the
    /// crate's production source; and narrowing the sweep itself, since both
    /// floors are asserted before the absence is.
    #[test]
    fn the_tunnel_crate_names_no_mint_and_no_burn_anywhere() {
        // Assembled at runtime so this file does not itself contain the
        // literals it forbids.
        let forbidden: Vec<String> = vec![format!("{}{}", "mi", "nt"), format!("{}{}", "bu", "rn")];

        let sources = production_sources();
        assert_eq!(
            sources.len(),
            TUNNEL_SRC_FILES_AT_THIS_TASK,
            "the sweep saw {} source file(s), not {}. If a file was added, raise the constant in \
             the same commit; do not lower it to meet a red floor",
            sources.len(),
            TUNNEL_SRC_FILES_AT_THIS_TASK
        );
        let total: usize = sources.iter().map(|(_, t)| t.len()).sum();
        assert!(
            total >= MIN_SWEPT_PRODUCTION_BYTES,
            "the sweep read only {total} byte(s) of production text, below the \
             {MIN_SWEPT_PRODUCTION_BYTES} floor — a truncating pre-filter would pass a file-count \
             floor while reading almost nothing"
        );

        // Positive control: the same matcher, over text that does contain the
        // tokens, must fire. An absence result from a scanner that never fires
        // is not evidence.
        let control = format!("this line says {} and {}", forbidden[0], forbidden[1]);
        let control_lower = control.to_ascii_lowercase();
        for token in &forbidden {
            assert!(
                control_lower.contains(token.as_str()),
                "the scanner cannot see its own control string"
            );
        }

        for (name, text) in &sources {
            let lower = text.to_ascii_lowercase();
            for token in &forbidden {
                assert!(
                    !lower.contains(token.as_str()),
                    "{name} names a retired token; this lane has no such mechanism, in any \
                     direction, at any layer"
                );
            }
        }
    }
}
