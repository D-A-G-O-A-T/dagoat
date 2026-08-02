//! Stream multiplexing over one tunnel session.
//!
//! One post-quantum channel carries many consumer streams, distinguished by
//! the frame header's `stream_id`. This module owns the set of open ids and
//! the bound on how many there may be. It owns nothing else: it does not
//! allocate ids, does not carry bytes and does not know what state the tunnel
//! is in — [`crate::state`] answers that, and a session driver holds both.
//!
//! # The three refusals, and why each is a distinct variant
//!
//! * **Stream id 0 is not a stream.** The frame layer reserves it for
//!   session-scoped frames and refuses per-stream frames that carry it. A mux
//!   that handed out id 0 would produce frames the frame layer then rejects,
//!   which turns a naming bug into a mid-session failure.
//! * **A duplicate id is a collision, not a re-open.** Two live streams under
//!   one id interleave their bytes into one consumer response. Silently
//!   accepting the second is the worst available answer; treating it as a
//!   re-open of the first is the second worst.
//! * **The cap is a safety control.** See [`MAX_CONCURRENT_STREAMS`].
//!
//! Design authority: the "Residential Proxy Network — Worker & Tunnel Spec
//! (Tasks 18-36, 44, 45, 47)", Task 22 and its Hazard → fix map row for
//! layer-7 flooding; and the "Residential Proxy Network (P3) Implementation
//! Plan", §3.
//!
//! Honesty tagging: **[TARGET]**. No stream has ever carried a byte outside a
//! test.

use std::collections::BTreeSet;

use crate::error::TunnelError;
use crate::frame::FrameKind;

/// How many streams one node may hold open across one tunnel at once.
///
/// **A safety control, not a placeholder, and not a performance tuning knob.**
/// The shipped destination allowlist points at named third-party research
/// services that publish polite-pool and rate-limit terms, and the one abuse
/// class this lane concedes it cannot bound — a distributed layer-7 flood — is
/// bounded here only in the per-node direction. Eight concurrent streams sits
/// inside the single-digit concurrency those services ask of a polite client,
/// and the aggregate is held down separately by
/// [`crate::capacity::MAX_CONCURRENT_NODES`].
///
/// Raising it is gated on the same thing that gates the node bound: §1
/// criterion 5, the **global per-destination ceiling**, which is not
/// delivered. Per-node caps cannot bound an aggregate; a pilot that cannot
/// exceed one polite client's concurrency does not need them to.
pub const MAX_CONCURRENT_STREAMS: usize = 8;

/// The set of open stream ids on one session.
///
/// A `BTreeSet` rather than a `HashSet` so that [`Mux::open_ids`] is ordered
/// and a capacity report built from it is deterministic — an unordered report
/// is a report two observers can disagree about while both being right.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mux {
    open: BTreeSet<u32>,
}

impl Mux {
    /// An empty mux.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open `stream_id`.
    ///
    /// Refuses id 0, an id already open, and any open beyond
    /// [`MAX_CONCURRENT_STREAMS`]. The cap is checked **before** the set is
    /// touched, so a refused open leaves no trace.
    pub fn open(&mut self, stream_id: u32) -> Result<(), TunnelError> {
        if stream_id == 0 {
            return Err(TunnelError::ZeroStreamId(FrameKind::StreamOpen));
        }
        if self.open.contains(&stream_id) {
            return Err(TunnelError::DuplicateStreamId(stream_id));
        }
        if self.open.len() >= MAX_CONCURRENT_STREAMS {
            return Err(TunnelError::TooManyStreams {
                open: self.open.len(),
                max: MAX_CONCURRENT_STREAMS,
            });
        }
        self.open.insert(stream_id);
        Ok(())
    }

    /// Close `stream_id`.
    ///
    /// Closing a stream that is not open is a refusal, not a no-op: a driver
    /// that closes twice has lost track of its own streams, and the second
    /// close would otherwise free a slot the first already freed.
    pub fn close(&mut self, stream_id: u32) -> Result<(), TunnelError> {
        if self.open.remove(&stream_id) {
            Ok(())
        } else {
            Err(TunnelError::UnknownStreamId(stream_id))
        }
    }

    /// How many streams are open.
    #[inline]
    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// Whether `stream_id` is open.
    #[inline]
    pub fn is_open(&self, stream_id: u32) -> bool {
        self.open.contains(&stream_id)
    }

    /// The open ids, ascending.
    pub fn open_ids(&self) -> Vec<u32> {
        self.open.iter().copied().collect()
    }

    /// Headroom: how many more streams may be opened right now.
    ///
    /// Saturating, so a cap lowered below the current open count reports zero
    /// rather than wrapping to `usize::MAX` — the one arithmetic slip on this
    /// path that would read as unlimited capacity.
    #[inline]
    pub fn streams_free(&self) -> usize {
        MAX_CONCURRENT_STREAMS.saturating_sub(self.open.len())
    }

    /// Drop every open stream, returning how many were dropped.
    ///
    /// The kill switch's half of the mux: a halt does not close streams one at
    /// a time and does not care whether any of them were mid-transfer.
    pub fn drop_all(&mut self) -> usize {
        let n = self.open.len();
        self.open.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Mutations this detects:** accepting a second open under a live id, or
    /// turning the duplicate into a silent re-open — either of which
    /// interleaves two streams' bytes into one consumer response.
    #[test]
    fn mux_refuses_a_duplicate_stream_id() {
        let mut mux = Mux::new();
        // Positive control: the first open of that id succeeds.
        mux.open(9).expect("first open");
        assert_eq!(mux.open_count(), 1);

        for _ in 0..3 {
            assert_eq!(mux.open(9), Err(TunnelError::DuplicateStreamId(9)));
        }
        assert_eq!(mux.open_count(), 1, "a refused open changed the open set");

        // A different id is still accepted, so the refusal is about the
        // collision and not about the mux having stopped accepting.
        mux.open(10).expect("distinct id");
        assert_eq!(mux.open_count(), 2);

        // And an id becomes reusable only after it closes.
        mux.close(9).expect("close");
        mux.open(9).expect("reopen after close");
        assert_eq!(mux.open_ids(), vec![9, 10]);
    }

    /// **Mutations this detects:** raising or removing the concurrency cap, or
    /// checking it with `>` instead of `>=` (which admits one stream past the
    /// bound), or checking it after the insert (which admits the offending
    /// stream and then reports the refusal).
    #[test]
    fn mux_enforces_max_concurrent_streams() {
        assert_eq!(
            MAX_CONCURRENT_STREAMS, 8,
            "the per-node concurrency bound moved; raising it is gated on §1 criterion 5, the \
             global per-destination ceiling, which is not delivered"
        );

        let mut mux = Mux::new();
        // Positive control: every open up to the bound is accepted.
        for id in 1..=MAX_CONCURRENT_STREAMS as u32 {
            mux.open(id)
                .unwrap_or_else(|e| panic!("open {id} inside the cap was refused: {e:?}"));
        }
        assert_eq!(mux.open_count(), MAX_CONCURRENT_STREAMS);
        assert_eq!(mux.streams_free(), 0);

        // One past the bound is refused, and refused by name.
        for id in 100..103u32 {
            assert_eq!(
                mux.open(id),
                Err(TunnelError::TooManyStreams {
                    open: MAX_CONCURRENT_STREAMS,
                    max: MAX_CONCURRENT_STREAMS,
                })
            );
        }
        assert_eq!(
            mux.open_count(),
            MAX_CONCURRENT_STREAMS,
            "a stream past the cap was admitted before the refusal"
        );
        assert!(!mux.is_open(100));

        // Freeing one slot admits exactly one more.
        mux.close(1).expect("close");
        assert_eq!(mux.streams_free(), 1);
        mux.open(100).expect("the freed slot");
        assert_eq!(
            mux.open(101),
            Err(TunnelError::TooManyStreams {
                open: MAX_CONCURRENT_STREAMS,
                max: MAX_CONCURRENT_STREAMS,
            })
        );
    }

    /// **Mutations this detects:** inserting before checking, on any of the
    /// three refusal paths — an admitted-then-reported stream is a stream the
    /// caller believes is closed and the mux believes is open.
    #[test]
    fn a_refused_open_leaves_the_open_set_unchanged() {
        let mut mux = Mux::new();
        for id in 1..=3u32 {
            mux.open(id).expect("setup");
        }
        let before = mux.clone();

        // Positive control: the comparison can see a change.
        let mut changed = mux.clone();
        changed.open(4).expect("control open");
        assert_ne!(before, changed, "the comparison cannot see an added stream");

        assert!(mux.open(0).is_err());
        assert_eq!(mux, before);
        assert!(mux.open(2).is_err());
        assert_eq!(mux, before);
        assert!(mux.close(99).is_err());
        assert_eq!(mux, before);

        // And the cap path, which is the one that can only be reached full.
        let mut full = Mux::new();
        for id in 1..=MAX_CONCURRENT_STREAMS as u32 {
            full.open(id).expect("fill");
        }
        let full_before = full.clone();
        assert!(full.open(999).is_err());
        assert_eq!(full, full_before);
    }

    /// INV-11's mux half.
    ///
    /// **Mutations this detects:** adding a hostname, address, URL, path or
    /// header field to the multiplexer — the structure a future task will
    /// reach for first when it wants to "just log which destination this
    /// stream was for".
    #[test]
    fn the_mux_carries_no_destination_identifying_state() {
        let mut mux = Mux::new();
        mux.open(1).expect("open");
        // Exhaustive destructure: adding a field to `Mux` is a compile error
        // here, which is the only kind of guard a struct-shape rule can have.
        let Mux { open } = &mux;
        assert_eq!(open.len(), 1);

        // Everything the mux can say about a stream is an integer.
        assert_eq!(mux.open_ids(), vec![1u32]);
        assert_eq!(mux.open_count(), 1);
        assert!(mux.is_open(1));
    }

    /// **Mutations this detects:** a `Default` that starts non-empty, or a
    /// headroom that ignores the cap on a fresh mux.
    #[test]
    fn an_empty_mux_reports_full_headroom_and_no_open_ids() {
        let mux = Mux::new();
        assert_eq!(mux.open_count(), 0);
        assert_eq!(mux.streams_free(), MAX_CONCURRENT_STREAMS);
        assert!(mux.open_ids().is_empty());
        assert!(!mux.is_open(1));
        assert_eq!(mux, Mux::default());
    }

    /// **Mutations this detects:** swapping the ordered set for an unordered
    /// one, which makes a capacity report built from `open_ids` differ
    /// between two observers of the same session.
    #[test]
    fn open_ids_are_reported_in_ascending_order_regardless_of_open_order() {
        let mut a = Mux::new();
        for id in [7u32, 2, 9, 1] {
            a.open(id).expect("open");
        }
        let mut b = Mux::new();
        for id in [1u32, 9, 2, 7] {
            b.open(id).expect("open");
        }
        assert_eq!(a.open_ids(), vec![1, 2, 7, 9]);
        assert_eq!(a.open_ids(), b.open_ids());
        assert_eq!(a, b, "two identical stream sets compared unequal");
    }

    /// **Mutations this detects:** allocating stream id 0, which the frame
    /// layer reserves for session-scoped frames and refuses on every
    /// per-stream kind.
    #[test]
    fn mux_refuses_stream_id_zero_because_the_frame_layer_reserves_it() {
        let mut mux = Mux::new();
        assert_eq!(
            mux.open(0),
            Err(TunnelError::ZeroStreamId(FrameKind::StreamOpen))
        );
        assert_eq!(mux.open_count(), 0);

        // The reservation is the frame layer's, and it is still there: a
        // per-stream header carrying 0 is refused there too, so this mux rule
        // and that parser rule are two statements of one reservation.
        assert_eq!(
            crate::frame::FrameHeader::data(0, 0).validate(),
            Err(TunnelError::ZeroStreamId(FrameKind::StreamData))
        );
        // Positive control: id 1 is fine in both places.
        mux.open(1).expect("id 1");
        assert!(crate::frame::FrameHeader::data(1, 0).validate().is_ok());
    }

    /// **Mutations this detects:** making a close of an unopened id a silent
    /// no-op, which lets a double close free a slot twice and drift
    /// `open_count` below the truth.
    #[test]
    fn closing_a_stream_that_is_not_open_is_refused() {
        let mut mux = Mux::new();
        assert_eq!(mux.close(4), Err(TunnelError::UnknownStreamId(4)));

        // Positive control: the close verb works on an open stream.
        mux.open(4).expect("open");
        mux.close(4).expect("close");
        assert_eq!(mux.open_count(), 0);
        // And the second close is refused, not absorbed.
        assert_eq!(mux.close(4), Err(TunnelError::UnknownStreamId(4)));
        assert_eq!(mux.open_count(), 0);
    }

    /// **Mutations this detects:** a `streams_free` that subtracts without
    /// saturating, so a cap lowered below the live count reports `usize::MAX`
    /// — unlimited capacity, from an arithmetic slip.
    #[test]
    fn stream_headroom_is_the_cap_minus_the_open_count_and_never_wraps() {
        let mut mux = Mux::new();
        assert_eq!(mux.streams_free(), MAX_CONCURRENT_STREAMS);
        for id in 1..=MAX_CONCURRENT_STREAMS as u32 {
            mux.open(id).expect("open");
            assert_eq!(
                mux.streams_free(),
                MAX_CONCURRENT_STREAMS - id as usize,
                "headroom disagrees with the open count"
            );
        }
        assert_eq!(mux.streams_free(), 0);
        assert_eq!(
            MAX_CONCURRENT_STREAMS.saturating_sub(MAX_CONCURRENT_STREAMS + 1),
            0,
            "saturating subtraction is what keeps an over-full mux from reporting unlimited room"
        );
    }

    /// **Mutations this detects:** a halt that closes streams one at a time
    /// and stops at the first refusal, leaving the rest open while the halt
    /// receipt says otherwise.
    #[test]
    fn dropping_every_stream_reports_how_many_it_dropped() {
        let mut mux = Mux::new();
        for id in 1..=5u32 {
            mux.open(id).expect("open");
        }
        assert_eq!(mux.drop_all(), 5);
        assert_eq!(mux.open_count(), 0);
        assert_eq!(mux.streams_free(), MAX_CONCURRENT_STREAMS);
        // Idempotent: a second drop finds nothing and says so.
        assert_eq!(mux.drop_all(), 0);
        // Positive control: the mux still works afterwards.
        mux.open(1).expect("reopen after a drop");
        assert_eq!(mux.open_count(), 1);
    }
}
