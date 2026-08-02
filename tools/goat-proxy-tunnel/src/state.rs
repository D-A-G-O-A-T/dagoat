//! The tunnel's state machine, and the endpoint→role mapping the handshake
//! hands it.
//!
//! # Why a total function and not a set of `if`s
//!
//! [`step`] is total over `(TunnelState, TunnelEvent)`: all forty-nine pairs
//! are written out, every one of them either naming a next state or returning
//! [`TunnelError::IllegalTransition`]. There is no wildcard arm anywhere in
//! it, so adding a state or an event is a **compile error** in seven places
//! rather than a silent fall-through to "ignore". A state machine whose
//! unhandled pairs are ignored is not a state machine; it is a suggestion.
//!
//! # Stream data crosses in exactly one state
//!
//! [`TunnelState::may_carry_stream_data`] answers `true` for `Ready` and for
//! nothing else, and `step` refuses `StreamOpened` from every other state.
//! Those are two separate mechanisms that must agree, so a test asserts they
//! agree for every state — a predicate widened without widening the
//! transition (or the reverse) is the drift this crate would otherwise ship.
//!
//! # The kill switch is legal from every state
//!
//! Every other event has states that refuse it. `KillSwitchEngaged` never
//! does: from a live state it moves to `Halting`, and from `Halting` or
//! `Closed` it is idempotent. A kill switch that can return `Err` is a kill
//! switch a caller may read as "the halt did not happen", and that reading is
//! the failure this rule removes.
//!
//! # `Halting` is terminal in the sense that matters
//!
//! `Halting` is not a dead end — the halt completes and the tunnel reaches
//! `Closed`. What is terminal is the *capability*: no sequence of events from
//! `Halting`, of any length, reaches a state where stream data may cross. The
//! test proves that by closing over the reachable set, not by asserting that
//! `Halting` has no outgoing edges.
//!
//! Design authority: the "Residential Proxy Network — Worker & Tunnel Spec
//! (Tasks 18-36, 44, 45, 47)", Task 22 and §State transitions, whose normative
//! enums this file reproduces spelling for spelling; and the "Residential
//! Proxy Network (P3) Implementation Plan", §2 (INV-5, INV-12) and §6.
//!
//! Honesty tagging: **[TARGET]**. No gateway is deployed and no session has
//! ever been driven through these transitions outside a test.

use crate::channel::{tunnel_seam, Aes256GcmTunnelChannel, ChannelRole, TunnelSeam};
use crate::error::TunnelError;

/// The carriage + post-quantum channel lifecycle.
///
/// Reproduced spelling for spelling from the spec's normative enum. The
/// variant order is the happy path, and nothing reads the discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelState {
    /// Consent verified, allowlist loaded, budget open. No carriage yet.
    Idle,
    /// The outbound WSS carriage is up. No session key exists.
    CarriageUp,
    /// The node's hello is on the wire.
    HelloSent,
    /// The peer answered and this endpoint has emitted its own confirm.
    ConfirmSent,
    /// Both sides confirmed. AES-256-GCM framing is live and this is the one
    /// state in which stream data may cross.
    Ready,
    /// The kill switch is engaged. Sockets are being closed and counted.
    Halting,
    /// The halt completed, or the carriage went away after a halt. Nothing
    /// crosses this endpoint again.
    Closed,
}

impl TunnelState {
    /// Stream data may cross the channel in exactly one state. Everything else
    /// is an illegal transition, not a warning.
    #[inline]
    pub fn may_carry_stream_data(self) -> bool {
        matches!(self, TunnelState::Ready)
    }

    /// The name carried in [`TunnelError::IllegalTransition`].
    ///
    /// A `&'static str` rather than a `Debug` render, because the refusal is
    /// asserted on in tests and a `Debug` impl is not a stable surface.
    #[inline]
    pub fn name(self) -> &'static str {
        match self {
            TunnelState::Idle => "Idle",
            TunnelState::CarriageUp => "CarriageUp",
            TunnelState::HelloSent => "HelloSent",
            TunnelState::ConfirmSent => "ConfirmSent",
            TunnelState::Ready => "Ready",
            TunnelState::Halting => "Halting",
            TunnelState::Closed => "Closed",
        }
    }

    /// Every state, for exhaustive sweeps. Order is the declaration order.
    pub const ALL: [TunnelState; 7] = [
        TunnelState::Idle,
        TunnelState::CarriageUp,
        TunnelState::HelloSent,
        TunnelState::ConfirmSent,
        TunnelState::Ready,
        TunnelState::Halting,
        TunnelState::Closed,
    ];
}

/// What happened to the tunnel.
///
/// Reproduced spelling for spelling from the spec's normative enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelEvent {
    /// The outbound WSS dial succeeded.
    CarriageConnected,
    /// This endpoint put its hello on the wire.
    HelloSent,
    /// A peer confirm arrived and verified.
    PeerConfirmed,
    /// A multiplexed stream opened.
    StreamOpened,
    /// A multiplexed stream closed.
    StreamClosed,
    /// The kill switch was engaged, by either side.
    KillSwitchEngaged,
    /// The carriage went away. Recoverable while not halted: the carriage is
    /// dumb transport, so losing it costs the session key and nothing else.
    CarriageLost,
}

impl TunnelEvent {
    /// The name carried in [`TunnelError::IllegalTransition`].
    #[inline]
    pub fn name(self) -> &'static str {
        match self {
            TunnelEvent::CarriageConnected => "CarriageConnected",
            TunnelEvent::HelloSent => "HelloSent",
            TunnelEvent::PeerConfirmed => "PeerConfirmed",
            TunnelEvent::StreamOpened => "StreamOpened",
            TunnelEvent::StreamClosed => "StreamClosed",
            TunnelEvent::KillSwitchEngaged => "KillSwitchEngaged",
            TunnelEvent::CarriageLost => "CarriageLost",
        }
    }

    /// Every event, for exhaustive sweeps. Order is the declaration order.
    pub const ALL: [TunnelEvent; 7] = [
        TunnelEvent::CarriageConnected,
        TunnelEvent::HelloSent,
        TunnelEvent::PeerConfirmed,
        TunnelEvent::StreamOpened,
        TunnelEvent::StreamClosed,
        TunnelEvent::KillSwitchEngaged,
        TunnelEvent::CarriageLost,
    ];
}

#[inline]
fn illegal(from: TunnelState, event: TunnelEvent) -> TunnelError {
    TunnelError::IllegalTransition {
        from: from.name(),
        event: event.name(),
    }
}

/// The transition function.
///
/// Total over all forty-nine pairs, with no wildcard arm: every `(state,
/// event)` either names a next state here or is refused here.
///
/// A transition that returns `Ok(same_state)` is deliberate and distinct from
/// a refusal — `Ready + StreamOpened` stays `Ready` because opening a stream
/// does not change the channel's phase, whereas `Idle + StreamOpened` is a
/// refusal because there is no channel.
pub fn step(state: TunnelState, event: TunnelEvent) -> Result<TunnelState, TunnelError> {
    use TunnelEvent as E;
    use TunnelState as S;

    match state {
        S::Idle => match event {
            E::CarriageConnected => Ok(S::CarriageUp),
            E::KillSwitchEngaged => Ok(S::Halting),
            // There is no carriage to lose, no hello to have sent and no
            // stream to move in `Idle`.
            E::HelloSent
            | E::PeerConfirmed
            | E::StreamOpened
            | E::StreamClosed
            | E::CarriageLost => Err(illegal(state, event)),
        },
        S::CarriageUp => match event {
            E::HelloSent => Ok(S::HelloSent),
            E::KillSwitchEngaged => Ok(S::Halting),
            // Losing the carriage costs the whole session: the next attempt
            // re-dials and re-handshakes from `Idle`, deriving a fresh key.
            E::CarriageLost => Ok(S::Idle),
            E::CarriageConnected | E::PeerConfirmed | E::StreamOpened | E::StreamClosed => {
                Err(illegal(state, event))
            }
        },
        S::HelloSent => match event {
            E::PeerConfirmed => Ok(S::ConfirmSent),
            E::KillSwitchEngaged => Ok(S::Halting),
            E::CarriageLost => Ok(S::Idle),
            E::CarriageConnected | E::HelloSent | E::StreamOpened | E::StreamClosed => {
                Err(illegal(state, event))
            }
        },
        S::ConfirmSent => match event {
            // The second confirm: both sides have now confirmed and the
            // framing is live.
            E::PeerConfirmed => Ok(S::Ready),
            E::KillSwitchEngaged => Ok(S::Halting),
            E::CarriageLost => Ok(S::Idle),
            E::CarriageConnected | E::HelloSent | E::StreamOpened | E::StreamClosed => {
                Err(illegal(state, event))
            }
        },
        S::Ready => match event {
            E::StreamOpened => Ok(S::Ready),
            E::StreamClosed => Ok(S::Ready),
            E::KillSwitchEngaged => Ok(S::Halting),
            E::CarriageLost => Ok(S::Idle),
            E::CarriageConnected | E::HelloSent | E::PeerConfirmed => Err(illegal(state, event)),
        },
        S::Halting => match event {
            // The halt completed: every socket is gone.
            E::CarriageLost => Ok(S::Closed),
            // Engaging an engaged kill switch is not an error.
            E::KillSwitchEngaged => Ok(S::Halting),
            E::CarriageConnected
            | E::HelloSent
            | E::PeerConfirmed
            | E::StreamOpened
            | E::StreamClosed => Err(illegal(state, event)),
        },
        S::Closed => match event {
            E::KillSwitchEngaged => Ok(S::Closed),
            E::CarriageConnected
            | E::HelloSent
            | E::PeerConfirmed
            | E::StreamOpened
            | E::StreamClosed
            | E::CarriageLost => Err(illegal(state, event)),
        },
    }
}

/// Which end of the tunnel an endpoint is.
///
/// This is the mapping from a handshake outcome to a nonce space. The node
/// runs [`crate::handshake::initiate`] and the gateway runs
/// [`crate::handshake::respond`]; the two derive the same session key and must
/// then seal into **different** halves of the nonce space, or every frame one
/// sends collides with a frame the other sent under the same key and nonce —
/// the one catastrophic misuse of AES-GCM.
///
/// Before this type nothing in the crate connected the two: `initiate` handed
/// back a key with no statement about which [`ChannelRole`] its caller owns,
/// and a caller that guessed wrong got a channel that silently fails every tag
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelEndpoint {
    /// The operator's node. Dials out, runs `initiate`.
    Node,
    /// The gateway. Answers, runs `respond`.
    Gateway,
}

impl TunnelEndpoint {
    /// The nonce space this endpoint seals into.
    ///
    /// Node = [`ChannelRole::Initiator`] (prefix byte `0`), gateway =
    /// [`ChannelRole::Responder`] (prefix byte `1`). The direction is not
    /// arbitrary: it matches the spine's host backend, where the dialler owns
    /// prefix `0`, so a frame captured from one stack is readable by the
    /// other's decoder rather than by neither.
    #[inline]
    pub fn channel_role(self) -> ChannelRole {
        match self {
            TunnelEndpoint::Node => ChannelRole::Initiator,
            TunnelEndpoint::Gateway => ChannelRole::Responder,
        }
    }

    /// The other end.
    #[inline]
    pub fn peer(self) -> Self {
        match self {
            TunnelEndpoint::Node => TunnelEndpoint::Gateway,
            TunnelEndpoint::Gateway => TunnelEndpoint::Node,
        }
    }
}

/// The framing seam for one endpoint over a derived session key.
///
/// The only supported way to turn a handshake outcome into a channel. Taking
/// the endpoint rather than the role is the point: callers know which end they
/// are, and they should never have to know which nonce prefix that implies.
pub fn seam_for_endpoint(
    endpoint: TunnelEndpoint,
    session_key: [u8; 32],
) -> TunnelSeam<Aes256GcmTunnelChannel> {
    tunnel_seam(session_key, endpoint.channel_role())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        open_frame, seal_frame, FrameHeader, FrameKind, MAX_FRAME_PAYLOAD, MAX_FRAME_WIRE,
    };
    use crate::handshake::{
        initiate, respond, GatewayPolicy, HelloBinding, HelloReplayCache, MlKem768MlDsa65,
        PeerKemOffer,
    };
    use std::collections::HashSet;

    /// The expected next state for a legal pair, or `None` for a refusal.
    ///
    /// Written out independently of `step`'s own `match`, so this table and
    /// the implementation are two statements of the same thing that must
    /// agree. A table that simply called `step` would assert nothing.
    fn expected(state: TunnelState, event: TunnelEvent) -> Option<TunnelState> {
        use TunnelEvent as E;
        use TunnelState as S;
        match (state, event) {
            (S::Idle, E::CarriageConnected) => Some(S::CarriageUp),
            (S::CarriageUp, E::HelloSent) => Some(S::HelloSent),
            (S::HelloSent, E::PeerConfirmed) => Some(S::ConfirmSent),
            (S::ConfirmSent, E::PeerConfirmed) => Some(S::Ready),
            (S::Ready, E::StreamOpened) => Some(S::Ready),
            (S::Ready, E::StreamClosed) => Some(S::Ready),
            (S::CarriageUp | S::HelloSent | S::ConfirmSent | S::Ready, E::CarriageLost) => {
                Some(S::Idle)
            }
            (S::Halting, E::CarriageLost) => Some(S::Closed),
            (S::Halting, E::KillSwitchEngaged) => Some(S::Halting),
            (S::Closed, E::KillSwitchEngaged) => Some(S::Closed),
            (
                S::Idle | S::CarriageUp | S::HelloSent | S::ConfirmSent | S::Ready,
                E::KillSwitchEngaged,
            ) => Some(S::Halting),
            _ => None,
        }
    }

    /// **Mutations this detects:** any edit to `step` that adds, removes or
    /// redirects a single edge of the forty-nine-pair matrix; and any pair
    /// left unhandled, since the sweep visits all of them and a missing arm
    /// is a compile error in `step` itself.
    #[test]
    fn every_state_event_pair_maps_to_a_named_state_or_an_illegal_transition() {
        assert_eq!(TunnelState::ALL.len(), 7);
        assert_eq!(TunnelEvent::ALL.len(), 7);

        // Positive control: the sweep does see legal edges, so an all-refusal
        // result below would be a red rather than an artefact of a matrix that
        // was never walked.
        let mut legal = 0usize;
        let mut refused = 0usize;

        for state in TunnelState::ALL {
            for event in TunnelEvent::ALL {
                let got = step(state, event);
                match expected(state, event) {
                    Some(next) => {
                        legal += 1;
                        assert_eq!(
                            got,
                            Ok(next),
                            "{}+{} should reach {}",
                            state.name(),
                            event.name(),
                            next.name()
                        );
                    }
                    None => {
                        refused += 1;
                        assert_eq!(
                            got,
                            Err(TunnelError::IllegalTransition {
                                from: state.name(),
                                event: event.name(),
                            }),
                            "{}+{} should be refused, and refused by name",
                            state.name(),
                            event.name()
                        );
                    }
                }
            }
        }
        assert_eq!(legal + refused, 49, "the matrix is not 7x7");
        // Eighteen legal edges: 2 from Idle, 3 each from CarriageUp,
        // HelloSent and ConfirmSent, 4 from Ready, 2 from Halting, 1 from
        // Closed. Thirty-one refusals is the rest of the 7x7.
        assert_eq!(legal, 18, "the legal-edge count moved");
        assert_eq!(refused, 31, "the refusal count moved");
    }

    /// **Mutations this detects:** widening `may_carry_stream_data` to any
    /// second state, or allowing `StreamOpened` from a state that cannot carry
    /// data — the two halves of the same rule, which are enforced by two
    /// different mechanisms and would otherwise be free to drift apart.
    #[test]
    fn no_stream_data_flows_before_ready() {
        let mut carriers = 0usize;
        for state in TunnelState::ALL {
            let opens = step(state, TunnelEvent::StreamOpened).is_ok();
            assert_eq!(
                opens,
                state.may_carry_stream_data(),
                "{} disagrees with itself: may_carry_stream_data()={}, StreamOpened accepted={}",
                state.name(),
                state.may_carry_stream_data(),
                opens
            );
            if state.may_carry_stream_data() {
                carriers += 1;
            }
        }
        // Positive control plus the bound: exactly one state carries data, and
        // it is `Ready`.
        assert_eq!(carriers, 1, "more than one state may carry stream data");
        assert!(TunnelState::Ready.may_carry_stream_data());
        assert!(!TunnelState::ConfirmSent.may_carry_stream_data());
    }

    /// **Mutations this detects:** any edge out of `Halting` or `Closed` that
    /// reaches a data-carrying state — including one added through a chain of
    /// several events, which an edge-by-edge assertion would miss.
    #[test]
    fn halting_is_terminal() {
        // Close over everything reachable from `Halting` by any sequence of
        // events, of any length.
        let mut seen: HashSet<TunnelState> = HashSet::new();
        let mut frontier = vec![TunnelState::Halting];
        while let Some(state) = frontier.pop() {
            if !seen.insert(state) {
                continue;
            }
            for event in TunnelEvent::ALL {
                if let Ok(next) = step(state, event) {
                    frontier.push(next);
                }
            }
        }

        assert_eq!(
            seen,
            HashSet::from([TunnelState::Halting, TunnelState::Closed]),
            "the reachable closure from Halting is {seen:?}"
        );
        for state in &seen {
            assert!(
                !state.may_carry_stream_data(),
                "{} is reachable from Halting and carries stream data",
                state.name()
            );
        }

        // Positive control: the same closure from `Idle` DOES reach `Ready`,
        // so an empty-of-`Ready` result above is a property of `Halting` and
        // not of a walker that never walks.
        let mut from_idle: HashSet<TunnelState> = HashSet::new();
        let mut frontier = vec![TunnelState::Idle];
        while let Some(state) = frontier.pop() {
            if !from_idle.insert(state) {
                continue;
            }
            for event in TunnelEvent::ALL {
                if let Ok(next) = step(state, event) {
                    frontier.push(next);
                }
            }
        }
        assert!(
            from_idle.contains(&TunnelState::Ready),
            "the walker cannot reach Ready from Idle, so its Halting result means nothing"
        );
    }

    /// **Mutations this detects:** making the kill switch refusable from any
    /// state — a caller reading that `Err` as "the halt did not happen" is the
    /// exact misreading this rule removes.
    #[test]
    fn the_kill_switch_is_legal_from_every_state() {
        for state in TunnelState::ALL {
            let next = step(state, TunnelEvent::KillSwitchEngaged)
                .unwrap_or_else(|e| panic!("kill switch refused from {}: {e:?}", state.name()));
            assert!(
                !next.may_carry_stream_data(),
                "the kill switch left {} in a data-carrying state",
                state.name()
            );
        }
        // Positive control: some other event IS refused somewhere, so "legal
        // everywhere" above is a property of the kill switch and not of a
        // `step` that accepts everything.
        assert!(step(TunnelState::Idle, TunnelEvent::PeerConfirmed).is_err());
    }

    /// **Mutations this detects:** re-pointing `CarriageLost` at `CarriageUp`
    /// (which would resume a session on a key derived for a carriage that is
    /// gone) or at `Closed` (which would make a recoverable transport drop
    /// unrecoverable).
    #[test]
    fn losing_the_carriage_rewinds_to_idle_and_never_preserves_the_session() {
        for state in [
            TunnelState::CarriageUp,
            TunnelState::HelloSent,
            TunnelState::ConfirmSent,
            TunnelState::Ready,
        ] {
            assert_eq!(
                step(state, TunnelEvent::CarriageLost),
                Ok(TunnelState::Idle)
            );
        }
        // And from `Idle` there is no shortcut back to a keyed state: the only
        // way forward is a fresh dial and a fresh handshake.
        assert!(step(TunnelState::Idle, TunnelEvent::PeerConfirmed).is_err());
        assert!(step(TunnelState::Idle, TunnelEvent::HelloSent).is_err());
        assert_eq!(
            step(TunnelState::Idle, TunnelEvent::CarriageConnected),
            Ok(TunnelState::CarriageUp)
        );
    }

    /// **Mutations this detects:** collapsing `ConfirmSent` into `HelloSent`,
    /// so one confirm reaches `Ready` and framing goes live before both sides
    /// have confirmed.
    #[test]
    fn the_happy_path_needs_both_confirms_before_ready() {
        let mut state = TunnelState::Idle;
        for (event, want) in [
            (TunnelEvent::CarriageConnected, TunnelState::CarriageUp),
            (TunnelEvent::HelloSent, TunnelState::HelloSent),
            (TunnelEvent::PeerConfirmed, TunnelState::ConfirmSent),
            (TunnelEvent::PeerConfirmed, TunnelState::Ready),
        ] {
            state = step(state, event).expect("happy path step");
            assert_eq!(state, want);
            if want != TunnelState::Ready {
                assert!(
                    !state.may_carry_stream_data(),
                    "{} carried data before Ready",
                    state.name()
                );
            }
        }
        assert!(state.may_carry_stream_data());
    }

    /// **Mutations this detects:** an `IllegalTransition` that reports a fixed
    /// or empty pair, which would let one refusal stand in for all of them and
    /// pass every refusal assertion in the crate.
    #[test]
    fn an_illegal_transition_names_the_state_and_the_event_it_refused() {
        assert_eq!(
            step(TunnelState::Closed, TunnelEvent::CarriageConnected),
            Err(TunnelError::IllegalTransition {
                from: "Closed",
                event: "CarriageConnected",
            })
        );
        // Distinct pairs produce distinct refusals.
        assert_ne!(
            step(TunnelState::Closed, TunnelEvent::CarriageConnected),
            step(TunnelState::Idle, TunnelEvent::CarriageLost)
        );
        // And the names are the enum spellings, not a `Debug` render that a
        // derive change could silently move.
        for state in TunnelState::ALL {
            assert!(!state.name().is_empty());
            assert_eq!(state.name(), format!("{state:?}"));
        }
        for event in TunnelEvent::ALL {
            assert_eq!(event.name(), format!("{event:?}"));
        }
    }

    /// **Mutations this detects:** renaming any variant of either normative
    /// enum. The spec's §State transitions block is reproduced spelling for
    /// spelling here and in three sibling lanes; a rename in one of them is a
    /// silent contract break in the others.
    #[test]
    fn the_normative_state_and_event_spellings_match_the_spec() {
        assert_eq!(
            TunnelState::ALL.map(|s| s.name()),
            [
                "Idle",
                "CarriageUp",
                "HelloSent",
                "ConfirmSent",
                "Ready",
                "Halting",
                "Closed",
            ]
        );
        assert_eq!(
            TunnelEvent::ALL.map(|e| e.name()),
            [
                "CarriageConnected",
                "HelloSent",
                "PeerConfirmed",
                "StreamOpened",
                "StreamClosed",
                "KillSwitchEngaged",
                "CarriageLost",
            ]
        );
    }

    /// **Mutations this detects:** a copy-paste in either `name()` that gives
    /// two variants the same string, which makes an `IllegalTransition`
    /// ambiguous about what it refused and lets one refusal assertion pass for
    /// a different pair.
    #[test]
    fn every_state_name_and_every_event_name_is_unique() {
        let states: HashSet<&'static str> = TunnelState::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(
            states.len(),
            TunnelState::ALL.len(),
            "two states share a name"
        );
        let events: HashSet<&'static str> = TunnelEvent::ALL.iter().map(|e| e.name()).collect();
        assert_eq!(
            events.len(),
            TunnelEvent::ALL.len(),
            "two events share a name"
        );
        // Positive control: the collector does collapse duplicates, so the
        // counts above are evidence rather than an artefact.
        let dupes: HashSet<&'static str> = ["Ready", "Ready"].into_iter().collect();
        assert_eq!(dupes.len(), 1);
    }

    /// **Mutations this detects:** hidden state behind `step` — a counter, a
    /// cache or a once-cell that makes the second answer for a pair differ
    /// from the first, which would make the matrix sweep above depend on the
    /// order it happened to walk in.
    #[test]
    fn stepping_the_same_pair_twice_gives_the_same_answer() {
        for state in TunnelState::ALL {
            for event in TunnelEvent::ALL {
                let first = step(state, event);
                let second = step(state, event);
                assert_eq!(
                    first,
                    second,
                    "{}+{} answered differently on the second call",
                    state.name(),
                    event.name()
                );
            }
        }
    }

    /// **Mutations this detects:** letting a halted tunnel re-dial —
    /// `Halting + CarriageConnected` reaching `CarriageUp`, or `Closed`
    /// accepting anything at all, either of which turns the kill switch into a
    /// reconnect delay.
    #[test]
    fn a_halt_completes_when_the_carriage_goes_away_and_never_reconnects() {
        let halting = step(TunnelState::Ready, TunnelEvent::KillSwitchEngaged).expect("halt");
        assert_eq!(halting, TunnelState::Halting);

        // Positive control: `CarriageConnected` IS the dial event, and from
        // `Idle` it works.
        assert_eq!(
            step(TunnelState::Idle, TunnelEvent::CarriageConnected),
            Ok(TunnelState::CarriageUp)
        );

        // From `Halting` it does not.
        assert!(step(halting, TunnelEvent::CarriageConnected).is_err());
        let closed = step(halting, TunnelEvent::CarriageLost).expect("halt completes");
        assert_eq!(closed, TunnelState::Closed);
        assert!(step(closed, TunnelEvent::CarriageConnected).is_err());
        assert!(step(closed, TunnelEvent::CarriageLost).is_err());
        assert_eq!(
            step(closed, TunnelEvent::KillSwitchEngaged),
            Ok(TunnelState::Closed)
        );
    }

    /// The handshake-outcome → nonce-space mapping, proved end to end against
    /// the real ML-KEM-768 / ML-DSA-65 handshake.
    ///
    /// **Mutations this detects:** giving both endpoints the same
    /// [`ChannelRole`] (every frame then collides in one nonce space, and the
    /// round trip fails its tag), and inverting the node/gateway mapping away
    /// from the spine's dialler-is-prefix-0 convention.
    #[test]
    fn the_node_is_the_initiator_and_the_gateway_is_the_responder() {
        // The value assertion. A round trip alone cannot catch a *global*
        // inversion, because two inverted roles are still opposite.
        assert_eq!(TunnelEndpoint::Node.channel_role(), ChannelRole::Initiator);
        assert_eq!(
            TunnelEndpoint::Gateway.channel_role(),
            ChannelRole::Responder
        );
        assert_eq!(TunnelEndpoint::Node.peer(), TunnelEndpoint::Gateway);
        assert_ne!(
            TunnelEndpoint::Node.channel_role(),
            TunnelEndpoint::Gateway.channel_role()
        );

        // The real handshake, both sides.
        let node = MlKem768MlDsa65::node_from_seed([11u8; 32]);
        let gateway = MlKem768MlDsa65::gateway_from_seed([22u8; 32]);
        let binding = HelloBinding {
            consent_record_hash: [3u8; 32],
            policy_text_hash: [4u8; 32],
            allowlist_digest: [5u8; 32],
        };
        let policy = GatewayPolicy::new(&[[5u8; 32]]);
        let mut replay = HelloReplayCache::new();
        let (hello, node_key) = initiate(
            &node,
            &gateway.kem_public().expect("gateway kem key"),
            &PeerKemOffer::post_quantum(),
            &binding,
        )
        .expect("initiate");
        let (_confirm, gateway_key) =
            respond(&gateway, &hello, &policy, &mut replay).expect("respond");
        assert_eq!(
            node_key, gateway_key,
            "the two sides derived different keys"
        );

        // Node seals, gateway opens.
        let mut node_seam = seam_for_endpoint(TunnelEndpoint::Node, node_key);
        let mut gateway_seam = seam_for_endpoint(TunnelEndpoint::Gateway, gateway_key);
        let mut wire = vec![0u8; MAX_FRAME_WIRE];
        let mut out = vec![0u8; MAX_FRAME_PAYLOAD];
        let header = FrameHeader::data(7, 2);
        let n = seal_frame(&mut node_seam, &header, b"up", &mut wire).expect("seal");
        let (got, len) = open_frame(&mut gateway_seam, &wire[..n], &mut out).expect("open");
        assert_eq!(got.stream_id, 7);
        assert_eq!(got.kind, FrameKind::StreamData);
        assert_eq!(&out[..len], b"up");

        // And an endpoint built with the SENDER's role cannot open the sender's
        // bytes: it opens from the peer half of the nonce space, which is what
        // makes the mapping load-bearing rather than decorative.
        let mut same_role = seam_for_endpoint(TunnelEndpoint::Node, gateway_key);
        let header = FrameHeader::data(7, 4);
        let n = seal_frame(&mut node_seam, &header, b"down", &mut wire).expect("seal");
        assert!(
            open_frame(&mut same_role, &wire[..n], &mut out).is_err(),
            "an endpoint sealing into the same nonce space opened the peer's frame"
        );
    }
}
