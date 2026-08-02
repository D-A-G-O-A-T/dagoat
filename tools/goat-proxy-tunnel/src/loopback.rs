//! An in-process carriage.
//!
//! [`LoopbackCarriage`] is a complete [`Carriage`] that opens **no socket at
//! all** — two `tokio` queues and nothing else. It exists so the layers above
//! (framing, handshake, state machine, metering) can be exercised end to end
//! without a network, and so the refusal paths that a real dial can never
//! reach in a test are reachable.
//!
//! It is not a stand-in for the transport in the sense the old in-process bus
//! was. The real carriage is [`crate::carriage::WssCarriage`] and it is
//! shipped; this one is a test and parity instrument, and it enforces the same
//! datagram bound and the same closed-is-sticky rule so that a property proved
//! over the loopback is a property of the seam and not of the loopback.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::carriage::{Carriage, CloseReason, MAX_DATAGRAM_BYTES};
use crate::error::TunnelError;

/// One end of an in-process carriage pair.
pub struct LoopbackCarriage {
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: mpsc::Receiver<Vec<u8>>,
    closed: Option<CloseReason>,
    sent: u64,
    received: u64,
}

impl LoopbackCarriage {
    /// Two endpoints wired to each other, each queue holding `capacity`
    /// datagrams.
    pub fn pair(capacity: usize) -> (Self, Self) {
        let capacity = capacity.max(1);
        let (a_tx, b_rx) = mpsc::channel(capacity);
        let (b_tx, a_rx) = mpsc::channel(capacity);
        (
            Self {
                tx: Some(a_tx),
                rx: a_rx,
                closed: None,
                sent: 0,
                received: 0,
            },
            Self {
                tx: Some(b_tx),
                rx: b_rx,
                closed: None,
                sent: 0,
                received: 0,
            },
        )
    }

    /// Datagrams this endpoint actually queued.
    pub fn sent_datagrams(&self) -> u64 {
        self.sent
    }

    /// Datagrams this endpoint actually took off the queue.
    pub fn received_datagrams(&self) -> u64 {
        self.received
    }

    /// Why this endpoint closed, if it has.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.closed
    }
}

#[async_trait]
impl Carriage for LoopbackCarriage {
    async fn send_datagram(&mut self, datagram: &[u8]) -> Result<(), TunnelError> {
        if let Some(reason) = self.closed {
            return Err(TunnelError::CarriageClosed(reason));
        }
        if datagram.len() > MAX_DATAGRAM_BYTES {
            return Err(TunnelError::FrameTooLarge {
                len: datagram.len(),
                max: MAX_DATAGRAM_BYTES,
            });
        }
        let tx = self.tx.as_ref().ok_or(TunnelError::CarriageNotOpen)?;
        tx.send(datagram.to_vec())
            .await
            .map_err(|_| TunnelError::CarriageClosed(CloseReason::PeerGone))?;
        self.sent += 1;
        Ok(())
    }

    async fn recv_datagram(&mut self) -> Result<Vec<u8>, TunnelError> {
        if let Some(reason) = self.closed {
            return Err(TunnelError::CarriageClosed(reason));
        }
        match self.rx.recv().await {
            Some(d) => {
                self.received += 1;
                Ok(d)
            }
            None => {
                self.closed = Some(CloseReason::PeerGone);
                Err(TunnelError::CarriageClosed(CloseReason::PeerGone))
            }
        }
    }

    async fn close(&mut self, reason: CloseReason) -> Result<(), TunnelError> {
        match self.closed {
            // Closed-is-sticky: a non-recoverable reason is never downgraded.
            Some(existing) if !existing.is_recoverable() => {}
            _ => self.closed = Some(reason),
        }
        // Dropping the sender is what makes the peer's `recv` observe
        // `PeerGone` rather than hanging forever.
        self.tx = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Mutations this detects:** counting a refused datagram as sent, or
    /// counting a datagram twice.
    #[tokio::test]
    async fn the_loopback_counters_track_only_datagrams_that_moved() {
        let (mut a, mut b) = LoopbackCarriage::pair(2);
        assert_eq!(a.sent_datagrams(), 0);
        a.send_datagram(b"one").await.unwrap();
        a.send_datagram(b"two").await.unwrap();
        assert_eq!(a.sent_datagrams(), 2);
        assert_eq!(b.received_datagrams(), 0);
        assert_eq!(b.recv_datagram().await.unwrap(), b"one");
        assert_eq!(b.received_datagrams(), 1);

        let over = vec![0u8; MAX_DATAGRAM_BYTES + 1];
        assert!(a.send_datagram(&over).await.is_err());
        assert_eq!(a.sent_datagrams(), 2, "a refused datagram was counted");
    }

    /// **Mutations this detects:** letting `close` downgrade a kill switch to
    /// a normal close, which would let a supervisor redial.
    #[tokio::test]
    async fn a_non_recoverable_close_is_sticky_on_the_loopback_too() {
        let (mut a, _b) = LoopbackCarriage::pair(1);
        a.close(CloseReason::PolicyRefusal).await.unwrap();
        a.close(CloseReason::Normal).await.unwrap();
        assert_eq!(a.close_reason(), Some(CloseReason::PolicyRefusal));

        let (mut c, _d) = LoopbackCarriage::pair(1);
        c.close(CloseReason::Normal).await.unwrap();
        c.close(CloseReason::PeerGone).await.unwrap();
        assert_eq!(
            c.close_reason(),
            Some(CloseReason::PeerGone),
            "a recoverable reason must still be updatable"
        );
    }
}
