//! MTU-safe application-layer datagram chunking + bounded reassembly (MTU-chunking).
//!
//! Outer transport framing only — does **not** change frozen semantic wire structs
//! (`HandshakeInitiation` / `HandshakeResponse` / SecureFrame bodies). Large logical
//! datagrams are split into chunks of at most [`MAX_UDP_DATAGRAM`] bytes so IP
//! fragmentation is unnecessary on a 1500-byte path (with tunnel overhead margin).
//!
//! ## Wire format (tag [`CHUNK_TAG`])
//!
//! ```text
//! tag(1) ‖ msg_id_le(4) ‖ frag_idx_le(2) ‖ frag_count_le(2) ‖ total_len_le(4) ‖ payload
//! ```
//!
//! ## DoS bounds (non-negotiable)
//!
//! - Max logical message [`MAX_LOGICAL_LEN`] (covers largest handshake + margin).
//! - Max concurrent partial messages **per peer** [`MAX_PARTIALS_PER_PEER`].
//! - Max peers with partials [`MAX_PEERS_WITH_PARTIALS`].
//! - Stale partials evicted after [`PARTIAL_TTL`].
//! - Oversized / inconsistent headers rejected with no allocation beyond a fixed header parse.
//! - Reassembly is **purely cheap** (memcpy); no PQ work happens here. RECON-11 cookie still
//!   gates ML-DSA/ML-KEM after the logical datagram is complete.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Outer tag for a chunk frame (distinct from core `packet_tag` 0x01–0x04 and cookie reply 0x81).
pub const CHUNK_TAG: u8 = 0xF1;

/// Conservative max UDP datagram size (header + payload) to survive PPPoE/VPN under a 1500 MTU path.
pub const MAX_UDP_DATAGRAM: usize = 1200;

/// Chunk header size after the tag: msg_id(4)+idx(2)+count(2)+total_len(4).
pub const CHUNK_HEADER_LEN: usize = 4 + 2 + 2 + 4;

/// Max payload bytes in one chunk: `MAX_UDP_DATAGRAM - 1 - CHUNK_HEADER_LEN`.
pub const MAX_CHUNK_PAYLOAD: usize = MAX_UDP_DATAGRAM - 1 - CHUNK_HEADER_LEN;

/// Hard cap on a reassembled logical message (largest CookieEcho ~6.5 KB + headroom).
pub const MAX_LOGICAL_LEN: usize = 16_384;

/// Max fragments per logical message.
pub const MAX_FRAGS: u16 = 32;

/// Max concurrent incomplete messages retained for one peer.
pub const MAX_PARTIALS_PER_PEER: usize = 2;

/// Max distinct peers holding any incomplete reassembly at once.
pub const MAX_PEERS_WITH_PARTIALS: usize = 64;

/// Incomplete reassembly TTL.
pub const PARTIAL_TTL: Duration = Duration::from_secs(5);

/// Why reassembly rejected a chunk (cheap, no PQ).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyError {
    Malformed,
    TooLarge,
    TooManyFrags,
    PeerQuota,
    GlobalPeerQuota,
    Inconsistent,
}

/// Fragment a complete logical datagram into MTU-safe UDP payloads.
/// Packets already ≤ [`MAX_UDP_DATAGRAM`] are returned as a single-element vec (unchanged).
pub fn fragment_datagram(logical: &[u8], msg_id: u32) -> Vec<Vec<u8>> {
    if logical.len() <= MAX_UDP_DATAGRAM {
        return vec![logical.to_vec()];
    }
    if logical.len() > MAX_LOGICAL_LEN {
        // Caller must not send oversize; drop to empty rather than panic.
        return Vec::new();
    }
    let payload_max = MAX_CHUNK_PAYLOAD;
    let n = logical.len().div_ceil(payload_max);
    if n > MAX_FRAGS as usize {
        return Vec::new();
    }
    let frag_count = n as u16;
    let mut out = Vec::with_capacity(n);
    for (i, chunk) in logical.chunks(payload_max).enumerate() {
        let mut frame = Vec::with_capacity(1 + CHUNK_HEADER_LEN + chunk.len());
        frame.push(CHUNK_TAG);
        frame.extend_from_slice(&msg_id.to_le_bytes());
        frame.extend_from_slice(&(i as u16).to_le_bytes());
        frame.extend_from_slice(&frag_count.to_le_bytes());
        frame.extend_from_slice(&(logical.len() as u32).to_le_bytes());
        frame.extend_from_slice(chunk);
        debug_assert!(frame.len() <= MAX_UDP_DATAGRAM);
        out.push(frame);
    }
    out
}

/// Expand an egress batch so every logical packet is MTU-safe.
pub fn expand_egress_batch(
    batch: Vec<(SocketAddr, Vec<u8>)>,
    next_msg_id: &mut u32,
) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut out = Vec::with_capacity(batch.len());
    for (addr, pkt) in batch {
        let id = *next_msg_id;
        *next_msg_id = next_msg_id.wrapping_add(1);
        for frag in fragment_datagram(&pkt, id) {
            out.push((addr, frag));
        }
    }
    out
}

struct PartialMsg {
    total_len: u32,
    frag_count: u16,
    /// Bitset of received fragment indices (MAX_FRAGS ≤ 32).
    received: u32,
    buf: Vec<u8>,
    first_seen: Instant,
}

/// Bounded reassembly table keyed by `(peer, msg_id)`.
pub struct ReassemblyTable {
    /// peer → (msg_id → partial)
    peers: HashMap<SocketAddr, HashMap<u32, PartialMsg>>,
}

impl Default for ReassemblyTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Evict partials older than [`PARTIAL_TTL`].
    pub fn gc(&mut self, now: Instant) {
        self.peers.retain(|_, msgs| {
            msgs.retain(|_, p| now.duration_since(p.first_seen) < PARTIAL_TTL);
            !msgs.is_empty()
        });
    }

    /// Ingest a UDP datagram. Returns:
    /// - `Ok(None)` — not a chunk, or incomplete chunk (caller should process non-chunks as logical).
    /// - `Ok(Some(logical))` — fully reassembled logical datagram.
    /// - `Err` — malformed / quota / oversize chunk (drop).
    ///
    /// Non-chunk packets return `Ok(None)` with a sentinel: use [`is_chunk`] first.
    pub fn ingest_chunk(
        &mut self,
        peer: SocketAddr,
        raw: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        self.gc(now);
        if raw.first() != Some(&CHUNK_TAG) {
            return Ok(None);
        }
        if raw.len() < 1 + CHUNK_HEADER_LEN {
            return Err(ReassemblyError::Malformed);
        }
        let msg_id = u32::from_le_bytes(raw[1..5].try_into().unwrap());
        let frag_idx = u16::from_le_bytes(raw[5..7].try_into().unwrap());
        let frag_count = u16::from_le_bytes(raw[7..9].try_into().unwrap());
        let total_len = u32::from_le_bytes(raw[9..13].try_into().unwrap());
        let payload = &raw[13..];

        if total_len as usize > MAX_LOGICAL_LEN || total_len == 0 {
            return Err(ReassemblyError::TooLarge);
        }
        // reassembly-hardening / M1: frag_count MUST match total_len (blocks attacker-chosen 32-bit mask).
        let expected_frags = (total_len as usize).div_ceil(MAX_CHUNK_PAYLOAD);
        if expected_frags == 0 || expected_frags > MAX_FRAGS as usize {
            return Err(ReassemblyError::TooManyFrags);
        }
        if frag_count as usize != expected_frags {
            return Err(ReassemblyError::Inconsistent);
        }
        if frag_count == 0 || frag_idx >= frag_count {
            return Err(ReassemblyError::TooManyFrags);
        }
        if payload.len() > MAX_CHUNK_PAYLOAD {
            return Err(ReassemblyError::Malformed);
        }
        // Expected payload size for this fragment.
        let start = frag_idx as usize * MAX_CHUNK_PAYLOAD;
        if start >= total_len as usize {
            return Err(ReassemblyError::Inconsistent);
        }
        let expect = (total_len as usize - start).min(MAX_CHUNK_PAYLOAD);
        if payload.len() != expect {
            return Err(ReassemblyError::Inconsistent);
        }

        // Admit peer slot.
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS_WITH_PARTIALS {
            return Err(ReassemblyError::GlobalPeerQuota);
        }
        let peer_map = self.peers.entry(peer).or_default();
        if !peer_map.contains_key(&msg_id) && peer_map.len() >= MAX_PARTIALS_PER_PEER {
            return Err(ReassemblyError::PeerQuota);
        }

        let partial = peer_map.entry(msg_id).or_insert_with(|| PartialMsg {
            total_len,
            frag_count,
            received: 0,
            buf: vec![0u8; total_len as usize],
            first_seen: now,
        });

        if partial.total_len != total_len || partial.frag_count != frag_count {
            peer_map.remove(&msg_id);
            return Err(ReassemblyError::Inconsistent);
        }
        if partial.buf.len() != total_len as usize {
            peer_map.remove(&msg_id);
            return Err(ReassemblyError::Inconsistent);
        }

        // frag_idx ≤ frag_count - 1 ≤ expected_frags - 1 ≤ 13 for MAX_LOGICAL_LEN, always < 32.
        let bit = 1u32 << frag_idx;
        if partial.received & bit == 0 {
            partial.buf[start..start + payload.len()].copy_from_slice(payload);
            partial.received |= bit;
        }

        // Defense in depth (M1): u64 shift is well-defined for frag_count ∈ 1..=32.
        let need = ((1u64 << frag_count) - 1) as u32;
        if partial.received != need {
            return Ok(None);
        }

        let complete = std::mem::take(&mut partial.buf);
        peer_map.remove(&msg_id);
        if peer_map.is_empty() {
            self.peers.remove(&peer);
        }
        Ok(Some(complete))
    }
}

/// Whether `raw` is a chunk frame (needs reassembly).
#[inline]
pub fn is_chunk(raw: &[u8]) -> bool {
    raw.first() == Some(&CHUNK_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(p: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), p)
    }

    #[test]
    fn small_packet_not_fragmented() {
        let p = vec![0x01u8; 100];
        let f = fragment_datagram(&p, 1);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0], p);
    }

    #[test]
    fn large_packet_roundtrips() {
        let logical: Vec<u8> = (0..6500u32).map(|i| (i % 251) as u8).collect();
        assert!(logical.len() > MAX_UDP_DATAGRAM);
        let frags = fragment_datagram(&logical, 42);
        assert!(frags.len() > 1);
        assert!(frags.iter().all(|f| f.len() <= MAX_UDP_DATAGRAM));
        assert!(frags.iter().all(|f| f[0] == CHUNK_TAG));

        let mut table = ReassemblyTable::new();
        let now = Instant::now();
        let addr = peer(9);
        let mut done = None;
        for f in &frags {
            if let Some(full) = table.ingest_chunk(addr, f, now).unwrap() {
                done = Some(full);
            }
        }
        assert_eq!(done.unwrap(), logical);
        assert!(table.peers.is_empty());
    }

    #[test]
    fn rejects_oversized_total_len() {
        let mut frame = vec![CHUNK_TAG];
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&((MAX_LOGICAL_LEN as u32) + 1).to_le_bytes());
        frame.extend_from_slice(&[0u8; 10]);
        let mut table = ReassemblyTable::new();
        assert_eq!(
            table.ingest_chunk(peer(1), &frame, Instant::now()),
            Err(ReassemblyError::TooLarge)
        );
    }

    /// reassembly-hardening / M1: crafted `frag_count = 32` must return Err and never panic under
    /// overflow-checks (enabled in debug/`cargo test`).
    #[test]
    fn frag_count_32_returns_err_not_panic() {
        let total_len = MAX_CHUNK_PAYLOAD as u32; // legitimate single-frag size
        let mut frame = vec![CHUNK_TAG];
        frame.extend_from_slice(&9u32.to_le_bytes()); // msg_id
        frame.extend_from_slice(&0u16.to_le_bytes()); // frag_idx
        frame.extend_from_slice(&32u16.to_le_bytes()); // attacker frag_count
        frame.extend_from_slice(&total_len.to_le_bytes());
        frame.extend_from_slice(&vec![0xABu8; MAX_CHUNK_PAYLOAD]);
        let mut table = ReassemblyTable::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            table.ingest_chunk(peer(3), &frame, Instant::now())
        }));
        assert!(result.is_ok(), "must not panic on frag_count=32");
        assert_eq!(result.unwrap(), Err(ReassemblyError::Inconsistent));
    }

    #[test]
    fn frag_count_mismatch_total_len_rejected() {
        // total_len implies 1 frag; claim 2.
        let total_len = 100u32;
        let mut frame = vec![CHUNK_TAG];
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&2u16.to_le_bytes());
        frame.extend_from_slice(&total_len.to_le_bytes());
        frame.extend_from_slice(&[0u8; 100]);
        let mut table = ReassemblyTable::new();
        assert_eq!(
            table.ingest_chunk(peer(4), &frame, Instant::now()),
            Err(ReassemblyError::Inconsistent)
        );
    }

    #[test]
    fn peer_quota_bounds_partials() {
        let mut table = ReassemblyTable::new();
        let now = Instant::now();
        let addr = peer(2);
        // Open MAX_PARTIALS_PER_PEER distinct incomplete messages (frag 0 of 2 only).
        for msg_id in 0..MAX_PARTIALS_PER_PEER as u32 {
            let mut frame = vec![CHUNK_TAG];
            frame.extend_from_slice(&msg_id.to_le_bytes());
            frame.extend_from_slice(&0u16.to_le_bytes());
            frame.extend_from_slice(&2u16.to_le_bytes());
            let total = (MAX_CHUNK_PAYLOAD * 2) as u32;
            frame.extend_from_slice(&total.to_le_bytes());
            frame.extend_from_slice(&vec![0xABu8; MAX_CHUNK_PAYLOAD]);
            assert!(table.ingest_chunk(addr, &frame, now).unwrap().is_none());
        }
        assert_eq!(
            table.peers.get(&addr).map(|m| m.len()).unwrap_or(0),
            MAX_PARTIALS_PER_PEER
        );
        // One more should hit peer quota.
        let mut frame = vec![CHUNK_TAG];
        frame.extend_from_slice(&99u32.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&2u16.to_le_bytes());
        let total = (MAX_CHUNK_PAYLOAD * 2) as u32;
        frame.extend_from_slice(&total.to_le_bytes());
        frame.extend_from_slice(&vec![0xABu8; MAX_CHUNK_PAYLOAD]);
        assert_eq!(
            table.ingest_chunk(addr, &frame, now),
            Err(ReassemblyError::PeerQuota)
        );
    }

    #[test]
    fn expand_egress_chunks_large_only() {
        let mut id = 0u32;
        let small = vec![(peer(1), vec![1u8; 50])];
        let e = expand_egress_batch(small, &mut id);
        assert_eq!(e.len(), 1);
        let large = vec![(peer(1), vec![2u8; 3000])];
        let e2 = expand_egress_batch(large, &mut id);
        assert!(e2.len() > 1);
        assert!(e2.iter().all(|(_, b)| b.len() <= MAX_UDP_DATAGRAM));
    }
}
