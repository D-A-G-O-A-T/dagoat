//! Deterministic reference "compute" shared by the reference backends (DEVICE layer).
//! Stands in for a real inference engine; a production backend swaps these for engine calls
//! behind the identical GoatBackend trait. Payload is treated as OPAQUE bytes (only hashed).

use sha3::{Digest, Sha3_256};

pub const FP_SCALE: u32 = 1_000_000;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&d);
    o
}

pub fn reference_tokens(payload: &[u8], seed: u64, n: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(n);
    let mut h = sha(&[b"tok", payload, &seed.to_be_bytes()]);
    let mut ctr: u32 = 0;
    while out.len() < n {
        h = sha(&[&h, &ctr.to_be_bytes()]);
        let mut i = 0;
        while i + 2 <= h.len() && out.len() < n {
            let v = u16::from_be_bytes([h[i], h[i + 1]]) as u32 % 32000;
            out.push(v);
            i += 2;
        }
        ctr += 1;
    }
    out
}

pub fn reference_vector_base(payload: &[u8], seed: u64, n: usize) -> Vec<i64> {
    let h = sha(&[b"vec", payload, &seed.to_be_bytes()]);
    (0..n)
        .map(|i| {
            let b = [h[i * 4], h[i * 4 + 1], h[i * 4 + 2], h[i * 4 + 3]];
            (u32::from_be_bytes(b) % FP_SCALE) as i64
        })
        .collect()
}

/// Deterministic per-index delta in [-magnitude, +magnitude]; models FP roundoff.
pub fn bounded_perturbation(base: &[i64], magnitude: i64) -> Vec<i64> {
    if magnitude == 0 {
        return base.to_vec();
    }
    base.iter()
        .enumerate()
        .map(|(i, &v)| {
            let d = ((i as i64 * 7 + 3) % (2 * magnitude + 1)) - magnitude;
            v + d
        })
        .collect()
}
