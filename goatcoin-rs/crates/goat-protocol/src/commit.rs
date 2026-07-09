//! Canonical commitment (device-agnostic).
//!
//! Amendment A-6: the commitment is a function of TASK semantics only
//! (task_class_id, tokens, numeric outputs, engine_build_id) and carries NO device
//! identity — two device classes computing the same task commit identically. This is
//! what makes cross-class verification and the D8-behavioral neutrality property possible.

use sha3::{Digest, Sha3_256};

use crate::types::TaskResult;

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn put_i64(out: &mut Vec<u8>, n: i64) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// Deterministic, field-ordered, length-prefixed TLV. Same object -> same bytes.
pub fn canonical_serialize(r: &TaskResult) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GRES\x01");
    put_u32(&mut out, r.task_class_id);
    let bid = r.engine_build_id.as_bytes();
    put_u32(&mut out, bid.len() as u32);
    out.extend_from_slice(bid);
    put_u32(&mut out, r.tokens.len() as u32);
    for &t in &r.tokens {
        put_u32(&mut out, t);
    }
    put_u32(&mut out, r.vector.len() as u32);
    for &v in &r.vector {
        put_i64(&mut out, v);
    }
    out
}

/// 32-byte SHA3-256 output commitment.
pub fn commit(r: &TaskResult) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(canonical_serialize(r));
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
