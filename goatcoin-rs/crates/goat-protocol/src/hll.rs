//! Deterministic HyperLogLog for coverage counting (device-agnostic). WP-0.3, closes R-MAT1.
//!
//! Production replacement for the reference's exact-set coverage. Two properties matter:
//!   * DETERMINISTIC serialization — same multiset -> byte-identical registers -> identical
//!     accumulator roots across independent recomputers (the fraud-proof precondition).
//!   * MERGEABLE — union is element-wise max, so COHORT_MERGE (F6) can collapse clusters.
//!
//! With p = 12 (4096 registers) and linear counting, cardinalities in the coverage-threshold
//! range (tens to hundreds of distinct clusters/ASNs) are counted essentially exactly, so the
//! GATE behaves like the exact-set reference at these scales while remaining a real HLL.

use sha3::{Digest, Sha3_256};

const P: u32 = 12;
const M: usize = 1 << P; // 4096 registers

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hll {
    registers: Vec<u8>,
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl Hll {
    pub fn new() -> Self {
        Self {
            registers: vec![0u8; M],
        }
    }

    fn hash64(item: &[u8]) -> u64 {
        let mut h = Sha3_256::new();
        h.update(item);
        let d = h.finalize();
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[..8]);
        u64::from_be_bytes(b)
    }

    pub fn add(&mut self, item: &[u8]) {
        let hash = Self::hash64(item);
        let idx = (hash >> (64 - P)) as usize;
        // rank = position of the leftmost 1 in the (64-P)-bit suffix, +1.
        let w = hash << P; // suffix bits move to the top; low P bits become zero
        let rank = if w == 0 {
            (64 - P + 1) as u8
        } else {
            ((w.leading_zeros() + 1) as u8).min((64 - P + 1) as u8)
        };
        if rank > self.registers[idx] {
            self.registers[idx] = rank;
        }
    }

    /// Union in place (element-wise max). Used by COHORT_MERGE coverage collapse.
    pub fn merge(&mut self, other: &Hll) {
        for i in 0..M {
            if other.registers[i] > self.registers[i] {
                self.registers[i] = other.registers[i];
            }
        }
    }

    pub fn estimate(&self) -> f64 {
        let m = M as f64;
        let sum: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m {
            let zeros = self.registers.iter().filter(|&&r| r == 0).count();
            if zeros > 0 {
                return m * (m / zeros as f64).ln(); // linear counting (exact-ish for small n)
            }
        }
        raw
    }

    /// Rounded distinct-count for the GATE.
    pub fn count(&self) -> u64 {
        self.estimate().round() as u64
    }

    /// Deterministic serialization: the register bytes in order. Same multiset -> same bytes.
    pub fn serialize(&self) -> &[u8] {
        &self.registers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hll_of(items: impl IntoIterator<Item = u32>) -> Hll {
        let mut h = Hll::new();
        for i in items {
            h.add(&i.to_be_bytes());
        }
        h
    }

    #[test]
    fn deterministic_and_order_independent() {
        let a = hll_of((0..50).collect::<Vec<_>>());
        let b = hll_of((0..50).rev().collect::<Vec<_>>());
        assert_eq!(a.serialize(), b.serialize()); // order-independent registers
        assert_eq!(a, b);
    }

    #[test]
    fn small_cardinality_is_essentially_exact() {
        for n in [10u32, 25, 30, 100] {
            let c = hll_of(0..n).count();
            let err = (c as i64 - n as i64).abs();
            assert!(err <= 1, "n={n} count={c}"); // linear-counting exactness at these scales
        }
    }

    #[test]
    fn merge_is_union() {
        let mut a = hll_of(0..20);
        let b = hll_of(15..35);
        a.merge(&b);
        let both = hll_of(0..35);
        assert_eq!(a.serialize(), both.serialize());
    }

    #[test]
    fn duplicates_do_not_inflate() {
        let mut h = Hll::new();
        for _ in 0..1000 {
            h.add(b"same");
        }
        assert_eq!(h.count(), 1);
    }
}
