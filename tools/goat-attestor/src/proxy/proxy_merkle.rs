//! Domain-tagged Merkle leaves for the fetch-network settlement lane.
//!
//! ```text
//! leaf = keccak256(bytes.concat(keccak256(abi.encode(
//!            PROXY_LEAF_DOMAIN, operator, epochId, totalBytes, payoutGoatWei))))
//! ```
//!
//! Five 32-byte words, in that order, and the first of them is the whole point.
//! The compute lane's leaf is two words, `(worker, cumulativeScore)`, hashed the
//! same way and verified by the contract that ISSUES SUPPLY. Without a domain
//! word in the preimage the two leaf spaces are one space, and a proof issued
//! for a bandwidth payout would be a valid proof of compute work against it.
//! The domain word makes the preimages different lengths AND different content,
//! so a collision is not merely unlikely, it is not constructible from the same
//! numeric inputs -- which is what
//! `proxy_leaf_can_never_collide_with_an_epoch_settlement_leaf` asserts.
//!
//! Internal nodes use the sorted-pair rule and an odd node is carried up
//! unpaired, so the tree matches OpenZeppelin `MerkleProof.verify` exactly as
//! the compute tree already does. That code is deliberately duplicated rather
//! than shared: the compute tree is pinned by deployed contracts and must not be
//! touched to add a second consumer.
//!
//! The hashes in `pinned_proxy_solidity_cross_check_vectors` are the same
//! constants as `contracts/test/ProxyRevenueMerkleParity.t.sol`. A drift reds
//! both suites at once, by design. Never edit a pin to make a red test green: a
//! disagreement between the two encoders means every daemon-produced proof would
//! be refused on chain, and the pin is the only thing that says so before a
//! deploy does.
//!
//! Nothing here issues supply and nothing here destroys supply.

use crate::merkle::{hash_pair, keccak256};
use crate::proposer::ENROLLMENT_EPOCH_BASE;

/// The domain word's preimage. Immutable at deploy on the contract side, so
/// changing this string orphans every published root.
pub const PROXY_LEAF_DOMAIN_STR: &str = "GOAT_PROXY_REVENUE_LEAF_V1";

/// Start of the fetch-network epoch id space.
///
/// **This is the crate's only declaration of this constant.** Anything else that
/// needs it re-exports this item with `pub use`; two declarations of one number
/// in one crate is exactly the drift that silently splits an id space in half.
pub const PROXY_EPOCH_BASE: u64 = 8_000_000_000_000;

/// One gibibyte. The metering denominator, exact and a power of two.
pub const GIB_BYTES: u128 = 1_073_741_824;

/// `keccak256("GOAT_PROXY_REVENUE_LEAF_V1")`, computed rather than pinned so the
/// string above is the single source of truth on this side.
pub fn proxy_leaf_domain() -> [u8; 32] {
    keccak256(PROXY_LEAF_DOMAIN_STR.as_bytes())
}

/// True for epoch ids in the fetch-network space.
///
/// The upper bound is the enrolment base itself, not a second copy of the same
/// number: the two spaces are adjacent, and writing the ceiling as a literal
/// here would let one move without the other.
pub fn is_proxy_epoch(epoch_id: u64) -> bool {
    (PROXY_EPOCH_BASE..ENROLLMENT_EPOCH_BASE).contains(&epoch_id)
}

/// Gross payable for `total_bytes` at `rate_wei_per_gib`, floor-exact.
///
/// Multiplies before dividing. The other order truncates every sub-gibibyte
/// operator to zero, and a settlement that pays zero for real bytes moved is a
/// bug that no test of the Merkle tree would ever catch.
pub fn gross_for_bytes(total_bytes: u128, rate_wei_per_gib: u128) -> u128 {
    total_bytes
        .checked_mul(rate_wei_per_gib)
        .expect("gross overflows u128")
        / GIB_BYTES
}

/// One row of a published batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLeaf {
    pub operator: [u8; 20],
    /// Inside the leaf on purpose: a third replay defence, after the domain word
    /// and the per-epoch root.
    pub epoch_id: u64,
    pub total_bytes: u128,
    pub payout_goat_wei: u128,
}

/// The five-word ABI encoding, laid out by hand so the layout is inspectable.
///
/// Word 0 domain, word 1 address (left-padded to 32), word 2 `uint256` epoch,
/// word 3 `uint256` bytes, word 4 `uint256` wei. All big-endian, all right
/// aligned in their word.
pub fn abi_encode_proxy_leaf(leaf: &ProxyLeaf) -> [u8; 160] {
    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(&proxy_leaf_domain());
    buf[44..64].copy_from_slice(&leaf.operator);
    buf[88..96].copy_from_slice(&leaf.epoch_id.to_be_bytes());
    buf[112..128].copy_from_slice(&leaf.total_bytes.to_be_bytes());
    buf[144..160].copy_from_slice(&leaf.payout_goat_wei.to_be_bytes());
    buf
}

/// Double-hashed leaf matching `ProxyRevenueSettlement.claim`.
pub fn proxy_leaf_hash(leaf: &ProxyLeaf) -> [u8; 32] {
    let inner = keccak256(&abi_encode_proxy_leaf(leaf));
    keccak256(&inner)
}

/// Sorted-pair Merkle tree over [`ProxyLeaf`], OpenZeppelin compatible.
#[derive(Debug, Clone)]
pub struct ProxyMerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
    leaves: Vec<ProxyLeaf>,
    leaf_hashes: Vec<[u8; 32]>,
}

impl ProxyMerkleTree {
    pub fn build(leaves: Vec<ProxyLeaf>) -> Self {
        if leaves.is_empty() {
            return Self {
                layers: vec![vec![[0u8; 32]]],
                leaves,
                leaf_hashes: vec![],
            };
        }
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(proxy_leaf_hash).collect();
        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.clone()];
        while layers.last().expect("non-empty").len() > 1 {
            let prev = layers.last().expect("non-empty");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(hash_pair(&prev[i], &prev[i + 1]));
                } else {
                    // OpenZeppelin odd-node carry: promoted unpaired, NOT
                    // doubled with itself.
                    next.push(prev[i]);
                }
                i += 2;
            }
            layers.push(next);
        }
        Self {
            layers,
            leaves,
            leaf_hashes,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.root()))
    }

    /// Sibling hashes bottom-up for the leaf at `index`.
    pub fn proof(&self, index: usize) -> Result<Vec<[u8; 32]>, String> {
        if index >= self.leaf_hashes.len() {
            return Err(format!("index {index} out of range"));
        }
        let mut idx = index;
        let mut proof = Vec::new();
        for lvl in 0..self.layers.len().saturating_sub(1) {
            let layer = &self.layers[lvl];
            let sibling = idx ^ 1;
            if sibling < layer.len() {
                proof.push(layer[sibling]);
            }
            idx /= 2;
        }
        Ok(proof)
    }

    pub fn leaves(&self) -> &[ProxyLeaf] {
        &self.leaves
    }

    pub fn leaf_hashes(&self) -> &[[u8; 32]] {
        &self.leaf_hashes
    }
}

/// Verify a sorted-pair proof.
pub fn verify(leaf: [u8; 32], proof: &[[u8; 32]], root: [u8; 32]) -> bool {
    let mut h = leaf;
    for p in proof {
        h = hash_pair(&h, p);
    }
    h == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{leaf_hash as compute_leaf_hash, Leaf as ComputeLeaf};
    use crate::proposer::daily_epoch_id;

    fn addr(byte: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = byte;
        a
    }

    /// The sample epoch used by every pinned vector, and by the Solidity file.
    const SAMPLE_EPOCH: u64 = 8_000_000_020_664;

    /// The three id spaces this crate hands to a settlement contract must not
    /// overlap, or an epoch id decides which contract it belongs to by accident.
    ///
    /// Mutations this detects: `PROXY_EPOCH_BASE` lowered into the daily
    /// `YYYYMMDD` range or raised into the enrolment range; `is_proxy_epoch`
    /// losing either bound.
    #[test]
    fn three_epoch_id_spaces_are_pairwise_disjoint() {
        // Daily ids are literal YYYYMMDD, so the whole space is bounded above by
        // the largest eight-digit date.
        const MAX_DAILY_EPOCH: u64 = 99_991_231;
        // Bound through `let`, not through the constants directly: a comparison
        // of two consts folds at compile time and clippy refuses it as an
        // assertion that cannot fail. The values are still the real ones.
        let daily_ceiling: u64 = MAX_DAILY_EPOCH;
        let proxy_base: u64 = PROXY_EPOCH_BASE;
        let enrollment_base: u64 = ENROLLMENT_EPOCH_BASE;
        assert!(daily_ceiling < proxy_base);
        assert!(proxy_base < enrollment_base);

        // The fetch-network space is hourly. A century of hours must still fit
        // below the enrolment base.
        assert!(proxy_base + 100 * 365 * 24 < enrollment_base);
        assert_eq!(enrollment_base, 9_000_000_000_000);
        assert_eq!(proxy_base, 8_000_000_000_000);

        // Positive control first: the predicate must accept something, or an
        // always-false predicate would satisfy every rejection below.
        assert!(is_proxy_epoch(PROXY_EPOCH_BASE));
        assert!(is_proxy_epoch(SAMPLE_EPOCH));
        assert!(is_proxy_epoch(ENROLLMENT_EPOCH_BASE - 1));

        assert!(!is_proxy_epoch(MAX_DAILY_EPOCH));
        assert!(!is_proxy_epoch(daily_epoch_id(1_800_000_000)));
        assert!(!is_proxy_epoch(PROXY_EPOCH_BASE - 1));
        assert!(!is_proxy_epoch(ENROLLMENT_EPOCH_BASE));
    }

    /// INV-16, the Rust half. A fetch-network leaf and a compute leaf built from
    /// the same numeric inputs must not be the same 32 bytes, or a bandwidth
    /// proof settles through the SUPPLY-ISSUING contract.
    ///
    /// Mutations this detects: the domain word dropped from
    /// `abi_encode_proxy_leaf`; the fetch leaf reduced to `(operator, amount)`;
    /// the double hash reduced to one on either side.
    #[test]
    fn proxy_leaf_can_never_collide_with_an_epoch_settlement_leaf() {
        let operator = addr(0xA1);
        let amount: u128 = 250_000_000_000_000_000;

        let compute = compute_leaf_hash(&ComputeLeaf {
            wallet: operator,
            cumulative_score: amount,
        });

        // Positive control: the compute encoder is live and produces a real hash
        // for these inputs. Comparing against a stuck zero would pass trivially.
        assert_ne!(compute, [0u8; 32]);

        for (epoch_id, total_bytes) in [
            (SAMPLE_EPOCH, GIB_BYTES),
            (SAMPLE_EPOCH, 0u128),
            (PROXY_EPOCH_BASE, amount),
        ] {
            let proxy = proxy_leaf_hash(&ProxyLeaf {
                operator,
                epoch_id,
                total_bytes,
                payout_goat_wei: amount,
            });
            assert_ne!(proxy, [0u8; 32]);
            assert_ne!(
                proxy, compute,
                "fetch leaf collides with a compute leaf at epoch {epoch_id}"
            );
        }

        // And the preimages differ in length, not only in content: 160 bytes
        // against 64.
        assert_eq!(
            abi_encode_proxy_leaf(&ProxyLeaf {
                operator,
                epoch_id: SAMPLE_EPOCH,
                total_bytes: GIB_BYTES,
                payout_goat_wei: amount,
            })
            .len(),
            160
        );
    }

    /// The OpenZeppelin convention, on the smallest tree that exercises it.
    ///
    /// Mutations this detects: an odd node doubled with itself instead of
    /// carried up, which produces a root no `MerkleProof.verify` will accept.
    #[test]
    fn odd_cardinality_carries_the_last_node_up_unpaired() {
        let leaves: Vec<ProxyLeaf> = (1u8..=3)
            .map(|i| ProxyLeaf {
                operator: addr(i),
                epoch_id: SAMPLE_EPOCH,
                total_bytes: u128::from(i) * GIB_BYTES,
                payout_goat_wei: u128::from(i) * 1_000_000,
            })
            .collect();
        let tree = ProxyMerkleTree::build(leaves.clone());

        let h: Vec<[u8; 32]> = leaves.iter().map(proxy_leaf_hash).collect();
        // Layer 1 is [pair(h0,h1), h2] -- the third hash promoted verbatim.
        let expected_root = hash_pair(&hash_pair(&h[0], &h[1]), &h[2]);
        assert_eq!(tree.root(), expected_root);
        assert_ne!(
            tree.root(),
            hash_pair(&hash_pair(&h[0], &h[1]), &hash_pair(&h[2], &h[2]))
        );

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).expect("in range");
            assert!(
                verify(proxy_leaf_hash(leaf), &proof, tree.root()),
                "proof failed for leaf {i}"
            );
        }
        // The proof for the carried node is one level shorter.
        assert_eq!(tree.proof(2).expect("in range").len(), 1);
        assert_eq!(tree.proof(0).expect("in range").len(), 2);
        assert!(tree.proof(3).is_err());
    }

    /// Metering arithmetic is floor-exact and multiplies before dividing.
    ///
    /// Mutations this detects: dividing before multiplying (one byte pays zero);
    /// rounding up (the pool pays out more than it holds, one wei at a time,
    /// once per operator per epoch).
    #[test]
    fn aggregation_is_floor_exact_and_multiplies_before_dividing() {
        const GIB: u128 = 1_073_741_824;
        const RATE_WEI_PER_GIB: u128 = 250_000_000_000_000_000; // 0.25 GOAT / GiB
        assert_eq!(GIB, GIB_BYTES);

        // 1 GiB pays exactly the rate; 1 byte pays floor(rate / 2^30) and NOT one more.
        assert_eq!(gross_for_bytes(GIB, RATE_WEI_PER_GIB), RATE_WEI_PER_GIB);
        assert_eq!(gross_for_bytes(1, RATE_WEI_PER_GIB), 232_830_643);
        assert_ne!(
            gross_for_bytes(1, RATE_WEI_PER_GIB),
            232_830_644,
            "must floor, never ceil"
        );

        assert_eq!(gross_for_bytes(0, RATE_WEI_PER_GIB), 0);
        assert_eq!(
            gross_for_bytes(4 * GIB, RATE_WEI_PER_GIB),
            4 * RATE_WEI_PER_GIB
        );
        // Sub-gibibyte input survives: this is the assertion that dies if the
        // division moves ahead of the multiplication.
        assert!(gross_for_bytes(GIB - 1, RATE_WEI_PER_GIB) > 0);
    }

    /// Byte-identical constants shared with
    /// `contracts/test/ProxyRevenueMerkleParity.t.sol`. Regenerate with
    /// `cargo test --lib proxy::proxy_merkle::tests::pinned_proxy_solidity_cross_check_vectors -- --nocapture`
    /// and copy the printed values into BOTH files.
    ///
    /// Mutations this detects: any change to word order, word width, padding
    /// side, the domain string, or the number of hash rounds -- on either side
    /// of the language boundary.
    #[test]
    fn pinned_proxy_solidity_cross_check_vectors() {
        assert_eq!(
            hex::encode(proxy_leaf_domain()),
            "dd2589f55eb2ee3c3dd13e47736b7f4acdda56b1e6e7bbb2e9cadcf7ab812d15",
            "PROXY_LEAF_DOMAIN"
        );

        let vectors = [
            (addr(0xA1), 1_073_741_824u128, 250_000_000_000_000_000u128),
            (addr(0xB2), 1u128, 232_830_643u128),
            (addr(0xA1), 4_294_967_296u128, 1_000_000_000_000_000_000u128),
        ];
        let leaves: Vec<ProxyLeaf> = vectors
            .iter()
            .map(|&(operator, total_bytes, payout_goat_wei)| ProxyLeaf {
                operator,
                epoch_id: SAMPLE_EPOCH,
                total_bytes,
                payout_goat_wei,
            })
            .collect();

        for (label, leaf) in ["A", "B", "C"].iter().zip(leaves.iter()) {
            println!("LEAF_{label} = 0x{}", hex::encode(proxy_leaf_hash(leaf)));
        }
        let two = ProxyMerkleTree::build(vec![leaves[0].clone(), leaves[1].clone()]);
        println!("TWO_LEAF_ROOT = {}", two.root_hex());

        assert_eq!(
            hex::encode(proxy_leaf_hash(&leaves[0])),
            "231e1232b6f86534b6c979a68e95c2d22dadfe390c6129ea50d3ae5de1b4f4cd",
            "leaf A"
        );
        assert_eq!(
            hex::encode(proxy_leaf_hash(&leaves[1])),
            "8dc20ea0c0ab4e2a08cfa61064e44ec8045f320589659b3ee3cc8e331f439508",
            "leaf B"
        );
        assert_eq!(
            hex::encode(proxy_leaf_hash(&leaves[2])),
            "b488ac365921e6abce7f8ee2a6258769fe4ed9c5fbcbc02b6d60ce9262930e62",
            "leaf C"
        );
        assert_eq!(
            two.root_hex(),
            "0xad9982dfabd1dd84bd95d9dc80b6771027daf545c621611fcb01854455ac2d44",
            "two-leaf root"
        );

        // The tree's own proof must verify against its own root, or the pinned
        // root above is a number with no structure behind it.
        let p0 = two.proof(0).expect("in range");
        assert!(verify(proxy_leaf_hash(&leaves[0]), &p0, two.root()));
        assert_eq!(hex::encode(p0[0]), hex::encode(proxy_leaf_hash(&leaves[1])));
    }

    /// The domain word is inside the preimage, not beside it.
    ///
    /// Mutations this detects: the domain word written into a word the hash does
    /// not cover, or `abi_encode_proxy_leaf` overwriting word 0 with the address.
    #[test]
    fn test_proxy_leaf_domain_word_is_present_in_the_preimage() {
        let leaf = ProxyLeaf {
            operator: addr(0xA1),
            epoch_id: SAMPLE_EPOCH,
            total_bytes: GIB_BYTES,
            payout_goat_wei: 250_000_000_000_000_000,
        };
        let real = proxy_leaf_hash(&leaf);

        let encoded = abi_encode_proxy_leaf(&leaf);
        assert_eq!(&encoded[0..32], &proxy_leaf_domain()[..]);

        // Flip one bit of the domain word and re-hash by hand.
        let mut tampered = encoded;
        tampered[7] ^= 0x01;
        let tampered_hash = keccak256(&keccak256(&tampered));
        assert_ne!(
            real, tampered_hash,
            "one flipped domain byte left the leaf unchanged"
        );

        // The domain string itself, not only its digest.
        assert_eq!(PROXY_LEAF_DOMAIN_STR, "GOAT_PROXY_REVENUE_LEAF_V1");
        assert_ne!(
            proxy_leaf_domain(),
            keccak256(b"GOAT_PROXY_REVENUE_LEAF_V2")
        );
    }

    /// Every field of the leaf must move the hash, or the field is decorative
    /// and two different batches share a proof.
    ///
    /// Mutations this detects: a field dropped from the encoding; two fields
    /// written into the same word; the epoch id truncated out of the preimage.
    #[test]
    fn test_proxy_leaf_every_field_changes_the_hash() {
        let base = ProxyLeaf {
            operator: addr(0xA1),
            epoch_id: SAMPLE_EPOCH,
            total_bytes: GIB_BYTES,
            payout_goat_wei: 250_000_000_000_000_000,
        };
        let h = proxy_leaf_hash(&base);
        assert_eq!(h, proxy_leaf_hash(&base.clone()), "not deterministic");

        let variants = [
            ProxyLeaf {
                operator: addr(0xA2),
                ..base.clone()
            },
            ProxyLeaf {
                epoch_id: SAMPLE_EPOCH + 1,
                ..base.clone()
            },
            ProxyLeaf {
                total_bytes: GIB_BYTES + 1,
                ..base.clone()
            },
            ProxyLeaf {
                payout_goat_wei: base.payout_goat_wei + 1,
                ..base.clone()
            },
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(proxy_leaf_hash(v), h, "field {i} does not reach the hash");
        }
    }

    /// The ABI layout, asserted on offsets rather than on a digest, so a failure
    /// says which word moved.
    ///
    /// Mutations this detects: an address right-padded instead of left-padded;
    /// a `uint256` written little-endian.
    #[test]
    fn test_abi_encode_proxy_leaf_word_offsets() {
        let leaf = ProxyLeaf {
            operator: addr(0xA1),
            epoch_id: SAMPLE_EPOCH,
            total_bytes: 1,
            payout_goat_wei: 2,
        };
        let enc = abi_encode_proxy_leaf(&leaf);
        assert_eq!(enc.len(), 160);
        assert_eq!(&enc[32..44], &[0u8; 12], "address must be left-padded");
        assert_eq!(&enc[44..64], &leaf.operator);
        assert_eq!(&enc[64..88], &[0u8; 24]);
        assert_eq!(&enc[88..96], &SAMPLE_EPOCH.to_be_bytes());
        assert_eq!(enc[127], 1, "totalBytes is big-endian in word 3");
        assert_eq!(enc[159], 2, "payoutGoatWei is big-endian in word 4");
        assert_eq!(&enc[96..127], &[0u8; 31]);
        assert_eq!(&enc[128..159], &[0u8; 31]);
    }

    /// An empty tree has a zero root and no proofs, rather than panicking.
    ///
    /// Mutations this detects: `build` indexing an empty layer.
    #[test]
    fn test_empty_tree_has_a_zero_root_and_no_proof() {
        let tree = ProxyMerkleTree::build(vec![]);
        assert_eq!(tree.root(), [0u8; 32]);
        assert!(tree.proof(0).is_err());
        assert!(tree.leaves().is_empty());
        assert!(tree.leaf_hashes().is_empty());

        // Positive control: the same builder does produce a non-zero root.
        let one = ProxyMerkleTree::build(vec![ProxyLeaf {
            operator: addr(1),
            epoch_id: SAMPLE_EPOCH,
            total_bytes: 1,
            payout_goat_wei: 1,
        }]);
        assert_ne!(one.root(), [0u8; 32]);
        assert_eq!(one.proof(0).expect("in range").len(), 0);
    }
}
