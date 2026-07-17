//! Ethereum Merkle tree matching EpochSettlement / OpenZeppelin MerkleProof.
//!
//! leaf = keccak256(bytes.concat(keccak256(abi.encode(worker, provenCumulativeScore))))
//! pairing = sorted (commutative) keccak256(a || b); odd node carried up unpaired.

use tiny_keccak::{Hasher, Keccak};

/// 32-byte Keccak-256.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// ABI-encode `address` (12 zero bytes + 20) + `uint256` (32 BE).
pub fn abi_encode_address_uint256(address: &[u8; 20], score: u128) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(address);
    // uint256 big-endian in second 32-byte word; we only use low 128 bits.
    let be = score.to_be_bytes();
    buf[48..64].copy_from_slice(&be);
    buf
}

/// Parse a 0x-prefixed or bare 40-hex address into 20 bytes.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.len() != 40 {
        return Err(format!("address must be 20 bytes (40 hex), got len {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub wallet: [u8; 20],
    pub cumulative_score: u128,
}

impl Leaf {
    pub fn from_hex(wallet_hex: &str, cumulative_score: u128) -> Result<Self, String> {
        Ok(Self {
            wallet: parse_address(wallet_hex)?,
            cumulative_score,
        })
    }
}

/// Double-hashed leaf matching `EpochSettlement.claimPayout`.
pub fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    let encoded = abi_encode_address_uint256(&leaf.wallet, leaf.cumulative_score);
    let inner = keccak256(&encoded);
    keccak256(&inner)
}

/// Sorted-pair hash (OpenZeppelin commutative MerkleProof).
pub fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
    } else {
        buf[..32].copy_from_slice(b);
        buf[32..].copy_from_slice(a);
    }
    keccak256(&buf)
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Layer 0 = leaves (hashed), last layer = [root]
    layers: Vec<Vec<[u8; 32]>>,
    /// Original leaves in insertion order (for proof lookup by wallet).
    leaves: Vec<Leaf>,
    leaf_hashes: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn build(leaves: Vec<Leaf>) -> Self {
        if leaves.is_empty() {
            return Self {
                layers: vec![vec![[0u8; 32]]],
                leaves,
                leaf_hashes: vec![],
            };
        }
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
        let mut layers: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.clone()];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(hash_pair(&prev[i], &prev[i + 1]));
                } else {
                    // OZ odd-node carry
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

    /// Merkle proof for the leaf at `index` (sibling hashes bottom-up).
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

    /// Proof for a wallet address (first matching leaf).
    pub fn proof_for_wallet(&self, wallet: &[u8; 20]) -> Result<Vec<[u8; 32]>, String> {
        let idx = self
            .leaves
            .iter()
            .position(|l| &l.wallet == wallet)
            .ok_or_else(|| format!("wallet not in tree: 0x{}", hex::encode(wallet)))?;
        self.proof(idx)
    }

    pub fn leaves(&self) -> &[Leaf] {
        &self.leaves
    }
}

/// Verify a Merkle proof (OZ sorted-pair).
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

    fn addr(byte: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = byte;
        a
    }

    #[test]
    fn leaf_hash_deterministic() {
        let leaf = Leaf {
            wallet: addr(0xA1),
            cumulative_score: 2_400_000,
        };
        let h1 = leaf_hash(&leaf);
        let h2 = leaf_hash(&leaf);
        assert_eq!(h1, h2);
        // Not all zeros
        assert_ne!(h1, [0u8; 32]);
    }

    /// Pinned vectors shared with `contracts/test/RustDaemonMerkleParity.t.sol`.
    /// Do not change without regenerating the forge test constants.
    #[test]
    fn pinned_solidity_cross_check_vectors() {
        let a = addr(0xA1);
        let b = addr(0xB2);

        let enc = abi_encode_address_uint256(&a, 2_400_000);
        assert_eq!(
            hex::encode(enc),
            "00000000000000000000000000000000000000000000000000000000000000a1\
             0000000000000000000000000000000000000000000000000000000000249f00"
        );

        let la = leaf_hash(&Leaf {
            wallet: a,
            cumulative_score: 2_400_000,
        });
        let lb = leaf_hash(&Leaf {
            wallet: b,
            cumulative_score: 600_000,
        });
        assert_eq!(
            hex::encode(la),
            "735d83c0039ed03f4cca68b065b6e55d6c07c6ac7eb5ad442617b505ea9a90ad"
        );
        assert_eq!(
            hex::encode(lb),
            "78dafc39810f27c2d406a8f9fd8f9b72d732a084e94ccbbcec98f55dca76c584"
        );

        let tree = MerkleTree::build(vec![
            Leaf {
                wallet: a,
                cumulative_score: 2_400_000,
            },
            Leaf {
                wallet: b,
                cumulative_score: 600_000,
            },
        ]);
        assert_eq!(
            hex::encode(tree.root()),
            "2e0d8025677441483e6272a58d9330425259dd82b8dea14744ca3e1517f2c269"
        );
        let proof0 = tree.proof(0).unwrap();
        assert_eq!(proof0.len(), 1);
        assert_eq!(
            hex::encode(proof0[0]),
            "78dafc39810f27c2d406a8f9fd8f9b72d732a084e94ccbbcec98f55dca76c584"
        );

        // Single-leaf claim vector (root == leaf) used by forge claimPayout e2e.
        let leaf_100k = leaf_hash(&Leaf {
            wallet: a,
            cumulative_score: 100_000,
        });
        assert_eq!(
            hex::encode(leaf_100k),
            "f57f8dacf75442d4a5bf6d6e25e75e5fa87abc1a7b255f00b4456e922bdcb413"
        );
    }

    #[test]
    fn two_leaf_root_and_proof_roundtrip() {
        let leaves = vec![
            Leaf {
                wallet: addr(0xA1),
                cumulative_score: 2_400_000,
            },
            Leaf {
                wallet: addr(0xB2),
                cumulative_score: 600_000,
            },
        ];
        let tree = MerkleTree::build(leaves.clone());
        let root = tree.root();

        let la = leaf_hash(&leaves[0]);
        let lb = leaf_hash(&leaves[1]);
        let expected = hash_pair(&la, &lb);
        assert_eq!(root, expected);

        let proof = tree.proof(0).unwrap();
        assert!(verify(la, &proof, root));
        let proof1 = tree.proof(1).unwrap();
        assert!(verify(lb, &proof1, root));
    }

    #[test]
    fn odd_node_carry_three_leaves() {
        let leaves = vec![
            Leaf {
                wallet: addr(1),
                cumulative_score: 10,
            },
            Leaf {
                wallet: addr(2),
                cumulative_score: 20,
            },
            Leaf {
                wallet: addr(3),
                cumulative_score: 30,
            },
        ];
        let tree = MerkleTree::build(leaves.clone());
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                verify(leaf_hash(leaf), &proof, tree.root()),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn abi_encode_layout() {
        let mut wallet = [0u8; 20];
        wallet[19] = 0xA1;
        let enc = abi_encode_address_uint256(&wallet, 100);
        assert_eq!(&enc[0..12], &[0u8; 12]);
        assert_eq!(&enc[12..32], &wallet);
        assert_eq!(&enc[32..64], &{
            let mut w = [0u8; 32];
            w[31] = 100;
            w
        });
    }
}
