//! Regenerates pinned Merkle hex for `contracts/test/RustDaemonMerkleParity.t.sol`.
//! Run: `cargo test --test print_vectors -- --nocapture`

use goat_attestor::merkle::{Leaf, MerkleTree, abi_encode_address_uint256, leaf_hash};

#[test]
fn print_pinned_vectors() {
    let mut a = [0u8; 20];
    a[19] = 0xA1;
    let mut b = [0u8; 20];
    b[19] = 0xB2;
    println!(
        "enc={}",
        hex::encode(abi_encode_address_uint256(&a, 2_400_000))
    );
    println!(
        "leaf_a=0x{}",
        hex::encode(leaf_hash(&Leaf {
            wallet: a,
            cumulative_score: 2_400_000
        }))
    );
    println!(
        "leaf_b=0x{}",
        hex::encode(leaf_hash(&Leaf {
            wallet: b,
            cumulative_score: 600_000
        }))
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
    println!("root=0x{}", hex::encode(tree.root()));
    for (i, p) in tree.proof(0).unwrap().iter().enumerate() {
        println!("p0_{}=0x{}", i, hex::encode(p));
    }
    let leaf100 = leaf_hash(&Leaf {
        wallet: a,
        cumulative_score: 100_000,
    });
    println!("leaf_100k=0x{}", hex::encode(leaf100));
}
