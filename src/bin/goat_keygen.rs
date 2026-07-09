//! GoatCoin ML-DSA-65 key material helper (Track C + identity-hardening).
//!
//! ## Modes
//!
//! ### Deterministic testnet (forgeable — lab only)
//! ```text
//! cargo run --bin goat-keygen
//! cargo run --bin goat-keygen -- --testnet
//! ```
//! Prints seeds `testnet_signing_seed(0..4)` and matching public keys. **Anyone with the repo
//! can reconstruct these secrets.** Use only for loopback / `GOATD_ALLOW_TESTNET_SEEDS=1` labs.
//!
//! ### Random per-node secrets (Alpha / off-host)
//! ```text
//! cargo run --bin goat-keygen -- --random --count 5 --out-dir keys/
//! ```
//! Writes `keys/node-N/signing_seed` (64 hex) and prints a `genesis_orchestrators` JSON fragment
//! with matching 1952-byte public keys. Export each seed as `GOATD_SIGNING_SEED`. **Never commit
//! seed files.**

use std::env;
use std::fs;
use std::path::PathBuf;

use ml_dsa::{Keypair as _, MlDsa65, SigningKey, VerifyingKey, B32};

fn testnet_signing_seed(node_index: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x60;
    s[1] = 0xA7;
    s[2] = 0x7E;
    s[3] = 0x57;
    s[4] = node_index;
    s[31] = 0xC1;
    s
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let random = args.iter().any(|a| a == "--random");
    let count = arg_value(&args, "--count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5u8)
        .max(1);
    let out_dir = arg_value(&args, "--out-dir").map(PathBuf::from);

    if random {
        emit_random(count, out_dir.as_deref());
    } else {
        eprintln!(
            "goat-keygen: DETERMINISTIC testnet seeds (FORGEABLE). Lab only — identity-hardening / ALPHA_PILOT."
        );
        for i in 0u8..count.min(5) {
            let seed = testnet_signing_seed(i);
            let pk_hex = pk_hex_from_seed(&seed);
            println!("node-{i} seed={}", hex(&seed));
            println!("node-{i} pk={pk_hex}");
            println!();
        }
    }
}

fn emit_random(count: u8, out_dir: Option<&std::path::Path>) {
    eprintln!(
        "goat-keygen: generating {count} RANDOM ML-DSA-65 seeds (secret). Do not commit seed files."
    );
    if let Some(dir) = out_dir {
        fs::create_dir_all(dir).expect("create out-dir");
    }

    println!("  \"genesis_orchestrators\": [");
    for i in 0..count {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS RNG for signing seed");
        let pk_hex = pk_hex_from_seed(&seed);
        let seed_hex = hex(&seed);

        if let Some(dir) = out_dir {
            let node_dir = dir.join(format!("node-{i}"));
            fs::create_dir_all(&node_dir).expect("node dir");
            let seed_path = node_dir.join("signing_seed");
            fs::write(&seed_path, format!("{seed_hex}\n")).expect("write seed");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600));
            }
            eprintln!("  wrote {}", seed_path.display());
        } else {
            eprintln!("node-{i} seed={seed_hex}  # SECRET — store offline; set GOATD_SIGNING_SEED");
        }

        // Legacy-style node_id: i repeated as hex nibble pattern (matches existing testnet genesis).
        let nibble = format!("{i:x}");
        let node_id: String = nibble.chars().cycle().take(64).collect();
        let comma = if i + 1 < count { "," } else { "" };
        println!("    {{");
        println!("      \"node_id\": \"{node_id}\",");
        println!("      \"ml_dsa_65_public_key\": \"{pk_hex}\",");
        println!("      \"role\": \"genesis-orchestrator\"");
        println!("    }}{comma}");
    }
    println!("  ]");
}

fn pk_hex_from_seed(seed: &[u8; 32]) -> String {
    let seed_arr = B32::try_from(&seed[..]).expect("32 bytes");
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let vk: VerifyingKey<MlDsa65> = sk.verifying_key();
    hex(vk.encode().as_slice())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().map(String::as_str);
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v);
        }
    }
    None
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
