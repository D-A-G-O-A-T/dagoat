//! Password-protected multi-wallet with **Rust-side** Ethereum signing.
//!
//! Design: `docs/superpowers/specs/2026-07-13-stronghold-wallet-design.md`.
//!
//! ## The one invariant
//! The secp256k1 private key **NEVER** crosses the IPC bridge into JS. It exists
//! only as (a) an encrypted-at-rest record inside a Stronghold snapshot on disk
//! and (b) a transient, zeroized buffer inside a `PrivateKeySigner` in *this*
//! process while an unlock/sign is in flight. Every command returns only
//! addresses and signatures.
//!
//! ## At-rest protection (spec §4 / §9)
//! Keys live in **genuine Stronghold snapshots** — one snapshot per wallet. Each
//! snapshot is encrypted (XChaCha20-Poly1305 internally) under a snapshot key
//! that is **Argon2id(password, per-wallet salt)** (memory-hard, 19 MiB / t=2 /
//! p=1). The private key is stored as a record in that snapshot's Stronghold
//! client store; on unlock the snapshot is opened with the derived key, the key
//! bytes are read into an `alloy` `PrivateKeySigner` in Rust memory, and the
//! transient buffers are zeroized. A **non-secret** name→address index (plain
//! JSON — it holds no secrets, only the address, the Argon2 salt, and the
//! snapshot filename) backs `wallet_list`.
//!
//! One snapshot per wallet is why each wallet is gated by its *own* password
//! (a single shared snapshot would have only one snapshot password).
//!
//! Wrong password ⇒ the Argon2id-derived key can't decrypt the snapshot ⇒ a
//! clean, non-leaky error; no partial state is committed.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::dyn_abi::TypedData;
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;

use argon2::{Algorithm, Argon2, Params, Version};
use iota_stronghold::{KeyProvider, SnapshotPath, Stronghold};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

const WALLET_INDEX_FILE: &str = "wallets.index.json";
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32; // secp256k1 private key / derived snapshot key

/// Stronghold client path (one client per snapshot) and the store record key
/// under which the 32-byte secp256k1 private key is kept.
const CLIENT_PATH: &[u8] = b"dagoat-wallet";
const STORE_KEY: &[u8] = b"secp256k1-private-key";

const MIN_PASSWORD_LEN: usize = 8;

// Argon2id parameters (OWASP-recommended memory-hard profile).
const ARGON2_M_COST: u32 = 19_456; // KiB (19 MiB)
const ARGON2_T_COST: u32 = 2; // iterations
const ARGON2_P_COST: u32 = 1; // lanes

/// Non-secret wallet identity returned across the IPC bridge. `{ name, address }`.
#[derive(Serialize, Deserialize, Clone)]
pub struct WalletMeta {
    pub name: String,
    /// EIP-55 checksummed `0x…` address.
    pub address: String,
}

/// One **non-secret** index entry. It names where the wallet's Stronghold
/// snapshot lives and how to derive that snapshot's key from the password — but
/// holds no key material. The private key itself lives only inside the encrypted
/// snapshot file named here.
#[derive(Serialize, Deserialize, Clone)]
struct WalletEntry {
    /// EIP-55 address — the non-secret index used by `wallet_list`.
    address: String,
    /// Argon2id salt (hex) for deriving this wallet's snapshot key.
    salt: String,
    /// Filename of this wallet's Stronghold snapshot (under the app data dir).
    snapshot: String,
}

#[derive(Serialize, Deserialize, Default)]
struct WalletIndex {
    version: u32,
    wallets: BTreeMap<String, WalletEntry>,
}

/// In-memory session state. Signers exist ONLY between `wallet_unlock` and
/// `wallet_lock`; on lock the map is cleared and the `k256` keys zeroize on drop.
#[derive(Default)]
pub struct WalletState {
    sessions: Mutex<HashMap<String, PrivateKeySigner>>,
    active: Mutex<Option<WalletMeta>>,
}

// ---------------------------------------------------------------------------
// Non-secret index file I/O (holds addresses + salts + snapshot filenames only).
// ---------------------------------------------------------------------------

fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "could not resolve app data dir".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|_| "could not create app data dir".to_string())?;
    Ok(dir)
}

fn index_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(WALLET_INDEX_FILE))
}

fn load_index(app: &tauri::AppHandle) -> Result<WalletIndex, String> {
    let path = index_path(app)?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "wallet index is corrupt".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WalletIndex {
            version: 1,
            wallets: BTreeMap::new(),
        }),
        Err(_) => Err("could not read wallet index".to_string()),
    }
}

fn save_index(app: &tauri::AppHandle, index: &WalletIndex) -> Result<(), String> {
    let path = index_path(app)?;
    let bytes = serde_json::to_vec_pretty(index).map_err(|_| "could not serialize wallet index".to_string())?;
    std::fs::write(&path, bytes).map_err(|_| "could not write wallet index".to_string())
}

// ---------------------------------------------------------------------------
// Crypto helpers. Every plaintext key buffer is zeroized before it drops.
// ---------------------------------------------------------------------------

/// Reject empty / too-short passwords at the Rust trust boundary (the command is
/// the real gate — a JS check can be bypassed).
fn check_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

/// Argon2id(password, salt) → 32-byte snapshot key. Never substitutes a null key:
/// on any KDF error it propagates the error (see spec §5 / finding 5). Caller
/// must zeroize the result.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|_| "kdf parameter error".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| "key derivation failed".to_string())?;
    Ok(out)
}

/// Write `key_bytes` (the 32-byte secp256k1 private key) into a **new** Stronghold
/// snapshot at `path`, encrypted under `snapshot_key`. AppHandle-free so it is
/// unit-testable. The caller still owns / must zeroize `key_bytes`.
fn store_key_in_snapshot(path: &Path, snapshot_key: &[u8; KEY_LEN], key_bytes: &[u8]) -> Result<(), String> {
    let stronghold = Stronghold::default();
    let keyprovider = KeyProvider::try_from(Zeroizing::new(snapshot_key.to_vec()))
        .map_err(|_| "could not initialize vault key".to_string())?;

    let client = stronghold
        .create_client(CLIENT_PATH)
        .map_err(|_| "could not create vault client".to_string())?;
    client
        .store()
        .insert(STORE_KEY.to_vec(), key_bytes.to_vec(), None)
        .map_err(|_| "could not store key in vault".to_string())?;

    stronghold
        .commit_with_keyprovider(&SnapshotPath::from_path(path), &keyprovider)
        .map_err(|_| "could not write vault snapshot".to_string())?;
    Ok(())
}

/// Open the Stronghold snapshot at `path` with `snapshot_key` and read the stored
/// private key. Wrong key (wrong password) ⇒ non-leaky error. AppHandle-free so
/// it is unit-testable. Caller must zeroize the returned bytes.
fn read_key_from_snapshot(path: &Path, snapshot_key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    let stronghold = Stronghold::default();
    let keyprovider = KeyProvider::try_from(Zeroizing::new(snapshot_key.to_vec()))
        .map_err(|_| "could not initialize vault key".to_string())?;

    let snapshot = SnapshotPath::from_path(path);
    // Wrong password ⇒ the derived key can't decrypt the snapshot.
    stronghold
        .load_snapshot(&keyprovider, &snapshot)
        .map_err(|_| "wrong password".to_string())?;
    let client = stronghold
        .load_client(CLIENT_PATH)
        .map_err(|_| "wrong password".to_string())?;

    let value = client
        .store()
        .get(STORE_KEY)
        .map_err(|_| "vault snapshot is corrupt".to_string())?
        .ok_or_else(|| "vault snapshot is corrupt".to_string())?;

    if value.len() != KEY_LEN {
        let mut v = value;
        v.zeroize();
        return Err("vault snapshot is corrupt".to_string());
    }
    Ok(value)
}

/// Build a signer from raw key bytes, then zeroize the caller's buffer copy.
/// The signer owns a `k256::SigningKey` that zeroizes on drop.
fn signer_from_bytes(key_bytes: &mut Vec<u8>) -> Result<PrivateKeySigner, String> {
    let signer = PrivateKeySigner::from_slice(key_bytes).map_err(|_| "invalid private key".to_string());
    key_bytes.zeroize();
    signer
}

fn meta_from_signer(name: &str, signer: &PrivateKeySigner) -> WalletMeta {
    WalletMeta {
        name: name.to_string(),
        address: signer.address().to_checksum(None),
    }
}

/// Fresh random snapshot filename (hex id). Non-secret; it just names a file.
fn new_snapshot_name() -> String {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    format!("wallet-{}.stronghold", hex::encode(id))
}

// ---------------------------------------------------------------------------
// viem transaction JSON → alloy TxEip1559
// ---------------------------------------------------------------------------

/// Flexible numeric parse: accepts JSON number, decimal string, or `0x…` hex
/// string (viem serializes BigInts as strings). Missing/null ⇒ 0.
fn parse_u256(v: Option<&Value>) -> Result<U256, String> {
    match v {
        None | Some(Value::Null) => Ok(U256::ZERO),
        Some(Value::Number(n)) => {
            if let Some(u) = n.as_u64() {
                Ok(U256::from(u))
            } else {
                U256::from_str_radix(&n.to_string(), 10).map_err(|_| "invalid number".to_string())
            }
        }
        Some(Value::String(s)) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                if hex.is_empty() {
                    return Ok(U256::ZERO);
                }
                U256::from_str_radix(hex, 16).map_err(|_| "invalid hex number".to_string())
            } else {
                U256::from_str_radix(s, 10).map_err(|_| "invalid number".to_string())
            }
        }
        _ => Err("invalid numeric field".to_string()),
    }
}

fn parse_u64(v: Option<&Value>) -> Result<u64, String> {
    u64::try_from(parse_u256(v)?).map_err(|_| "numeric field out of range".to_string())
}

fn parse_u128(v: Option<&Value>) -> Result<u128, String> {
    u128::try_from(parse_u256(v)?).map_err(|_| "numeric field out of range".to_string())
}

/// Look up a key in either camelCase or an alternate spelling.
fn field<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| obj.get(*k))
}

fn build_tx(tx_json: &str) -> Result<TxEip1559, String> {
    let root: Value = serde_json::from_str(tx_json).map_err(|_| "invalid transaction json".to_string())?;
    let obj = root.as_object().ok_or_else(|| "transaction json must be an object".to_string())?;

    let chain_id_v = field(obj, &["chainId", "chain_id"]);
    if chain_id_v.is_none() || matches!(chain_id_v, Some(Value::Null)) {
        return Err("transaction is missing chainId".to_string());
    }
    let chain_id = parse_u64(chain_id_v)?;

    let nonce = parse_u64(field(obj, &["nonce"]))?;
    let gas_limit = parse_u64(field(obj, &["gas", "gasLimit", "gas_limit"]))?;
    let max_fee_per_gas = parse_u128(field(obj, &["maxFeePerGas", "max_fee_per_gas"]))?;
    let max_priority_fee_per_gas =
        parse_u128(field(obj, &["maxPriorityFeePerGas", "max_priority_fee_per_gas"]))?;
    let value = parse_u256(field(obj, &["value"]))?;

    let to = match field(obj, &["to"]) {
        None | Some(Value::Null) => TxKind::Create,
        Some(Value::String(s)) if s.is_empty() => TxKind::Create,
        Some(Value::String(s)) => {
            TxKind::Call(Address::from_str(s.trim()).map_err(|_| "invalid `to` address".to_string())?)
        }
        _ => return Err("invalid `to` field".to_string()),
    };

    let input: Bytes = match field(obj, &["data", "input"]) {
        None | Some(Value::Null) => Bytes::new(),
        Some(Value::String(s)) => {
            let s = s.trim();
            let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            if s.is_empty() {
                Bytes::new()
            } else {
                Bytes::from(hex::decode(s).map_err(|_| "invalid `data` hex".to_string())?)
            }
        }
        _ => return Err("invalid `data` field".to_string()),
    };

    let access_list: AccessList = match field(obj, &["accessList", "access_list"]) {
        None | Some(Value::Null) => AccessList::default(),
        Some(v) => serde_json::from_value(v.clone()).map_err(|_| "invalid accessList".to_string())?,
    };

    Ok(TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to,
        value,
        access_list,
        input,
    })
}

/// Clone the active signer out from under the lock so we never hold a
/// `MutexGuard` across an `.await` (the guard is not `Send`).
fn active_signer(state: &WalletState) -> Result<PrivateKeySigner, String> {
    let active = state.active.lock().map_err(|_| "wallet state poisoned".to_string())?;
    let name = active
        .as_ref()
        .map(|m| m.name.clone())
        .ok_or_else(|| "no wallet is unlocked".to_string())?;
    let sessions = state.sessions.lock().map_err(|_| "wallet state poisoned".to_string())?;
    sessions
        .get(&name)
        .cloned()
        .ok_or_else(|| "no wallet is unlocked".to_string())
}

/// Guard against signing with the wrong wallet after a switch: the caller binds
/// an `expected_address`; if the currently-active signer isn't that address we
/// refuse (non-leaky) rather than sign with the wrong key/nonce. Compared
/// case-insensitively (EIP-55 checksum vs. lowercase both accepted).
fn ensure_expected(signer: &PrivateKeySigner, expected: &str) -> Result<(), String> {
    let actual = signer.address().to_checksum(None);
    if actual.eq_ignore_ascii_case(expected.trim()) {
        Ok(())
    } else {
        Err("active wallet does not match the requested address".to_string())
    }
}

/// Fetch the active signer and verify it matches the caller's bound address.
fn active_signer_checked(state: &WalletState, expected: &str) -> Result<PrivateKeySigner, String> {
    let signer = active_signer(state)?;
    ensure_expected(&signer, expected)?;
    Ok(signer)
}

// ---------------------------------------------------------------------------
// Tauri commands — the exact contract (all return non-leaky errors).
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn wallet_list(app: tauri::AppHandle) -> Result<Vec<WalletMeta>, String> {
    let index = load_index(&app)?;
    Ok(index
        .wallets
        .into_iter()
        .map(|(name, entry)| WalletMeta {
            name,
            address: entry.address,
        })
        .collect())
}

#[tauri::command]
pub async fn wallet_create(
    app: tauri::AppHandle,
    name: String,
    password: String,
) -> Result<WalletMeta, String> {
    if name.trim().is_empty() {
        return Err("wallet name cannot be empty".to_string());
    }
    check_password(&password)?;
    let mut index = load_index(&app)?;
    if index.wallets.contains_key(&name) {
        return Err("a wallet with that name already exists".to_string());
    }

    let signer = PrivateKeySigner::random();
    let address = signer.address().to_checksum(None);

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let mut snapshot_key = derive_key(&password, &salt)?;

    let snapshot = new_snapshot_name();
    let snapshot_path = app_data_dir(&app)?.join(&snapshot);

    let mut key_bytes = signer.to_bytes().to_vec();
    let sealed = store_key_in_snapshot(&snapshot_path, &snapshot_key, &key_bytes);
    key_bytes.zeroize();
    snapshot_key.zeroize();
    sealed?;

    index.wallets.insert(
        name.clone(),
        WalletEntry {
            address: address.clone(),
            salt: hex::encode(salt),
            snapshot,
        },
    );
    save_index(&app, &index)?;

    Ok(WalletMeta { name, address })
}

#[tauri::command]
pub async fn wallet_import(
    app: tauri::AppHandle,
    name: String,
    password: String,
    private_key_hex: String,
) -> Result<WalletMeta, String> {
    if name.trim().is_empty() {
        return Err("wallet name cannot be empty".to_string());
    }
    check_password(&password)?;
    let mut index = load_index(&app)?;
    if index.wallets.contains_key(&name) {
        return Err("a wallet with that name already exists".to_string());
    }

    let hex_str = private_key_hex.trim();
    let hex_str = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    let mut key_bytes = hex::decode(hex_str).map_err(|_| "private key is not valid hex".to_string())?;
    if key_bytes.len() != KEY_LEN {
        key_bytes.zeroize();
        return Err("private key must be 32 bytes".to_string());
    }

    // Validate the key produces a real signer; derive the address from it.
    let signer = PrivateKeySigner::from_slice(&key_bytes).map_err(|_| {
        key_bytes.zeroize();
        "invalid private key".to_string()
    })?;
    let address = signer.address().to_checksum(None);

    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let mut snapshot_key = derive_key(&password, &salt)?;

    let snapshot = new_snapshot_name();
    let snapshot_path = app_data_dir(&app)?.join(&snapshot);

    let sealed = store_key_in_snapshot(&snapshot_path, &snapshot_key, &key_bytes);
    key_bytes.zeroize();
    snapshot_key.zeroize();
    sealed?;

    index.wallets.insert(
        name.clone(),
        WalletEntry {
            address: address.clone(),
            salt: hex::encode(salt),
            snapshot,
        },
    );
    save_index(&app, &index)?;

    Ok(WalletMeta { name, address })
}

#[tauri::command]
pub async fn wallet_unlock(
    app: tauri::AppHandle,
    state: tauri::State<'_, WalletState>,
    name: String,
    password: String,
) -> Result<WalletMeta, String> {
    let index = load_index(&app)?;
    let entry = index
        .wallets
        .get(&name)
        .ok_or_else(|| "no such wallet".to_string())?
        .clone();

    let snapshot_path = app_data_dir(&app)?.join(&entry.snapshot);
    if !snapshot_path.is_file() {
        return Err("wallet vault file is missing — re-import this wallet".to_string());
    }

    // Argon2id + Stronghold decrypt are CPU-heavy and can panic on corrupt
    // snapshots. Run them on a blocking pool so the Tauri/async UI thread is
    // not starved, and catch_unwind so a vault bug becomes a string error
    // instead of killing the whole desktop process.
    let name_for_task = name.clone();
    let (meta, signer) = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_wallet_signer(&name_for_task, &password, &entry, &snapshot_path)
        }))
        .map_err(|_| {
            "wallet unlock failed (vault error). Wrong password, or re-import the key."
                .to_string()
        })?
    })
    .await
    .map_err(|_| "wallet unlock task failed".to_string())??;

    {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "wallet state poisoned".to_string())?;
        sessions.insert(name.clone(), signer);
    }
    {
        let mut active = state
            .active
            .lock()
            .map_err(|_| "wallet state poisoned".to_string())?;
        *active = Some(meta.clone());
    }
    Ok(meta)
}

/// Open a stored wallet: Argon2id(password) → decrypt Stronghold → PrivateKeySigner.
/// Synchronous; intended for `spawn_blocking` only.
fn open_wallet_signer(
    name: &str,
    password: &str,
    entry: &WalletEntry,
    snapshot_path: &Path,
) -> Result<(WalletMeta, PrivateKeySigner), String> {
    let salt = hex::decode(&entry.salt).map_err(|_| "wallet index is corrupt".to_string())?;
    if salt.len() != SALT_LEN {
        return Err("wallet index is corrupt".to_string());
    }
    let mut snapshot_key = derive_key(password, &salt)?;
    let opened = read_key_from_snapshot(snapshot_path, &snapshot_key);
    snapshot_key.zeroize();
    let mut key_bytes = opened?;
    let signer = signer_from_bytes(&mut key_bytes)?;
    let meta = meta_from_signer(name, &signer);
    // Defense: index address must match the key we just opened (detect corrupt index).
    if !meta.address.eq_ignore_ascii_case(&entry.address) {
        return Err("wallet vault does not match index — re-import this wallet".to_string());
    }
    Ok((meta, signer))
}

#[tauri::command]
pub async fn wallet_lock(state: tauri::State<'_, WalletState>) -> Result<(), String> {
    {
        let mut sessions = state.sessions.lock().map_err(|_| "wallet state poisoned".to_string())?;
        sessions.clear(); // signers drop here; k256 keys zeroize on drop
    }
    {
        let mut active = state.active.lock().map_err(|_| "wallet state poisoned".to_string())?;
        *active = None;
    }
    Ok(())
}

#[tauri::command]
pub async fn wallet_active(state: tauri::State<'_, WalletState>) -> Result<Option<WalletMeta>, String> {
    let active = state.active.lock().map_err(|_| "wallet state poisoned".to_string())?;
    Ok(active.clone())
}

#[tauri::command]
pub async fn wallet_remove(
    app: tauri::AppHandle,
    state: tauri::State<'_, WalletState>,
    name: String,
    password: String,
) -> Result<(), String> {
    let mut index = load_index(&app)?;
    let entry = index
        .wallets
        .get(&name)
        .ok_or_else(|| "no such wallet".to_string())?
        .clone();

    // Password-gate the removal: must be able to open the snapshot.
    let salt = hex::decode(&entry.salt).map_err(|_| "wallet index is corrupt".to_string())?;
    let mut snapshot_key = derive_key(&password, &salt)?;
    let snapshot_path = app_data_dir(&app)?.join(&entry.snapshot);
    let opened = read_key_from_snapshot(&snapshot_path, &snapshot_key);
    snapshot_key.zeroize();
    let mut key_bytes = opened?;
    key_bytes.zeroize();

    // Delete the snapshot file (best-effort) and the index entry.
    let _ = std::fs::remove_file(&snapshot_path);
    index.wallets.remove(&name);
    save_index(&app, &index)?;

    // Drop any live session / active pointer for this wallet.
    {
        let mut sessions = state.sessions.lock().map_err(|_| "wallet state poisoned".to_string())?;
        sessions.remove(&name);
    }
    {
        let mut active = state.active.lock().map_err(|_| "wallet state poisoned".to_string())?;
        if active.as_ref().map(|m| m.name.as_str()) == Some(name.as_str()) {
            *active = None;
        }
    }
    Ok(())
}

/// Sign an EIP-1559 tx with the active signer and return the **signed raw tx**
/// (`0x`-prefixed EIP-2718 type-0x02 bytes) for `eth_sendRawTransaction`.
///
/// `expected_address` binds the caller's intended wallet: if a wallet switch
/// changed the active signer since the caller was built, we refuse rather than
/// sign with the wrong key/nonce.
#[tauri::command]
pub async fn wallet_sign_transaction(
    state: tauri::State<'_, WalletState>,
    expected_address: String,
    tx_json: String,
) -> Result<String, String> {
    let signer = active_signer_checked(&state, &expected_address)?;
    let tx = build_tx(&tx_json)?;

    let signature = signer
        .sign_hash(&tx.signature_hash())
        .await
        .map_err(|_| "signing failed".to_string())?;

    let signed = tx.into_signed(signature);
    let envelope = TxEnvelope::from(signed);
    Ok(format!("0x{}", hex::encode(envelope.encoded_2718())))
}

/// EIP-191 `personal_sign` over the raw bytes decoded from `message_hex`.
/// Returns the `0x`-prefixed 65-byte signature (r‖s‖v, v = 27/28).
#[tauri::command]
pub async fn wallet_sign_message(
    state: tauri::State<'_, WalletState>,
    expected_address: String,
    message_hex: String,
) -> Result<String, String> {
    let signer = active_signer_checked(&state, &expected_address)?;

    let s = message_hex.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let message = if s.is_empty() {
        Vec::new()
    } else {
        hex::decode(s).map_err(|_| "message is not valid hex".to_string())?
    };

    let signature = signer
        .sign_message(&message)
        .await
        .map_err(|_| "signing failed".to_string())?;
    Ok(format!("0x{}", hex::encode(signature.as_bytes())))
}

/// EIP-712 typed-data signature. `typed_json` = `{domain, types, primaryType,
/// message}`. Returns the `0x`-prefixed 65-byte signature (r‖s‖v, v = 27/28).
#[tauri::command]
pub async fn wallet_sign_typed_data(
    state: tauri::State<'_, WalletState>,
    expected_address: String,
    typed_json: String,
) -> Result<String, String> {
    let signer = active_signer_checked(&state, &expected_address)?;

    let typed: TypedData =
        serde_json::from_str(&typed_json).map_err(|_| "invalid typed data json".to_string())?;
    let hash = typed
        .eip712_signing_hash()
        .map_err(|_| "invalid typed data".to_string())?;

    let signature = signer
        .sign_hash(&hash)
        .await
        .map_err(|_| "signing failed".to_string())?;
    Ok(format!("0x{}", hex::encode(signature.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::eip191_hash_message;

    /// A unique temp path (no external tempfile dev-dep needed).
    fn temp_snapshot() -> PathBuf {
        let mut id = [0u8; 16];
        rand::rng().fill_bytes(&mut id);
        std::env::temp_dir().join(format!("dagoat-test-{}.stronghold", hex::encode(id)))
    }

    #[test]
    fn stronghold_roundtrip_and_wrong_password() {
        let path = temp_snapshot();
        let key = [3u8; KEY_LEN]; // "snapshot key" (derived from a password)
        let secret = [7u8; KEY_LEN]; // the stored private key
        store_key_in_snapshot(&path, &key, &secret).unwrap();

        let opened = read_key_from_snapshot(&path, &key).unwrap();
        assert_eq!(opened, secret.to_vec());

        // A different snapshot key (i.e. wrong password) must fail cleanly.
        let wrong = [9u8; KEY_LEN];
        assert!(read_key_from_snapshot(&path, &wrong).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn derive_key_is_deterministic_and_never_null() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key("hunter2long", &salt).unwrap();
        let b = derive_key("hunter2long", &salt).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; KEY_LEN]); // never an all-zero key
        // Different password ⇒ different key.
        assert_ne!(derive_key("different-pw", &salt).unwrap(), a);
    }

    #[test]
    fn check_password_rejects_short() {
        assert!(check_password("").is_err());
        assert!(check_password("short7!").is_err()); // 7 chars
        assert!(check_password("longenough").is_ok());
    }

    #[test]
    fn ensure_expected_matches_case_insensitively() {
        let signer = PrivateKeySigner::random();
        let checksummed = signer.address().to_checksum(None);
        assert!(ensure_expected(&signer, &checksummed).is_ok());
        assert!(ensure_expected(&signer, &checksummed.to_lowercase()).is_ok());
        // A different address is refused.
        let other = PrivateKeySigner::random().address().to_checksum(None);
        assert!(ensure_expected(&signer, &other).is_err());
    }

    #[test]
    fn import_derives_expected_address() {
        // anvil account #0 private key → known address.
        let pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let mut bytes = hex::decode(pk).unwrap();
        let signer = signer_from_bytes(&mut bytes).unwrap();
        assert_eq!(
            signer.address().to_checksum(None),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    #[tokio::test]
    async fn message_signature_recovers_to_address() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let msg = b"gm goat";
        let sig = signer.sign_message(msg).await.unwrap();
        let recovered = sig
            .recover_address_from_prehash(&eip191_hash_message(msg))
            .unwrap();
        assert_eq!(recovered, addr);
        assert_eq!(sig.as_bytes().len(), 65);
    }

    #[test]
    fn build_tx_parses_hex_and_decimal() {
        let json = r#"{
            "chainId":"0x7a69","nonce":3,"to":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "value":"0xde0b6b3a7640000","gas":"21000",
            "maxFeePerGas":"0x77359400","maxPriorityFeePerGas":"1000000000","data":"0x"
        }"#;
        let tx = build_tx(json).unwrap();
        assert_eq!(tx.chain_id, 31337);
        assert_eq!(tx.nonce, 3);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000u128);
        assert!(matches!(tx.to, TxKind::Call(_)));
    }

    #[test]
    fn build_tx_requires_chain_id() {
        assert!(build_tx(r#"{"nonce":1}"#).is_err());
    }
}
