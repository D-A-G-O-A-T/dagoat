// Wallet-manager wrappers over the Rust `wallet_*` command contract, plus the
// active-wallet state the tabs read (this is what replaces the old plaintext
// loadKey/saveKey/clearKey in client.js).
//
// The private key never enters JS — these commands only ever move names,
// addresses, passwords (into Rust), and signatures (out of Rust). See
// docs/superpowers/specs/2026-07-13-stronghold-wallet-design.md §3.2.
import { useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import { load } from "@tauri-apps/plugin-store";
import { createRustAccount } from "./rustAccount.js";

// One-time migration: the pre-Stronghold build stored a RAW private key in
// plaintext via the plugin-store file "wallet.dat" under "testnet_private_key".
// Keys now live only in password-encrypted Stronghold snapshots, so that record
// is orphaned plaintext on disk — delete it on first run of the new build. The
// whole thing is a harmless no-op when the file/key is absent or we're not in
// Tauri (the load/get/delete just resolve to nothing or throw, and we swallow).
export async function purgeLegacyPlaintextKey() {
  try {
    const store = await load("wallet.dat", { autoSave: false });
    const existing = await store.get("testnet_private_key");
    if (existing !== undefined && existing !== null) {
      await store.delete("testnet_private_key");
      await store.save();
    }
  } catch {
    // No legacy store, key already gone, or no Tauri runtime — nothing to do.
  }
}

// ---- command wrappers -------------------------------------------------------
// Tauri v2 maps these camelCase JS arg keys to the snake_case Rust params
// (privateKeyHex → private_key_hex, etc.) automatically.

/// [{ name, address }] for every stored wallet — from a non-secret index,
/// never touches key bytes.
export function listWallets() {
  return invoke("wallet_list");
}

/// Generate a fresh secp256k1 key in Rust, store it encrypted, return
/// { name, address }. Never returns the key.
export function createWallet(name, password) {
  return invoke("wallet_create", { name, password });
}

/// Encrypt an existing 0x/hex 32-byte key under name+password. Returns
/// { name, address }.
export function importWallet(name, password, privateKeyHex) {
  return invoke("wallet_import", { name, password, privateKeyHex });
}

/// Decrypt into an in-memory Rust signer for this session and set it active;
/// returns { name, address }. Refreshes the active-wallet store so every tab
/// picks up the new signer.
export async function unlock(name, password) {
  const meta = await invoke("wallet_unlock", { name, password });
  await refreshActive();
  return meta;
}

/// Drop + zeroize all in-memory signers; no active wallet afterwards.
export async function lock() {
  await invoke("wallet_lock");
  await refreshActive();
}

/// The currently unlocked wallet ({ name, address }) or null.
export function activeWallet() {
  return invoke("wallet_active");
}

/// Delete a stored wallet (password-gated). Refreshes active state in case the
/// removed wallet was the active one.
export async function removeWallet(name, password) {
  await invoke("wallet_remove", { name, password });
  await refreshActive();
}

// ---- active-wallet store (cross-tab reactive) -------------------------------
// A tiny external store so Wallet/Ops/Market/Miner all re-render when the user
// unlocks / locks / switches, without prop-drilling or a context provider.

let activeMeta = null; // { name, address } | null
let loaded = false;
const listeners = new Set();

function emit() {
  for (const listener of listeners) listener();
}

async function refreshActive() {
  try {
    const meta = await invoke("wallet_active");
    activeMeta = meta ?? null;
  } catch {
    // Outside Tauri (tests/plain browser) there's no active wallet.
    activeMeta = null;
  }
  loaded = true;
  emit();
  return activeMeta;
}

function subscribe(callback) {
  listeners.add(callback);
  if (!loaded) refreshActive(); // lazy first read on first subscriber
  return () => listeners.delete(callback);
}

function getMetaSnapshot() {
  return activeMeta;
}

// Cache the viem account by address so its identity is stable across renders
// (a fresh object each render would churn every walletClient useMemo).
let cachedAccount = null;
let cachedAddress = null;
function accountForMeta(meta) {
  if (!meta?.address) {
    cachedAccount = null;
    cachedAddress = null;
    return null;
  }
  if (meta.address !== cachedAddress) {
    cachedAccount = createRustAccount(meta.address);
    cachedAddress = meta.address;
  }
  return cachedAccount;
}

/// React hook: the active wallet metadata ({ name, address }) or null.
/// Re-renders on unlock/lock/switch/remove.
export function useActiveWallet() {
  return useSyncExternalStore(subscribe, getMetaSnapshot, () => null);
}

/// React hook: the active viem account (Rust-backed) or null. This is the
/// single helper the tx tabs use in place of the old loadKey() state — pass it
/// straight to getWalletClient / runTx.
export function useActiveAccount() {
  const meta = useActiveWallet();
  return accountForMeta(meta);
}
