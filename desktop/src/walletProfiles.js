// Per-wallet FAH identity profiles.
//
// Folding@home only has one live (username, passkey, team) config on disk. Each Goat wallet
// that earns GOAT needs its own GOAT-<name> bound 1:1 on-chain. When the user switches the
// active wallet we swap the live FAH config to that wallet's profile so bind/enroll and
// attribution target the right identity.
//
// Profiles are stored in app-state.dat (non-secret map). Passkeys are identity tokens (A2:
// shown read-only in Attribution), not wallet keys.
import { invoke } from "@tauri-apps/api/core";
import { readAppState, writeAppState } from "./onboarding/appState.js";
import { saveIdentity } from "./identity.js";

export const WALLET_FAH_PROFILES_KEY = "wallet_fah_profiles_v1";

/** @param {string | null | undefined} address */
export function normalizeWalletAddress(address) {
  return (address ?? "").trim().toLowerCase();
}

/** @returns {Promise<Record<string, { username: string, passkey: string }>>} */
export async function loadAllWalletFahProfiles() {
  try {
    const map = await readAppState(WALLET_FAH_PROFILES_KEY, {});
    return map && typeof map === "object" && !Array.isArray(map) ? map : {};
  } catch {
    // FIX-4: a readAppState failure must not crash callers that don't already defensively .catch().
    return {};
  }
}

/**
 * @param {string | null | undefined} address
 * @returns {Promise<{ username: string, passkey: string } | null>}
 */
export async function getWalletFahProfile(address) {
  try {
    const addr = normalizeWalletAddress(address);
    if (!addr) return null;
    const map = await loadAllWalletFahProfiles();
    const row = map[addr];
    if (!row?.username || typeof row.username !== "string") return null;
    return {
      username: row.username.trim(),
      passkey: typeof row.passkey === "string" ? row.passkey : "",
    };
  } catch {
    // FIX-4: same hardening as loadAllWalletFahProfiles — safe default on any thrown error.
    return null;
  }
}

/**
 * Persist this wallet's FAH identity. Overwrites any previous row for the address.
 * @param {string} address
 * @param {{ username: string, passkey?: string }} profile
 */
export async function saveWalletFahProfile(address, { username, passkey = "" }) {
  const addr = normalizeWalletAddress(address);
  const user = (username ?? "").trim();
  if (!addr || !user) return false;
  const map = await loadAllWalletFahProfiles();
  map[addr] = { username: user, passkey: (passkey ?? "").trim() };
  return writeAppState(WALLET_FAH_PROFILES_KEY, map);
}

/**
 * Write identity to the live FAH backend and remember it for this wallet.
 * @param {string} address
 * @param {{ username: string, passkey?: string }} profile
 * @param {typeof invoke} [invokeFn]
 */
export async function bindWalletFahProfile(address, { username, passkey = "" }, invokeFn = invoke) {
  const user = (username ?? "").trim();
  if (!user) return null;
  const pk = (passkey ?? "").trim();
  await saveIdentity({ username: user, passkey: pk || undefined }, invokeFn);
  const saved = await saveWalletFahProfile(address, { username: user, passkey: pk });
  if (!saved) {
    // FIX-2: propagate persistence failure instead of returning a live-but-unpersisted identity.
    throw new Error(`Failed to persist FAH profile for ${user} (wallet ${address})`);
  }
  return { username: user, passkey: pk };
}

/**
 * After unlock/switch: make FAH match this wallet's stored profile.
 *
 * Migration: if the profile map is empty, FAH already has a username, and this is the only
 * stored wallet, adopt that identity once (legacy single-wallet installs). Never seed when
 * multiple wallets exist or the map already has rows — that was the Bob-stuck-on-Rookie bug
 * (Bob unlocked while live FAH was still Alice's GOAT-Rookie).
 *
 * @param {string | null | undefined} address
 * @param {typeof invoke} [invokeFn]
 * @param {{ walletCount?: number, networkId?: number, readBoundUsername?: (networkId: number, address: string) => Promise<string|null> }} [opts]
 *   walletCount: pass listWallets().length from unlock. networkId/readBoundUsername: inject a
 *   chain-read function so resolution order is chain > local > seed (B2: chain is set-once
 *   truth) — injected rather than importing attribution.js directly so this module stays
 *   pure-logic Vitest testable without RPC.
 * @returns {Promise<{ username: string, passkey: string } | null>}
 */
export async function syncFahProfileForWallet(address, invokeFn = invoke, opts = {}) {
  const addr = normalizeWalletAddress(address);
  if (!addr) return null;

  let profile = await getWalletFahProfile(addr);

  // B2: chain is set-once truth. Consult it before falling back to local/seed. Injected so
  // tests supply chain state without touching RPC; production passes chain/attribution.js's
  // readBoundUsername bound to the active networkId.
  if (typeof opts.readBoundUsername === "function" && opts.networkId != null) {
    try {
      const chainUsername = await opts.readBoundUsername(opts.networkId, addr);
      const trimmed = (chainUsername ?? "").trim();
      if (trimmed && trimmed !== profile?.username) {
        const passkey = profile?.passkey ?? "";
        await saveWalletFahProfile(addr, { username: trimmed, passkey });
        profile = { username: trimmed, passkey };
      }
    } catch {
      // Chain read failed (RPC down, not deployed) — fall through to local/seed resolution.
    }
  }

  if (!profile?.username) {
    const map = await loadAllWalletFahProfiles();
    const hasAny = Object.keys(map).length > 0;
    // Only auto-seed when we *know* there is exactly one wallet. walletCount 0/undefined
    // must not claim the live FAH username for a brand-new second wallet.
    const soleWallet = opts.walletCount === 1;
    if (!hasAny && soleWallet) {
      try {
        const snap = await invokeFn("backend_fah_identity");
        const username = (snap?.username ?? "").trim();
        if (username) {
          const passkey = typeof snap?.passkey === "string" ? snap.passkey : "";
          await saveWalletFahProfile(addr, { username, passkey });
          profile = { username, passkey };
        }
      } catch {
        // Outside Tauri / no FAH backend — nothing to seed.
      }
    }
  }

  if (!profile?.username) return null;

  try {
    await saveIdentity(
      { username: profile.username, passkey: profile.passkey || undefined },
      invokeFn,
    );
  } catch {
    // Unlock must still succeed if FAH configure fails; Attribution surfaces identity gaps.
  }
  return profile;
}
