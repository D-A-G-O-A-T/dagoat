// viem client construction.
//
// There is NO plaintext-key path here anymore. Private keys live only in the
// Rust Stronghold vault; JS builds a Rust-backed viem account via
// chain/rustAccount.js and drives the active wallet through chain/wallet.js
// (see docs/superpowers/specs/2026-07-13-stronghold-wallet-design.md §3.2).
// The old wallet.dat raw-key store (saveKey/loadKey/clearKey) was removed.
//
// RED WARNING (surfaced verbatim by the Wallet key-import UI):
//   "Testnet key only — NEVER paste a key that holds real funds."
import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import { getNetwork } from "./addresses.js";

export const KEY_IMPORT_WARNING = "Testnet key only — NEVER paste a key that holds real funds.";

/// Builds a viem chain definition strictly from our own NETWORKS entry —
/// never from viem/chains — so the only RPC strings in this codebase are
/// the two in chain/addresses.js.
function toViemChain(network) {
  return defineChain({
    id: network.id,
    name: network.name,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [network.rpc] } },
  });
}

export function getPublicClient(chainId) {
  const network = getNetwork(chainId);
  if (!network) throw new Error(`Unknown network id ${chainId}`);
  return createPublicClient({ chain: toViemChain(network), transport: http(network.rpc) });
}

/// account: the active Rust-backed viem account (from wallet.js
/// useActiveAccount). Returns null if no wallet is unlocked — callers should
/// gate write actions on this.
export function getWalletClient(chainId, account) {
  if (!account) return null;
  const network = getNetwork(chainId);
  if (!network) throw new Error(`Unknown network id ${chainId}`);
  return createWalletClient({ chain: toViemChain(network), transport: http(network.rpc), account });
}

// Custom Solidity error names the Wallet/Ops UIs know how to translate into
// readable copy (see chain/abis.js — these are the `error` entries we kept
// in the trimmed ABIs specifically so viem can decode them by name).
const KNOWN_CONTRACT_ERRORS = new Set([
  "TransferRestricted",
  "NotEnrolled",
  "NoActiveSession",
  "CapExceeded",
  "ZeroPayout",
  "OwnerCannotSell",
  // Ops tab (WorkMinter / EnrollmentRegistry / BuyDesk safe- and
  // owner-gated actions) — see chain/abis.js.
  "NotSafe",
  "NotOwner",
  "JobExists",
  "JobUnknown",
  "JobClosed",
  "InvalidHoldback",
  "InvalidUnitReward",
  "FounderAcceptRequired",
  "LengthMismatch",
  "HoldbackOpen",
  "ManifestReplayed",
  // Market tab (BuyDeskFactory.sol) — see chain/abis.js BUY_DESK_FACTORY_ABI.
  "AlreadyHasDesk",
  "NoDesk",
  "ZeroAddress",
  // OpenZeppelin ERC20 standard reverts, bubbled through BuyDesk.sell() in the
  // allowance model: balance short (owner's wallet fell below payout) or
  // allowance short (desk cap exhausted/unset) — see chain/abis.js BUY_DESK_ABI.
  "ERC20InsufficientBalance",
  "ERC20InsufficientAllowance",
]);

/// Walks a viem BaseError's `.cause` chain looking for a decoded custom
/// error name (from simulateContract/writeContract reverts). Returns null
/// if none of our known errors matched, so callers can fall back to
/// `err.shortMessage`.
export function extractErrorName(err) {
  let cursor = err;
  while (cursor) {
    const name = cursor?.data?.errorName ?? cursor?.errorName;
    if (name && KNOWN_CONTRACT_ERRORS.has(name)) return name;
    if (cursor?.name && KNOWN_CONTRACT_ERRORS.has(cursor.name)) return cursor.name;
    cursor = cursor.cause;
  }
  return null;
}
