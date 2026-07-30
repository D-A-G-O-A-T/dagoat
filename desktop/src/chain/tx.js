// Shared simulate-then-write transaction helper (Wallet + Ops tabs).
//
// Pattern (originally inline in Wallet.jsx's `runTx`, extracted here so Ops
// doesn't duplicate it): simulateContract first — this is a free eth_call
// that surfaces a decoded custom-error name (see chain/client.js
// extractErrorName) BEFORE the wallet ever signs anything — then
// writeContract, then wait for the receipt so callers can rely on on-chain
// confirmation before touching local state (e.g. journal.markMinted must
// only run after mintBatch has actually landed).
//
// RECEIPT STATUS (review round 1, "also"). simulateContract runs against the
// state at call time; the real mined transaction can still revert on a state
// change between simulate and inclusion (another tx lands first, a session
// closes, a cap changes — classic TOCTOU) even though it was never rejected
// and genuinely consumed gas. Before this check, `runTx` resolved on ANY
// receipt regardless of `status`, so every caller's success path (e.g.
// Market.jsx's "Sold (testnet)" + onSuccess floor-clear) ran for a reverted,
// gas-spent transaction. Throwing here makes a reverted receipt behave like
// any other failed send: the caller's existing catch/friendlyError path
// handles it, and (for the gas-floor callers) no floor gets wrongly cleared.
//
// Stream C Task 1: receipt wait is `waitForReceipt` (60s default timeout +
// reverted throw) so public L2 RPCs cannot hang the UI forever.
import { waitForReceipt } from "./receipt.js";

export async function runTx({ publicClient, walletClient, account, address, abi, functionName, args }) {
  await publicClient.simulateContract({ address, abi, functionName, args, account });
  const hash = await walletClient.writeContract({ address, abi, functionName, args });
  await waitForReceipt(publicClient, { hash });
  return hash;
}
