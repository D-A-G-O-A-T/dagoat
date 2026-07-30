// Shared wait-for-receipt helper (Stream C Task 1).
//
// Every wallet-gas path that previously called waitForTransactionReceipt without
// a timeout could hang the UI forever on a slow public L2 RPC. Pilot default is
// 60s (founder-ratified via consultant rec for Design §8 Q4) — Base Sepolia
// inclusion under congestion often exceeds 30s.
//
// Also enforces receipt.status !== "reverted" so a mined-but-reverted tx is not
// treated as success (same TOCTOU fix as the original runTx path).

/** Default wait for public L2 inclusion (ms). */
export const DEFAULT_RECEIPT_TIMEOUT_MS = 60_000;

/**
 * waitForTransactionReceipt with timeout + reverted-status throw.
 *
 * @param {{ waitForTransactionReceipt: Function }} publicClient
 * @param {{ hash: string, timeoutMs?: number }} opts
 * @returns {Promise<object>} receipt
 */
export async function waitForReceipt(
  publicClient,
  { hash, timeoutMs = DEFAULT_RECEIPT_TIMEOUT_MS },
) {
  if (!publicClient?.waitForTransactionReceipt) {
    throw new Error("waitForReceipt: publicClient missing waitForTransactionReceipt");
  }
  if (!hash) {
    throw new Error("waitForReceipt: hash required");
  }
  const timeout = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_RECEIPT_TIMEOUT_MS;
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout });
  if (receipt?.status === "reverted") {
    throw new Error(`Transaction reverted on-chain (${hash}). Nothing was confirmed.`);
  }
  return receipt;
}
