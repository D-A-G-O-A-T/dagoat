// Shared simulate-then-write transaction helper (Wallet + Ops tabs).
//
// Pattern (originally inline in Wallet.jsx's `runTx`, extracted here so Ops
// doesn't duplicate it): simulateContract first — this is a free eth_call
// that surfaces a decoded custom-error name (see chain/client.js
// extractErrorName) BEFORE the wallet ever signs anything — then
// writeContract, then wait for the receipt so callers can rely on on-chain
// confirmation before touching local state (e.g. journal.markMinted must
// only run after mintBatch has actually landed).
export async function runTx({ publicClient, walletClient, account, address, abi, functionName, args }) {
  await publicClient.simulateContract({ address, abi, functionName, args, account });
  const hash = await walletClient.writeContract({ address, abi, functionName, args });
  await publicClient.waitForTransactionReceipt({ hash });
  return hash;
}
