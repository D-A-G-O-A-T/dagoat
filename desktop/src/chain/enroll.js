// Self-enroll helpers. Enrollment is permissionless via enrollSelf (caller pays
// native ETH gas). It is NOT automatic on wallet create/import — that would
// surprise users on real networks. The Wallet UI calls ensureEnrolled after
// unlock when the user opts in or for local pilot convenience.

import { ENROLLMENT_REGISTRY_ABI } from "./abis.js";
import { getDeployment } from "./addresses.js";
import { getPublicClient, getWalletClient } from "./client.js";
import { createRustAccount } from "./rustAccount.js";
import { commandError } from "./errors.js";
import { waitForReceipt } from "./receipt.js";

/**
 * @returns {Promise<boolean>} true if already enrolled or enroll succeeded
 */
export async function isEnrolled(publicClient, enrollmentRegistry, wallet) {
  if (!publicClient || !enrollmentRegistry || !wallet) return false;
  return Boolean(
    await publicClient.readContract({
      address: enrollmentRegistry,
      abi: ENROLLMENT_REGISTRY_ABI,
      functionName: "enrolled",
      args: [wallet],
    }),
  );
}

/**
 * Call EnrollmentRegistry.enrollSelf() if not already enrolled.
 * Requires walletClient with ETH for gas (anvil accounts have ETH).
 * Created worker wallets start at 0 ETH — skip with a clear error instead of
 * viem's "total cost exceeds the balance" (use gasless bind+enroll relayer).
 *
 * @returns {Promise<{ already: boolean, hash?: `0x${string}`, skipped?: boolean, error?: string }>}
 */
export async function ensureEnrolled({ publicClient, walletClient, account, enrollmentRegistry }) {
  if (!publicClient || !walletClient || !account?.address || !enrollmentRegistry) {
    throw new Error("Missing client, account, or enrollment registry address");
  }
  const already = await isEnrolled(publicClient, enrollmentRegistry, account.address);
  if (already) return { already: true };

  let ethBal = 0n;
  try {
    ethBal = await publicClient.getBalance({ address: account.address });
  } catch {
    ethBal = 0n;
  }
  if (ethBal === 0n) {
    return {
      already: false,
      skipped: true,
      error:
        "Wallet has 0 ETH — enrollSelf needs gas. Use Contribute → Bind & enroll (gasless relayer on :8787), or fund a little anvil ETH.",
    };
  }

  try {
    const hash = await walletClient.writeContract({
      account,
      address: enrollmentRegistry,
      abi: ENROLLMENT_REGISTRY_ABI,
      functionName: "enrollSelf",
      args: [],
    });
    // Wait for receipt so UI can refresh enrolled=true (60s timeout — Stream C T1).
    await waitForReceipt(publicClient, { hash });
    return { already: false, hash };
  } catch (err) {
    const msg = err?.shortMessage || err?.message || String(err);
    if (/exceeds the balance|insufficient funds/i.test(msg)) {
      return {
        already: false,
        skipped: true,
        error:
          "Not enough ETH for enrollSelf gas. Use Bind & enroll (gasless) or fund ETH on this wallet.",
      };
    }
    throw err;
  }
}

/** After unlock/import: enrollSelf if needed (pays native ETH gas — anvil accounts have ETH). */
export async function tryAutoEnroll(networkId, address) {
  if (!address) return { skipped: true };
  const deployment = getDeployment(networkId);
  if (!deployment?.enrollmentRegistry) return { skipped: true, reason: "no registry" };
  let publicClient;
  try {
    publicClient = getPublicClient(networkId);
  } catch {
    return { skipped: true, reason: "no rpc" };
  }
  const account = createRustAccount(address);
  const walletClient = getWalletClient(networkId, account);
  if (!walletClient) return { skipped: true, reason: "no wallet client" };
  try {
    const out = await ensureEnrolled({
      publicClient,
      walletClient,
      account,
      enrollmentRegistry: deployment.enrollmentRegistry,
    });
    // ensureEnrolled may soft-skip (0 ETH) with { skipped, error } — do not throw
    if (out?.skipped && out?.error) return { error: out.error, skipped: true };
    return out;
  } catch (err) {
    return { error: commandError(err) };
  }
}
