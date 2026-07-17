// Self-enroll helpers. Enrollment is permissionless via enrollSelf (caller pays
// native ETH gas). It is NOT automatic on wallet create/import — that would
// surprise users on real networks. The Wallet UI calls ensureEnrolled after
// unlock when the user opts in or for local pilot convenience.

import { ENROLLMENT_REGISTRY_ABI } from "./abis.js";

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
    // Wait for receipt so UI can refresh enrolled=true
    await publicClient.waitForTransactionReceipt({ hash });
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
