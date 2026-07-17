// Live-anvil end-to-end smoke test for the Ops tab's core loop:
// createJob -> mintBatch -> journal.markMinted — driven through the REAL
// manifest.js canonicalization and the REAL chain/tx.js runTx (simulate-
// then-write) helper against a real running anvil + a real
// DeployFreeMarket.s.sol deployment. Nothing chain-related here is mocked;
// only @tauri-apps/plugin-store is stubbed (same pattern as journal.test.js)
// since this runs in plain Node, not inside Tauri.
//
// Skipped by default — requires anvil + a wired v2 deployment already up.
// To run (from repo root, Git Bash):
//   export PATH="$HOME/.foundry/bin:$PATH"
//   anvil &
//   cd contracts
//   SAFE_ADDRESS=<anvil #0> FOUNDER_ADDRESS=<anvil #0> RESERVE_ADDRESS=<anvil #0> \
//     DEPLOYER_PRIVATE_KEY=<anvil #0 key> \
//     forge script script/DeployFreeMarket.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
//   cast send $ESCROW "setVault(address)" $WORKMINTER --private-key <key> --rpc-url http://127.0.0.1:8545
//   cast send $GOAT "setMinter(address,bool)" $WORKMINTER true --private-key <key> --rpc-url http://127.0.0.1:8545
//   cd ../desktop
//   GOAT_E2E=1 npx vitest run src/ops.e2e.test.js
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { createPublicClient, createWalletClient, defineChain, http, keccak256, stringToBytes, zeroAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

vi.mock("@tauri-apps/plugin-store", () => ({
  load: vi.fn(async () => {
    const data = new Map();
    return {
      get: async (key) => data.get(key),
      set: async (key, value) => {
        data.set(key, value);
      },
      delete: async (key) => {
        data.delete(key);
      },
      save: async () => {},
    };
  }),
}));

const RUN_E2E = process.env.GOAT_E2E === "1";
const RPC_URL = process.env.GOAT_E2E_RPC_URL ?? "http://127.0.0.1:8545";
// Well-known anvil default account #0 — deterministic, testnet-only, never
// holds real funds. Overridable for a differently-seeded anvil.
const SIGNER_KEY =
  process.env.GOAT_E2E_PRIVATE_KEY ?? "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYMENT_PATH =
  process.env.GOAT_E2E_DEPLOYMENT ?? fileURLToPath(new URL("../../contracts/deployments/31337.json", import.meta.url));

describe.skipIf(!RUN_E2E)("Ops e2e: createJob -> mintBatch -> journal-stamp (live anvil)", () => {
  let publicClient;
  let walletClient;
  let account;
  let deployment;

  beforeAll(() => {
    deployment = JSON.parse(readFileSync(DEPLOYMENT_PATH, "utf8"));
    account = privateKeyToAccount(SIGNER_KEY);
    const anvilChain = defineChain({
      id: 31337,
      name: "anvil (e2e)",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [RPC_URL] } },
    });
    publicClient = createPublicClient({ chain: anvilChain, transport: http(RPC_URL) });
    walletClient = createWalletClient({ chain: anvilChain, transport: http(RPC_URL), account });
  });

  it("mints exactly units x unitReward with the 95/5 split, and stamps the journal only after confirmation", async () => {
    const { runTx } = await import("./chain/tx.js");
    const { computeManifestRoot } = await import("./manifest.js");
    const { appendPending, loadPending, markMinted } = await import("./journal.js");
    const { WORK_MINTER_ABI, GOAT_COIN_ABI, HOLDBACK_ESCROW_ABI } = await import("./chain/abis.js");
    const { SEASON0_FAH_JOB_ID, SEASON0_FAH_JOB_ID_STR, WORK_UNIT_FORMULA } = await import("./chain/constants.js");

    const catalogHash = keccak256(stringToBytes(WORK_UNIT_FORMULA));

    // Idempotent across reruns against the same anvil: create the job only
    // if it doesn't exist yet (jobs()[1] === unitReward; 0n = sentinel).
    const existing = await publicClient.readContract({
      address: deployment.workMinter,
      abi: WORK_MINTER_ABI,
      functionName: "jobs",
      args: [SEASON0_FAH_JOB_ID],
    });
    if (existing[1] === 0n) {
      await runTx({
        publicClient,
        walletClient,
        account,
        address: deployment.workMinter,
        abi: WORK_MINTER_ABI,
        functionName: "createJob",
        args: [SEASON0_FAH_JOB_ID, catalogHash, 1_000000000000000000n, 500, zeroAddress, true],
      });
    }

    const jobBefore = await publicClient.readContract({
      address: deployment.workMinter,
      abi: WORK_MINTER_ABI,
      functionName: "jobs",
      args: [SEASON0_FAH_JOB_ID],
    });
    const [, unitReward, mintedBefore] = jobBefore;
    const liquidBefore = await publicClient.readContract({
      address: deployment.goatCoin,
      abi: GOAT_COIN_ABI,
      functionName: "balanceOf",
      args: [account.address],
    });
    const holdbackBefore = await publicClient.readContract({
      address: deployment.holdbackEscrow,
      abi: HOLDBACK_ESCROW_ABI,
      functionName: "holdbackOf",
      args: [SEASON0_FAH_JOB_ID, account.address],
    });

    // Fabricate two accepted work units through the REAL journal
    // (appendPending) — the exact shape Miner's checkCompletions persists.
    const stamp = Date.now();
    const units = [
      { unit_id: `e2e-wu-${stamp}-b`, weight: 2, backend_ref: "e2e", at: Math.floor(stamp / 1000), evidence: "e2e-evidence-b" },
      { unit_id: `e2e-wu-${stamp}-a`, weight: 1, backend_ref: "e2e", at: Math.floor(stamp / 1000), evidence: "e2e-evidence-a" },
    ];
    await appendPending(units, "folding_at_home");
    const pendingBatch = (await loadPending()).filter((u) => u.unit_id.startsWith(`e2e-wu-${stamp}`));
    expect(pendingBatch).toHaveLength(2);
    const totalUnits = pendingBatch.reduce((sum, u) => sum + Number(u.weight), 0);
    expect(totalUnits).toBe(3);

    // REAL manifest.js canonicalization — order-insensitive input (units
    // fed in reverse-of-append order above) must still match what a
    // sorted-order caller would compute.
    const manifestRoot = computeManifestRoot(SEASON0_FAH_JOB_ID_STR, pendingBatch);
    const manifestRootSorted = computeManifestRoot(SEASON0_FAH_JOB_ID_STR, [...pendingBatch].reverse());
    expect(manifestRoot).toBe(manifestRootSorted);

    // REAL chain/tx.js runTx — simulate, write, wait for receipt.
    const hash = await runTx({
      publicClient,
      walletClient,
      account,
      address: deployment.workMinter,
      abi: WORK_MINTER_ABI,
      functionName: "mintBatch",
      args: [SEASON0_FAH_JOB_ID, manifestRoot, [account.address], [BigInt(totalUnits)]],
    });
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);

    // journal.markMinted only after the on-chain confirmation above.
    const unitIds = pendingBatch.map((u) => u.unit_id);
    const batchRef = manifestRoot.slice(0, 10);
    const stamped = await markMinted(unitIds, batchRef);
    for (const id of unitIds) {
      expect(stamped.find((e) => e.unit_id === id).mintedInBatch).toBe(batchRef);
    }

    const expectedGoat = BigInt(totalUnits) * unitReward;
    const expectedHoldback = (expectedGoat * 500n) / 10_000n;
    const expectedLiquid = expectedGoat - expectedHoldback;

    const jobAfter = await publicClient.readContract({
      address: deployment.workMinter,
      abi: WORK_MINTER_ABI,
      functionName: "jobs",
      args: [SEASON0_FAH_JOB_ID],
    });
    expect(jobAfter[2] - mintedBefore).toBe(expectedGoat);

    const liquidAfter = await publicClient.readContract({
      address: deployment.goatCoin,
      abi: GOAT_COIN_ABI,
      functionName: "balanceOf",
      args: [account.address],
    });
    expect(liquidAfter - liquidBefore).toBe(expectedLiquid);

    const holdbackAfter = await publicClient.readContract({
      address: deployment.holdbackEscrow,
      abi: HOLDBACK_ESCROW_ABI,
      functionName: "holdbackOf",
      args: [SEASON0_FAH_JOB_ID, account.address],
    });
    expect(holdbackAfter - holdbackBefore).toBe(expectedHoldback);
  }, 30_000);
});
