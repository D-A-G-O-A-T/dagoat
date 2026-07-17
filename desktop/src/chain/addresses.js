// Network + deployment address registry for the desktop UI.
//
// The bundled JSON files under ./deployments/ are COPIES of
// contracts/deployments/{chainId}.json, checked in so the built app doesn't
// depend on the contracts/ tree at runtime. dev-up.ps1 refreshes them.
//
// A chain's deployment is assembled from SEVERAL fragment files, because the
// contracts deploy in separate forge scripts that each write their own file:
//   - 31337.json          — base free-market v2 (DeployFreeMarket.s.sol)
//   - 31337.factory.json  — BuyDeskFactory (DeployBuyDeskFactory.s.sol)
//   - 31337.epoch.json    — EpochSettlement lane (DeployEpochSettlement.s.sol)
// They are merged here so `getDeployment(31337)` returns EVERY address (e.g.
// `buyDeskFactory`, which the Market tab needs). A clean redeploy regenerates
// the base file WITHOUT the factory/epoch keys, so relying on the base file
// alone silently hides the Market tab — merge the fragments instead.
//
// Season-0 networks ONLY. Do not add mainnet, and do not add any other RPC
// string anywhere else in this codebase — grep for "rpc:" to audit.
import anvilDeployment from "./deployments/31337.json";
import anvilFactory from "./deployments/31337.factory.json";
import anvilEpoch from "./deployments/31337.epoch.json";
import baseSepoliaDeployment from "./deployments/84532.json";

export const NETWORKS = [
  { id: 31337, name: "Local anvil", rpc: "http://127.0.0.1:8545" },
  { id: 84532, name: "Base Sepolia", rpc: "https://sepolia.base.org" },
];

export const DEFAULT_NETWORK_ID = 31337;

const DEPLOYMENTS = {
  // Merge the anvil fragments (base + factory + epoch) into one address map.
  // Overlapping keys (chainId, goatCoin, mockUSDT, enrollmentRegistry) hold
  // the same values across fragments, so later spreads are no-ops for them and
  // only add the fragment-specific addresses (buyDeskFactory, epoch*).
  31337: { ...anvilDeployment, ...anvilFactory, ...anvilEpoch },
  84532: baseSepoliaDeployment,
};

export function getNetwork(chainId) {
  return NETWORKS.find((n) => n.id === Number(chainId)) ?? null;
}

/// Raw deployment JSON for a chain (addresses as decimal-string / hex /
/// null — not yet BigInt-parsed). Sepolia's entry is all-null until v2 is
/// deployed there; callers must handle that (see chain/client.js `isDeployed`).
export function getDeployment(chainId) {
  return DEPLOYMENTS[Number(chainId)] ?? null;
}

/// True only when every contract address in the deployment is present
/// (i.e. not the Sepolia placeholder).
export function isDeployed(chainId) {
  const d = getDeployment(chainId);
  if (!d) return false;
  return Boolean(d.goatCoin && d.enrollmentRegistry && d.holdbackEscrow && d.workMinter && d.buyDesk && d.mockUSDT);
}
