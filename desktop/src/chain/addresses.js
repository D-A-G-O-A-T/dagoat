// Network + deployment address registry for the desktop UI.
//
// The bundled JSON files under ./deployments/ are COPIES of
// contracts/deployments/{chainId}.json, checked in so the built app doesn't
// depend on the contracts/ tree at runtime. dev-up.ps1 / testnet-up.ps1 refresh them.
//
// A chain's deployment is assembled from SEVERAL fragment files, because the
// contracts deploy in separate forge scripts that each write their own file:
//   - {id}.json          — base free-market v2 (DeployFreeMarket.s.sol)
//   - {id}.factory.json  — BuyDeskFactory (DeployBuyDeskFactory.s.sol)
//   - {id}.epoch.json    — EpochSettlement lane (DeployEpochSettlement.s.sol)
// They are merged here so `getDeployment(id)` returns EVERY address (e.g.
// `buyDeskFactory`, which the Market tab needs). A clean redeploy regenerates
// the base file WITHOUT the factory/epoch keys, so relying on the base file
// alone silently hides the Market tab — merge the fragments instead.
//
// Season-0 networks ONLY. Do not add mainnet, and do not add any other RPC
// string anywhere else in this codebase — grep for "rpc:" to audit.
//
// Stream C T2: pilot builds set VITE_DEFAULT_NETWORK_ID=84532 and VITE_PILOT=1
// (or VITE_HIDE_ANVIL=1) so volunteers never land on dead anvil.
import anvilDeployment from "./deployments/31337.json";
import anvilFactory from "./deployments/31337.factory.json";
import anvilEpoch from "./deployments/31337.epoch.json";
import baseSepoliaDeployment from "./deployments/84532.json";
import baseSepoliaFactory from "./deployments/84532.factory.json";
import baseSepoliaEpoch from "./deployments/84532.epoch.json";

export const NETWORKS = [
  { id: 31337, name: "Local anvil", rpc: "http://127.0.0.1:8545" },
  { id: 84532, name: "Base Sepolia", rpc: "https://sepolia.base.org" },
];

/**
 * Pure: resolve default network from a Vite-style env bag.
 * Unset → 31337 (lab). Pilot release: VITE_DEFAULT_NETWORK_ID=84532.
 * @param {Record<string, string | undefined>} [env]
 */
export function resolveDefaultNetworkId(env = {}) {
  const raw = String(env.VITE_DEFAULT_NETWORK_ID ?? "").trim();
  if (raw === "84532" || raw === "31337") return Number(raw);
  return 31337;
}

/**
 * Pure: hide anvil in pilot/release builds.
 * @param {Record<string, string | undefined>} [env]
 */
export function resolveHideAnvil(env = {}) {
  const pilot = String(env.VITE_PILOT ?? "").trim().toLowerCase();
  const hide = String(env.VITE_HIDE_ANVIL ?? "").trim().toLowerCase();
  return pilot === "1" || pilot === "true" || hide === "1" || hide === "true";
}

/**
 * Networks shown in the UI switcher.
 * @param {Record<string, string | undefined>} [env] — defaults to import.meta.env
 */
export function visibleNetworks(env) {
  const e =
    env ??
    (typeof import.meta !== "undefined" && import.meta.env ? import.meta.env : {});
  if (resolveHideAnvil(e)) {
    return NETWORKS.filter((n) => n.id !== 31337);
  }
  return NETWORKS;
}

function viteEnv() {
  return typeof import.meta !== "undefined" && import.meta.env ? import.meta.env : {};
}

export const DEFAULT_NETWORK_ID = resolveDefaultNetworkId(viteEnv());

/** Core free-market addresses required before UI treats a chain as live. */
export const CORE_DEPLOYMENT_KEYS = [
  "goatCoin",
  "enrollmentRegistry",
  "holdbackEscrow",
  "workMinter",
  "buyDesk",
  "mockUSDT",
];

const DEPLOYMENTS = {
  // Merge fragments (base + factory + epoch) into one address map.
  // Overlapping keys hold the same values across fragments; later spreads
  // only add fragment-specific addresses (buyDeskFactory, epoch*, …).
  31337: { ...anvilDeployment, ...anvilFactory, ...anvilEpoch },
  84532: { ...baseSepoliaDeployment, ...baseSepoliaFactory, ...baseSepoliaEpoch },
};

export function getNetwork(chainId) {
  return NETWORKS.find((n) => n.id === Number(chainId)) ?? null;
}

/// Raw deployment JSON for a chain (addresses as decimal-string / hex /
/// null — not yet BigInt-parsed). Base Sepolia carried all-null placeholders
/// until the pilot deployment filled them in; both chains are populated now.
export function getDeployment(chainId) {
  return DEPLOYMENTS[Number(chainId)] ?? null;
}

/**
 * True only when every **core** free-market contract address on `deployment` is
 * a usable address. Ignores factory/epoch placeholders and `note` / numeric
 * metadata. Null, empty string, bare `0x` and the zero address all count as not
 * deployed.
 *
 * Exported separately from {@link isDeployed} so the REJECTION branch stays
 * testable. `isDeployed` reads a module-level map, so once every chain in that
 * map is really deployed the only reachable negative is "unknown chain id" —
 * the four conditions below would go uncovered while the suite stayed green.
 * That is what happened when the pilot populated 84532.
 */
export function hasCoreAddresses(deployment) {
  if (!deployment) return false;
  return CORE_DEPLOYMENT_KEYS.every((k) => {
    const v = deployment[k];
    return typeof v === "string" && v.length > 0 && v !== "0x" && !/^0x0{40}$/i.test(v);
  });
}

/**
 * True only when every **core** free-market contract address is a non-empty string.
 * Ignores factory/epoch placeholders and `note` / numeric metadata.
 * Null, empty string, and missing keys all count as not deployed.
 */
export function isDeployed(chainId) {
  return hasCoreAddresses(getDeployment(chainId));
}
