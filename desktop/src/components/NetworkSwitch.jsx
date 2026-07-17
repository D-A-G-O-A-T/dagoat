import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { DEFAULT_NETWORK_ID, NETWORKS, getNetwork } from "../chain/addresses.js";

const STORAGE_KEY = "goat-desktop:network-id";

const NetworkContext = createContext(null);

function readStoredNetworkId() {
  const stored = Number(window.localStorage.getItem(STORAGE_KEY));
  return NETWORKS.some((n) => n.id === stored) ? stored : DEFAULT_NETWORK_ID;
}

/// Wrap the app in this once; any descendant can call useNetwork() to read
/// the selected network (anvil | Base Sepolia — no mainnet, ever) or switch
/// it. Selection is persisted to localStorage.
export function NetworkProvider({ children }) {
  const [networkId, setNetworkId] = useState(readStoredNetworkId);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, String(networkId));
  }, [networkId]);

  const value = useMemo(
    () => ({ networkId, network: getNetwork(networkId), setNetworkId }),
    [networkId]
  );

  return <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>;
}

export function useNetwork() {
  const ctx = useContext(NetworkContext);
  if (!ctx) throw new Error("useNetwork() must be used inside a <NetworkProvider>.");
  return ctx;
}

/// anvil | Base Sepolia toggle. Intentionally offers only the two networks
/// in NETWORKS — never add a mainnet option here.
export default function NetworkSwitch() {
  const { networkId, setNetworkId } = useNetwork();

  return (
    <div className="network-switch" role="group" aria-label="Network">
      {NETWORKS.map((n) => (
        <button
          key={n.id}
          type="button"
          className={`network-switch__btn ${networkId === n.id ? "active" : ""}`}
          aria-pressed={networkId === n.id}
          onClick={() => setNetworkId(n.id)}
        >
          {n.name}
        </button>
      ))}
    </div>
  );
}
