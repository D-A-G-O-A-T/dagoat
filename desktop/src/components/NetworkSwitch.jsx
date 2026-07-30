import { createContext, useContext, useEffect, useMemo, useState } from "react";
import {
  DEFAULT_NETWORK_ID,
  getNetwork,
  visibleNetworks,
} from "../chain/addresses.js";

const STORAGE_KEY = "goat-desktop:network-id";

const NetworkContext = createContext(null);

function readStoredNetworkId() {
  const visible = visibleNetworks();
  const stored = Number(
    typeof window !== "undefined" ? window.localStorage.getItem(STORAGE_KEY) : NaN,
  );
  if (visible.some((n) => n.id === stored)) return stored;
  // Stored anvil while pilot hide-anvil is on → fall through to default.
  if (visible.some((n) => n.id === DEFAULT_NETWORK_ID)) return DEFAULT_NETWORK_ID;
  return visible[0]?.id ?? DEFAULT_NETWORK_ID;
}

/// Wrap the app in this once; any descendant can call useNetwork() to read
/// the selected network (anvil | Base Sepolia — no mainnet, ever) or switch
/// it. Selection is persisted to localStorage.
export function NetworkProvider({ children }) {
  const [networkId, setNetworkId] = useState(readStoredNetworkId);
  const visible = useMemo(() => visibleNetworks(), []);

  useEffect(() => {
    // If pilot build hides anvil, snap off a stale stored 31337.
    if (!visible.some((n) => n.id === networkId)) {
      const next = visible[0]?.id ?? DEFAULT_NETWORK_ID;
      setNetworkId(next);
    }
  }, [visible, networkId]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, String(networkId));
    }
  }, [networkId]);

  const value = useMemo(
    () => ({
      networkId,
      network: getNetwork(networkId),
      setNetworkId,
      visibleNetworks: visible,
    }),
    [networkId, visible],
  );

  return <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>;
}

export function useNetwork() {
  const ctx = useContext(NetworkContext);
  if (!ctx) throw new Error("useNetwork() must be used inside a <NetworkProvider>.");
  return ctx;
}

/// anvil | Base Sepolia toggle. Pilot builds (VITE_PILOT / VITE_HIDE_ANVIL)
/// omit anvil so volunteers cannot select a dead local chain.
export default function NetworkSwitch() {
  const { networkId, setNetworkId, visibleNetworks: networks } = useNetwork();

  return (
    <div className="network-switch" role="group" aria-label="Network">
      {networks.map((n) => (
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
