import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import HonestyBanner from "./components/HonestyBanner.jsx";
import NetworkSwitch, { NetworkProvider, useNetwork } from "./components/NetworkSwitch.jsx";
import FirstRunUsername, { shouldShowFirstRun } from "./components/FirstRunUsername.jsx";
import {
  ContributeModeContext,
  loadContributeMode,
  MODE_PUBLIC_GOOD,
  MODE_WITH_GOAT,
  saveContributeMode,
} from "./contributeMode.js";
import { getDeployment, isDeployed } from "./chain/addresses.js";
import { getPublicClient } from "./chain/client.js";
import { ENROLLMENT_REGISTRY_ABI } from "./chain/abis.js";
import { useActiveAccount } from "./chain/wallet.js";
import { canSeeOpsTab, isFounderWallet } from "./opsAccess.js";
import Miner from "./tabs/Miner.jsx";
import Wallet from "./tabs/Wallet.jsx";
import Market from "./tabs/Market.jsx";
import Ops from "./tabs/Ops.jsx";

// Season-0 shell: Contribute + Wallet + Market (multi-desk) + Ops (gated).
// Tab id "miner" kept for stability.
const TABS = [
  { id: "miner", label: "Contribute" },
  { id: "wallet", label: "Wallet" },
  { id: "market", label: "Market" },
  { id: "ops", label: "Ops" },
];

const PANELS = { miner: Miner, wallet: Wallet, market: Market, ops: Ops };

export default function App() {
  return (
    <NetworkProvider>
      <AppShell />
    </NetworkProvider>
  );
}

function AppShell() {
  const [active, setActive] = useState("miner");
  const [mode, setModeState] = useState(() => loadContributeMode());
  const [identity, setIdentity] = useState(null);
  const [firstRunDismissed, setFirstRunDismissed] = useState(false);
  const [opsVisible, setOpsVisible] = useState(false);

  const { networkId } = useNetwork();
  const account = useActiveAccount();
  const ActivePanel = PANELS[active] ?? Miner;

  // First-run gate (A-D T9): read once on launch. Failure/no-backend leaves identity null,
  // which needsFirstRun() treats as "still loading" — never flash the modal on a guess.
  useEffect(() => {
    invoke("backend_fah_identity")
      .then(setIdentity)
      .catch(() => setIdentity(null));
  }, []);

  // Ops tab: founder only (EnrollmentRegistry.safe). Enrolled workers never see it.
  useEffect(() => {
    let cancelled = false;
    async function checkOpsAccess() {
      if (!account?.address || !isDeployed(networkId)) {
        if (!cancelled) setOpsVisible(false);
        return;
      }
      const deployment = getDeployment(networkId);
      if (!deployment?.enrollmentRegistry) {
        if (!cancelled) setOpsVisible(false);
        return;
      }
      try {
        const publicClient = getPublicClient(networkId);
        const safeAddress = await publicClient.readContract({
          address: deployment.enrollmentRegistry,
          abi: ENROLLMENT_REGISTRY_ABI,
          functionName: "safe",
        });
        const isFounder = isFounderWallet(account.address, safeAddress);
        if (!cancelled) setOpsVisible(canSeeOpsTab({ isFounder }));
      } catch {
        if (!cancelled) setOpsVisible(false);
      }
    }
    checkOpsAccess();
    return () => {
      cancelled = true;
    };
  }, [account?.address, networkId]);

  // If Ops is no longer visible while on that tab, leave it.
  useEffect(() => {
    if (active === "ops" && !opsVisible) {
      setActive("miner");
    }
  }, [active, opsVisible]);

  const setMode = (next) => {
    setModeState(next);
    saveContributeMode(next);
  };

  const modeValue = useMemo(
    () => ({
      mode,
      setMode,
      goatPilot: mode === MODE_WITH_GOAT,
    }),
    [mode],
  );

  const visibleTabs = TABS.filter((tab) => tab.id !== "ops" || opsVisible);

  return (
    <ContributeModeContext.Provider value={modeValue}>
      <div className="app">
        {shouldShowFirstRun(identity, firstRunDismissed) && (
          <FirstRunUsername
            onDone={async (saved) => {
              setFirstRunDismissed(true);
              // Refresh identity after Save so Contribute shows the new GOAT-* name;
              // Later leaves username empty until set on Contribute.
              if (saved) {
                try {
                  const snap = await invoke("backend_fah_identity");
                  setIdentity(snap);
                } catch {
                  /* keep prior snapshot */
                }
              }
            }}
          />
        )}

        <header className="header">
          <div className="brand">
            <span className="logo" aria-hidden>
              🐐
            </span>
            <h1>D.A. G.O.A.T.</h1>
          </div>
          <p className="subtitle">Season 0 · Contribute · optional GOAT pilot</p>
          <NetworkSwitch />
        </header>

        <div className="mode-toggle" role="group" aria-label="Contribute mode">
          <button
            type="button"
            className={`mode-toggle__btn ${mode === MODE_PUBLIC_GOOD ? "active" : ""}`}
            aria-pressed={mode === MODE_PUBLIC_GOOD}
            onClick={() => setMode(MODE_PUBLIC_GOOD)}
          >
            Public good only
          </button>
          <button
            type="button"
            className={`mode-toggle__btn ${mode === MODE_WITH_GOAT ? "active" : ""}`}
            aria-pressed={mode === MODE_WITH_GOAT}
            onClick={() => setMode(MODE_WITH_GOAT)}
          >
            Public good + GOAT pilot (testnet)
          </button>
        </div>

        <HonestyBanner />

        <nav className="tabs" role="tablist">
          {visibleTabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active === tab.id}
              className={`tab ${active === tab.id ? "active" : ""}`}
              onClick={() => setActive(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        <main className="tab-content" role="tabpanel">
          <ActivePanel />
        </main>
      </div>
    </ContributeModeContext.Provider>
  );
}
