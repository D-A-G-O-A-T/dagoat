import { useEffect, useMemo, useRef, useState } from "react";
import { motion, MotionConfig } from "motion/react";
import { invoke } from "@tauri-apps/api/core";
import HonestyBanner from "./components/HonestyBanner.jsx";
import NetworkSwitch, { NetworkProvider, useNetwork } from "./components/NetworkSwitch.jsx";
import BrandLockup from "./components/BrandLockup.jsx";
import EarnSwitch from "./components/EarnSwitch.jsx";
import {
  ContributeModeContext,
  loadContributeModeV2,
  MODE_PUBLIC_GOOD,
  MODE_WITH_GOAT,
  saveContributeModeV2,
} from "./contributeMode.js";
import { getDeployment, isDeployed } from "./chain/addresses.js";
import { getPublicClient } from "./chain/client.js";
import { ENROLLMENT_REGISTRY_ABI } from "./chain/abis.js";
import { useActiveAccount } from "./chain/wallet.js";
import { canSeeOpsTab, isFounderWallet } from "./opsAccess.js";
import OnboardingWizard from "./onboarding/OnboardingWizard.jsx";
import { loadOnboardingFlags, routeBoot, saveOnboardingFlags } from "./onboarding/onboardingState.js";
import { listWallets } from "./chain/wallet.js";
import { getWalletFahProfile } from "./walletProfiles.js";
import Miner, {
  isActiveStatus,
  finishingNote,
  setFoldGateNote,
  clearFoldGateNote,
  clearContributeSession,
  shouldGateOnWalletSwitch,
} from "./tabs/Miner.jsx";
import Wallet from "./tabs/Wallet.jsx";
import Market from "./tabs/Market.jsx";
import Ops from "./tabs/Ops.jsx";

const FAH_BACKEND_ID = "folding_at_home"; // Season 0's only real work backend (module const, not per-render)

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
    // reducedMotion="user" makes EVERY motion/react animation (wizard steps,
    // tab spring, switch) honor the OS prefers-reduced-motion setting (spec §4).
    <MotionConfig reducedMotion="user">
      <NetworkProvider>
        <BootGate />
      </NetworkProvider>
    </MotionConfig>
  );
}

function BootGate() {
  // null = still resolving (render only the gradient — no wizard/shell flash).
  const [boot, setBoot] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [flags, wallets] = await Promise.all([
        loadOnboardingFlags(),
        listWallets().catch(() => []),
      ]);
      const route = routeBoot({ flags, walletCount: wallets.length });
      if (route.selfHeal) await saveOnboardingFlags(route.selfHeal);
      if (!cancelled) setBoot({ route, flags: route.selfHeal ?? flags });
    })();
    return () => { cancelled = true; };
  }, []);

  if (!boot) return null; // theme.css body gradient shows while loading
  if (boot.route.screen !== "shell") {
    return (
      <OnboardingWizard
        initialStep={boot.route.screen === "disclaimer" ? "disclaimer" : "wallet_gate"}
        onFinished={(flags) => setBoot({ route: { screen: "shell", selfHeal: null }, flags })}
      />
    );
  }
  return <AppShell onboardingFlags={boot.flags} />;
}

function AppShell({ onboardingFlags }) {
  const [active, setActive] = useState("miner");
  const [mode, setModeState] = useState(MODE_PUBLIC_GOOD); // resolves async below
  const [wizardRequest, setWizardRequest] = useState(false);
  const [opsVisible, setOpsVisible] = useState(false);

  const { networkId } = useNetwork();
  const account = useActiveAccount();
  const ActivePanel = PANELS[active] ?? Miner;

  useEffect(() => {
    loadContributeModeV2(onboardingFlags?.choice).then(({ effective }) => setModeState(effective));
  }, [onboardingFlags?.choice]);

  // B4/B4a: wallet switch auto-stops folding — no hot-swap of the live identity mid-fold. If a
  // managed run is active when the active wallet changes, put the FAH client into its native
  // "finish" state (in-flight unit completes + uploads under the OLD name, then idles) instead of
  // silently reassigning the live identity. The new wallet's Start stays gated (Miner's
  // foldGateNote) until the client reports idle again. Dump (per-row, in Miner) remains the
  // no-wait escape for a user who doesn't want to wait.
  const prevWalletAddressRef = useRef(null);
  useEffect(() => {
    const prevAddr = prevWalletAddressRef.current;
    const nextAddr = account?.address ?? null;
    prevWalletAddressRef.current = nextAddr;
    if (!shouldGateOnWalletSwitch(prevAddr, nextAddr)) return;

    // FIX-A: each switch run owns the gate — drop any prior instance's note up front so a
    // stranded note (rapid A→B→A cancelled the first run mid-poll) can never survive into a
    // run that early-returns below, and a fresh run never shows a stale name pair.
    clearFoldGateNote();

    let cancelled = false;
    (async () => {
      let status = null;
      try {
        status = await invoke("backend_status", { id: FAH_BACKEND_ID });
      } catch {
        return; // not attached — nothing folding, nothing to gate
      }
      if (cancelled || !isActiveStatus(status)) return;

      const [oldProfile, newProfile] = await Promise.all([
        getWalletFahProfile(prevAddr).catch(() => null),
        getWalletFahProfile(nextAddr).catch(() => null),
      ]);
      if (cancelled) return;
      setFoldGateNote(finishingNote(oldProfile?.username, newProfile?.username));
      try {
        await invoke("backend_finish", { id: FAH_BACKEND_ID });
      } catch {
        // FIX-A: fail-open — a rejected finish must not brick Start. The run keeps folding
        // (still managed: Pause/Stop/Dump remain in Miner), and Start-time identity sync
        // still protects attribution on the next Start.
        clearFoldGateNote();
        return;
      }
      clearContributeSession(FAH_BACKEND_ID);

      while (!cancelled) {
        await new Promise((r) => setTimeout(r, 3000));
        if (cancelled) return;
        let snap = null;
        try {
          snap = await invoke("backend_status", { id: FAH_BACKEND_ID });
        } catch {
          break; // client gone — nothing left to wait for
        }
        if (!isActiveStatus(snap)) break;
      }
      if (!cancelled) clearFoldGateNote();
    })();

    return () => {
      cancelled = true;
    };
  }, [account?.address]);

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
    saveContributeModeV2(next);
  };

  async function handleEarnSwitch(next) {
    if (next) {
      const wallets = await listWallets().catch(() => []);
      if (wallets.length === 0) {
        setWizardRequest(true); // D4: earning needs a wallet — route into the wizard
        return;
      }
    }
    setMode(next ? MODE_WITH_GOAT : MODE_PUBLIC_GOOD);
  }

  // NOTE (deviation from brief): useMemo is hoisted above the wizardRequest early
  // return. The brief's snippet placed this useMemo after the early return, but a
  // hook called on some renders and skipped on others (depending on wizardRequest)
  // violates React's rules of hooks — the hook count for this fiber would differ
  // between renders and React would throw "Rendered fewer hooks than expected."
  // All hooks must run unconditionally before any conditional return.
  const modeValue = useMemo(
    () => ({
      mode,
      setMode,
      goatPilot: mode === MODE_WITH_GOAT,
    }),
    [mode],
  );

  if (wizardRequest) {
    return (
      <OnboardingWizard
        initialStep="wallet_gate"
        onFinished={(flags) => {
          setWizardRequest(false);
          // D4: only a wallet outcome turns earning on. A user who reached the
          // gate via the switch but clicked the opt-out link stays public-good.
          if (flags?.choice === "wallet") setMode(MODE_WITH_GOAT);
        }}
      />
    );
  }

  const visibleTabs = TABS.filter((tab) => tab.id !== "ops" || opsVisible);

  return (
    <ContributeModeContext.Provider value={modeValue}>
      <div className="app">
        <header className="header glass">
          <BrandLockup />
          <div className="header__right">
            <EarnSwitch on={mode === MODE_WITH_GOAT} onChange={handleEarnSwitch} />
            <NetworkSwitch />
          </div>
        </header>

        <nav className="tabs glass" role="tablist">
          {visibleTabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active === tab.id}
              className={`tab ${active === tab.id ? "active" : ""}`}
              onClick={() => setActive(tab.id)}
            >
              {active === tab.id && (
                <motion.span layoutId="tab-highlight" className="tab__highlight"
                  transition={{ type: "spring", stiffness: 420, damping: 34 }} />
              )}
              <span className="tab__label">{tab.label}</span>
            </button>
          ))}
        </nav>

        <main className="tab-content" role="tabpanel">
          {/* T25 C4: no AnimatePresence/exit — old tab unmounts synchronously, new
              content fades in 150ms. mode="wait" serialized ~320ms of dead time. */}
          <motion.div key={active}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.15, ease: "easeOut" }}>
            <ActivePanel />
          </motion.div>
        </main>

        <HonestyBanner />
      </div>
    </ContributeModeContext.Provider>
  );
}
