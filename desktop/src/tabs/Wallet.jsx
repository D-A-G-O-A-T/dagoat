import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getAddress } from "viem";
import { useContributeMode } from "../contributeMode.js";
import AddWalletOverlay from "../components/AddWalletOverlay.jsx";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import { getDeployment, isDeployed } from "../chain/addresses.js";
import { extractErrorName, getPublicClient, getWalletClient } from "../chain/client.js";
import { listWallets, unlock, useActiveAccount, useActiveWallet, useUnlockProgress } from "../chain/wallet.js";
import { runTx } from "../chain/tx.js";
import { commandError, rpcUnreachableHint } from "../chain/errors.js";
import {
  cleanCustomName, fullUsername, generatePasskey, GOAT_USERNAME_PREFIX,
} from "../identity.js";
import { bindWalletFahProfile, getWalletFahProfile } from "../walletProfiles.js";
import { tryAutoEnroll } from "../chain/enroll.js";
import { USERNAME_CAUTION } from "../onboarding/copy.js";
import {
  GOAT_COIN_ABI,
  HOLDBACK_ESCROW_ABI,
  MOCK_USDT_ABI,
  WORK_MINTER_ABI,
} from "../chain/abis.js";
import { FAH_CATALOG_LABEL, SEASON0_FAH_JOB_ID, WORK_UNIT_FORMULA } from "../chain/constants.js";
import { formatGoat, formatUsdt, parseGoat, parseUsdt, shortHash, testnetAmount } from "../chain/format.js";
import { isTestnetWithMockUsdt } from "../opsAccess.js";

const POLL_MS = 10_000;

const MINT_BATCH_EVENT = WORK_MINTER_ABI.find((item) => item.type === "event" && item.name === "MintBatch");

const ERROR_COPY = {
  TransferRestricted:
    "Transfer blocked: both addresses must be enrolled (use Market → Enroll myself, or founder enroll) — GoatCoin reverted with TransferRestricted.",
};

function friendlyError(err, networkId) {
  const hint = rpcUnreachableHint(err, networkId);
  if (hint) return hint;
  const name = extractErrorName(err);
  if (name && ERROR_COPY[name]) return ERROR_COPY[name];
  return err?.shortMessage || err?.message || String(err);
}

const EMPTY_BALANCES = { liquid: 0n, holdback: 0n, usdt: 0n };
const shortAddr = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "");

export default function Wallet() {
  const { goatPilot } = useContributeMode();
  const { networkId, network } = useNetwork();
  const deployment = getDeployment(networkId);
  const deployed = isDeployed(networkId);

  // Active wallet lives in Rust; JS only ever sees the address + a Rust-backed
  // viem account. No private key is ever in JS.
  const account = useActiveAccount();

  const [balances, setBalances] = useState(EMPTY_BALANCES);
  const [provenance, setProvenance] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [lastRefreshed, setLastRefreshed] = useState(null);

  const [transferTo, setTransferTo] = useState("");
  const [transferAmount, setTransferAmount] = useState("");
  const [transferState, setTransferState] = useState({ status: "idle", message: "" });

  const [usdtTo, setUsdtTo] = useState("");
  const [usdtAmount, setUsdtAmount] = useState("");
  const [usdtSendState, setUsdtSendState] = useState({ status: "idle", message: "" });

  const [faucetAmount, setFaucetAmount] = useState("1000");
  const [faucetState, setFaucetState] = useState({ status: "idle", message: "" });
  // Show faucet whenever this chain has MockUSDT (Season-0 testnets). Workers can mint for
  // desk/donor testing; 0 balance is still the normal worker default.
  const showMockUsdtFaucet =
    Boolean(deployment?.mockUSDT) &&
    (isTestnetWithMockUsdt(networkId) || Number(networkId) === 31337 || Number(networkId) === 84532);

  const address = account?.address ?? null;

  const publicClient = useMemo(() => {
    try {
      return getPublicClient(networkId);
    } catch {
      return null;
    }
  }, [networkId]);

  const walletClient = useMemo(() => {
    try {
      return getWalletClient(networkId, account);
    } catch {
      return null;
    }
  }, [networkId, account]);

  const refresh = useCallback(async () => {
    if (!publicClient || !deployed) return;
    setLoading(true);
    setLoadError("");
    try {
      // Provenance is best-effort and bounded — full-history eth_getLogs after unlock
      // has frozen/crashed the desktop shell on Windows (consultant pilot).
      try {
        const latest = await publicClient.getBlockNumber();
        const window = 5_000n;
        const fromBlock = latest > window ? latest - window : 0n;
        const mintLogs = await publicClient.getLogs({
          address: deployment.workMinter,
          event: MINT_BATCH_EVENT,
          args: { jobId: SEASON0_FAH_JOB_ID },
          fromBlock,
          toBlock: "latest",
        });
        setProvenance(
          mintLogs
            .map((log) => ({
              key: `${log.transactionHash}-${log.logIndex}`,
              manifestRoot: log.args.manifestRoot,
              totalUnits: log.args.totalUnits,
              totalGoat: log.args.totalGoat,
              blockNumber: log.blockNumber,
            }))
            .sort((a, b) => (b.blockNumber > a.blockNumber ? 1 : -1)),
        );
      } catch {
        setProvenance([]);
      }

      if (address) {
        const [liquid, holdback, usdt] = await Promise.all([
          publicClient.readContract({
            address: deployment.goatCoin,
            abi: GOAT_COIN_ABI,
            functionName: "balanceOf",
            args: [address],
          }),
          publicClient.readContract({
            address: deployment.holdbackEscrow,
            abi: HOLDBACK_ESCROW_ABI,
            functionName: "holdbackOf",
            args: [SEASON0_FAH_JOB_ID, address],
          }),
          publicClient.readContract({
            address: deployment.mockUSDT,
            abi: MOCK_USDT_ABI,
            functionName: "balanceOf",
            args: [address],
          }),
        ]);
        setBalances({ liquid, holdback, usdt });
      } else {
        setBalances(EMPTY_BALANCES);
      }
      setLastRefreshed(new Date());
    } catch (err) {
      setLoadError(friendlyError(err, networkId));
    } finally {
      setLoading(false);
    }
  }, [publicClient, deployed, deployment, address]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  async function tx({ address: contractAddress, abi, functionName, args }) {
    return runTx({ publicClient, walletClient, account, address: contractAddress, abi, functionName, args });
  }

  async function handleTransfer(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment) return;
    setTransferState({ status: "pending", message: "" });
    try {
      const to = getAddress(transferTo.trim());
      const amount = parseGoat(transferAmount);
      if (amount === 0n) throw new Error("Enter an amount greater than 0.");
      const hash = await tx({
        address: deployment.goatCoin,
        abi: GOAT_COIN_ABI,
        functionName: "transfer",
        args: [to, amount],
      });
      setTransferState({ status: "success", message: `Sent (testnet). Tx ${shortHash(hash)}` });
      setTransferAmount("");
      refresh();
    } catch (err) {
      setTransferState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // MockUSDT send — optional. Workers usually stay at 0 USDT; donors/sellers may move USDT out.
  // Not used for bind/enroll (those need ETH gas or the gasless relayer).
  async function handleSendUsdt(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment) return;
    setUsdtSendState({ status: "pending", message: "" });
    try {
      const to = getAddress(usdtTo.trim());
      const amount = parseUsdt(usdtAmount);
      if (amount === 0n) throw new Error("Enter an amount greater than 0.");
      const hash = await tx({
        address: deployment.mockUSDT,
        abi: MOCK_USDT_ABI,
        functionName: "transfer",
        args: [to, amount],
      });
      setUsdtSendState({ status: "success", message: `Sent (testnet). Tx ${shortHash(hash)}` });
      setUsdtAmount("");
      refresh();
    } catch (err) {
      setUsdtSendState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // MockUSDT faucet (testnets only: anvil 31337 / Base Sepolia 84532).
  async function handleFaucet(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment?.mockUSDT) return;
    setFaucetState({ status: "pending", message: "" });
    try {
      const amount = parseUsdt(faucetAmount);
      if (amount === 0n) throw new Error("Enter an amount greater than 0.");
      const hash = await tx({
        address: deployment.mockUSDT,
        abi: MOCK_USDT_ABI,
        functionName: "mint",
        args: [account.address, amount],
      });
      setFaucetState({ status: "success", message: `Minted (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setFaucetState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  if (!deployed) {
    return (
      <section className="tab-panel">
        <h2 className="page-title">Wallet</h2>
        {!goatPilot && (
          <p className="mode-gate-note" role="status">
            You&apos;re in public-good-only mode. Switch to Public good + GOAT pilot to use wallet
            features.
          </p>
        )}
        <WalletManager />
        <p className="placeholder-note">
          {network?.name ?? `Chain ${networkId}`} has no Season-0 v2 deployment yet.
          {deployment?.note ? ` ${deployment.note}` : ""}
        </p>
      </section>
    );
  }

  return (
    <section className="tab-panel wallet-tab">
      <h2 className="page-title">Wallet</h2>

      {!goatPilot && (
        <p className="mode-gate-note" role="status">
          You&apos;re in public-good-only mode. Switch to Public good + GOAT pilot to use wallet
          features.
        </p>
      )}

      <WalletManager />

      <div className="wallet-section">
        <div className="wallet-section-header">
          <h3>Balances</h3>
          <div className="wallet-actions-row">
            <button type="button" onClick={refresh} disabled={loading}>
              {loading ? "Refreshing…" : "Refresh"}
            </button>
            {lastRefreshed && <span className="muted">Updated {lastRefreshed.toLocaleTimeString()}</span>}
          </div>
        </div>
        {loadError && <p className="error-text">{loadError}</p>}
        {!account ? (
          <p className="placeholder-note">Unlock a wallet to see balances.</p>
        ) : (
          <dl className="balance-grid">
            <dt>Liquid GOAT</dt>
            <dd>{testnetAmount(formatGoat(balances.liquid), "GOAT")}</dd>
            <dt>Holdback (unsettled 5%)</dt>
            <dd>{testnetAmount(formatGoat(balances.holdback), "GOAT")}</dd>
            <dt>Total GOAT</dt>
            <dd>{testnetAmount(formatGoat(balances.liquid + balances.holdback), "GOAT")}</dd>
            <dt>MockUSDT</dt>
            <dd>{testnetAmount(formatUsdt(balances.usdt), "USDT")}</dd>
          </dl>
        )}
        <p className="placeholder-note">
          Workers usually keep MockUSDT at <strong>0</strong> (earn GOAT; sell on Market if wanted).
          Bind &amp; enroll does <strong>not</strong> use MockUSDT — needs gasless relayer or a little{" "}
          <strong>ETH</strong>.
        </p>
      </div>

      <div className="wallet-section">
        <h3>MockUSDT faucet</h3>
        {showMockUsdtFaucet ? (
          <div className="wallet-form-block">
            <p className="muted">
              Testnet only — mint MockUSDT to this wallet (signer). Not gas; not required for bind/enroll.
            </p>
            <form className="wallet-form" onSubmit={handleFaucet}>
              <input
                type="text"
                placeholder="Amount (USDT)"
                value={faucetAmount}
                onChange={(e) => setFaucetAmount(e.target.value)}
                disabled={!account}
              />
              <button type="submit" disabled={!account || faucetState.status === "pending"}>
                {faucetState.status === "pending" ? "Minting…" : "MockUSDT faucet (testnet)"}
              </button>
            </form>
            {faucetState.message && (
              <p className={faucetState.status === "error" ? "error-text" : "status-ok"}>
                {faucetState.message}
              </p>
            )}
          </div>
        ) : (
          <p className="placeholder-note">
            MockUSDT faucet is only on Local anvil (31337) / Base Sepolia (84532) when MockUSDT is
            deployed. Switch network or redeploy Season-0 if this is missing.
          </p>
        )}
      </div>

      <div className="wallet-section">
        <h3>Provenance</h3>
        {provenance.length === 0 ? (
          <p className="placeholder-note">No mint batches recorded yet.</p>
        ) : (
          <ul className="provenance-list">
            {provenance.map((p) => (
              <li key={p.key}>
                batch {shortHash(p.manifestRoot)} — {p.totalUnits.toString()} units →{" "}
                {testnetAmount(formatGoat(p.totalGoat), "GOAT")}
                <span className="muted"> · {FAH_CATALOG_LABEL}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="wallet-section">
        <h3>Transfer</h3>
        <p className="placeholder-note">
          Both the sender and recipient must be enrolled, or GoatCoin reverts with TransferRestricted.
        </p>
        <form className="wallet-form" onSubmit={handleTransfer}>
          <input
            type="text"
            placeholder="0x… recipient"
            value={transferTo}
            onChange={(e) => setTransferTo(e.target.value)}
            disabled={!account}
          />
          <input
            type="text"
            placeholder="Amount (GOAT)"
            value={transferAmount}
            onChange={(e) => setTransferAmount(e.target.value)}
            disabled={!account}
          />
          <button type="submit" disabled={!account || transferState.status === "pending"}>
            {transferState.status === "pending" ? "Sending…" : "Send"}
          </button>
        </form>
        {transferState.message && (
          <p className={transferState.status === "error" ? "error-text" : "status-ok"}>{transferState.message}</p>
        )}
      </div>

      <div className="wallet-section">
        <h3>Send USDT</h3>
        <p className="placeholder-note">
          Optional. MockUSDT is not gas. Send to any address when you hold USDT (sell proceeds or
          faucet). Workers can leave this at zero.
        </p>
        <form className="wallet-form" onSubmit={handleSendUsdt}>
          <input
            type="text"
            placeholder="0x… recipient"
            value={usdtTo}
            onChange={(e) => setUsdtTo(e.target.value)}
            disabled={!account}
          />
          <input
            type="text"
            placeholder="Amount (USDT)"
            value={usdtAmount}
            onChange={(e) => setUsdtAmount(e.target.value)}
            disabled={!account}
          />
          <button type="submit" disabled={!account || usdtSendState.status === "pending"}>
            {usdtSendState.status === "pending" ? "Sending…" : "Send USDT"}
          </button>
        </form>
        {usdtSendState.message && (
          <p className={usdtSendState.status === "error" ? "error-text" : "status-ok"}>
            {usdtSendState.message}
          </p>
        )}
      </div>

      <footer className="wallet-footer">
        <p>{WORK_UNIT_FORMULA}</p>
      </footer>
    </section>
  );
}

// Password-protected multi-wallet manager. The private key never enters JS —
// create/import/unlock/lock all round-trip through the Rust wallet_* commands
// (see the "Password-Protected Multi-Wallet with Rust-Side Signing — Design"
// spec, §3.3).
function WalletManager() {
  const activeMeta = useActiveWallet();
  const { networkId } = useNetwork();

  const [wallets, setWallets] = useState([]);
  const [listError, setListError] = useState("");

  const reloadList = useCallback(async () => {
    try {
      const list = await listWallets();
      setWallets(Array.isArray(list) ? list : []);
      setListError("");
    } catch (err) {
      // Outside Tauri (dev in a plain browser) there are simply no wallets.
      setWallets([]);
      setListError(commandError(err));
    }
  }, []);

  useEffect(() => {
    reloadList();
  }, [reloadList, activeMeta?.address]);

  // ---- unlock / switch -----------------------------------------------------
  // unlockProgress is module-level (wallet.js): App unmounts this tab on switch,
  // so local "Unlocking…" state would reset while wallet_unlock is still in flight.
  const unlockProgress = useUnlockProgress();
  const [selectedName, setSelectedName] = useState("");
  const [unlockPw, setUnlockPw] = useState("");
  // Pre-submit validation only (pick wallet / empty password) — not used for pending.
  const [unlockFormError, setUnlockFormError] = useState("");

  // T27 P8: dropdown always lists the currently active wallet first.
  const orderedWallets = sortWalletsActiveFirst(wallets, activeMeta?.name);

  // Default the dropdown to the first listed wallet (= active when one is unlocked).
  useEffect(() => {
    if (!selectedName && orderedWallets.length > 0) setSelectedName(orderedWallets[0].name);
  }, [orderedWallets, selectedName]);

  async function handleUnlock(e) {
    e.preventDefault();
    if (!selectedName) return setUnlockFormError("Pick a wallet.");
    if (!unlockPw) return setUnlockFormError("Enter the wallet password.");
    if (unlockProgress.status === "pending") return;
    setUnlockFormError("");
    try {
      await unlock(selectedName, unlockPw);
      setUnlockPw("");
    } catch {
      // Error message lives on unlockProgress (survives remount); password stays for retry.
    }
  }

  const unlockPending = unlockProgress.status === "pending";
  const unlockMessage = unlockFormError || unlockProgress.message;
  const unlockMessageIsError = Boolean(unlockFormError) || unlockProgress.status === "error";

  const hasWallets = wallets.length > 0;

  // A1 (spec §16, amends D3): "Add another wallet" opens an overlay reusing the wizard's
  // create/import steps. Visible whether or not a wallet is currently unlocked. Closing it
  // (Cancel, Done, or a completed import) reloads the stored-wallet list so the new entry
  // (and its now-active/unlocked state) appears immediately.
  const [addWalletOpen, setAddWalletOpen] = useState(false);

  // Missing FAH profile (e.g. Bob created before per-wallet usernames): one-time bind form.
  const [fahProfile, setFahProfile] = useState(undefined); // undefined=loading, null=missing
  const [bindUser, setBindUser] = useState("");
  const [bindBusy, setBindBusy] = useState(false);
  const [bindError, setBindError] = useState("");
  const [bindOk, setBindOk] = useState("");

  useEffect(() => {
    let cancelled = false;
    setFahProfile(undefined);
    setBindOk("");
    setBindError("");
    if (!activeMeta?.address) {
      setFahProfile(null);
      return undefined;
    }
    getWalletFahProfile(activeMeta.address).then((p) => {
      if (!cancelled) setFahProfile(p);
    });
    return () => {
      cancelled = true;
    };
  }, [activeMeta?.address]);

  async function handleBindFahProfile(e) {
    e.preventDefault();
    if (!activeMeta?.address || bindBusy) return;
    const username = fullUsername(bindUser);
    if (!username) {
      setBindError("Enter a GOAT username (letters, digits, _).");
      return;
    }
    setBindBusy(true);
    setBindError("");
    setBindOk("");
    try {
      const pk = generatePasskey();
      await bindWalletFahProfile(activeMeta.address, { username, passkey: pk });
      await tryAutoEnroll(networkId, activeMeta.address);
      setFahProfile({ username, passkey: pk });
      setBindUser("");
      setBindOk(`FAH profile set to ${username}. Bind & enroll continues under Contribute if needed.`);
    } catch (err) {
      setBindError(commandError(err));
    } finally {
      setBindBusy(false);
    }
  }

  return (
    <div className="wallet-section wallet-manager">
      <div className="wallet-section-header">
        <h3>Wallets</h3>
        <button type="button" onClick={() => setAddWalletOpen(true)}>
          Add another wallet
        </button>
      </div>

      {addWalletOpen && (
        <AddWalletOverlay
          onClose={() => {
            setAddWalletOpen(false);
            reloadList();
            if (activeMeta?.address) {
              getWalletFahProfile(activeMeta.address).then(setFahProfile);
            }
          }}
        />
      )}

      {activeMeta ? (
        <div className="wallet-actions-row">
          <div>
            <p>
              Wallet name: <strong>{activeMeta.name}</strong>
            </p>
            <p>
              Wallet address: <code>{activeMeta.address}</code>
            </p>
            {fahProfile?.username && (
              <p>
                GOAT username: <strong className="key-value">{fahProfile.username}</strong>
              </p>
            )}
            <RevealKeyRow activeMeta={activeMeta} />
          </div>
        </div>
      ) : (
        <p className="muted">No wallet unlocked. Unlock a stored wallet, or create/import one from the setup wizard.</p>
      )}

      {activeMeta && fahProfile === null && (
        <form className="wallet-form" onSubmit={handleBindFahProfile}>
          <p className="warning-text">
            This wallet has no GOAT username yet. Without one, FAH stays on another wallet&apos;s
            profile and bind/enroll will fail. Choose a unique name for this wallet.
          </p>
          <label className="muted">GOAT username</label>
          <div className="firstrun-input-row">
            <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
            <input
              type="text"
              placeholder="your name (letters, digits, _)"
              value={bindUser}
              onChange={(e) => setBindUser(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <p className="warning-text">{USERNAME_CAUTION}</p>
          <button type="submit" disabled={bindBusy || !cleanCustomName(bindUser)}>
            {bindBusy ? "Binding…" : "Set GOAT username for this wallet"}
          </button>
          {bindError && <p className="error-text">{bindError}</p>}
          {bindOk && <p className="status-ok">{bindOk}</p>}
        </form>
      )}

      {listError && <p className="placeholder-note">{listError}</p>}

      {hasWallets && (
        <form className="wallet-form" onSubmit={handleUnlock}>
          <label className="muted" htmlFor="wallet-select">
            {activeMeta ? "Switch / unlock a stored wallet" : "Unlock a stored wallet"}
          </label>
          <select
            id="wallet-select"
            value={selectedName}
            onChange={(e) => setSelectedName(e.target.value)}
          >
            {orderedWallets.map((w) => (
              <option key={w.name} value={w.name}>
                Name: {w.name} · Address: {shortAddr(w.address)}
              </option>
            ))}
          </select>
          <input
            type="password"
            placeholder="Wallet password"
            value={unlockPw}
            onChange={(e) => setUnlockPw(e.target.value)}
          />
          <button type="submit" disabled={unlockPending}>
            {unlockPending ? "Unlocking…" : "Unlock"}
          </button>
        </form>
      )}
      {unlockMessage && (
        <p className={unlockMessageIsError ? "error-text" : "status-ok"}>{unlockMessage}</p>
      )}
    </div>
  );
}

/** D1: the revealed key auto-remasks whenever the unlocked wallet goes away or changes. */
export function shouldRemask(prevAddress, nextAddress) {
  return Boolean(prevAddress) && prevAddress !== nextAddress;
}

/** T27 P8 (pure): the currently active wallet always lists first; the rest keep
 *  their stored order. Unknown/absent active name = order unchanged. */
export function sortWalletsActiveFirst(wallets, activeName) {
  const list = Array.isArray(wallets) ? wallets : [];
  if (!activeName) return list;
  const idx = list.findIndex((w) => w?.name === activeName);
  if (idx <= 0) return list;
  return [list[idx], ...list.slice(0, idx), ...list.slice(idx + 1)];
}

// Masked-by-default private-key reveal row. The key only ever exists in this
// component's state, is never logged, and is cleared on re-mask / lock /
// switch / unmount (see shouldRemask + the effects below) — D1 §11.
function RevealKeyRow({ activeMeta }) {
  const [revealed, setRevealed] = useState(null); // string | null
  const [error, setError] = useState("");
  const prevAddr = useRef(activeMeta?.address ?? null);

  useEffect(() => {
    if (shouldRemask(prevAddr.current, activeMeta?.address ?? null)) {
      setRevealed(null);
      setError("");
    }
    prevAddr.current = activeMeta?.address ?? null;
  }, [activeMeta?.address]);

  useEffect(() => () => setRevealed(null), []); // unmount (tab change) remasks

  async function toggle() {
    if (revealed) {
      setRevealed(null);
      return;
    }
    try {
      const key = await invoke("wallet_reveal_key", { expectedAddress: activeMeta.address });
      setRevealed(key);
      setError("");
    } catch (err) {
      setError(String(err?.message ?? err)); // stays masked on failure (spec §11)
    }
  }

  return (
    <div className="reveal-key-row">
      <span className="muted">Private key:</span>
      <button
        type="button"
        className="reveal-key-row__value"
        onClick={toggle}
        title={revealed ? "Click to hide" : "Click to reveal"}
      >
        {revealed ? <code>{revealed}</code> : <span aria-label="hidden">••••••••••</span>}
      </button>
      {error && <span className="error-text">{error}</span>}
    </div>
  );
}
