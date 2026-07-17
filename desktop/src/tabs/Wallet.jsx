import { useCallback, useEffect, useMemo, useState } from "react";
import { getAddress } from "viem";
import { useContributeMode } from "../contributeMode.js";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import { getDeployment, isDeployed } from "../chain/addresses.js";
import { KEY_IMPORT_WARNING, extractErrorName, getPublicClient, getWalletClient } from "../chain/client.js";
import {
  createWallet,
  importWallet,
  lock,
  listWallets,
  unlock,
  useActiveAccount,
  useActiveWallet,
} from "../chain/wallet.js";
import { createRustAccount } from "../chain/rustAccount.js";
import { ensureEnrolled } from "../chain/enroll.js";
import { runTx } from "../chain/tx.js";
import { rpcUnreachableHint } from "../chain/errors.js";
import {
  GOAT_COIN_ABI,
  HOLDBACK_ESCROW_ABI,
  MOCK_USDT_ABI,
  WORK_MINTER_ABI,
} from "../chain/abis.js";
import { FAH_CATALOG_LABEL, SEASON0_FAH_JOB_ID, WORK_UNIT_FORMULA } from "../chain/constants.js";
import { formatGoat, formatUsdt, parseGoat, parseUsdt, shortHash, testnetAmount } from "../chain/format.js";
import { isTestnetWithMockUsdt } from "../opsAccess.js";
import {
  cleanCustomName,
  fullUsername,
  GOAT_USERNAME_PREFIX,
  saveUsername,
} from "../components/FirstRunUsername.jsx";

const POLL_MS = 10_000;
const MIN_PASSWORD_LENGTH = 8;

// The password unlocks the encrypted vault; it is never stored and can't be
// recovered. If forgotten, the only way back in is the backed-up private key.
const PASSWORD_WARNING =
  "Your password can't be recovered. If you forget it, only your backed-up private key can restore this wallet — back it up now.";

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

// Tauri command rejections arrive as plain strings (Result<_, String>); normal
// JS errors arrive as Error. Surface either without leaking anything else.
function commandError(err) {
  if (typeof err === "string") return err;
  return err?.message || String(err);
}

const EMPTY_BALANCES = { liquid: 0n, holdback: 0n, usdt: 0n };
const shortAddr = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "");

/** After unlock/import: enrollSelf if needed (pays native ETH gas — anvil accounts have ETH). */
async function tryAutoEnroll(networkId, address) {
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
        <h2>Wallet</h2>
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
      <h2>Wallet</h2>

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
// (see docs/superpowers/specs/2026-07-13-stronghold-wallet-design.md §3.3).
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

  // ---- create --------------------------------------------------------------
  const [createName, setCreateName] = useState("");
  const [createPw, setCreatePw] = useState("");
  const [createPw2, setCreatePw2] = useState("");
  /** Custom part of GOAT- username (typebox); required before create. */
  const [createGoatUser, setCreateGoatUser] = useState("");
  const [createState, setCreateState] = useState({ status: "idle", message: "" });
  /** When set, show confirm dialog before actually creating. */
  const [createConfirmOpen, setCreateConfirmOpen] = useState(false);

  function handleCreateSubmit(e) {
    e.preventDefault();
    const name = createName.trim();
    if (!name) return setCreateState({ status: "error", message: "Enter a wallet name." });
    if (createPw.length < MIN_PASSWORD_LENGTH)
      return setCreateState({
        status: "error",
        message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
      });
    if (createPw !== createPw2)
      return setCreateState({ status: "error", message: "Passwords do not match." });
    if (!cleanCustomName(createGoatUser))
      return setCreateState({
        status: "error",
        message: "Enter a GOAT username (letters, digits, underscore) — this wallet will bind to it.",
      });
    setCreateState({ status: "idle", message: "" });
    setCreateConfirmOpen(true);
  }

  async function handleCreateConfirmed() {
    const name = createName.trim();
    const goatFull = fullUsername(createGoatUser);
    setCreateConfirmOpen(false);
    setCreateState({ status: "pending", message: "" });
    try {
      // Persist FAH/GOAT username first so Contribute + auto-bind use the same name.
      await saveUsername(createGoatUser);
      const meta = await createWallet(name, createPw);
      await unlock(name, createPw);
      const enroll = await tryAutoEnroll(networkId, meta.address);
      setCreateName("");
      setCreatePw("");
      setCreatePw2("");
      setCreateGoatUser("");
      let msg = `Created and unlocked ${shortAddr(meta.address)}. FAH username ${goatFull} saved. Back up your key.`;
      if (enroll?.already) msg += " Already enrolled.";
      else if (enroll?.hash) msg += " Enrolled on-chain (self).";
      else if (enroll?.error) msg += ` Enrollment skipped: ${enroll.error}`;
      msg += " Open Contribute to Bind & enroll (gasless) under that GOAT- name.";
      setCreateState({ status: "success", message: msg });
      reloadList();
    } catch (err) {
      setCreateState({ status: "error", message: commandError(err) });
    }
  }

  // ---- import --------------------------------------------------------------
  const [importName, setImportName] = useState("");
  const [importPw, setImportPw] = useState("");
  const [importKey, setImportKey] = useState("");
  const [importState, setImportState] = useState({ status: "idle", message: "" });

  async function handleImport(e) {
    e.preventDefault();
    const name = importName.trim();
    if (!name) return setImportState({ status: "error", message: "Enter a wallet name." });
    if (importPw.length < MIN_PASSWORD_LENGTH)
      return setImportState({ status: "error", message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
    if (!importKey.trim()) return setImportState({ status: "error", message: "Enter a private key." });
    setImportState({ status: "pending", message: "" });
    try {
      const meta = await importWallet(name, importPw, importKey.trim());
      await unlock(name, importPw); // make the imported wallet the active signer
      const enroll = await tryAutoEnroll(networkId, meta.address);
      setImportName("");
      setImportPw("");
      setImportKey("");
      let msg = `Imported and unlocked ${shortAddr(meta.address)}.`;
      if (enroll?.already) msg += " Already enrolled.";
      else if (enroll?.hash) msg += " Enrolled on-chain (self).";
      else if (enroll?.error) msg += ` Enrollment skipped: ${enroll.error}`;
      setImportState({ status: "success", message: msg });
      reloadList();
    } catch (err) {
      setImportState({ status: "error", message: commandError(err) });
    }
  }

  // ---- unlock / switch -----------------------------------------------------
  const [selectedName, setSelectedName] = useState("");
  const [unlockPw, setUnlockPw] = useState("");
  const [unlockState, setUnlockState] = useState({ status: "idle", message: "" });

  // Default the dropdown to the first stored wallet once the list loads.
  useEffect(() => {
    if (!selectedName && wallets.length > 0) setSelectedName(wallets[0].name);
  }, [wallets, selectedName]);

  async function handleUnlock(e) {
    e.preventDefault();
    if (!selectedName) return setUnlockState({ status: "error", message: "Pick a wallet." });
    if (!unlockPw) return setUnlockState({ status: "error", message: "Enter the wallet password." });
    setUnlockState({ status: "pending", message: "" });
    try {
      const meta = await unlock(selectedName, unlockPw);
      setUnlockPw("");
      setUnlockState({ status: "success", message: `Unlocked ${shortAddr(meta.address)}.` });
    } catch (err) {
      // Non-leaky: Rust returns a typed "wrong password" style string.
      setUnlockState({ status: "error", message: commandError(err) });
    }
  }

  async function handleLock() {
    try {
      await lock();
      setUnlockState({ status: "idle", message: "" });
    } catch (err) {
      setUnlockState({ status: "error", message: commandError(err) });
    }
  }

  const hasWallets = wallets.length > 0;

  return (
    <div className="wallet-section wallet-manager">
      <h3>Wallets</h3>

      {activeMeta ? (
        <div className="wallet-actions-row">
          <div>
            <p>
              Wallet name: <strong>{activeMeta.name}</strong>
            </p>
            <p>
              Wallet address: <code>{activeMeta.address}</code>
            </p>
          </div>
          <button type="button" onClick={handleLock}>
            Lock
          </button>
        </div>
      ) : (
        <p className="muted">No wallet unlocked. Create, import, or unlock one below.</p>
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
            {wallets.map((w) => (
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
          <button type="submit" disabled={unlockState.status === "pending"}>
            {unlockState.status === "pending" ? "Unlocking…" : "Unlock"}
          </button>
        </form>
      )}
      {unlockState.message && (
        <p className={unlockState.status === "error" ? "error-text" : "status-ok"}>{unlockState.message}</p>
      )}

      <details className="wallet-add" open={!hasWallets}>
        <summary>{hasWallets ? "Add another wallet" : "Create or import a wallet"}</summary>

        <p className="warning-text">{PASSWORD_WARNING}</p>

        <div className="wallet-form-block">
          <h4>Create wallet</h4>
          <p className="muted">
            Generates a fresh key in Rust and seals it in a password-encrypted Stronghold snapshot —
            the key never leaves Rust and never enters this app&apos;s JavaScript.
          </p>
          <form className="wallet-form" onSubmit={handleCreateSubmit}>
            <input
              type="text"
              placeholder="Wallet name (local label)"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              autoComplete="off"
            />
            <label className="muted" htmlFor="create-goat-username" style={{ width: "100%" }}>
              GOAT username (FAH / pilot bind) — required
            </label>
            <div className="firstrun-input-row" style={{ width: "100%" }}>
              <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
              <input
                id="create-goat-username"
                type="text"
                placeholder="your name (letters, digits, _)"
                value={createGoatUser}
                onChange={(e) => setCreateGoatUser(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <p className="muted firstrun-preview">
              Will bind as <strong>{fullUsername(createGoatUser) || "GOAT-…"}</strong>
            </p>
            <input
              type="password"
              placeholder={`Password (min ${MIN_PASSWORD_LENGTH} chars)`}
              value={createPw}
              onChange={(e) => setCreatePw(e.target.value)}
            />
            <input
              type="password"
              placeholder="Confirm password"
              value={createPw2}
              onChange={(e) => setCreatePw2(e.target.value)}
            />
            <button type="submit" disabled={createState.status === "pending"}>
              {createState.status === "pending" ? "Creating…" : "Create wallet"}
            </button>
          </form>
          {createState.message && (
            <p className={createState.status === "error" ? "error-text" : "status-ok"}>
              {createState.message}
            </p>
          )}
        </div>

        {createConfirmOpen && (
          <div
            className="firstrun-overlay"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="create-wallet-confirm-title"
            onKeyDown={(e) => {
              if (e.key === "Escape") setCreateConfirmOpen(false);
            }}
          >
            <div className="firstrun-card">
              <h2 id="create-wallet-confirm-title">Confirm create wallet</h2>
              <p className="warning-text" role="alert">
                This wallet will be used for pilot attribution under{" "}
                <strong>{fullUsername(createGoatUser)}</strong>. On-chain bind is{" "}
                <strong>set-once</strong>: the name cannot move to another wallet later. Do not use
                the relayer / anvil gas key as a worker wallet.
              </p>
              <p className="muted">
                Local label: <strong>{createName.trim() || "—"}</strong>
                <br />
                FAH / GOAT username: <strong>{fullUsername(createGoatUser)}</strong>
              </p>
              <div className="firstrun-actions">
                <button type="button" onClick={handleCreateConfirmed}>
                  Confirm &amp; create
                </button>
                <button type="button" className="link-button" onClick={() => setCreateConfirmOpen(false)}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="wallet-form-block">
          <h4>Import key</h4>
          <p className="warning-text">{KEY_IMPORT_WARNING}</p>
          <form className="wallet-form" onSubmit={handleImport}>
            <input
              type="text"
              placeholder="Wallet name"
              value={importName}
              onChange={(e) => setImportName(e.target.value)}
            />
            <input
              type="password"
              placeholder={`Password (min ${MIN_PASSWORD_LENGTH} chars)`}
              value={importPw}
              onChange={(e) => setImportPw(e.target.value)}
            />
            <input
              type="password"
              placeholder="0x… testnet private key"
              value={importKey}
              onChange={(e) => setImportKey(e.target.value)}
            />
            <button type="submit" disabled={importState.status === "pending"}>
              {importState.status === "pending" ? "Importing…" : "Import key"}
            </button>
          </form>
          {importState.message && (
            <p className={importState.status === "error" ? "error-text" : "status-ok"}>{importState.message}</p>
          )}
        </div>
      </details>
    </div>
  );
}
