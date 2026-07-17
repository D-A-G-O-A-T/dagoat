import { useCallback, useEffect, useMemo, useState } from "react";
import { zeroAddress } from "viem";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import DeskTable from "../components/DeskTable.jsx";
import { getDeployment, isDeployed } from "../chain/addresses.js";
import { extractErrorName, getPublicClient, getWalletClient } from "../chain/client.js";
import { useActiveAccount } from "../chain/wallet.js";
import { runTx } from "../chain/tx.js";
import { rpcUnreachableHint } from "../chain/errors.js";
import { ensureEnrolled } from "../chain/enroll.js";
import {
  BUY_DESK_ABI,
  BUY_DESK_FACTORY_ABI,
  ENROLLMENT_REGISTRY_ABI,
  GOAT_COIN_ABI,
  MOCK_USDT_ABI,
} from "../chain/abis.js";
import { WORK_UNIT_FORMULA } from "../chain/constants.js";
import {
  formatBid,
  formatCap,
  formatGoat,
  formatUsdt,
  parseGoat,
  parseUsdt,
  quoteUsdtOut,
  shortHash,
  testnetAmount,
} from "../chain/format.js";
import {
  buildDeskRow,
  ENROLLMENT_WARNING_COPY,
  HOLD_NOTICE_COPY,
  isOwnDesk,
  maxSellableGoatWei,
  NOT_EXCHANGE_COPY,
  pickDefaultDesk,
  POSTED_BID_COPY,
  SELL_INSUFFICIENT_GOAT_COPY,
  SELL_INSUFFICIENT_OWNER_USDT_COPY,
  sortDesksByBestBid,
} from "../market.js";
import { isTestnetWithMockUsdt } from "../opsAccess.js";

const POLL_MS = 10_000;
const MAX_UINT256 = 2n ** 256n - 1n;
const IDLE = { status: "idle", message: "" };
/** Slider resolution: 0..SLIDER_STEPS maps to 0..maxSellable. */
const SLIDER_STEPS = 1000;

const ERROR_COPY = {
  TransferRestricted:
    "Transfer blocked: both addresses must be enrolled (use Enroll myself above, or founder enroll) — GoatCoin reverted with TransferRestricted.",
  NotEnrolled: "That desk owner is not enrolled — they must enroll (or the founder must enroll them) before selling.",
  NoActiveSession: "No trade session open on that desk.",
  CapExceeded: "That amount would exceed the per-account cap for this trade session.",
  ZeroPayout: "That amount is too small — it would pay out 0 USDT at the current bid.",
  OwnerCannotSell: "You can't sell to your own desk — pick another donor's desk.",
  // Ambiguous without context: sell() can revert InsufficientBalance on GOAT (seller)
  // or USDT (desk owner). Prefer client pre-checks; this is the owner-USDT residual.
  ERC20InsufficientBalance: SELL_INSUFFICIENT_OWNER_USDT_COPY,
  ERC20InsufficientAllowance:
    "This desk's cap is used up (or not set) — its owner needs to raise the cap before it can buy more GOAT.",
  NotOwner: "This key is not that desk's owner.",
  AlreadyHasDesk: "This wallet already has a desk — see My desk below.",
  NoDesk: "This wallet doesn't have a desk yet — open one first.",
  ZeroAddress: "Zero address is not a valid desk owner.",
};

function friendlyError(err, networkId, sellCtx = null) {
  const hint = rpcUnreachableHint(err, networkId);
  if (hint) return hint;
  const name = extractErrorName(err);
  // Disambiguate ERC20InsufficientBalance: sell() does GOAT transferFrom first.
  if (name === "ERC20InsufficientBalance" && sellCtx) {
    const { sellWei, myGoatBalance } = sellCtx;
    if (sellWei != null && myGoatBalance != null && sellWei > myGoatBalance) {
      return SELL_INSUFFICIENT_GOAT_COPY;
    }
  }
  if (name && ERROR_COPY[name]) return ERROR_COPY[name];
  return err?.shortMessage || err?.message || String(err);
}

export default function Market() {
  const { networkId, network } = useNetwork();
  const deployment = getDeployment(networkId);
  const deployed = isDeployed(networkId) && Boolean(deployment?.buyDeskFactory);

  // The active Rust-backed account (or null) — re-renders on unlock/lock/switch
  // in the Wallet tab. Signing happens in Rust; the key is never in JS.
  const account = useActiveAccount();

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

  async function tx({ address: contractAddress, abi, functionName, args }) {
    return runTx({ publicClient, walletClient, account, address: contractAddress, abi, functionName, args });
  }

  const [desks, setDesks] = useState([]);
  const [myDeskAddress, setMyDeskAddress] = useState(null);
  const [enrolled, setEnrolled] = useState(null);
  // True only when the connected wallet is the registry's founder/safe address.
  // Desk depth is shown only to a desk's own owner (My desk panel) and to the
  // founder (debug) — never on the public list (founder direction 2026-07-13).
  const [isFounder, setIsFounder] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [lastRefreshed, setLastRefreshed] = useState(null);

  const refresh = useCallback(async () => {
    if (!publicClient || !deployed) return;
    setLoading(true);
    setLoadError("");
    try {
      const length = await publicClient.readContract({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "desksLength",
      });
      const indices = Array.from({ length: Number(length) }, (_, i) => BigInt(i));
      const deskAddresses = await Promise.all(
        indices.map((i) =>
          publicClient.readContract({
            address: deployment.buyDeskFactory,
            abi: BUY_DESK_FACTORY_ABI,
            functionName: "desks",
            args: [i],
          })
        )
      );
      const rows = await Promise.all(
        deskAddresses.map(async (deskAddress) => {
          const [owner, bid, depth, sessionRaw] = await Promise.all([
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "owner" }),
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "bid" }),
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "depth" }),
            publicClient.readContract({ address: deskAddress, abi: BUY_DESK_ABI, functionName: "currentSession" }),
          ]);
          const name = await publicClient.readContract({
            address: deployment.buyDeskFactory,
            abi: BUY_DESK_FACTORY_ABI,
            functionName: "nameOf",
            args: [owner],
          });
          return buildDeskRow({ address: deskAddress, owner, name, bid, depth, sessionRaw });
        })
      );
      setDesks(sortDesksByBestBid(rows));

      if (address) {
        const [myDesk, isEnrolled, safeAddress] = await Promise.all([
          publicClient.readContract({
            address: deployment.buyDeskFactory,
            abi: BUY_DESK_FACTORY_ABI,
            functionName: "deskOf",
            args: [address],
          }),
          publicClient.readContract({
            address: deployment.enrollmentRegistry,
            abi: ENROLLMENT_REGISTRY_ABI,
            functionName: "enrolled",
            args: [address],
          }),
          publicClient.readContract({
            address: deployment.enrollmentRegistry,
            abi: ENROLLMENT_REGISTRY_ABI,
            functionName: "safe",
          }),
        ]);
        setMyDeskAddress(myDesk && myDesk.toLowerCase() !== zeroAddress ? myDesk : null);
        setEnrolled(isEnrolled);
        setIsFounder(safeAddress?.toLowerCase() === address.toLowerCase());
      } else {
        setMyDeskAddress(null);
        setEnrolled(null);
        setIsFounder(false);
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

  const myDeskRow = useMemo(
    () => desks.find((d) => myDeskAddress && d.address.toLowerCase() === myDeskAddress.toLowerCase()) ?? null,
    [desks, myDeskAddress]
  );
  const bestOpenAddress = useMemo(() => pickDefaultDesk(desks, null)?.address ?? null, [desks]);

  // --- Sell panel -----------------------------------------------------------
  const [selectedDesk, setSelectedDesk] = useState("");
  useEffect(() => {
    const stillValid = desks.some((d) => d.address === selectedDesk && !isOwnDesk(d, address));
    if (stillValid) return;
    const def = pickDefaultDesk(desks, address);
    setSelectedDesk(def ? def.address : "");
  }, [desks, address, selectedDesk]);

  const [sellAmount, setSellAmount] = useState("");
  const [sellAllowance, setSellAllowance] = useState(0n);
  const [myGoatBalance, setMyGoatBalance] = useState(0n);
  const [sellState, setSellState] = useState(IDLE);
  const sellWei = parseGoat(sellAmount);
  const sellRow = desks.find((d) => d.address === selectedDesk) ?? null;
  const maxSellable = useMemo(
    () =>
      maxSellableGoatWei({
        goatBalance: myGoatBalance,
        bid: sellRow?.bid ?? 0n,
        depth: sellRow?.depth ?? 0n,
        sessionCap: sellRow?.session?.cap ?? null,
      }),
    [myGoatBalance, sellRow],
  );
  const sellNeedsApproval = Boolean(account) && sellWei > 0n && sellAllowance < sellWei;
  const sellExceedsGoat = sellWei > myGoatBalance;
  const sellExceedsMax = maxSellable > 0n && sellWei > maxSellable;
  // Slider position 0..SLIDER_STEPS for current sell amount vs max.
  let sellSlider = 0;
  if (maxSellable > 0n) {
    const raw = (sellWei * BigInt(SLIDER_STEPS)) / maxSellable;
    sellSlider = Number(raw > BigInt(SLIDER_STEPS) ? BigInt(SLIDER_STEPS) : raw);
  }

  function setSellFromWei(wei) {
    const clamped = wei < 0n ? 0n : maxSellable > 0n && wei > maxSellable ? maxSellable : wei;
    // Avoid scientific notation; formatGoat is fine for display.
    setSellAmount(clamped === 0n ? "" : formatGoat(clamped));
  }

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address || !selectedDesk) {
      setSellAllowance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.goatCoin,
        abi: GOAT_COIN_ABI,
        functionName: "allowance",
        args: [account.address, selectedDesk],
      })
      .then((value) => {
        if (!cancelled) setSellAllowance(value);
      })
      .catch(() => {
        if (!cancelled) setSellAllowance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, selectedDesk, lastRefreshed]);

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address) {
      setMyGoatBalance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.goatCoin,
        abi: GOAT_COIN_ABI,
        functionName: "balanceOf",
        args: [account.address],
      })
      .then((value) => {
        if (!cancelled) setMyGoatBalance(value);
      })
      .catch(() => {
        if (!cancelled) setMyGoatBalance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, lastRefreshed]);

  async function handleSellApprove(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !selectedDesk) return;
    setSellState({ status: "pending", message: "" });
    try {
      if (sellWei === 0n) throw new Error("Enter an amount greater than 0.");
      if (sellExceedsGoat) throw new Error(SELL_INSUFFICIENT_GOAT_COPY);
      await tx({ address: deployment.goatCoin, abi: GOAT_COIN_ABI, functionName: "approve", args: [selectedDesk, sellWei] });
      setSellState({ status: "idle", message: "Approved (testnet). You can sell now." });
      refresh();
    } catch (err) {
      setSellState({
        status: "error",
        message: err?.message === SELL_INSUFFICIENT_GOAT_COPY ? err.message : friendlyError(err, networkId, { sellWei, myGoatBalance }),
      });
    }
  }

  async function handleSell(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !selectedDesk) return;
    setSellState({ status: "pending", message: "" });
    try {
      if (sellWei === 0n) throw new Error("Enter an amount greater than 0.");
      if (sellExceedsGoat) throw new Error(SELL_INSUFFICIENT_GOAT_COPY);
      if (sellExceedsMax) {
        throw new Error(
          "That amount is above what this desk can pay (depth / session limit) — use the slider or Max.",
        );
      }
      const hash = await tx({ address: selectedDesk, abi: BUY_DESK_ABI, functionName: "sell", args: [sellWei] });
      setSellState({ status: "success", message: `Sold (testnet). Tx ${shortHash(hash)}` });
      setSellAmount("");
      refresh();
    } catch (err) {
      const msg =
        typeof err?.message === "string" &&
        (err.message === SELL_INSUFFICIENT_GOAT_COPY || err.message.includes("slider"))
          ? err.message
          : friendlyError(err, networkId, { sellWei, myGoatBalance });
      setSellState({ status: "error", message: msg });
    }
  }

  // --- Open my buy desk -------------------------------------------------------
  const [deskNameInput, setDeskNameInput] = useState("");
  const [createState, setCreateState] = useState(IDLE);
  async function handleCreateDesk(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || enrolled !== true) return;
    setCreateState({ status: "pending", message: "" });
    try {
      const hash = await tx({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "createDesk",
        args: [deskNameInput.trim()],
      });
      setCreateState({ status: "success", message: `Desk opened (testnet). Tx ${shortHash(hash)}` });
      setDeskNameInput("");
      refresh();
    } catch (err) {
      setCreateState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: cap (allowance-based buying power) ------------------------------
  // Depth = the desk's USDT allowance FROM the owner (see BuyDesk.depth()), so
  // the desk's current cap is just myDeskRow.depth — no separate read. We only
  // read the owner's own wallet USDT so the panel can warn when the wallet
  // can't actually cover the committed cap (spec §3, honest residue).
  // USDT tools (faucet) live here for donors only — worker Wallet tab is GOAT-only.
  const [capAmount, setCapAmount] = useState("");
  const [myUsdtBalance, setMyUsdtBalance] = useState(0n);
  const [capState, setCapState] = useState(IDLE);
  const [faucetAmount, setFaucetAmount] = useState("1000");
  const [faucetState, setFaucetState] = useState(IDLE);
  const currentCap = myDeskRow?.depth ?? 0n;
  const showDonorUsdtFaucet =
    isTestnetWithMockUsdt(networkId) && Boolean(deployment?.mockUSDT) && Boolean(myDeskAddress);

  async function handleDonorFaucet(e) {
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

  useEffect(() => {
    let cancelled = false;
    if (!publicClient || !deployed || !account?.address || !myDeskAddress) {
      setMyUsdtBalance(0n);
      return;
    }
    publicClient
      .readContract({
        address: deployment.mockUSDT,
        abi: MOCK_USDT_ABI,
        functionName: "balanceOf",
        args: [account.address],
      })
      .then((balance) => {
        if (!cancelled) setMyUsdtBalance(balance);
      })
      .catch(() => {
        if (!cancelled) setMyUsdtBalance(0n);
      });
    return () => {
      cancelled = true;
    };
  }, [publicClient, deployed, deployment, account, myDeskAddress, lastRefreshed]);

  // Set the desk's cap = approve this much of your wallet USDT to the desk.
  // ONE transaction; the desk never custodies funds. Raising or lowering the
  // cap is the same call with a new amount.
  async function handleSetCap(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setCapState({ status: "pending", message: "" });
    try {
      const amount = parseUsdt(capAmount);
      if (amount === 0n) throw new Error("Enter a cap greater than 0 — use Close desk to set it to 0.");
      const hash = await tx({ address: deployment.mockUSDT, abi: MOCK_USDT_ABI, functionName: "approve", args: [myDeskAddress, amount] });
      setCapState({ status: "success", message: `Cap set (testnet). Tx ${shortHash(hash)}` });
      setCapAmount("");
      refresh();
    } catch (err) {
      setCapState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // Close the desk = approve(desk, 0): buying power drops to 0 immediately.
  // Your USDT never left your wallet, so there is nothing to withdraw.
  async function handleCloseDesk() {
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setCapState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: deployment.mockUSDT, abi: MOCK_USDT_ABI, functionName: "approve", args: [myDeskAddress, 0n] });
      setCapState({ status: "success", message: `Desk closed — cap set to 0 (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setCapState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: bid --------------------------------------------------------------
  const [bidAmount, setBidAmount] = useState("");
  const [bidState, setBidState] = useState(IDLE);
  async function handleSetBid(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setBidState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "setBid", args: [parseUsdt(bidAmount)] });
      setBidState({ status: "success", message: `Bid updated (testnet). Tx ${shortHash(hash)}` });
      setBidAmount("");
      refresh();
    } catch (err) {
      setBidState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: session -----------------------------------------------------------
  const [sessionMinutes, setSessionMinutes] = useState("60");
  const [sessionCap, setSessionCap] = useState("");
  const [sessionState, setSessionState] = useState(IDLE);
  async function handleOpenSession(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setSessionState({ status: "pending", message: "" });
    try {
      const minutes = Number(sessionMinutes);
      if (!Number.isFinite(minutes) || minutes <= 0) throw new Error("Enter a duration greater than 0 minutes.");
      if (currentCap === 0n) throw new Error("Set a desk cap first — a session with no buying power can't pay any seller.");
      const start = BigInt(Math.floor(Date.now() / 1000));
      const end = start + BigInt(Math.round(minutes * 60));
      const cap = sessionCap.trim() === "" ? MAX_UINT256 : parseGoat(sessionCap);
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "openSession", args: [start, end, cap] });
      setSessionState({ status: "success", message: `Session opened (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setSessionState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  async function handleCloseSession() {
    if (!walletClient || !account || !deployment || !myDeskAddress) return;
    setSessionState({ status: "pending", message: "" });
    try {
      const hash = await tx({ address: myDeskAddress, abi: BUY_DESK_ABI, functionName: "closeSession", args: [] });
      setSessionState({ status: "success", message: `Session closed (testnet). Tx ${shortHash(hash)}` });
      refresh();
    } catch (err) {
      setSessionState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  // --- My desk: rename -----------------------------------------------------------
  const [renameInput, setRenameInput] = useState("");
  const [renameState, setRenameState] = useState(IDLE);
  async function handleRename(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment) return;
    setRenameState({ status: "pending", message: "" });
    try {
      const hash = await tx({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "setDeskName",
        args: [renameInput.trim()],
      });
      setRenameState({ status: "success", message: `Renamed (testnet). Tx ${shortHash(hash)}` });
      setRenameInput("");
      refresh();
    } catch (err) {
      setRenameState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  if (!deployed) {
    return (
      <section className="tab-panel">
        <h2>Market</h2>
        <p className="placeholder-note">
          {network?.name ?? `Chain ${networkId}`} has no BuyDesk factory deployed yet.
          {deployment?.note ? ` ${deployment.note}` : ""}
        </p>
      </section>
    );
  }

  return (
    <section className="tab-panel wallet-tab market-tab">
      <h2>Market</h2>
      <p className="required-copy">{NOT_EXCHANGE_COPY}</p>

      <div className="wallet-section">
        <div className="wallet-section-header">
          <h3>Buy desks</h3>
          <div className="wallet-actions-row">
            <button type="button" onClick={refresh} disabled={loading}>
              {loading ? "Refreshing…" : "Refresh"}
            </button>
            {lastRefreshed && <span className="muted">Updated {lastRefreshed.toLocaleTimeString()}</span>}
          </div>
        </div>
        {loadError && <p className="error-text">{loadError}</p>}
        <DeskTable rows={desks} myAddress={address} bestOpenAddress={bestOpenAddress} showDepth={isFounder} />
      </div>

      <div className="wallet-section">
        <h3>Sell GOAT</h3>
        <p className="required-copy">{HOLD_NOTICE_COPY}</p>
        {!account ? (
          <p className="placeholder-note">Import a key in the Wallet tab to sell.</p>
        ) : desks.length === 0 ? (
          <p className="placeholder-note">No buy desks yet — nothing to sell to.</p>
        ) : (
          <>
            <div className="wallet-form">
              <select value={selectedDesk} onChange={(e) => setSelectedDesk(e.target.value)}>
                <option value="" disabled>
                  Choose a desk…
                </option>
                {desks.map((row) => {
                  const mine = isOwnDesk(row, address);
                  return (
                    <option key={row.address} value={row.address} disabled={mine}>
                      {row.displayName} — 1 GOAT = {formatBid(row.bid)} USDT
                      {row.isOpen ? "" : " (closed)"}
                      {mine ? " (your desk)" : ""}
                    </option>
                  );
                })}
              </select>
            </div>
            {sellRow && (
              <dl className="balance-grid">
                <dt>Your GOAT (wallet)</dt>
                <dd>{testnetAmount(formatGoat(myGoatBalance), "GOAT")}</dd>
                <dt>Max sellable here</dt>
                <dd>
                  {testnetAmount(formatGoat(maxSellable), "GOAT")} — limited by your balance, desk
                  USDT depth, and session cap
                </dd>
                <dt>Posted bid</dt>
                <dd>
                  1 GOAT = {testnetAmount(formatBid(sellRow.bid), "USDT")} — {POSTED_BID_COPY}
                </dd>
                {isFounder && (
                  <>
                    <dt>Desk depth</dt>
                    <dd>{testnetAmount(formatUsdt(sellRow.depth), "USDT")} (founder debug)</dd>
                  </>
                )}
                <dt>Session</dt>
                <dd>{sellRow.isOpen ? `Open (#${sellRow.session.id.toString()})` : "No trade session open."}</dd>
                {sellRow.isOpen && (
                  <>
                    <dt>Session per-seller cap</dt>
                    <dd>{formatCap(sellRow.session.cap)}</dd>
                  </>
                )}
              </dl>
            )}
            {sellRow && sellRow.depth === 0n && (
              <p className="placeholder-note">
                Desk is empty — public good already delivered; new buyers add liquidity.
              </p>
            )}
            {sellExceedsGoat && sellWei > 0n && (
              <p className="error-text" role="alert">
                {SELL_INSUFFICIENT_GOAT_COPY}
              </p>
            )}
            <form className="wallet-form sell-form" onSubmit={sellNeedsApproval ? handleSellApprove : handleSell}>
              <label className="muted" htmlFor="sell-slider">
                Amount (0 → max sellable)
              </label>
              <input
                id="sell-slider"
                type="range"
                className="sell-slider"
                min={0}
                max={SLIDER_STEPS}
                step={1}
                value={Number.isFinite(sellSlider) ? sellSlider : 0}
                disabled={!account || !selectedDesk || maxSellable <= 0n}
                onChange={(e) => {
                  const step = BigInt(e.target.value);
                  if (maxSellable <= 0n || step <= 0n) {
                    setSellAmount("");
                    return;
                  }
                  setSellFromWei((maxSellable * step) / BigInt(SLIDER_STEPS));
                }}
              />
              <div className="wallet-actions-row">
                <input
                  type="text"
                  placeholder="Amount (GOAT)"
                  value={sellAmount}
                  onChange={(e) => setSellAmount(e.target.value)}
                  disabled={!account || !selectedDesk}
                  aria-invalid={sellExceedsGoat || sellExceedsMax}
                />
                <button
                  type="button"
                  disabled={!account || !selectedDesk || maxSellable <= 0n}
                  onClick={() => setSellFromWei(maxSellable)}
                >
                  Max
                </button>
              </div>
              <button
                type="submit"
                disabled={
                  !account ||
                  !selectedDesk ||
                  sellWei === 0n ||
                  !sellRow?.isOpen ||
                  sellRow?.depth === 0n ||
                  sellExceedsGoat ||
                  sellExceedsMax ||
                  sellState.status === "pending"
                }
              >
                {sellState.status === "pending"
                  ? sellNeedsApproval
                    ? "Approving…"
                    : "Selling…"
                  : sellNeedsApproval
                    ? "Approve GOAT"
                    : "Sell"}
              </button>
            </form>
            {sellWei > 0n && sellRow && (
              <p className="muted">
                You would receive ~{testnetAmount(formatUsdt(quoteUsdtOut(sellWei, sellRow.bid)), "USDT")}{" "}
                (sell proceeds — workers earn GOAT; USDT only arrives when you sell here).
              </p>
            )}
            {sellState.message && (
              <p className={sellState.status === "error" ? "error-text" : "status-ok"}>{sellState.message}</p>
            )}
          </>
        )}
      </div>

      <div className="wallet-section">
        <h3>Enrollment</h3>
        {!account ? (
          <p className="placeholder-note">Unlock a wallet to check enrollment.</p>
        ) : enrolled === null ? (
          <p className="muted">Checking…</p>
        ) : enrolled ? (
          <p className="status-ok">Enrolled — can transfer GOAT, sell on desks, and open a buy desk.</p>
        ) : (
          <>
            <p className="status-warn">
              Not enrolled. Create/import auto-enrolls when the wallet has ETH for gas (anvil does).
              Or enroll yourself:
            </p>
            <button
              type="button"
              className="primary-cta"
              disabled={!walletClient || !deployment?.enrollmentRegistry}
              onClick={async () => {
                try {
                  await ensureEnrolled({
                    publicClient,
                    walletClient,
                    account,
                    enrollmentRegistry: deployment.enrollmentRegistry,
                  });
                  refresh();
                } catch (err) {
                  setLoadError(friendlyError(err, networkId));
                }
              }}
            >
              Enroll myself (pays ETH gas)
            </button>
          </>
        )}
        <p className="muted" style={{ marginTop: "0.5rem" }}>
          Gas is always native ETH (not GOAT). Anvil accounts ship with free ETH. Donors only need ETH for
          createDesk/approve — they do not need GOAT. Workers need ETH + GOAT to sell.
        </p>
      </div>

      <div className="wallet-section">
        <h3>{myDeskAddress ? "My desk" : "Open my buy desk"}</h3>
        {!account ? (
          <p className="placeholder-note">Import a key in the Wallet tab to become a donor.</p>
        ) : myDeskAddress ? (
          <>
            <p className="muted">
              Desk: <code>{myDeskAddress}</code>
            </p>
            {enrolled === false && <p className="status-warn">{ENROLLMENT_WARNING_COPY}</p>}
            <dl className="balance-grid">
              <dt>Desk cap (buying power)</dt>
              <dd>
                {testnetAmount(formatUsdt(currentCap), "USDT")} — USDT you’ve committed to this desk.
                Shrinks as GOAT is bought.
              </dd>
              <dt>Your wallet USDT</dt>
              <dd>
                {testnetAmount(formatUsdt(myUsdtBalance), "USDT")} — stays in your wallet; keep it ≥ your
                cap so sells clear
              </dd>
              <dt>Posted bid</dt>
              <dd>
                1 GOAT = {testnetAmount(formatBid(myDeskRow?.bid ?? 0n), "USDT")} — {POSTED_BID_COPY}
              </dd>
              <dt>Session</dt>
              <dd>
                {myDeskRow?.isOpen
                  ? `Open (#${myDeskRow.session.id.toString()}) until ${new Date(Number(myDeskRow.session.end) * 1000).toLocaleString()}`
                  : "No trade session open."}
              </dd>
              {myDeskRow?.isOpen && (
                <>
                  <dt>Per-seller sell limit</dt>
                  <dd>
                    {formatCap(myDeskRow.session.cap)} — the most GOAT any one seller can sell you this
                    session. A GOAT limit, separate from your desk cap. Blank when opening = no limit.
                  </dd>
                </>
              )}
            </dl>
            {currentCap === 0n && (
              <p className="status-warn">
                Your desk cap is 0, so it has no buying power and sellers can’t sell to it yet. Set a cap
                below — that approves some of your wallet USDT (you hold{" "}
                {testnetAmount(formatUsdt(myUsdtBalance), "USDT")}) for the desk to spend. Your USDT stays
                in your wallet until someone actually sells to you.
              </p>
            )}

            {showDonorUsdtFaucet && (
              <div className="wallet-form-block">
                <p className="muted">
                  <strong>Donor only</strong> — MockUSDT faucet (testnet). Workers never need USDT in
                  Wallet; they earn GOAT and sell it on this Market. Mint test USDT here to fund your desk
                  cap.
                </p>
                <form className="wallet-form" onSubmit={handleDonorFaucet}>
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
            )}

            <div className="wallet-form-block">
              <p className="muted">
                Set your desk cap — commit up to this much of your <strong>wallet</strong> USDT as buying
                power. One step, no funding: your USDT stays in your wallet until someone sells to you.
                Enter a new amount anytime to raise or lower it.
              </p>
              <form className="wallet-form" onSubmit={handleSetCap}>
                <input
                  type="text"
                  placeholder="Cap (USDT)"
                  value={capAmount}
                  onChange={(e) => setCapAmount(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || capState.status === "pending"}>
                  {capState.status === "pending" ? "Setting…" : "Set cap"}
                </button>
              </form>
              <div className="wallet-actions-row">
                <button
                  type="button"
                  onClick={handleCloseDesk}
                  disabled={!account || currentCap === 0n || capState.status === "pending"}
                >
                  Close desk (cap → 0)
                </button>
              </div>
              {capState.message && (
                <p className={capState.status === "error" ? "error-text" : "status-ok"}>{capState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">
                Set your bid — {POSTED_BID_COPY}; never retroactive. USDT (6dp) per 1 GOAT, e.g. 0.01 = 10000 raw
                units.
              </p>
              <form className="wallet-form" onSubmit={handleSetBid}>
                <input
                  type="text"
                  placeholder="Bid (USDT per GOAT)"
                  value={bidAmount}
                  onChange={(e) => setBidAmount(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || bidAmount.trim() === "" || bidState.status === "pending"}>
                  {bidState.status === "pending" ? "Setting…" : "Set bid"}
                </button>
              </form>
              {bidState.message && (
                <p className={bidState.status === "error" ? "error-text" : "status-ok"}>{bidState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">
                Open a trade session so sellers can sell to you. Blank per-seller limit = no limit.
              </p>
              {currentCap === 0n && (
                <p className="status-warn">Set a desk cap first — a session with no buying power can’t pay any seller.</p>
              )}
              <form className="wallet-form" onSubmit={handleOpenSession}>
                <input
                  type="text"
                  placeholder="Duration (minutes)"
                  value={sessionMinutes}
                  onChange={(e) => setSessionMinutes(e.target.value)}
                  disabled={!account}
                />
                <input
                  type="text"
                  placeholder="Per-seller limit (GOAT, blank = none)"
                  value={sessionCap}
                  onChange={(e) => setSessionCap(e.target.value)}
                  disabled={!account}
                />
                <button
                  type="submit"
                  disabled={!account || currentCap === 0n || sessionState.status === "pending"}
                >
                  {sessionState.status === "pending" ? "Opening…" : "Open session"}
                </button>
              </form>
              <div className="wallet-actions-row">
                <button
                  type="button"
                  onClick={handleCloseSession}
                  disabled={!account || !myDeskRow?.isOpen || sessionState.status === "pending"}
                >
                  Close session
                </button>
              </div>
              {sessionState.message && (
                <p className={sessionState.status === "error" ? "error-text" : "status-ok"}>{sessionState.message}</p>
              )}
            </div>

            <div className="wallet-form-block">
              <p className="muted">Rename your desk — shown to sellers instead of your address.</p>
              <form className="wallet-form" onSubmit={handleRename}>
                <input
                  type="text"
                  placeholder={myDeskRow?.name || "Unnamed desk"}
                  value={renameInput}
                  onChange={(e) => setRenameInput(e.target.value)}
                  disabled={!account}
                />
                <button type="submit" disabled={!account || renameState.status === "pending"}>
                  {renameState.status === "pending" ? "Renaming…" : "Rename"}
                </button>
              </form>
              {renameState.message && (
                <p className={renameState.status === "error" ? "error-text" : "status-ok"}>{renameState.message}</p>
              )}
            </div>
          </>
        ) : (
          <>
            <p className="placeholder-note">
              Become a donor from this wallet — no second wallet needed. Opening a desk deploys your own BuyDesk;
              GOAT sold to it goes straight to this address.
            </p>
            {enrolled !== true && <p className="status-warn">{ENROLLMENT_WARNING_COPY}</p>}
            <form className="wallet-form" onSubmit={handleCreateDesk}>
              <input
                type="text"
                placeholder="Desk name (e.g. Alice's Desk)"
                value={deskNameInput}
                onChange={(e) => setDeskNameInput(e.target.value)}
                disabled={!account || enrolled !== true}
              />
              <button
                type="submit"
                disabled={!account || enrolled !== true || createState.status === "pending"}
              >
                {createState.status === "pending" ? "Opening…" : "Open my buy desk"}
              </button>
            </form>
            {createState.message && (
              <p className={createState.status === "error" ? "error-text" : "status-ok"}>{createState.message}</p>
            )}
          </>
        )}
      </div>

      <footer className="wallet-footer">
        <p>{WORK_UNIT_FORMULA}</p>
      </footer>
    </section>
  );
}
