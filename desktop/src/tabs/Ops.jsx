import { useCallback, useEffect, useMemo, useState } from "react";
import { getAddress, keccak256, stringToBytes } from "viem";
import { useNetwork } from "../components/NetworkSwitch.jsx";
import { getDeployment, isDeployed } from "../chain/addresses.js";
import { extractErrorName, getPublicClient, getWalletClient } from "../chain/client.js";
import { useActiveAccount, useActiveWallet } from "../chain/wallet.js";
import { runTx } from "../chain/tx.js";
import { rpcUnreachableHint } from "../chain/errors.js";
import {
  BUY_DESK_ABI,
  BUY_DESK_FACTORY_ABI,
  ENROLLMENT_REGISTRY_ABI,
  GOAT_COIN_ABI,
  WORKER_BINDING_ABI,
} from "../chain/abis.js";
import { WORK_UNIT_FORMULA } from "../chain/constants.js";
import {
  decodeSession,
  formatBid,
  formatGoat,
  formatUsdt,
  shortAddress,
  shortHash,
  testnetAmount,
} from "../chain/format.js";
import { canSeeOpsTab, isFounderWallet, reduceEnrolledLogs } from "../opsAccess.js";

// Ops: founder enrollment (safe-gated), enrolled roster for all ops users,
// and a founder-only read-only dashboard. MockUSDT faucet lives on Wallet.
// Desk cap/bid/session management lives in the Market tab's "My desk" panel.

const POLL_MS = 10_000;

const SOLD_EVENT = BUY_DESK_ABI.find((item) => item.type === "event" && item.name === "Sold");
const ENROLLED_EVENT = ENROLLMENT_REGISTRY_ABI.find(
  (item) => item.type === "event" && item.name === "Enrolled",
);

// Q8 public-log copy — every BuyDesk.sell() sends GOAT to `owner`
// (BuyDesk.sol), so the Sold event log itself IS the founder's public
// acquisition record.
const PUBLIC_LOG_COPY = "All founder GOAT acquisitions are on-chain Sold events — public by construction.";

const ERROR_COPY = {
  NotSafe: "This key is not the Registry safe — switch to the founder's deploy key to enroll addresses.",
  NotOwner: "This key is not the BuyDesk owner — switch to the founder's deploy key.",
  NotEnrolled: "That address is not enrolled.",
  NoActiveSession: "No trade session open.",
  CapExceeded: "That amount would exceed the per-account cap for this trade session.",
  ZeroPayout: "That amount is too small — it would pay out 0 USDT at the current bid.",
  OwnerCannotSell: "The founder's own address cannot sell to its own desk.",
};

function friendlyError(err, networkId) {
  const hint = rpcUnreachableHint(err, networkId);
  if (hint) return hint;
  const name = extractErrorName(err);
  if (name && ERROR_COPY[name]) return ERROR_COPY[name];
  return err?.shortMessage || err?.message || String(err);
}

const IDLE = { status: "idle", message: "" };
const EMPTY_DESK = { depth: 0n, bid: 10_000n, session: null };
const EMPTY_DASHBOARD = { totalSupply: 0n, founderBalance: 0n };

async function resolveDisplayName(publicClient, deployment, address) {
  if (deployment?.workerBinding) {
    try {
      const username = await publicClient.readContract({
        address: deployment.workerBinding,
        abi: WORKER_BINDING_ABI,
        functionName: "usernameOf",
        args: [address],
      });
      if (username && String(username).trim()) return String(username).trim();
    } catch {
      // fall through
    }
  }
  if (deployment?.buyDeskFactory) {
    try {
      const name = await publicClient.readContract({
        address: deployment.buyDeskFactory,
        abi: BUY_DESK_FACTORY_ABI,
        functionName: "nameOf",
        args: [address],
      });
      if (name && String(name).trim()) return String(name).trim();
    } catch {
      // fall through
    }
  }
  return shortAddress(address);
}

export default function Ops() {
  const { networkId, network } = useNetwork();
  const deployment = getDeployment(networkId);
  const deployed = isDeployed(networkId);

  const account = useActiveAccount();

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

  const [access, setAccess] = useState({ enrolled: null, isFounder: false, safe: null });
  const [roster, setRoster] = useState([]);
  const [desk, setDesk] = useState(EMPTY_DESK);
  const [dashboard, setDashboard] = useState(EMPTY_DASHBOARD);
  const [soldLogs, setSoldLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [lastRefreshed, setLastRefreshed] = useState(null);

  const refresh = useCallback(async () => {
    if (!publicClient || !deployed || !deployment) return;
    setLoading(true);
    setLoadError("");
    try {
      const latest = await publicClient.getBlockNumber();
      const logFrom = latest > 5_000n ? latest - 5_000n : 0n;

      const [safeAddress, enrolledForAccount] = await Promise.all([
        publicClient.readContract({
          address: deployment.enrollmentRegistry,
          abi: ENROLLMENT_REGISTRY_ABI,
          functionName: "safe",
        }),
        account?.address
          ? publicClient.readContract({
              address: deployment.enrollmentRegistry,
              abi: ENROLLMENT_REGISTRY_ABI,
              functionName: "enrolled",
              args: [account.address],
            })
          : Promise.resolve(false),
      ]);
      const founder = isFounderWallet(account?.address, safeAddress);
      setAccess({ enrolled: Boolean(enrolledForAccount), isFounder: founder, safe: safeAddress });

      // Enrolled roster from Enrolled event logs (last-write-wins).
      let enrolledAddrs = [];
      if (ENROLLED_EVENT) {
        try {
          const eLogs = await publicClient.getLogs({
            address: deployment.enrollmentRegistry,
            event: ENROLLED_EVENT,
            fromBlock: logFrom,
            toBlock: "latest",
          });
          // getLogs is chronological ascending; reduce keeps final status per address.
          const chronological = eLogs
            .slice()
            .sort((a, b) => {
              if (a.blockNumber !== b.blockNumber) return a.blockNumber < b.blockNumber ? -1 : 1;
              return (a.logIndex ?? 0) - (b.logIndex ?? 0);
            })
            .map((log) => ({
              who: log.args?.who,
              status: Boolean(log.args?.status),
            }));
          enrolledAddrs = reduceEnrolledLogs(chronological);
        } catch {
          enrolledAddrs = [];
        }
      }

      const rosterRows = await Promise.all(
        enrolledAddrs.map(async (addr) => {
          const displayName = await resolveDisplayName(publicClient, deployment, addr);
          return { address: addr, displayName };
        }),
      );
      setRoster(rosterRows);

      // Founder-only dashboard reads — skip work for non-founders.
      if (founder) {
        const [depth, bid, sessionTuple, totalSupply, sLogs] = await Promise.all([
          publicClient.readContract({ address: deployment.buyDesk, abi: BUY_DESK_ABI, functionName: "depth" }),
          publicClient.readContract({ address: deployment.buyDesk, abi: BUY_DESK_ABI, functionName: "bid" }),
          publicClient.readContract({
            address: deployment.buyDesk,
            abi: BUY_DESK_ABI,
            functionName: "currentSession",
          }),
          publicClient.readContract({ address: deployment.goatCoin, abi: GOAT_COIN_ABI, functionName: "totalSupply" }),
          publicClient
            .getLogs({
              address: deployment.buyDesk,
              event: SOLD_EVENT,
              fromBlock: logFrom,
              toBlock: "latest",
            })
            .catch(() => []),
        ]);

        setDesk({ depth, bid, session: decodeSession(sessionTuple) });
        setSoldLogs(
          sLogs
            .map((log) => ({
              key: `${log.transactionHash}-${log.logIndex}`,
              sessionId: log.args.sessionId,
              seller: log.args.seller,
              goatAmount: log.args.goatAmount,
              usdtOut: log.args.usdtOut,
              blockNumber: log.blockNumber,
            }))
            .sort((a, b) => (b.blockNumber > a.blockNumber ? 1 : -1)),
        );

        const founderBalance = account?.address
          ? await publicClient.readContract({
              address: deployment.goatCoin,
              abi: GOAT_COIN_ABI,
              functionName: "balanceOf",
              args: [account.address],
            })
          : 0n;
        setDashboard({ totalSupply, founderBalance });
      } else {
        setDesk(EMPTY_DESK);
        setSoldLogs([]);
        setDashboard(EMPTY_DASHBOARD);
      }

      setLastRefreshed(new Date());
    } catch (err) {
      setLoadError(friendlyError(err, networkId));
    } finally {
      setLoading(false);
    }
  }, [publicClient, deployed, deployment, account, networkId]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  const sessionOpen = desk.session != null;
  const opsAllowed = canSeeOpsTab({ enrolled: access.enrolled, isFounder: access.isFounder });

  // --- Enrollment (founder / safe only) ------------------------------------
  const [enrollAddress, setEnrollAddress] = useState("");
  const [enrollState, setEnrollState] = useState(IDLE);
  async function handleEnroll(e) {
    e.preventDefault();
    if (!walletClient || !account || !deployment) return;
    setEnrollState({ status: "pending", message: "" });
    try {
      const addr = getAddress(enrollAddress.trim());
      // kycRef is a hash of the off-chain enrollment record (no PII
      // on-chain, EnrollmentRegistry.sol) — Season-0's founder-run pilot
      // has no separate KYC record yet, so this derives a stable,
      // non-reversible per-address placeholder reference.
      const kycRef = keccak256(stringToBytes(`${addr}season0`));
      const hash = await tx({
        address: deployment.enrollmentRegistry,
        abi: ENROLLMENT_REGISTRY_ABI,
        functionName: "setEnrolled",
        args: [addr, true, kycRef],
      });
      setEnrollState({ status: "success", message: `Enrolled (testnet). Tx ${shortHash(hash)}` });
      setEnrollAddress("");
      refresh();
    } catch (err) {
      setEnrollState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  const [checkAddress, setCheckAddress] = useState("");
  const [checkResult, setCheckResult] = useState(null);
  const [checkState, setCheckState] = useState(IDLE);
  async function handleCheckEnrolled(e) {
    e.preventDefault();
    if (!publicClient || !deployment) return;
    setCheckState({ status: "pending", message: "" });
    try {
      const addr = getAddress(checkAddress.trim());
      const result = await publicClient.readContract({
        address: deployment.enrollmentRegistry,
        abi: ENROLLMENT_REGISTRY_ABI,
        functionName: "enrolled",
        args: [addr],
      });
      setCheckResult(result);
      setCheckState(IDLE);
    } catch (err) {
      setCheckResult(null);
      setCheckState({ status: "error", message: friendlyError(err, networkId) });
    }
  }

  if (!deployed) {
    return (
      <section className="tab-panel">
        <h2>Ops</h2>
        <p className="required-copy">Founder personal pilot — not a multi-donor treasury</p>
        <SignerLine />
        <p className="placeholder-note">
          {network?.name ?? `Chain ${networkId}`} has no Season-0 v2 deployment yet.
          {deployment?.note ? ` ${deployment.note}` : ""}
        </p>
      </section>
    );
  }

  // Belt-and-suspenders if the tab is shown without access.
  if (!account || (access.enrolled !== null && !opsAllowed)) {
    return (
      <section className="tab-panel">
        <h2>Ops</h2>
        <SignerLine />
        <p className="status-warn">Ops is only for enrolled team members (or the registry safe / founder).</p>
      </section>
    );
  }

  return (
    <section className="tab-panel wallet-tab ops-tab">
      <h2>Ops</h2>
      <p className="required-copy">Founder personal pilot — not a multi-donor treasury</p>
      <SignerLine />

      <div className="wallet-actions-row">
        <button type="button" onClick={refresh} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
        {lastRefreshed && <span className="muted">Updated {lastRefreshed.toLocaleTimeString()}</span>}
      </div>
      {loadError && <p className="error-text">{loadError}</p>}

      {access.isFounder && (
        <div className="wallet-section">
          <h3>Enrollment</h3>
          <p className="muted">Founder-only — setEnrolled on the EnrollmentRegistry (safe-gated).</p>
          <form className="wallet-form" onSubmit={handleEnroll}>
            <input
              type="text"
              placeholder="0x… address to enroll"
              value={enrollAddress}
              onChange={(e) => setEnrollAddress(e.target.value)}
              disabled={!account}
            />
            <button type="submit" disabled={!account || enrollState.status === "pending"}>
              {enrollState.status === "pending" ? "Enrolling…" : "Enroll"}
            </button>
          </form>
          {enrollState.message && (
            <p className={enrollState.status === "error" ? "error-text" : "status-ok"}>{enrollState.message}</p>
          )}

          <form className="wallet-form ops-check-form" onSubmit={handleCheckEnrolled}>
            <input
              type="text"
              placeholder="0x… address to check"
              value={checkAddress}
              onChange={(e) => setCheckAddress(e.target.value)}
            />
            <button type="submit" disabled={checkState.status === "pending"}>
              Check enrolled
            </button>
          </form>
          {checkResult !== null && (
            <p className={checkResult ? "status-ok" : "status-warn"}>{checkResult ? "Enrolled" : "Not enrolled"}</p>
          )}
          {checkState.message && <p className="error-text">{checkState.message}</p>}
        </div>
      )}

      <div className="wallet-section">
        <h3>Enrolled roster</h3>
        <p className="muted">Currently enrolled addresses from on-chain Enrolled events (recent window).</p>
        {roster.length === 0 ? (
          <p className="placeholder-note">No enrolled addresses found in the recent log window.</p>
        ) : (
          <ul className="trade-list">
            {roster.map((row) => (
              <li key={row.address}>
                <strong>{row.displayName}</strong>{" "}
                <code>{row.address}</code>
              </li>
            ))}
          </ul>
        )}
        <p className="placeholder-note">
          Set your desk cap, set bid, and open/close sessions for your desk from the Market tab&apos;s
          &quot;My desk&quot; panel.
        </p>
      </div>

      {access.isFounder && (
        <div className="wallet-section">
          <h3>Dashboard</h3>
          <dl className="balance-grid">
            <dt>Total GOAT supply</dt>
            <dd>{testnetAmount(formatGoat(dashboard.totalSupply), "GOAT")}</dd>
            <dt>Desk depth</dt>
            <dd>{testnetAmount(formatUsdt(desk.depth), "USDT")}</dd>
            <dt>Posted bid</dt>
            <dd>1 GOAT = {testnetAmount(formatBid(desk.bid), "USDT")}</dd>
            <dt>Session</dt>
            <dd>{sessionOpen ? `Open (#${desk.session.id.toString()})` : "No trade session open."}</dd>
            <dt>Founder GOAT balance</dt>
            <dd>{testnetAmount(formatGoat(dashboard.founderBalance), "GOAT")}</dd>
          </dl>
          <p className="muted">{PUBLIC_LOG_COPY}</p>

          <div className="ops-dashboard-subsection">
            <h4>Founder acquisitions (Sold events)</h4>
            {soldLogs.length === 0 ? (
              <p className="placeholder-note">No sales recorded yet.</p>
            ) : (
              <ul className="trade-list">
                {soldLogs.slice(0, 10).map((s) => (
                  <li key={s.key}>
                    #{s.sessionId.toString()} {shortAddress(s.seller)} sold {testnetAmount(formatGoat(s.goatAmount), "GOAT")}{" "}
                    for {testnetAmount(formatUsdt(s.usdtOut), "USDT")} → founder
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      <footer className="wallet-footer">
        <p>{WORK_UNIT_FORMULA}</p>
      </footer>
    </section>
  );
}

function SignerLine() {
  const activeMeta = useActiveWallet();
  if (!activeMeta) {
    return <p className="status-warn">No wallet unlocked — create or unlock a wallet in the Wallet tab first.</p>;
  }
  return (
    <div className="muted">
      <p>
        Wallet name: <strong>{activeMeta.name}</strong>
      </p>
      <p>
        Wallet address: <code>{activeMeta.address}</code>
      </p>
      <p>
        Enrollment of others requires the Registry safe key; an unauthorized key surfaces readably as
        NotSafe the first time an action runs.
      </p>
    </div>
  );
}
