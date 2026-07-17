// Gasless bind + enroll helpers (Phase 4 T11).
// Pure EIP-712 builders + relayer fetch wrappers — unit-testable without Tauri.
// Relayer pays gas; worker signs Bind / Enroll typed data. Claims ≤ code: this is
// pilot/testnet wiring; success does not mean live GOAT earnings.
//
// RELAYER URL POLICY (consultant 2026-07-15):
// - Default `http://127.0.0.1:8787` is DEV-ONLY (founder runs attestor on the same machine).
// - Production ships with VITE_ATTESTOR_RELAYER_URL pointing at founder infrastructure
//   (e.g. https://api.example.com) — the daemon holds gas keys; workers never run it.
// - See `isLocalRelayerUrl` / EarningStatus banner before treating a build as user-facing.

import { getDeployment } from "./addresses.js";
import {
  ENROLLMENT_REGISTRY_ABI,
  EPOCH_SETTLEMENT_ABI,
  WORKER_BINDING_ABI,
} from "./abis.js";

/** Built-in fallback for local pilot only — never a production assumption. */
export const DEV_RELAYER_URL = "http://127.0.0.1:8787";

/**
 * Resolve the attestor relayer base URL.
 * Prefer `VITE_ATTESTOR_RELAYER_URL` at build time; fall back to localhost for lab use.
 */
export function resolveRelayerUrl(envUrl) {
  const fromArg = typeof envUrl === "string" ? envUrl.trim() : "";
  if (fromArg) return fromArg.replace(/\/$/, "");
  const fromVite =
    typeof import.meta !== "undefined" && import.meta.env?.VITE_ATTESTOR_RELAYER_URL
      ? String(import.meta.env.VITE_ATTESTOR_RELAYER_URL).trim()
      : "";
  if (fromVite) return fromVite.replace(/\/$/, "");
  return DEV_RELAYER_URL;
}

export const RELAYER_URL = resolveRelayerUrl();

/** True when URL targets loopback (dev pilot). Production builds must not leave this true. */
export function isLocalRelayerUrl(url = RELAYER_URL) {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
  } catch {
    return /127\.0\.0\.1|localhost/i.test(String(url ?? ""));
  }
}

/**
 * Operator-facing mode label for UI / diagnostics.
 * @returns {"local-dev"|"remote"}
 */
export function relayerMode(url = RELAYER_URL) {
  return isLocalRelayerUrl(url) ? "local-dev" : "remote";
}

/** Default signature lifetime for meta-tx (1 hour). */
export const DEFAULT_DEADLINE_SECS = 3600;

export const BIND_TYPES = {
  Bind: [
    { name: "wallet", type: "address" },
    { name: "username", type: "string" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

export const ENROLL_TYPES = {
  Enroll: [
    { name: "wallet", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

export function bindDomain({ chainId, verifyingContract }) {
  return {
    name: "GoatWorkerBinding",
    version: "1",
    chainId: Number(chainId),
    verifyingContract,
  };
}

export function enrollDomain({ chainId, verifyingContract }) {
  return {
    name: "GoatEnrollmentRegistry",
    version: "1",
    chainId: Number(chainId),
    verifyingContract,
  };
}

export function deadlineFromNow(nowSec = Math.floor(Date.now() / 1000), ttl = DEFAULT_DEADLINE_SECS) {
  return BigInt(nowSec) + BigInt(ttl);
}

/** Build EIP-712 typed data for WorkerBinding.Bind. */
export function buildBindTypedData({ chainId, workerBinding, wallet, username, nonce, deadline }) {
  return {
    domain: bindDomain({ chainId, verifyingContract: workerBinding }),
    types: BIND_TYPES,
    primaryType: "Bind",
    message: {
      wallet,
      username,
      nonce: typeof nonce === "bigint" ? nonce : BigInt(nonce),
      deadline: typeof deadline === "bigint" ? deadline : BigInt(deadline),
    },
  };
}

/** Build EIP-712 typed data for EnrollmentRegistry.Enroll. */
export function buildEnrollTypedData({ chainId, enrollmentRegistry, wallet, nonce, deadline }) {
  return {
    domain: enrollDomain({ chainId, verifyingContract: enrollmentRegistry }),
    types: ENROLL_TYPES,
    primaryType: "Enroll",
    message: {
      wallet,
      nonce: typeof nonce === "bigint" ? nonce : BigInt(nonce),
      deadline: typeof deadline === "bigint" ? deadline : BigInt(deadline),
    },
  };
}

/**
 * POST to the attestor relayer. Returns { ok, tx_hash?, error? }.
 * `fetchImpl` is injectable for tests.
 */
/** Map browser/network failures to an operator-facing relayer hint. */
export function formatRelayerFetchError(err, relayerUrl = RELAYER_URL) {
  const raw = err?.message || String(err || "Relayer unreachable");
  const lower = raw.toLowerCase();
  if (
    lower.includes("failed to fetch") ||
    lower.includes("networkerror") ||
    lower.includes("load failed") ||
    lower.includes("network request failed") ||
    lower.includes("fetch failed")
  ) {
    const base = resolveRelayerUrl(relayerUrl);
    return (
      `Relayer unreachable at ${base} (${raw}). ` +
      `Gasless bind needs goat-attestor: ` +
      `cd tools/goat-attestor && cargo run -- serve-relayer --bind 127.0.0.1:8787 ` +
      `(with RELAYER_PRIVATE_KEY + anvil). Or use wallet-gas fallback (ETH on Rookie).`
    );
  }
  return raw;
}

export async function postRelay(path, body, { relayerUrl, fetchImpl = fetch, timeoutMs = 20_000 } = {}) {
  const base = resolveRelayerUrl(relayerUrl ?? RELAYER_URL);
  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  let res;
  try {
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer =
      ctrl && timeoutMs > 0
        ? setTimeout(() => ctrl.abort(), timeoutMs)
        : null;
    try {
      res = await fetchImpl(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString(10) : v)),
        ...(ctrl ? { signal: ctrl.signal } : {}),
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  } catch (err) {
    const aborted = err?.name === "AbortError" || /aborted/i.test(String(err?.message || err));
    return {
      ok: false,
      error: aborted
        ? `Relayer timed out after ${timeoutMs}ms at ${base} — is serve-relayer hung? Or fund ETH for wallet-gas bind.`
        : formatRelayerFetchError(err, base),
      relayerDown: true,
    };
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    return {
      ok: false,
      tx_hash: data?.tx_hash ?? null,
      error: data?.error || `HTTP ${res.status}`,
    };
  }
  return {
    ok: Boolean(data?.ok ?? true),
    tx_hash: data?.tx_hash ?? null,
    error: data?.error ?? null,
  };
}

export function postBindRelay(body, opts) {
  return postRelay("/v1/relay/bind", body, opts);
}

export function postEnrollRelay(body, opts) {
  return postRelay("/v1/relay/enroll", body, opts);
}

/**
 * Read chain nonces for bind + enroll.
 * publicClient: viem public client with readContract.
 */
export async function readAttributionNonces(publicClient, { workerBinding, enrollmentRegistry, wallet }) {
  const [bindNonce, enrollNonce] = await Promise.all([
    publicClient.readContract({
      address: workerBinding,
      abi: WORKER_BINDING_ABI,
      functionName: "nonces",
      args: [wallet],
    }),
    publicClient.readContract({
      address: enrollmentRegistry,
      abi: ENROLLMENT_REGISTRY_ABI,
      functionName: "nonces",
      args: [wallet],
    }),
  ]);
  return { bindNonce, enrollNonce };
}

/**
 * Read earning-status views for a wallet (honest pilot UI).
 */
export async function readEarningStatus(publicClient, {
  workerBinding,
  epochSettlement,
  enrollmentRegistry,
  wallet,
}) {
  const [username, bound, enrolled, hasBaseline, lastClaimedCumulative] = await Promise.all([
    publicClient.readContract({
      address: workerBinding,
      abi: WORKER_BINDING_ABI,
      functionName: "usernameOf",
      args: [wallet],
    }),
    publicClient.readContract({
      address: workerBinding,
      abi: WORKER_BINDING_ABI,
      functionName: "bound",
      args: [wallet],
    }),
    enrollmentRegistry
      ? publicClient.readContract({
          address: enrollmentRegistry,
          abi: ENROLLMENT_REGISTRY_ABI,
          functionName: "enrolled",
          args: [wallet],
        })
      : Promise.resolve(false),
    epochSettlement
      ? publicClient.readContract({
          address: epochSettlement,
          abi: EPOCH_SETTLEMENT_ABI,
          functionName: "hasBaseline",
          args: [wallet],
        })
      : Promise.resolve(false),
    epochSettlement
      ? publicClient.readContract({
          address: epochSettlement,
          abi: EPOCH_SETTLEMENT_ABI,
          functionName: "lastClaimedCumulative",
          args: [wallet],
        })
      : Promise.resolve(0n),
  ]);
  return {
    username: username || "",
    bound: Boolean(bound),
    enrolled: Boolean(enrolled),
    hasBaseline: Boolean(hasBaseline),
    lastClaimedCumulative:
      typeof lastClaimedCumulative === "bigint"
        ? lastClaimedCumulative
        : BigInt(lastClaimedCumulative ?? 0),
  };
}

/**
 * Full gasless bind flow: read nonce → sign Bind → POST relayer.
 * `account` must expose signTypedData (Rust-backed viem account).
 */
export async function bindViaRelayer({
  publicClient,
  account,
  chainId,
  username,
  wallet,
  deadline,
  relayerUrl = RELAYER_URL,
  fetchImpl = fetch,
}) {
  const d = getDeployment(chainId);
  if (!d?.workerBinding) {
    return { ok: false, error: "WorkerBinding not deployed on this network" };
  }
  const walletAddr = wallet || account?.address;
  if (!walletAddr) return { ok: false, error: "No unlocked wallet" };
  if (!username?.startsWith("GOAT-")) {
    return { ok: false, error: 'Username must start with "GOAT-"' };
  }

  const nonce = await publicClient.readContract({
    address: d.workerBinding,
    abi: WORKER_BINDING_ABI,
    functionName: "nonces",
    args: [walletAddr],
  });
  const dl = deadline ?? deadlineFromNow();
  const typed = buildBindTypedData({
    chainId,
    workerBinding: d.workerBinding,
    wallet: walletAddr,
    username,
    nonce,
    deadline: dl,
  });
  const signature = await account.signTypedData(typed);
  return postBindRelay(
    {
      wallet: walletAddr,
      username,
      deadline: Number(dl),
      signature,
    },
    { relayerUrl, fetchImpl },
  );
}

/**
 * Full gasless enroll flow: read nonce → sign Enroll → POST relayer.
 */
export async function enrollViaRelayer({
  publicClient,
  account,
  chainId,
  wallet,
  deadline,
  relayerUrl = RELAYER_URL,
  fetchImpl = fetch,
}) {
  const d = getDeployment(chainId);
  if (!d?.enrollmentRegistry) {
    return { ok: false, error: "EnrollmentRegistry not deployed on this network" };
  }
  const walletAddr = wallet || account?.address;
  if (!walletAddr) return { ok: false, error: "No unlocked wallet" };

  const nonce = await publicClient.readContract({
    address: d.enrollmentRegistry,
    abi: ENROLLMENT_REGISTRY_ABI,
    functionName: "nonces",
    args: [walletAddr],
  });
  const dl = deadline ?? deadlineFromNow();
  const typed = buildEnrollTypedData({
    chainId,
    enrollmentRegistry: d.enrollmentRegistry,
    wallet: walletAddr,
    nonce,
    deadline: dl,
  });
  const signature = await account.signTypedData(typed);
  return postEnrollRelay(
    {
      wallet: walletAddr,
      deadline: Number(dl),
      signature,
    },
    { relayerUrl, fetchImpl },
  );
}

/**
 * Bind then enroll (typical first-run attribution). Returns per-step results.
 */
export async function bindAndEnrollViaRelayer(opts) {
  const bind = await bindViaRelayer(opts);
  if (!bind.ok) return { bind, enroll: null };
  const enroll = await enrollViaRelayer(opts);
  return { bind, enroll };
}

/**
 * Worker-paid bind (msg.sender = wallet). Needs ETH gas — works when relayer is down.
 */
export async function bindViaWallet({
  publicClient,
  walletClient,
  account,
  chainId,
  username,
  wallet,
}) {
  const d = getDeployment(chainId);
  if (!d?.workerBinding) {
    return { ok: false, error: "WorkerBinding not deployed on this network" };
  }
  const walletAddr = wallet || account?.address;
  if (!walletAddr || !walletClient || !account) {
    return { ok: false, error: "No unlocked wallet / wallet client" };
  }
  if (!username?.startsWith("GOAT-")) {
    return { ok: false, error: 'Username must start with "GOAT-"' };
  }
  try {
    const already = await publicClient.readContract({
      address: d.workerBinding,
      abi: WORKER_BINDING_ABI,
      functionName: "bound",
      args: [walletAddr],
    });
    if (already) return { ok: true, already: true, mode: "wallet-gas" };
    const hash = await walletClient.writeContract({
      account,
      address: d.workerBinding,
      abi: WORKER_BINDING_ABI,
      functionName: "bind",
      args: [username],
    });
    await publicClient.waitForTransactionReceipt({ hash, timeout: 30_000 });
    return { ok: true, tx_hash: hash, mode: "wallet-gas" };
  } catch (err) {
    return {
      ok: false,
      error: formatWalletGasError(err, "bind"),
      mode: "wallet-gas",
    };
  }
}

/**
 * Worker-paid enrollSelf. Needs ETH gas.
 */
export async function enrollViaWallet({ publicClient, walletClient, account, chainId, wallet }) {
  const d = getDeployment(chainId);
  if (!d?.enrollmentRegistry) {
    return { ok: false, error: "EnrollmentRegistry not deployed on this network" };
  }
  const walletAddr = wallet || account?.address;
  if (!walletAddr || !walletClient || !account) {
    return { ok: false, error: "No unlocked wallet / wallet client" };
  }
  try {
    const already = await publicClient.readContract({
      address: d.enrollmentRegistry,
      abi: ENROLLMENT_REGISTRY_ABI,
      functionName: "enrolled",
      args: [walletAddr],
    });
    if (already) return { ok: true, already: true, mode: "wallet-gas" };
    const hash = await walletClient.writeContract({
      account,
      address: d.enrollmentRegistry,
      abi: ENROLLMENT_REGISTRY_ABI,
      functionName: "enrollSelf",
      args: [],
    });
    await publicClient.waitForTransactionReceipt({ hash, timeout: 30_000 });
    return { ok: true, tx_hash: hash, mode: "wallet-gas" };
  } catch (err) {
    return {
      ok: false,
      error: formatWalletGasError(err, "enroll"),
      mode: "wallet-gas",
    };
  }
}

/** Map viem insufficient-funds to pilot-friendly copy (workers start at 0 ETH). */
function formatWalletGasError(err, action) {
  const raw = err?.shortMessage || err?.message || String(err);
  if (/exceeds the balance|insufficient funds/i.test(raw)) {
    return (
      `${action} needs ETH gas on this wallet (balance too low). ` +
      `Prefer gasless: start tools/goat-attestor serve-relayer on :8787, then Bind & enroll again. ` +
      `Or fund a little anvil ETH to Rookie. MockUSDT is not gas.`
    );
  }
  return raw;
}

/**
 * Bind + enroll with pilot-friendly routing:
 * 1. If wallet has ETH → wallet-gas first (fast, no EIP-712/relayer hang on anvil).
 * 2. Else → gasless relayer (0-ETH workers).
 * Never call wallet-gas when balance is 0 (viem "exceeds the balance" trap).
 * @returns {{ bind, enroll, mode: "relayer"|"wallet-gas" }}
 */
export async function bindAndEnrollAuto(opts) {
  const { publicClient, walletClient, account, chainId, username, wallet } = opts;
  const addr = wallet || account?.address;

  let ethBal = 0n;
  try {
    if (publicClient && addr) {
      ethBal = await publicClient.getBalance({ address: addr });
    }
  } catch {
    ethBal = 0n;
  }

  // Funded pilot wallet: self-pay bind is reliable; skip waiting on relayer.
  if (ethBal > 0n && walletClient && account) {
    const bind = await bindViaWallet({
      publicClient,
      walletClient,
      account,
      chainId,
      username,
      wallet: addr,
    });
    if (!bind.ok) {
      return { bind, enroll: null, mode: "wallet-gas" };
    }
    const enroll = await enrollViaWallet({
      publicClient,
      walletClient,
      account,
      chainId,
      wallet: addr,
    });
    return { bind, enroll, mode: "wallet-gas" };
  }

  // 0 ETH → gasless only
  const viaRelay = await bindAndEnrollViaRelayer(opts);
  if (viaRelay.bind?.ok && viaRelay.enroll?.ok) {
    return { ...viaRelay, mode: "relayer" };
  }

  const bindFail = viaRelay.bind?.error || "";
  const enrollFail = viaRelay.enroll?.error || "";
  const combined = `${bindFail} ${enrollFail}`;
  const relayerDown =
    Boolean(viaRelay.bind?.relayerDown) ||
    Boolean(viaRelay.enroll?.relayerDown) ||
    /relayer unreachable|failed to fetch/i.test(combined);

  return {
    bind: {
      ok: false,
      error:
        (bindFail || "Gasless bind failed") +
        (relayerDown
          ? `. Relayer down — start tools/goat-attestor/start-relayer.ps1, or fund ~0.01 ETH on this wallet.`
          : `. Wallet has 0 ETH so wallet-gas was not used. Fund anvil ETH or fix: ${enrollFail || bindFail}`),
    },
    enroll: viaRelay.enroll,
    mode: "relayer",
  };
}

/** FAH client username vs on-chain bound username — earning pauses on mismatch. */
export function usernameMismatch(fahUsername, boundUsername) {
  const a = (fahUsername ?? "").trim();
  const b = (boundUsername ?? "").trim();
  if (!a || !b) return false;
  return a !== b;
}
