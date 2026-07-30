/**
 * P1 / Stream C T3 — inject production origins into Tauri CSP.
 *
 * CRITICAL (consultant hazard): WebView2 / Tauri production must keep internal
 * schemes for IPC + assets. Never rewrite CSP to only external RPC/relayer hosts.
 * Required in connect-src (and related directives):
 *   ipc:  http(s)://ipc.localhost
 *   http(s)://tauri.localhost  wss://tauri.localhost  tauri:
 *   asset:  http(s)://asset.localhost
 *
 * Lab defaults also keep loopback :8787 + sepolia.base.org. For a packaged pilot:
 *   VITE_ATTESTOR_RELAYER_URL=https://api.example.com
 *   VITE_CSP_EXTRA_CONNECT=https://base-sepolia-rpc.publicnode.com
 *   (optional) VITE_RPC_URL=https://base-sepolia.g.alchemy.com/v2/...
 *
 * Vite bakes VITE_* at compile time — finalize tunnel + RPC before cargo tauri build.
 *
 * Cloudflare Access headers are separate (VITE_CF_ACCESS_* → relayerHeaders.js).
 * Access is a speed-bump only; H1 + spend_ledger are the load-bearing gates.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const confPath = path.resolve(__dirname, "../src-tauri/tauri.conf.json");

/**
 * Tauri / WebView2 internal origins — MUST appear in every generated CSP.
 * Stripping these blanks the shell or breaks invoke() IPC.
 */
export const TAURI_CONNECT = [
  "'self'",
  "ipc:",
  "http://ipc.localhost",
  "https://ipc.localhost",
  "http://tauri.localhost",
  "https://tauri.localhost",
  "ws://tauri.localhost",
  "wss://tauri.localhost",
  "tauri:",
  "asset:",
  "http://asset.localhost",
  "https://asset.localhost",
];

/** Lab RPC + relayer + FAH (always present). */
export const LAB_CONNECT = [
  "http://127.0.0.1:8545",
  "http://localhost:8545",
  "http://127.0.0.1:8787",
  "http://localhost:8787",
  "https://sepolia.base.org",
  "https://api.foldingathome.org",
];

/** Fixed connect-src base = Tauri internals + lab hosts. */
export const BASE_CONNECT = [...TAURI_CONNECT, ...LAB_CONNECT];

/** default-src must allow asset protocol + custom protocol for packaged assets. */
export const DEFAULT_SRC = [
  "'self'",
  "customprotocol:",
  "asset:",
  "http://asset.localhost",
  "https://asset.localhost",
  "http://tauri.localhost",
  "https://tauri.localhost",
  "tauri:",
];

/** img-src for brand assets + data URLs. */
export const IMG_SRC = [
  "'self'",
  "data:",
  "https:",
  "blob:",
  "asset:",
  "http://asset.localhost",
  "https://asset.localhost",
];

/**
 * @param {string|undefined|null} url
 * @returns {string|null} origin or null
 */
export function originFromEnv(url) {
  const raw = String(url ?? "").trim();
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const host = u.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * Parse comma-separated origins/URLs from VITE_CSP_EXTRA_CONNECT.
 * @param {string|undefined} raw
 * @returns {string[]}
 */
export function parseExtraConnect(raw) {
  const out = [];
  for (const part of String(raw ?? "").split(",")) {
    const t = part.trim();
    if (!t) continue;
    const o = originFromEnv(t.startsWith("http") ? t : `https://${t}`);
    if (o) out.push(o);
  }
  return out;
}

/**
 * @param {string[]} extraOrigins external only (relayer/RPC) — never replaces TAURI_CONNECT
 * @returns {string} full CSP string
 */
export function buildCsp(extraOrigins) {
  const connect = [...BASE_CONNECT];
  for (const o of extraOrigins) {
    if (o && !connect.includes(o)) connect.push(o);
  }
  // Guard: every Tauri token must still be present after extras merge.
  for (const req of TAURI_CONNECT) {
    if (!connect.includes(req)) {
      throw new Error(
        `inject-relayer-csp: refused to emit CSP missing Tauri scheme ${req}`,
      );
    }
  }
  return [
    `default-src ${DEFAULT_SRC.join(" ")}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src ${IMG_SRC.join(" ")}`,
    `connect-src ${connect.join(" ")}`,
    "script-src 'self' 'unsafe-eval'",
    "worker-src 'self' blob:",
  ].join("; ");
}

/**
 * Collect extras from process env (relayer + RPC + comma list).
 * @param {NodeJS.ProcessEnv} [env]
 */
export function collectExtraOrigins(env = process.env) {
  const extras = [];
  const relayer = originFromEnv(env.VITE_ATTESTOR_RELAYER_URL);
  if (relayer) extras.push(relayer);
  const rpc = originFromEnv(env.VITE_RPC_URL);
  if (rpc) extras.push(rpc);
  for (const o of parseExtraConnect(env.VITE_CSP_EXTRA_CONNECT)) {
    extras.push(o);
  }
  const seen = new Set();
  return extras.filter((o) => {
    if (seen.has(o)) return false;
    seen.add(o);
    return true;
  });
}

/** True if connect-src list includes all TAURI_CONNECT entries. */
export function hasAllTauriConnectTokens(connectList) {
  return TAURI_CONNECT.every((t) => connectList.includes(t));
}

function main() {
  const conf = JSON.parse(fs.readFileSync(confPath, "utf8"));
  const extras = collectExtraOrigins(process.env);
  const injectedRelayer = originFromEnv(process.env.VITE_ATTESTOR_RELAYER_URL);
  const csp = buildCsp(extras);

  conf.app = conf.app || {};
  conf.app.security = conf.app.security || {};
  conf.app.security.csp = csp;
  delete conf.app.security.cspRelayerOrigin;
  delete conf.app.security.cspExtraConnect;
  delete conf.app.security.cspAccessNote;
  delete conf.app.security.cspTauriNote;

  fs.writeFileSync(confPath, JSON.stringify(conf, null, 2) + "\n", "utf8");
  if (extras.length) {
    console.log(`[inject-relayer-csp] connect-src extras: ${extras.join(" ")}`);
  } else {
    console.log(
      "[inject-relayer-csp] lab CSP only (set VITE_ATTESTOR_RELAYER_URL / VITE_CSP_EXTRA_CONNECT for release)",
    );
  }
  console.log("[inject-relayer-csp] Tauri internal schemes preserved in connect-src + default-src/img-src");
}

const isMain =
  process.argv[1] &&
  path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}
