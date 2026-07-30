/**
 * Stream D0 — pure release gates (version parity + Base Sepolia address freeze).
 * Used by release-check.mjs and unit tests. Fail-closed on null 84532.
 *
 * WiX (consultant hazard): MSI requires WiX v3 candle/light on PATH. If absent,
 * effective targets fall back to NSIS-only (still a valid pilot ship).
 */

/** Same core keys as desktop/src/chain/addresses.js CORE_DEPLOYMENT_KEYS. */
export const CORE_DEPLOYMENT_KEYS = [
  "goatCoin",
  "enrollmentRegistry",
  "holdbackEscrow",
  "workMinter",
  "buyDesk",
  "mockUSDT",
];

/**
 * @param {unknown} v
 * @returns {boolean}
 */
export function isDeployedAddress(v) {
  if (typeof v !== "string") return false;
  const s = v.trim();
  if (!s || s === "0x") return false;
  if (/^0x0{40}$/i.test(s)) return false;
  return /^0x[0-9a-fA-F]{40}$/.test(s);
}

/**
 * @param {Record<string, unknown>} deploymentJson — contents of 84532.json (base free-market)
 * @returns {{ ok: boolean, missing: string[] }}
 */
export function check84532Core(deploymentJson) {
  const missing = [];
  if (!deploymentJson || typeof deploymentJson !== "object") {
    return { ok: false, missing: ["(invalid JSON object)"] };
  }
  for (const k of CORE_DEPLOYMENT_KEYS) {
    if (!isDeployedAddress(deploymentJson[k])) missing.push(k);
  }
  return { ok: missing.length === 0, missing };
}

/**
 * @param {{ packageVersion: string, tauriVersion: string, cargoVersion: string, appVersionJs: string }} v
 * @returns {{ ok: boolean, expected: string, mismatches: string[] }}
 */
export function checkVersionParity(v) {
  const expected = String(v.packageVersion ?? "").trim();
  const mismatches = [];
  if (!expected) {
    return { ok: false, expected: "", mismatches: ["package.json version empty"] };
  }
  const pairs = [
    ["tauri.conf.json", v.tauriVersion],
    ["Cargo.toml", v.cargoVersion],
    ["src/version.js APP_VERSION", v.appVersionJs],
  ];
  for (const [label, raw] of pairs) {
    if (String(raw ?? "").trim() !== expected) {
      mismatches.push(`${label}=${JSON.stringify(raw)} (want ${expected})`);
    }
  }
  return { ok: mismatches.length === 0, expected, mismatches };
}

/**
 * Parse `version = "x.y.z"` from Cargo.toml text.
 * @param {string} cargoToml
 * @returns {string|null}
 */
export function parseCargoPackageVersion(cargoToml) {
  // Prefer [package] block first version line after it.
  const pkg = cargoToml.match(/\[package\]([\s\S]*?)(\n\[|\s*$)/);
  const block = pkg ? pkg[1] : cargoToml;
  const m = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
  return m ? m[1] : null;
}

/**
 * Parse APP_VERSION = "x.y.z" from version.js
 * @param {string} versionJs
 * @returns {string|null}
 */
export function parseAppVersionJs(versionJs) {
  const m = versionJs.match(/export\s+const\s+APP_VERSION\s*=\s*["']([^"']+)["']/);
  return m ? m[1] : null;
}

/**
 * Soft checks on production env bag (do not print secret values).
 * @param {Record<string, string|undefined>} env
 * @param {{ strict?: boolean }} [opts]
 * @returns {{ errors: string[], warnings: string[] }}
 */
/**
 * Resolve which bundle targets to actually build.
 * Config may list both nsis+msi; without WiX, drop msi and warn (do not fail).
 *
 * @param {string[]|string|undefined} configTargets
 * @param {{ wixAvailable: boolean }} opts
 * @returns {{ ok: boolean, effective: string[], warnings: string[], errors: string[], configTargets: string[] }}
 */
export function resolveEffectiveBundleTargets(configTargets, { wixAvailable }) {
  const warnings = [];
  const errors = [];
  let list = [];
  if (Array.isArray(configTargets)) {
    list = configTargets.map(String);
  } else if (configTargets === "all") {
    list = ["nsis", "msi"];
  } else if (typeof configTargets === "string" && configTargets) {
    list = [configTargets];
  }

  if (!list.includes("nsis")) {
    errors.push('bundle.targets must include "nsis" (got ' + JSON.stringify(configTargets) + ")");
    return { ok: false, effective: list, warnings, errors, configTargets: list };
  }

  let effective = list.filter((t) => t === "nsis" || t === "msi");
  if (effective.includes("msi") && !wixAvailable) {
    effective = effective.filter((t) => t !== "msi");
    warnings.push(
      "WiX Toolset v3 (candle.exe / light.exe) not on PATH — MSI target skipped; building NSIS only. " +
        "Install: winget install --id WiXToolset.WiX -e   OR   choco install wixtoolset",
    );
  }
  if (wixAvailable && list.includes("msi") && !effective.includes("msi")) {
    // should not happen
    warnings.push("MSI unexpectedly dropped despite WiX available");
  }

  return {
    ok: effective.includes("nsis"),
    effective,
    warnings,
    errors,
    configTargets: list,
  };
}

/**
 * @param {Record<string, string|undefined>} env
 * @param {{ strict?: boolean }} [opts]
 */
export function checkProductionEnv(env, { strict = false } = {}) {
  const errors = [];
  const warnings = [];
  const relayer = String(env.VITE_ATTESTOR_RELAYER_URL ?? "").trim();
  const net = String(env.VITE_DEFAULT_NETWORK_ID ?? "").trim();
  const pilot = String(env.VITE_PILOT ?? "").trim();

  if (!relayer) {
    (strict ? errors : warnings).push("VITE_ATTESTOR_RELAYER_URL is unset");
  } else if (/127\.0\.0\.1|localhost/i.test(relayer)) {
    (strict ? errors : warnings).push(
      "VITE_ATTESTOR_RELAYER_URL still points at loopback (not a pilot tunnel)",
    );
  }

  if (net && net !== "84532") {
    (strict ? errors : warnings).push(`VITE_DEFAULT_NETWORK_ID=${net} (pilot expects 84532)`);
  } else if (!net) {
    warnings.push("VITE_DEFAULT_NETWORK_ID unset (lab default 31337 — set 84532 for pilot)");
  }

  if (pilot !== "1" && pilot.toLowerCase() !== "true") {
    warnings.push("VITE_PILOT not set — anvil may still appear in the network switcher");
  }

  const id = String(env.VITE_CF_ACCESS_CLIENT_ID ?? "").trim();
  const secret = String(env.VITE_CF_ACCESS_CLIENT_SECRET ?? "").trim();
  if ((id && !secret) || (!id && secret)) {
    warnings.push("CF Access: only one of CLIENT_ID/SECRET set (both required or neither)");
  }

  return { errors, warnings };
}
