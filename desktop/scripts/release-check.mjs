#!/usr/bin/env node
/**
 * Stream D0 — release-check CLI.
 * Exit 0 only if version parity holds AND 84532 core addresses are non-null
 * AND at least NSIS is an effective bundle target.
 *
 * WiX: if candle/light missing, MSI is dropped with WARN (not FAIL) — NSIS still ships.
 *
 * Usage:
 *   node scripts/release-check.mjs
 *   node scripts/release-check.mjs --strict-env
 *   node scripts/release-check.mjs --json
 *   node scripts/release-check.mjs --require-wix   # fail if MSI cannot be built
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  check84532Core,
  checkProductionEnv,
  checkVersionParity,
  parseAppVersionJs,
  parseCargoPackageVersion,
  resolveEffectiveBundleTargets,
} from "./release-gates.mjs";
import { detectWixAvailable } from "./detect-wix.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopRoot = path.resolve(__dirname, "..");

function read(p) {
  return fs.readFileSync(p, "utf8");
}

function loadDotEnvLocal() {
  const envPath = path.join(desktopRoot, ".env.production.local");
  const bag = { ...process.env };
  if (!fs.existsSync(envPath)) return { bag, path: envPath, present: false };
  for (const line of read(envPath).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i <= 0) continue;
    const k = t.slice(0, i).trim();
    let v = t.slice(i + 1).trim();
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    bag[k] = v;
  }
  return { bag, path: envPath, present: true };
}

function main() {
  const args = new Set(process.argv.slice(2));
  const strictEnv = args.has("--strict-env");
  const requireWix = args.has("--require-wix");
  const asJson = args.has("--json");

  const pkg = JSON.parse(read(path.join(desktopRoot, "package.json")));
  const tauri = JSON.parse(read(path.join(desktopRoot, "src-tauri/tauri.conf.json")));
  const cargo = read(path.join(desktopRoot, "src-tauri/Cargo.toml"));
  const versionJs = read(path.join(desktopRoot, "src/version.js"));
  const base84532 = JSON.parse(
    read(path.join(desktopRoot, "src/chain/deployments/84532.json")),
  );

  const versions = checkVersionParity({
    packageVersion: pkg.version,
    tauriVersion: tauri.version,
    cargoVersion: parseCargoPackageVersion(cargo),
    appVersionJs: parseAppVersionJs(versionJs),
  });

  const chain = check84532Core(base84532);
  const { bag, path: envPath, present } = loadDotEnvLocal();
  const envCheck = checkProductionEnv(bag, { strict: strictEnv });

  const wixAvailable = detectWixAvailable();
  const bundle = resolveEffectiveBundleTargets(tauri.bundle?.targets, { wixAvailable });
  if (requireWix && !wixAvailable) {
    bundle.errors.push(
      "--require-wix set but candle/light not on PATH (install WiX Toolset v3)",
    );
    bundle.ok = false;
  }

  const configHasBoth =
    Array.isArray(tauri.bundle?.targets) &&
    tauri.bundle.targets.includes("nsis") &&
    tauri.bundle.targets.includes("msi");

  const report = {
    ok:
      versions.ok &&
      chain.ok &&
      envCheck.errors.length === 0 &&
      bundle.ok &&
      bundle.errors.length === 0 &&
      configHasBoth,
    version: versions,
    chain84532: chain,
    wix: { available: wixAvailable },
    bundleTargets: {
      config: tauri.bundle?.targets,
      configDeclaresNsisAndMsi: configHasBoth,
      effective: bundle.effective,
      ok: bundle.ok && configHasBoth && bundle.errors.length === 0,
      warnings: bundle.warnings,
      errors: bundle.errors,
    },
    env: {
      path: envPath,
      present,
      errors: envCheck.errors,
      warnings: envCheck.warnings,
      hasRelayerUrl: Boolean(String(bag.VITE_ATTESTOR_RELAYER_URL ?? "").trim()),
      hasAccessPair: Boolean(
        String(bag.VITE_CF_ACCESS_CLIENT_ID ?? "").trim() &&
          String(bag.VITE_CF_ACCESS_CLIENT_SECRET ?? "").trim(),
      ),
    },
    decisions: {
      authenticode: "skipped (pilot)",
      updater: "deferred (feature off)",
      minisign: "yes on SHA256SUMS.txt when minisign available",
      host: "GitHub Releases / private distribution",
      installMode: "currentUser (AppData\\Local) — uninstall any prior machine-wide install first",
    },
  };

  // config must still declare both; effective may be nsis-only without WiX
  if (!configHasBoth) {
    report.ok = false;
  }

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("=== Stream D release-check ===");
    console.log(
      versions.ok
        ? `OK  version parity @ ${versions.expected}`
        : `FAIL version parity (want ${versions.expected}): ${versions.mismatches.join("; ")}`,
    );
    console.log(
      chain.ok
        ? "OK  84532 core addresses present (frozen deploy)"
        : `FAIL 84532 core addresses missing/null: ${chain.missing.join(", ")}`,
    );
    console.log(
      configHasBoth
        ? `OK  bundle.targets declares nsis+msi (${JSON.stringify(tauri.bundle?.targets)})`
        : `FAIL bundle.targets must declare ["nsis","msi"] (got ${JSON.stringify(tauri.bundle?.targets)})`,
    );
    console.log(
      wixAvailable
        ? "OK  WiX (candle/light) on PATH — MSI will be built"
        : "WARN WiX (candle/light) NOT on PATH — MSI skipped; NSIS only",
    );
    console.log(`     effective bundles: ${JSON.stringify(bundle.effective)}`);
    for (const w of bundle.warnings) console.log(`WARN bundle: ${w}`);
    for (const e of bundle.errors) console.log(`FAIL bundle: ${e}`);
    if (!present) {
      console.log(`WARN .env.production.local not found at ${envPath}`);
    } else {
      console.log(`OK  .env.production.local present (secrets not printed)`);
    }
    for (const w of envCheck.warnings) console.log(`WARN env: ${w}`);
    for (const e of envCheck.errors) console.log(`FAIL env: ${e}`);
    console.log(
      "NOTE installMode=currentUser → AppData\\Local. Uninstall any old Program Files install first (parallel installs).",
    );
    console.log(report.ok ? "RESULT: PASS" : "RESULT: FAIL (fail-closed)");
  }

  process.exit(report.ok ? 0 : 1);
}

main();
