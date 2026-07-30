/**
 * Detect WiX Toolset v3 on PATH (candle.exe + light.exe).
 * Windows: `where`; Unix CI: `which` (usually absent → false).
 */
import { execSync } from "node:child_process";

/**
 * @param {{ exec?: typeof execSync, platform?: string }} [deps]
 * @returns {boolean}
 */
export function detectWixAvailable(deps = {}) {
  const exec = deps.exec ?? execSync;
  const platform = deps.platform ?? process.platform;
  const finder = platform === "win32" ? "where" : "which";
  try {
    exec(`${finder} candle`, { stdio: "pipe", shell: true });
    exec(`${finder} light`, { stdio: "pipe", shell: true });
    return true;
  } catch {
    return false;
  }
}

// CLI: print "true" / "false"
if (
  process.argv[1] &&
  process.argv[1].replace(/\\/g, "/").endsWith("detect-wix.mjs")
) {
  process.stdout.write(detectWixAvailable() ? "true\n" : "false\n");
}
