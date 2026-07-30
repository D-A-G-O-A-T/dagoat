# D.A. G.O.A.T. desktop — Season-0 Contribute + Wallet + Ops

**[TARGET] — testnet pilot.** One Tauri v2 + React app. Users install **Goat only**; Folding@home is a **managed engine** behind `WorkBackend` (powered by Folding@home open source). Primary tab is **Contribute**. Dual mode: **Public good only** (default) or **Public good + GOAT pilot (testnet)**. The science is real when the engine is running; GOAT is a testnet pilot token whose trade price is a posted session bid and may find zero buyers. No mainnet, no real USDT (counsel gate). No claim in this app exceeds `RUNTIME_VS_SPEC.md`.

## Run

```powershell
cd desktop
npm install          # once
cargo tauri dev      # dev app (Vite on :5173 + Tauri shell)
```

Full founder walkthrough (anvil chain, deploy, wiring, one-product contribute path): **`contracts/SEASON0_UI_RUNBOOK.md`**.

### Primary user path

1. Install **Goat** (this app).
2. Open **Contribute** (Mode A by default).
3. Click **Start contributing** — Goat ensures/starts the FAH engine, or opens the official installer once if needed.
4. Optional: switch to **Public good + GOAT pilot** for Wallet / Ops mint path (testnet).

**Advanced:** attach an already-installed FAHClient (Connect controls remain).

## Architecture (universal Contribute / WorkBackend law)

```
React (src/)                          Rust (src-tauri/src/)
 tabs/Miner.jsx ── invoke ──▶ workbackend/mod.rs   trait WorkBackend + registry
   (Contribute UI)                     + EngineState / ensure_engine lifecycle
 tabs/Wallet.jsx ─ viem ──▶ chain    workbackend/catalog.rs  FAH enabled · NGO slots
 tabs/Ops.jsx ──── viem ──▶ chain    workbackend/fah.rs      managed FAHClient v8 (ws :7396)
 contributeMode.js (Mode A/B)        workbackend/rehearsal.rs (GOAT_REHEARSAL=1, CI only)
 journal.js  (pending units, tauri-store)
 chain/ (viem clients, trimmed ABIs, deployments/{31337,84532}.json)
```

- **Contribute is backend-pluggable**: the UI renders only `CatalogEntry` data and generic IPC — no FAH types outside the adapter. A future NGO backend = new adapter + catalog row + honest `ensure_engine` (see runbook §4).
- **Managed engines**: `ensure_engine` / `engine_state` / `start_engine` / `stop_engine` — one-product install; no dual-product journey.
- **Mint basis** (Mode B only): 1 credited Folding@home WU = 1 work unit = 1 GOAT (published; never GPU power/uptime). Completions from FAH stats credit, at-most-once, journaled before use.
- **Trade**: voluntary `sell()` to the founder-funded BuyDesk while a session is open. Holding forever is a first-class outcome.
- Networks: local anvil (31337) and Base Sepolia (84532) only — no mainnet RPC exists in this codebase.

## Pilot release build (Stream C + Stream D0)

**Prereq:** Stream B-live has frozen non-null `src/chain/deployments/84532*.json`. Tunnel hostname from Stream E.

**Stream D decisions (locked):** NSIS+MSI · GitHub Releases/private · minisign on `SHA256SUMS.txt` · **no** Authenticode · **no** updater for pilot.

```powershell
# Fail-closed gate (must FAIL while 84532 placeholders are null; PASS only after B-live freeze)
powershell -ExecutionPolicy Bypass -File scripts\release-check.ps1

# After freeze + .env.production.local ready:
powershell -ExecutionPolicy Bypass -File scripts\release-build.ps1 -StrictEnv
# → desktop/dist-release/<version>/  (installers + SHA256SUMS.txt [+ .minisig])
```

Volunteer docs: `docs/VOLUNTEER_INSTALL.md` · Operator: `docs/RELEASE_OPERATOR.md`

```powershell
cd desktop
copy .env.production.example .env.production.local
# edit .env.production.local:
#   VITE_DEFAULT_NETWORK_ID=84532
#   VITE_PILOT=1
#   VITE_ATTESTOR_RELAYER_URL=https://<your-tunnel-host>
#   optional VITE_CF_ACCESS_CLIENT_ID / _SECRET (speed-bump only)
#   optional VITE_CSP_EXTRA_CONNECT if using a non-default RPC origin

# Vite loads .env.production* for production mode; tauri beforeBuildCommand
# runs scripts/inject-relayer-csp.mjs so connect-src includes the tunnel origin.
cargo tauri build
```

Honesty: CF Access tokens ship inside the installer and are extractable. They are **bot friction**, not authentication. Relayer H1 signature verify + H2/H2b spend ceilings are load-bearing.

**Vite build-time lock:** every `VITE_*` value is baked into the JS bundle at `cargo tauri build`. Changing the Cloudflare Tunnel hostname or RPC later requires a **rebuild and re-distribute** (no runtime config, no updater). Finalize tunnel + RPC + frozen 84532 addresses **before** the production build.

**CSP:** `inject-relayer-csp.mjs` always preserves Tauri internal schemes (`ipc:`, `tauri.localhost`, `asset:`, …). Do not hand-edit those out of `tauri.conf.json`.

Do **not** cut a volunteer installer (Stream D) until addresses are frozen — there is no auto-updater.

## Tests

```powershell
npx vitest run                 # frontend units
cd src-tauri; cargo test --lib # Rust plane (+ live-FAH ignored)
```
