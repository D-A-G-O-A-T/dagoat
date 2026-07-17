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

## Tests

```powershell
npx vitest run                 # frontend units
cd src-tauri; cargo test --lib # Rust plane (+ live-FAH ignored)
```
