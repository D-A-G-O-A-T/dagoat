# Season-0 UI Runbook — Contribute + Wallet + Ops on Windows

**[TARGET] — testnet only.** Everything here runs on local anvil or Base Sepolia with MockUSDT. No mainnet, no real USDT (counsel gate). GOAT here is a pilot testnet token; its trade price is a posted session bid and may find zero buyers. Sponsor #1 is the founder; this proves the mechanism, not external demand.

**One product:** users install **Goat only**. Folding@home is a **managed engine** behind WorkBackend (powered by Folding@home open source). Primary tab is **Contribute**. Dual mode: **A — public good only** (default) / **B — public good + GOAT pilot (testnet)**. Advanced users may still attach a pre-installed FAHClient.

All commands are **Windows PowerShell** unless marked otherwise.

---

## 0. Prerequisites (once)

| Tool | Check | Install |
|---|---|---|
| Node ≥ 20 | `node --version` | https://nodejs.org |
| Rust + Cargo | `cargo --version` | https://rustup.rs |
| Tauri CLI 2 | `cargo tauri --version` | `cargo install tauri-cli` |
| Foundry | `forge --version` | Git Bash: `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`. Binaries land in `$HOME\.foundry\bin` — add to PATH. |
| **Goat desktop** | `cargo tauri dev` from `desktop/` | Install **this app only** for the primary path. |
| **FAH engine** (one-time, if needed) | port 7396 / FAHClient running | **Managed:** click **Start contributing** — Goat starts FAH if installed, or opens https://foldingathome.org/start-folding for a one-time install (accept FAH EULA), then leave the client running. **Advanced:** install FAH yourself and attach. |

One-time app deps:

```powershell
cd F:\flight\GPUCoin_Guidance\desktop
npm install
```

> If `forge`/`anvil` aren't on PATH in PowerShell: `$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"`

---

## 1. Local anvil loop (fastest full rehearsal)

> **Shortcut:** `powershell -ExecutionPolicy Bypass -File contracts\dev-up.ps1` automates all of §1
> (anvil + deploy + wire + UI config copy) and seeds the founder with 10,000 mockUSDT and 100 GOAT
> (real mint path, dev-seed job). It does NOT create the season0-fah job — use the Ops button.

**Terminal A — chain:**

```powershell
anvil
```

Leave it running. Anvil prints ten funded test accounts; this runbook uses account #0 as SAFE + FOUNDER + DEPLOYER and account #2 as RESERVE:

```
account0 addr: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
account0 key : 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
account2 addr: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
```

**Terminal B — deploy + wire (from `F:\flight\GPUCoin_Guidance\contracts`):**

```powershell
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"
$env:SAFE_ADDRESS         = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
$env:FOUNDER_ADDRESS      = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
$env:RESERVE_ADDRESS      = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
$env:DEPLOYER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

forge script script/DeployFreeMarket.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
```

The script logs six addresses and writes `contracts/deployments/31337.json`. Now wire (paste the logged addresses into variables first):

```powershell
$SAFE_KEY  = $env:DEPLOYER_PRIVATE_KEY
$RPC       = "http://127.0.0.1:8545"
# From the deploy log / deployments/31337.json:
$REGISTRY  = "<enrollmentRegistry>"
$GOAT      = "<goatCoin>"
$ESCROW    = "<holdbackEscrow>"
$MINTER    = "<workMinter>"
$DESK      = "<buyDesk>"

cast send $ESCROW "setVault(address)" $MINTER --private-key $SAFE_KEY --rpc-url $RPC
cast send $GOAT "setMinter(address,bool)" $MINTER true --private-key $SAFE_KEY --rpc-url $RPC
foreach ($a in @($ESCROW, $MINTER, $DESK, $env:FOUNDER_ADDRESS, $env:RESERVE_ADDRESS, $env:SAFE_ADDRESS)) {
  cast send $REGISTRY "setSystemAddress(address,bool)" $a true --private-key $SAFE_KEY --rpc-url $RPC
}
```

**Refresh the UI's address config** (required after every redeploy):

```powershell
Copy-Item F:\flight\GPUCoin_Guidance\contracts\deployments\31337.json F:\flight\GPUCoin_Guidance\desktop\src\chain\deployments\31337.json -Force
```

**Terminal C — the app:**

```powershell
cd F:\flight\GPUCoin_Guidance\desktop
cargo tauri dev
```

The window opens with the honesty banner, mode toggle, and three tabs: **Contribute | Wallet | Ops**. Pick network **Local anvil**.

---

## 2. Primary path — one product, dual mode

### 2a. Mode A (default) — public good only

1. Leave the mode toggle on **Public good only**.
2. **Contribute** tab → select **Folding@home** → **Start contributing**.
   - If FAH is already installed, Goat starts/attaches to the managed engine.
   - If missing, Goat opens the official installer page — install once (EULA), leave FAH running, click **Start contributing** again.
   - Live progress is FAH science (display-only). No wallet, no mint, no GOAT pressure.
3. Advanced controls (Connect / Start / Stop / Pause) remain for power users who already run FAH externally.

### 2b. Mode B — public good + GOAT pilot (founder acceptance path)

1. Switch mode to **Public good + GOAT pilot (testnet)**.
2. **Wallet tab** → import testnet key (anvil account0 key above; **never a key that holds real funds**). Address shows as your bound wallet.
3. **Ops tab** (same key = the safe):
   - *Enrollment panel*: enroll your own address.
   - *Season-0 job panel*: **Create Season-0 FAH job** (1 GOAT / WU, 5% holdback, founder-accept badge with the Sponsor-#1 line).
   - *Desk panel*: **MockUSDT faucet (testnet)** → then **fund desk** (e.g. 100 USDT) → confirm **posted bid** (default 1 GOAT = 0.01 USDT — a bid, not a peg) → **open session**.
4. **Contribute** tab → backend selector shows **Folding@home** as the only enabled card (greyed slot = future NGO engines; not implemented yet).
   - **Start contributing** (or advanced Connect → Start) → real FAH folding; GOAT stays testnet.
   - Set username/team/passkey in config (stored locally only).
   - **Check for accepted work**: credited WUs become *pending* after Folding@home stats credit them (stats can lag ~an hour — nothing is simulated).
5. **Ops tab** → *Accept & mint*: review pending units + manifestRoot → **Confirm & mint**. Double-mint blocked on-chain (`ManifestReplayed`).
6. **Wallet tab** → liquid GOAT (95%) + holdback (5%), provenance, voluntary **Sell** or **Hold** (*You never have to sell. Holding GOAT is always allowed.*).

**CI/dev only:** set `GOAT_REHEARSAL=1` before `cargo tauri dev` to expose a labeled REHEARSAL backend (fake deterministic work). It is never part of a founder demo.

---

## 3. Base Sepolia path

The v1 pilot contracts are already live on Sepolia; the free-market (v2) contracts need one deploy, **reusing** the live GoatCoin/Registry/MockUSDT so balances and enrollment carry over:

```powershell
cd F:\flight\GPUCoin_Guidance\contracts
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"
$env:BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org"
$env:SAFE_ADDRESS         = "<your Sepolia EOA>"
$env:FOUNDER_ADDRESS      = "<your Sepolia EOA>"
$env:RESERVE_ADDRESS      = "<reserve addr>"
$env:DEPLOYER_PRIVATE_KEY = "<funded Sepolia TESTNET key>"   # never in git; contracts/.env is gitignored
$env:EXISTING_USDT        = "0x7e7553bc827e1a86b54217d170b0fdae8fecc1bb"
$env:EXISTING_REGISTRY    = "0xa8326d35e6888253cea426ca37c1361acdf41eae"
$env:EXISTING_GOAT        = "0x63bb8f47003b754544bd20398e7b22941d5f8e6b"

forge script script/DeployFreeMarket.s.sol --rpc-url $env:BASE_SEPOLIA_RPC_URL --broadcast
```

Then run the same wiring block as §1 against `--rpc-url $env:BASE_SEPOLIA_RPC_URL`, copy `contracts/deployments/84532.json` to `desktop/src/chain/deployments/84532.json`, restart the app, and switch the network to **Base Sepolia**. The deploy script refuses every chain except 84532/31337 (`ChainNotAllowed`) — the mainnet embargo is code.

---

## 4. Registering a future NGO backend (one paragraph)

A new public-good project becomes a Contribute option by (1) implementing the `WorkBackend` trait in `desktop/src-tauri/src/workbackend/<id>.rs` — detection, **managed** `ensure_engine` / `engine_state` / start/stop where applicable, connect/start/stop, live status, `config_fields`, and `list_completions()` from the project's *own* acceptance/credit source; (2) adding a catalog row in `catalog.rs` with beneficiary, isolation class, honesty tags, and published unit conversion; and (3) registering it in `build_registry()`. Until catalog admission, NGO rows stay disabled and `ensure_engine` must return a clear "not implemented / not admitted" report — never fake progress. Contribute UI, journal, accept flow, and mint path need **zero** changes for a second engine.

---

## 5. Honesty checklist (enforced in copy — keep it that way)

- Persistent banner: *Testnet GOAT — not money… Sponsor #1 is the founder; this proves the mechanism, not external demand.*
- Formula published in Contribute, Wallet, README: **1 credited Folding@home work unit (WU) = 1 work unit = 1 GOAT** — never GPU model, TFLOPS, uptime, or power level (the power slider is an FAH resource control and says so).
- FAH is a managed open-source science engine; Goat does not claim a full GPU sandbox.
- Mode A never mints; Mode B is explicitly testnet pilot.
- Posted bid is a bid, not a peg; desk depth always visible; empty desk is an honest state.
- "You never have to sell. Holding GOAT is always allowed."
- Ops header: *Founder personal pilot — not a multi-donor treasury.* Founder GOAT acquisitions are on-chain `Sold` events — public by construction.
- Isolation honesty: FAH runs as the official FAHClient on the host (Class C) — no GPU-sandbox claim.
- Forbidden vocabulary in product copy: "mine crypto", wage/paycheck/salary, "guaranteed $", live-mainnet earnings.

## 6. Evidence snapshot (2026-07-11, branch feature/goatcoin-contracts)

- `forge test`: **91 passed / 0 failed** (incl. WorkMinter replay-guard, BuyDesk, 4 free-market invariants @ 512 runs ×25 depth; no solvency-vs-supply invariant by design — free-market law).
- `npx vitest run` (desktop): **52 passed / 1 skipped** (skip = opt-in live-anvil e2e, `GOAT_E2E=1`).
- `cargo test --lib` (src-tauri): **40 passed / 2 ignored** (ignored = live-FAH integration tests).
- Live-anvil e2e (S9): createJob → mintBatch → 85/15 split asserted on-chain → journal stamped only after confirmation.
- FAH detect→install-hint path verified on a machine without FAHClient (honest `Missing` state). Live fold + credited-WU delta is the founder's acceptance run (§2) — FAH stats field names carry a small residual risk noted in `F:\.superpowers\sdd\s6-report.md`; worst case is a visible no-op, never fake data.
