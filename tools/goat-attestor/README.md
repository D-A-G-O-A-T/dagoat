# goat-attestor

Standalone Rust daemon for **GOAT FAH attribution** (Phase 2): untrusted proposer, challenger, watcher heartbeat, and gas-sponsorship relayer.

> **Honesty:** core attribution logic is covered by unit tests against **MockChain**. Live broadcasting uses **alloy v2** HTTP (`RpcChain`) against `RPC_URL` when `GOAT_ATTESTOR_MOCK` is unset. Set `GOAT_ATTESTOR_MOCK=1` for offline / CI.

## Roles

| Role | What it does |
|------|----------------|
| **T5 FAH reader** | `GET {FAH_STATS_BASE}/user/{GOAT-username}` → cumulative `score`. Cached + rate-limited. Fixture tests in CI; `LiveHttp` (reqwest) when not using `--fixtures` and not mock. |
| **T6 Enrollment snapshot** | Newly bound workers get a prompt Merkle batch so first `claimPayout` can stamp baseline (mint 0). |
| **T7 Epoch proposer** | Daily freeform epoch (`YYYYMMDD` u64): scores → Merkle root → `proposeBatch` + evidence; watcher `confirmEpoch`. |
| **T8 Challenger** | Dual-mode: **inflate-only** post-baseline daily; **strict equality** for enrollment / pre-baseline (under-report = protocol theft). |
| **Relayer** | HTTP gas sponsorship: `POST /v1/relay/bind`, `POST /v1/relay/enroll`, `GET /health`. |
| **Auto-registry** | On every `run` / `once-propose` / `sync-registry`, pulls all `WorkerBinding.Bound` logs into `REGISTRY_JSON`. Successful gasless bind also upserts the worker immediately. Ops no longer hand-edit each new bind. |
| **Auto-earn** | `auto-earn` / `daemon` / `run`: propose → warp (anvil) → confirm → finalize → **claimPayout** for every leaf. See `docs/FOLD_TO_GOAT_AUTOMATION.md`. |

## Freeform epochs

`EpochSettlement.proposeBatch(uint256 epoch, …)` accepts any `uint256`. This daemon uses:

- **Daily:** `YYYYMMDD` as `u64` (UTC), e.g. `20260714`
- **Enrollment:** `9_000_000_000_000 + unix_secs` (disjoint namespace)

## Merkle parity (load-bearing)

Matches `EpochSettlement.claimPayout` / OpenZeppelin `MerkleProof`:

```text
leaf = keccak256(bytes.concat(keccak256(abi.encode(worker, provenCumulativeScore))))
pair = keccak256(concat(sort(a, b)))   // odd node carried up unpaired
```

## Env

Copy `.env.example`. Required:

- `RPC_URL`, `CHAIN_ID`
- `EPOCH_SETTLEMENT_ADDRESS`, `WORKER_BINDING_ADDRESS`, `ENROLLMENT_REGISTRY_ADDRESS`
- `REGISTRY_JSON` — local worker list (`{ "workers": [ { wallet, username, baseline_batched } ] }`)

### Mock vs live

| Mode | How | Chain | FAH |
|------|-----|-------|-----|
| **Mock** | `GOAT_ATTESTOR_MOCK=1` | `MockChain` (in-process) | `--fixtures` or default `fixtures/` |
| **Live** | unset mock | `RpcChain` (alloy → `RPC_URL`) | live API unless `--fixtures` |

Live role keys (0x-hex private keys):

- `PROPOSER_PRIVATE_KEY` — `proposeBatch` (+ bond value)
- `WATCHER_PRIVATE_KEY` — `confirmEpoch`
- `CHALLENGER_PRIVATE_KEY` — `challengeBatch` (+ bond value)
- `RELAYER_PRIVATE_KEY` — `bindWithSignature` / `enrollSelfWithSignature`

Optional defaults: `FAH_STATS_BASE`, `POLL_INTERVAL_S`, `MIN_FAH_INTERVAL_MS`, bonds, `RELAYER_BIND`, `STATE_DIR`, `EVIDENCE_DIR`.

### Local anvil

```bash
anvil --chain-id 31337
# deploy EpochSettlement / WorkerBinding / EnrollmentRegistry; set addresses in env

export RPC_URL=http://127.0.0.1:8545
export CHAIN_ID=31337
export EPOCH_SETTLEMENT_ADDRESS=0x...
export WORKER_BINDING_ADDRESS=0x...
export ENROLLMENT_REGISTRY_ADDRESS=0x...
export REGISTRY_JSON=./registry.json
# anvil account #0 (dev only):
export PROPOSER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export WATCHER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export CHALLENGER_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export RELAYER_PRIVATE_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
unset GOAT_ATTESTOR_MOCK

cargo run -- run --fixtures ./fixtures   # fixtures avoid live FAH while testing chain
```

### Mock (CI / offline)

```bash
export GOAT_ATTESTOR_MOCK=1
# export all required vars, or rely on mock defaults in some paths
cargo run -- once-propose --epoch 20260714 --fixtures ./fixtures
cargo run -- serve-relayer --bind 127.0.0.1:8787
cargo run -- run --fixtures ./fixtures
cargo run -- sync-registry   # pull Bound events → registry.json only
```

### Auto-register bound workers

You do **not** need to hand-edit `registry.json` for each new bind:

1. **`cargo run -- run`** / **`once-propose`** — scans `WorkerBinding.Bound` (wallet-gas and gasless) and merges into `REGISTRY_JSON` before proposing.
2. **`serve-relayer`** — on successful `POST /v1/relay/bind`, upserts that wallet+username immediately.
3. **`sync-registry`** — one-shot refresh without proposing.

Existing entries keep `baseline_batched` / `fah_id`. New wallets start with `baseline_batched: false` so enrollment snapshots still fire.

Optional ignored integration test (needs anvil):

```bash
cargo test rpc_chain_anvil_smoke -- --ignored --nocapture
```

## Fixtures (CI)

`fixtures/fah_user_alice.json` / `fah_user_bob.json` — `FixtureHttp` maps:

- URL contains `/user/GOAT-alice` → alice fixture  
- URL contains `/user/GOAT-bob` → bob fixture  
- else → 404  

No live Folding@home API calls in `cargo test`.

## Challenge rules (baseline under-report hazard)

First `claimPayout` stamps **baseline = proven cumulative** and mints 0. An under-reported
baseline is **not** “worker loss” — the next honest claim mints the entire historical delta
(`true − 0`). That drains the protocol.

| Context | Rule |
|---------|------|
| **Enrollment epoch** (`epoch >= 9_000_000_000_000`) | **Strict:** `proposed != public` → challenge (also if public FAH unavailable) |
| **Pre-baseline worker** (`!baseline_batched` or on-chain `!hasBaseline`) on any epoch | **Strict** (same) |
| **Post-baseline daily** | **Inflate-only:** challenge iff `proposed > public`; under-report OK (catch-up next epoch) |

```text
// enrollment / pre-baseline
if proposed != public  →  challengeBatch  // includes under-report
// post-baseline daily
if proposed >  public  →  challengeBatch
```

Running ≥1 honest challenger is a liveness/safety requirement of the optimistic lane.

## Merkle Solidity parity

Pinned vectors in `src/merkle.rs` (`pinned_solidity_cross_check_vectors`) must match
`contracts/test/RustDaemonMerkleParity.t.sol`, which runs live `claimPayout` against roots
produced by this daemon. Regenerate hex with:

```bash
cargo test --test print_vectors -- --nocapture
```

## Build / test

```bash
cd tools/goat-attestor
cargo test
cargo build
```

## Layout

```text
src/
  config.rs      env / map loader (+ role private keys)
  fah.rs         FAH stats client + FixtureHttp
  http_live.rs   LiveHttp (reqwest) + AnyHttp
  merkle.rs      keccak leaf + OZ tree
  registry.rs    worker JSON registry
  evidence.rs    evidence files + keccak ref
  chain.rs       ChainClient + MockChain + ABI encode/decode
  rpc_chain.rs   RpcChain (alloy live JSON-RPC)
  proposer.rs    build_epoch_batch / propose / confirm
  challenger.rs  evaluate_batch / review_epoch
  relayer.rs     axum HTTP API
  main.rs        clap subcommands
fixtures/        recorded FAH responses
```

## Relayer hosting (consultant 2026-07-15)

| Environment | Desktop `VITE_ATTESTOR_RELAYER_URL` | Who runs this daemon |
|-------------|------------------------------------|----------------------|
| Local pilot | unset → `http://127.0.0.1:8787` | Founder machine + anvil |
| User-facing build | `https://api.…` (founder infra) | Founder ops — **gas keys never on worker PCs** |

`serve-relayer` is infrastructure. Shipping localhost to end users is a misconfiguration, not a product mode.

## License

MIT OR Apache-2.0
