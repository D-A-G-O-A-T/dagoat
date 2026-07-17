# D.A. G.O.A.T. (GoatCoin)

**D.A. G.O.A.T.** — *Decentralized Architecture, Global Orchestration & Aligned Technology*

The software is the **D.A. G.O.A.T. Engine** — the post-quantum verification-mesh runtime (the
`goatd` daemon). Nodes form a PQ-authenticated gossip network, verify capability records, and
(Phase-0) run an out-of-process worker harness.

**License:** [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)

> **Honesty.** This is **not** a live token marketplace, rewards network, or production sandbox.
> Crypto on the wire is real (ML-DSA-65 / ML-KEM-768 / AES-256-GCM) via pre-1.0, unaudited crates.
> See [`RUNTIME_VS_SPEC.md`](RUNTIME_VS_SPEC.md) for shipped vs designed capabilities.

---

## Build & test

```bash
cargo test
cargo build --release --bin goatd
cargo build --release --bin goat-worker
cargo build --release --bin goat-keygen
```

Requires a recent stable Rust toolchain.

---

## Run a local multi-node lab

```bash
cp .env.example .env          # optional: set GOATD_CPU_LIMIT
docker compose up --build
```

- Five nodes on UDP ports `4640`–`4644` (host) → `4646` inside containers  
- Power dial: `GOATD_CPU_LIMIT` in `.env` (Docker cgroups CPU quota)  
- Lab identities are **forgeable by design** unless you set unique `GOATD_SIGNING_SEED`s  

Operator walkthrough: **[`ALPHA_PILOT.md`](ALPHA_PILOT.md)**  
Deploy checklist: **[`DEPLOY.md`](DEPLOY.md)** · Key migration: **[`MIGRATION.md`](MIGRATION.md)**

---

## Repository layout

| Path | Role |
|------|------|
| `src/` | **D.A. G.O.A.T. Engine** deploy spine — `goatd` / crypto / isolation binaries |
| `goatcoin-rs/` | Mechanism workspace (protocol, ledger, net experiments) |
| `reference/` | Python reference implementations & tests |
| `desktop/` | Early desktop shell (optional, incomplete product) |
| `genesis.json` | Lab genesis (public keys only; forgeable testnet IDs labeled) |
| `RUNTIME_VS_SPEC.md` | **Canonical** shipped-vs-designed matrix |
| `ARCHITECTURE.md` | Node crate architecture |
| `ARCHITECTURE_CONVERGENCE.md` | Deploy spine vs `goatcoin-rs` ownership |
| `GoatCoin_Yellowpaper.md` | Protocol specification (engineering — not a token offering) |
| `GoatCoin_Threat_Model.md` | Threat / RECON register |
| `GoatHAL_*.md` | Phase-0 isolation design & threats |

---

## Direction (not shipped)

Long-term intent: align idle machines toward **verifiable public-good batch compute**, with
economics that never pay out more than real external inflow (**No-Ponzi**). That product path is
**design**, not current runtime. Code truth always wins: `RUNTIME_VS_SPEC.md`.

---

## Security notes for operators

- Do **not** expose a lab node with deterministic testnet seeds on a public bind.  
- Prefer `GOATD_SIGNING_SEED` (64 hex) per node for any off-host use.  
- Phase-0 isolation is cooperative process separation — **not** a multi-tenant production sandbox.  
- Report security issues responsibly; this software is experimental.

---

## Contributing

1. Read `RUNTIME_VS_SPEC.md` before changing capability claims in docs.  
2. `cargo fmt` / `cargo clippy` / `cargo test` on the root package.  
3. Keep fail-closed behavior for identity, genesis, and isolation gates.
