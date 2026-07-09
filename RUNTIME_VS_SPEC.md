# RUNTIME_VS_SPEC.md — What is shipped vs what is designed (P6 honesty matrix)

**Date:** 2026-07-08 · **Track:** B (P6) · **Owner:** Project
**Predecessor:** AR88 (Track A archive) · **Companion:** `ARCHITECTURE_CONVERGENCE.md` (P1), README.md

**Why this file is the arbiter.** GoatCoin's vision documents describe a post-quantum,
anti-monopolization compute *marketplace*. The code that actually runs is much smaller. This matrix
is the single place that states, per capability, **what the running software does today** — so no
operator-facing or deploy-facing document can imply a finished product. If a doc's language exceeds a
row's `Status`, the doc is wrong, not this table.

---

## 0. The three configurations (columns)

| Cfg | What it is | Ships in Docker / Alpha? | Crypto reality |
|-----|-----------|--------------------------|----------------|
| **C1** | **Deploy spine, default build** — root `src/` + `src/bin/goatd.rs`, `cargo build` (`alloc`, testnet). This is what the `docker-compose` cluster and the Alpha run. | **YES** | **REAL integration** (Track C) of **pre-1.0, not externally audited** crates (`ml-dsa` 0.1.1, `ml-kem` 0.3.2, `aes-gcm` 0.11.0, `sha3` 0.10.x — **A3 open**). Not a FIPS-certified product. |
| **C2** | **Sealed core, `--no-default-features`** — the `#![no_std]`, allocation-free, panic-free enclave build of the same root modules. | Not directly (it is the audited core inside C1) | Core is crypto-*agnostic* (traits only); host backends are std/`goatd` only. |
| **C3** | **`goatcoin-rs/` mechanism workspace** — the 5-crate MVP (`goat-protocol/ledger/net/backends/neutrality`). Off the deploy path. | **NO** (demos + harness + auditor only; no daemon) | **REAL** — same crate family; still the mechanism/oracle tree (ledger, F6, etc.). |

> **Updated (Track C):** deploy-path (C1) PQ auth and AEAD are **real**. The mesh is still **not** a
> compute marketplace (no rewards, settlement, or task market). Economic MVP remains C3/design.

---

## 1. The matrix

`Status` values: **SHIPPED** (runs on the deploy path C1 and does what it says) · **PARTIAL** (runs,
but with a load-bearing caveat) · **MVP-ONLY** (implemented, but only in C3 / off the deploy path) ·
**DESIGN** (spec/vision only; no implementation in any config).

| # | Claim | Where it lives (code path) | C1 | C2 | C3 | Status | Forbidden claim (must NOT appear in ALPHA/DEPLOY/README) |
|---|-------|----------------------------|----|----|----|--------|-----------------------------------------------------------|
| 1 | **Golden Goal** — any idle computer earns; farms can't monopolize | Vision docs; anti-farm *primitives* in root `state::derive_authorization_set`, `crypto::fold_verified_attributed`, `normalize_weights_largest_remainder`; F6 in C3 | ◑ primitives only | ◑ primitives only | ◑ MVP | **DESIGN** | "Idle machines worldwide are earning GOAT" / "monopolization is prevented in the live network" |
| 2 | **Idle earnings / passive income / rewards** | *Nowhere* — no emissions/token/reward code in any config (`goat-ledger/src/lib.rs:4` "token/reward-related is out of scope") | ✗ | ✗ | ✗ | **DESIGN** | "Earn rewards" / "passive income" / "get paid for compute" as a present-tense capability |
| 3 | **F6 anti-farm / Sybil density** | `goat-protocol::capability::evaluate_density`, `goat-net::density` (C3 only); root has device-agnostic fold/lottery but **not** F6 | ✗ | ✗ | ✓ | **MVP-ONLY** | "The running mesh detects and suppresses farms/Sybils" |
| 4 | **Fraud proofs / challenge adjudication** | `goat-ledger::{ledger,actors}`, `goat-protocol::maturity::verify_posting` (C3 only) | ✗ | ✗ | ✓ | **MVP-ONLY** | "Fraud proofs protect the live network" |
| 5 | **CET settlement + oracle** | `Dynamic-CETSettlement & Oracle …md` (design doc). **No implementation anywhere.** | ✗ | ✗ | ✗ | **DESIGN** | "CET settlement is operational" / "oracle-priced compute" |
| 6 | **PQ authentication** (ML-DSA-65 sign/verify, ML-KEM-768 key agreement) | C1 `host_crypto` + C3. **Signatures real**; det-seed identities forgeable (identity-hardening). Crates **pre-1.0, not externally audited (A3)**. | ✓ sig / ◑ id | traits | ✓ | **PARTIAL** (C1) | "Prevents peer impersonation" / "unforgeable identity" / "externally audited" / "FIPS certified product" / "side-channel resistant" |
| 7 | **PQ-only, no classical fallback** (design invariant) | True in every config — no classical primitive is imported; SHA3-256 is real throughout. | ✓ | ✓ | ✓ | **SHIPPED** (invariant only — not an audit claim) | "Side-channel resistant" / "constant-time proven" |
| 8 | **Post-quantum encrypted transport + handshake** | Real ML-KEM+AES + **MTU-safe chunking** (≤1200 B UDP, MTU-chunking). Identity secrecy + **A3** still open. Lab wire proven; full cross-NAT 1500-MTU field trial still residual. | ✓ crypto+chunk / ◑ id | traits | ✓ | **PARTIAL** (C1) | "Unforgeable identity" / "audited FIPS" / "side-channel resistant" / "proven on every residential NAT" without field evidence |
| 9 | **Signed gossip: verify-before-forward** | Real verify + registry; det-seed impersonation risk; **A3 open**. | ✓ verify / ◑ id | ✓ | ✓ | **PARTIAL** (C1) | "Prevents peer impersonation" / "externally audited" |
| 10 | **Anti-DoS: stateless cookie, single-use replay guard, hash-before-verify dedup, bounded ingress, session cap** | root `transport::{issue_cookie,CookieCache}`, `gossip::MessageCache`, `goatd` bounded `mpsc` + LRU session cap (RECON-11/12/14) | ✓ | ✓ | partial | **SHIPPED** | — (honest & load-bearing; this is the real strength of the running mesh) |
| 12 | **Decentralized compute marketplace** (task submit → distribute → execute → settle) | No task-execution, distribution-to-consumers, or settlement path in any config; C3 has *verification* rounds, not a market | ✗ | ✗ | ✗ (verification only) | **DESIGN** | "A working / production compute marketplace" |
| 13 | **Execution isolation (GoatHAL / Vector 1.1)** | Host-edge out-of-process worker (`goat-worker` + `isolation` supervisor). Hostile probes (fs outside scratch, net, spawn, crash) **denied/contained**; fail-closed if worker missing. **Not** a production multi-OS GPU sandbox; Linux namespaces/seccomp design-only. | ✓ Phase-0 proof | n/a | oracle HAL | **PARTIAL** (C1 Phase-0) | "Secure multi-tenant sandbox product" / "safe to run arbitrary vLLM/Triton on any host" / marketplace |

Legend: ✓ real & present · ◑ present but caveated (scaffold/primitive) · ✗ absent.

---

## 2. The one-paragraph honest description (use this everywhere)

> **GoatCoin today is an experimental post-quantum verification mesh.** Running nodes perform a
> RECON-11 cookie handshake, real ML-DSA-65 **signature** checks, ML-KEM-768 session establishment,
> and AES-256-GCM gossip (Track C / `host_crypto` — **pre-1.0 RustCrypto crates, not externally
> audited; A3 open**), with fail-closed registry and chain-id binding (Track A). A Phase-0
> **out-of-process execution isolation** harness (`goat-worker`) can contain hostile probe payloads
> to a scratch dir / denied net-spawn, but it is **not** a production multi-OS ML sandbox. On the
> default deterministic-seed testnet, **node private keys are publicly derivable** (identity-hardening). There
> is still **no token, no rewards, no useful-work marketplace, and no settlement**. It is safe to run
> and easy to stop; it is **not** a secured or audited compute marketplace.

---

## 3. Doc-language rulings (what each doc may / may not say)

| Doc | May say | May **not** say (until Track C exit + product path) |
|-----|---------|------------------------------------------------------|
| `ALPHA_PILOT.md` | "experimental verification mesh + verification scaffolding", "placeholder signatures", "no value at stake" | "post-quantum secured", "earn rewards", "production marketplace" |
| `DEPLOY.md` | "reference backends active, NOT FOR PRODUCTION", "Backend Swap Checklist pending" | "PQ crypto shipped", "audited" |
| `README.md` / README.md | the *vision* (clearly labeled as design intent) + a pointer to this matrix | vision language presented as current runtime capability |
| `ARCHITECTURE.md` | the sealed-core design + the frozen-trait contract | "ML-DSA-65 / ML-KEM-768 implemented" without the §6.4 placeholder caveat |

**Verification of current docs (2026-07-08):** `ALPHA_PILOT.md` and `DEPLOY.md` already carry the
required disclaimers and **pass**. `ARCHITECTURE.md` §3 needed a one-line placeholder caveat added
next to the PQ-primitives list (done this turn, cross-referencing §6.4). `README.md` / README.md
gained a "Runtime reality" pointer to this matrix (done this turn).

---

## 4. Exit condition for changing this matrix

A row moves from PARTIAL/MVP-ONLY/DESIGN to **SHIPPED** only when the capability runs on the **deploy
path (C1)** with a passing test and a live smoke — e.g. row #6/#8/#9 flip to SHIPPED only after Track
C wires C3's real crypto behind the frozen `SignatureVerifier` / `SecureChannel` / `GossipCodec`
traits and `DEPLOY.md` C-1…C-10 are green. Economic rows (#1–#5, #12) require a real product path that
does not yet exist. **Do not edit a doc to make a claim true; edit the code, prove it, then edit this
matrix, then the doc.**
