# ARCHITECTURE_CONVERGENCE.md — One production spine (P1)

**Date:** 2026-07-08 · **Track:** B (P1) · **Owner:** Project
**Predecessor:** AR88 · **Companions:** `RUNTIME_VS_SPEC.md` (P6), README.md, `ARCHITECTURE.md`

**Problem (P1).** The repository contains **two Rust trees** that both look like "the product":
- `src/` + `src/bin/goatd.rs` — the sealed `#![no_std]` core + the only async daemon (the tree Docker
  builds).
- `goatcoin-rs/` — a 5-crate `std` workspace (`goat-protocol`, `goat-backends`, `goat-neutrality`,
  `goat-ledger`, `goat-net`) with demos, a testnet harness, and — importantly — **real PQ crypto** and
  the **economic-mechanism MVP** (maturity, fraud loop, ledger, F6 density).

Two trees ⇒ drift, double maintenance, and the reader cannot tell which is production. This document
picks **one** spine and assigns every module exactly one disposition.

---

## 1. ADR-B1 — The deploy spine is root `goat-core` + `goatd`; `goatcoin-rs` is the mechanism oracle

**Decision.** The **production spine is the root tree** (`src/` sealed `#![no_std]` core +
`src/bin/goatd.rs`). `goatcoin-rs/` is **not** a second product: it is (a) the **crypto oracle** that
Track C ports from, and (b) the **mechanism/parity oracle** for the economic design. No second
production daemon exists or will be created.

**Blocker check (the mandate said: use this default unless you prove a blocker).** No blocker found —
the evidence *reinforces* the default:

| Evidence (verified this turn) | Consequence |
|-------------------------------|-------------|
| `goatcoin-rs` has **no daemon** — only `goat-mvp1/2/3-demo`, `goat-collect` (harness), `goat-neutrality` (auditor). The only `fn main` production daemon in the repo is `src/bin/goatd.rs`. | There is nothing to "choose between" at the daemon level. Root wins by default. |
| **No `goatcoin-rs` crate is `#![no_std]`**; none have `alloc`/`std` features; all use `Vec`/`String`/`HashMap`/`std::{fs,env}`. | The sealed enclave core exists **only** in root. `goatcoin-rs` cannot be the audited core. |
| `goatcoin-rs` has **real** ML-DSA-65 (`goat-protocol::pqsign`), ML-KEM-768 + AES-256-GCM (`goat-net::transport`); root has **placeholders**. | `goatcoin-rs` is the ideal **Track-C source**, wrapped behind root's frozen traits — not a rival spine. |
| Dependency law already **holds** in `goatcoin-rs` (`goat-protocol` has no backend dep). | The neutrality discipline is portable to the spine, not something to rescue. |

**Consequences.**
1. Docker/Alpha/DEPLOY/MIGRATION continue to build **only** the root tree. `goatcoin-rs` is never
   shipped in the image (it isn't today; this makes it a rule).
2. Real crypto is unified by **porting C3 → C1 behind frozen traits (Track C)**, not by shipping C3.
   After Track C there must be **exactly one** real-crypto path — the one `goatd` uses (dependency law
   §3.3).
3. Economic mechanisms absent from the spine (maturity, fraud loop, ledger, F6/density, HLL) are
   **PORT** candidates — but porting requires a `no_std` + allocation-free rewrite (they are `std`
   today), so it is deliberately staged, not a bulk move.
4. **No mass-delete of `goatcoin-rs`.** It is preserved as ORACLE/PORT source; this map is its
   inventory of record.

---

## 2. Module ownership map

**Vocabulary (exactly one per module).** **CANON** = production impl going forward · **ORACLE** =
parity/tests only, never in Docker · **PORT** = must move into the spine (owner named), executed in a
later track · **ARCHIVE** = frozen, no new features.

### 2.1 Root deploy spine — all CANON

| Path | Status | Note |
|------|--------|------|
| `src/lib.rs`, `src/types.rs`, `src/crypto.rs`, `src/state.rs`, `src/transport.rs`, `src/gossip.rs`, `src/daemon.rs` | **CANON** | The sealed `#![no_std]` core. Frozen traits `SignatureVerifier`, `KeyRegistry`, `SecureChannel`, `GossipCodec` live here — Track C wraps, never reshapes them. |
| `src/bin/goatd.rs` | **CANON** | The **only** async/`std`/`alloc` binary boundary. All four RECON guardrails + Track-A fail-closed startup. |
| `Cargo.toml`, `genesis.json`, `Dockerfile`, `docker-compose.yml`, `.env.example` | **CANON** | The deploy artifacts. |

### 2.2 `goatcoin-rs` — per-module disposition

**`goat-protocol`** (device-agnostic; no backend dep — CANON *discipline*, mixed *module* fate):

| Module | Status | Rationale / owner |
|--------|--------|-------------------|
| `pqsign.rs` (real ML-DSA-65) | **PORT** | Track C: wrap behind root `crypto::SignatureVerifier` (+ a signer for identity). The proven `ml-dsa 0.1.1` binding. |
| `capability.rs` (incl. `evaluate_density` / F6) | **PORT** | Golden-Goal anti-farm. F6 density has no root counterpart → owner: a future `src/` fairness module (no_std rewrite). |
| `maturity.rs` (controller, gate, `verify_posting`) | **PORT** | Fair-rewards state machine; no root counterpart. |
| `hll.rs` (deterministic HyperLogLog, R-MAT1) | **PORT** | Coverage counter needed by maturity/density. |
| `verification.rs` (cross-class fold/agree) | **ORACLE** | Root `crypto::fold_verified_attributed` is CANON; this is its parity oracle. |
| `commit.rs`, `types.rs`, `backend.rs`, `provenance.rs`, `attestation_chain.rs`, `conformance.rs` | **ORACLE** | Reference shapes / D1–D8 conformance / reference device-trait; parity only. `provenance` partially overlaps root `ExecutionAttestation` (root is CANON). |

**`goat-net`** (real PQ transport + distributed verification):

| Module | Status | Rationale / owner |
|--------|--------|-------------------|
| `transport.rs` (real ML-KEM-768 + AES-256-GCM + ML-DSA auth) | **PORT** | Track C: wrap ML-KEM/AEAD behind root `transport::SecureChannel` + real `derive_session_key`. **Root keeps** the RECON-11/12 cookie DoS layer (no C3 counterpart) — port the *crypto beneath* the frozen trait, not the whole module. |
| `distributed.rs` (executor-set spread, signed assignment logs, C-selection) | **PORT** | Anti-monopolization assignment mechanism; no root counterpart. Staged after crypto. |
| `density.rs` (F6 Sybil cohort-merge) | **PORT** | Anti-farm; pairs with `capability::evaluate_density`. |
| `codec.rs` (wire codec) | **ORACLE** | Root `CanonicalGossipCodec` (goatd) is CANON; reference decoder. |
| `stats.rs`, `testnet.rs` | **ORACLE** | Telemetry export + testnet-acceptance harness; test infrastructure. |
| `bin/demo.rs`, `bin/demo3.rs`, `bin/collect.rs` | **ARCHIVE** | Demos/harness. Never shipped. Frozen. |

**`goat-ledger`** (permissioned MVP ledger + fraud loop):

| Module | Status | Rationale / owner |
|--------|--------|-------------------|
| `ledger.rs` (accumulator roots, bonds, slashing, challenge adjudication) | **PORT** | The fraud-proof adjudication core; no root counterpart. Large; staged (Track C+). |
| `beacon.rs` (commit-reveal + delay-sealed beacon) | **PORT** | Beacon *source*; pairs with root `state::derive_authorization_set` (the lottery consumer). **VDF is a placeholder** (iterated SHA3-256) — a real Wesolowski/Pietrzak VDF is `R-C4` / `DEPLOY.md` C-11. |
| `actors.rs` (orchestrator/challenger/ledger roles) | **ORACLE** | Demo role harness driving the fraud loop; not spine code. |
| `bin/demo.rs` | **ARCHIVE** | Demo. |

**`goat-backends`** (reference device backends):

| Module | Status | Rationale |
|--------|--------|-----------|
| `refcompute.rs`, `reference_a.rs`, `reference_b.rs`, `tests/parity.rs` | **ORACLE** | Reference profiles + the **parity oracle** (reproduces the Python reference's numeric/behavioral outcomes). Deliberately excluded from the neutrality scan. Never shipped. |

**`goat-neutrality`** (the auditor):

| Module | Status | Rationale |
|--------|--------|-----------|
| `src/main.rs` (`goat-neutrality` bin) | **CANON** (tooling) | The neutrality **merge gate** — a canonical CI tool, not a runtime artifact. Must be **extended to also scan root `src/`** (Phase-0 P0-2), since the spine is now where device-agnosticism must be enforced. Do not weaken. |

---

## 3. Dependency law (the invariants that keep it one spine)

**3.1 Protocol must not depend on backends (device-neutrality).** *Holds today* — verified:
`goat-protocol/Cargo.toml` deps are exactly `sha3` + `ml-dsa` (no path-dep to `goat-backends`, no
transitive path). Direction is one-way `goat-backends → goat-protocol`. **Forward rule:** the spine's
core layers (`types`, `crypto`, `state`) must never gain a device-backend dependency; a device class
stays an opaque tag the protocol never branches on. Enforced by (a) the manifest graph and (b) the
`goat-neutrality` source scan — which must be pointed at `src/` too (P0-2).

**3.2 `goatd` is the only async/`std` binary boundary.** *Holds today* — verified: `goatcoin-rs` has
no daemon, only demos/harness/auditor. **Forward rule:** no second production daemon. `goatcoin-rs`
binaries are ARCHIVE and must never enter the Docker image or be presented as a product entrypoint.

**3.3 No second "real crypto" path `goatd` doesn't use (post-Track-C).** *Today there are two crypto
realities* — placeholder (C1) and real (C3). This is the P6 hazard `RUNTIME_VS_SPEC.md` documents.
**Forward rule:** Track C makes C3's real crypto the single path `goatd` uses (behind the frozen
traits); after Track C, the placeholder backends are deleted (`DEPLOY.md` C-8) and no independent
real-crypto path may remain unused. One spine, one crypto path.

---

## 4. Phase-0 — what is safe to do now, and the PR plan for the rest

**Implemented this turn (low-risk, doc-only — "stop looking like two products"):**
- **P0-0 (done).** This document + `RUNTIME_VS_SPEC.md` + README.md establish the single spine,
  the honesty matrix, and the doc hierarchy. `goatcoin-rs/README.md` gets an orientation banner
  pointing here (it is the oracle, not a second product).

**Ticketed (exact PR plan — NOT executed in Track B; each is its own reviewable PR):**

| PR | Title | Files | Risk | Track |
|----|-------|-------|------|-------|
| **P0-1** | Unify the workspace framing | Add a top-level orientation note in `ARCHITECTURE.md` §0 (done) + `goatcoin-rs/ARCHITECTURE.md` header; **defer** an actual Cargo workspace merge (root is `no_std`+features, `goatcoin-rs` is `std` — edition/feature clash makes a single `[workspace]` risky). | Low (docs); the Cargo merge is deferred as its own spike. | B/C |
| **P0-2** | Neutrality gate covers the spine | Extend `goat-neutrality/src/main.rs` default scan targets to include root `src/` (currently only scans `goat-protocol/ledger/net`). Add a self-test asserting a device term in `src/` fails the gate. | Low–Med (the auditor is standalone; adding a path is contained). | B/C |
| **P0-3** | One CI story | Add `.github/workflows/ci.yml` (none exists today) running, in one matrix: `goat-neutrality` gate → root core gates (`build`/`clippy -D warnings`/`fmt --check`/`test`) in **both** feature configs → `goatd` tests → `goatcoin-rs` `cargo test` + `tests/parity.rs`. | Low (additive; no code change). | B/C |
| **P0-4** | Track C wiring (first PR) | `src/bin/goatd.rs`: replace `ReferenceMlDsaVerifier` with a wrapper over `goat-protocol::pqsign` behind `crypto::SignatureVerifier`; add `goat-protocol` as a path dep of the root crate (host side only). Gated on `DEPLOY.md` C-1…C-10 + `handshake_and_gossip_round_trip_api_contract`. | **High** — real crypto swap. | **C (do not start this session)** |

**Guardrails on Phase-0:** no mass-delete of `goatcoin-rs` (this map is the inventory), no bulk port
of ledger/maturity into `goatd` in Track B (they need a `no_std` rewrite — staged), and no CI/workspace
change that could break the four merge gates in either feature config.

---

## 5. What this decision deliberately does NOT do (Track B non-goals)

- No real ML-DSA / ML-KEM / AES swap (that is Track C / P2 — only *decided & ticketed* here).
- No CET/emissions/oracle implementation; no F5 study; no execution-isolation product.
- No `no_std` rewrite/port of maturity/ledger/HLL/density (staged as PORT with owners; not executed).
- No Cargo `[workspace]` merge of the two trees (deferred as a spike; framing done via docs).
- No change to the frozen trait surfaces, RECON-11/12/14 ordering, the `AdvisoryStakeFloor` tripwire,
  or the Track-A fail-closed gates.
