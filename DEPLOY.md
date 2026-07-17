# DEPLOY.md — D.A. G.O.A.T. Engine (goatd) deployment & the Backend Swap Checklist

This document governs the one deployment step the external review flagged as the critical
implementation risk: **replacing the reference crypto backends in `src/bin/goatd.rs` with audited FIPS
crates.** Read [`ARCHITECTURE.md`](ARCHITECTURE.md) §6 first. For what is placeholder vs shipped on the
current runtime — and which `goatcoin-rs` modules this swap ports from — see
[`RUNTIME_VS_SPEC.md`](RUNTIME_VS_SPEC.md) and [`ARCHITECTURE_CONVERGENCE.md`](ARCHITECTURE_CONVERGENCE.md).

---

## 1. What is a reference backend

**Track C (2026-07-08):** reference placeholders are **gone** on the deploy spine. Host backends live in
`src/bin/host_crypto.rs` and implement the frozen traits with real crates (same stack as `goatcoin-rs` C3):

| Backend | Trait it satisfies | Implementation |
|---------|--------------------|----------------|
| `Aes256GcmChannel` | `goat_core::transport::SecureChannel` | `aes-gcm` 0.11.0 AES-256-GCM; role-disjoint nonces |
| `HostMlDsaVerifier` / `HostMlDsaSigner` | `SignatureVerifier` + daemon signer | `ml-dsa` 0.1.1 ML-DSA-65 (FIPS 204) |
| `CanonicalGossipCodec` | `goat_core::daemon::GossipCodec` | Canonical wire deserializer (unchanged) |
| `kem_encapsulate` / `kem_decapsulate` + `derive_session_key` | session establishment | `ml-kem` 0.3.2 ML-KEM-768 + SHA3-256 KDF |

Signing seeds (identity-hardening): **`GOATD_SIGNING_SEED` (64 hex secret) preferred.** Deterministic
`testnet_signing_seed(node-index)` is lab-only: allowed on loopback, or on non-loopback with
`GOATD_ALLOW_TESTNET_SEEDS=1` (loud forgeable-identity banner); **always refused** under
`GOATD_ENV=production` / mainnet. Random Alpha keys:
`cargo run --bin goat-keygen -- --random --count 5 --out-dir keys/`.

## 2. The frozen API contract

> **The `SecureChannel`, `SignatureVerifier`, and `GossipCodec` trait surfaces are a FROZEN API
> CONTRACT.** The audited crate is wrapped *behind* the existing trait; the sealed `#![no_std]` core
> sees **zero** difference. Never change a trait signature to accommodate a backend — that inverts the
> dependency and defeats the whole layered design (`ARCHITECTURE.md` §2). If a real crate cannot be
> expressed behind the trait as-is, the swap is blocked pending a *core* amendment (Yellowpaper §4
> discipline), not an ad-hoc trait edit in the daemon.

## 3. The Backend Swap Checklist (mandatory, in order)

A swap PR is **not mergeable** until every box is checked and cited.

- [x] **C-1 Signatures unchanged.** Frozen traits untouched; host structs implement them verbatim.
- [x] **C-2 Error paths preserved (exactly).** `BufferTooSmall` / `DecryptionFailed` / `NonceExhausted`;
      real ML-DSA verify is exact; codec still `None` on malformed.
- [x] **C-3 Nonce discipline preserved.** Role-bit + monotonic counters; peer decrypt uses `1 - role`.
- [x] **C-4 Chain-id binding intact (RECON-15).** Preimages still via `write_preimage` / Track A chain id.
- [x] **C-5 Safety posture intact.** `#![forbid(unsafe_code)]` in goatd; no new daemon `unsafe`.
- [x] **C-6 THE REGRESSION GATE.** `handshake_and_gossip_round_trip_api_contract` +
      `aes_channel_round_trips_and_rejects_tamper` green (see design note 90).
- [x] **C-7 Full core gates, both feature configs.** clippy `-D warnings` + tests 91/90 + 29 goatd.
- [x] **C-8 Reference scaffolding removed.** No always-true verifier / `0x42` signer / cookie-as-key;
      startup banner reports real crates. (Dev `--dev-accept-all-registry` remains loopback-only for
      identity *authorization*, not signature forgery.)
- [x] **C-9 Live smoke / wire proof (blocking before Alpha — wire-proof + MTU-chunking).**
      1. **Logical sizes (unchanged):** Initiation ≈ **3185 B**; cookie reply = **41 B**;
         CookieEcho ≈ **6534 B**; Response ≈ **6398 B**; SecureFrame ≈ **~6 KB**.
      2. **MTU mitigation (MTU-chunking):** application-layer chunking (`datagram_framing`, tag `0xF1`)
         caps every **UDP** datagram at **≤ 1200 B** (`MAX_UDP_DATAGRAM`). Bootstrap logs
         `sent HandshakeInitiation (N MTU-safe fragment(s))`. Reassembly is bounded
         (per-peer / global partial quotas + 5 s TTL); no PQ until a logical datagram is complete.
      3. **2-node wire proof with chunking (AR94):** seed/bootstrap on `0.0.0.0` binds, peer via
         `127.0.0.1`, release binary — cookie → COOKIE_ECHO → RESPONSE → AES gossip both ways;
         initiation sent as **3** fragments. Unit test: `handshake_survives_mtu_safe_chunking`.
      4. **Baseline (pre-mitigation):** unchunked handshake **must** IP-fragment on a true 1500 MTU
         path (sizes above). Mitigation removes that dependence for the deploy path.
      5. **RNG:** host ML-KEM path proven (RESPONSE). Docker hardened 5-node re-verify: run
         `docker compose up` when the engine is available (AR94 blocker if engine down).
- [x] **C-10 Sign-off.** Resolved versions (from committed `Cargo.lock`, supply-chain):  
      `ml-dsa 0.1.1`, `ml-kem 0.3.2`, `aes-gcm 0.11.0`, `sha3 0.10.9` (direct dep `0.10`; lock also
      pulls `sha3 0.11.0` transitively). **Pre-1.0 / not externally audited — A3 remains open.**
      Do not claim FIPS certification or side-channel resistance. CI: `.github/workflows/ci.yml`
      runs `cargo audit` (continue-on-error until first triage). Evidence: AR90–AR93.
- [ ] **C-11 VDF Verification Asymmetry.** When selecting and swapping the production VDF to resolve
      `R-C4`, the verification path must be benchmarked on low-power target architectures. While proof
      generation is intentionally slow, proof verification must remain exceptionally cheap to ensure it
      does not violate the strict CPU-resource constraints defined in `ACCESSIBILITY.md`.
- [ ] **C-12 Persistent Session Nonce Safety.** Our nonce discipline assumes session keys are volatile and
      safely wipe on sudden reboots. If a future iteration introduces persistent session storage, the
      sequence counters must be written via an atomic Write-Ahead Log (WAL) or transactional fence
      *before* the outbound packet hits the network interface. Sequence counters must never roll
      backward or repeat across a reboot cycle.

## 4. Rollback

If C-6 or C-9 fails, **revert to the reference backend and file a core amendment**; do not "patch
around" a trait mismatch in the daemon. A contract deviation is a red flag that the core's assumptions
(nonce discipline, error semantics, preimage shape) were not met — that is a design conversation, not
a hotfix.

---

*The reference-backend swap is the last mile before Testnet Genesis. The `handshake_and_gossip_round_trip_api_contract`
test exists precisely so this mile cannot silently regress the transport or verification planes.*

---

## Fail-closed startup contract (Track A / P3 + P4)

Independent of the crypto swap, `goatd` now **refuses to run fail-open**. This is a hard precondition

- **Genesis required.** No/invalid/short-key `genesis.json` ⇒ non-zero exit. Keys must decode to
  **exactly 1952 bytes** (no silent zero-extension). The only escape is `--dev-accept-all-registry`,
  which is **loopback-only** and refused under `GOATD_ENV=production` or on mainnet, printing a loud
  banner every boot.
- **Node secret required.** Loaded from `GOATD_NODE_SECRET` (64 hex), `--node-secret-file`,
  `GOATD_NODE_SECRET_FILE`, or `/etc/goatd/node_secret`. Missing outside dev ⇒ non-zero exit. There is
  no compiled-in `[0u8; 32]` fallback.
- **Chain-id agreement (RECON-15).** The active network is a build-time selection — default
  **testnet**, `--features mainnet` for mainnet — surfaced as `goat_core::crypto::ACTIVE_CHAIN_ID`.
  `goatd` exits non-zero if `genesis.json`'s `chain_id_u32` disagrees, so a testnet daemon can never
  emit a mainnet-domain preimage (and vice-versa). `chain_id_u32` is the authoritative wire domain;
  the string `chain_id` is descriptive only.

**Post–Track C / security hardening residuals:**

| Residual | Notes |
|----------|--------|
| **A3 external crypto-integration audit** | Open — blocks any valued network |
| Pre-1.0 RustCrypto crates | Pinned in `Cargo.lock`; `cargo audit` in CI (soft-fail) |
| Side-channel / constant-time | **Unverified** for hostile co-resident hosts (relevant to D-5 later) |
| Deterministic testnet seeds | Gated (identity-hardening); Alpha needs `GOATD_SIGNING_SEED` |
| WAN MTU / IP fragmentation | Operational bound (wire-proof) |
| VDF / isolation / external DA | C-11+, design |
