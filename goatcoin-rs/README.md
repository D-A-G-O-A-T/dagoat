# goatcoin-rs — GoatCoin (GOAT) Phase 3 mechanisms in Rust (MVP-0)

> **Orientation — this is NOT the deploy spine.** Per [`../ARCHITECTURE_CONVERGENCE.md`](../ARCHITECTURE_CONVERGENCE.md)
> (ADR-B1), the production spine is the root tree (`../src/` sealed `#![no_std]` core +
> `../src/bin/goatd.rs`, the only daemon — the tree Docker builds). **This workspace is the mechanism
> & crypto *oracle*:** it holds the real PQ crypto (`goat-protocol::pqsign` ML-DSA-65,
> `goat-net::transport` ML-KEM-768 + AES-GCM) that Track C will wrap behind the spine's frozen traits,
> plus the parity oracle and the economic-mechanism MVP. It ships **no** binary in the Docker image and
> is **not** a second product. See [`../ARCHITECTURE_CONVERGENCE.md`](../ARCHITECTURE_CONVERGENCE.md)
> §2 for the per-module CANON/ORACLE/PORT/ARCHIVE map.

Production Rust port of the Phase 3 reference implementation (Items 1–4), with the
AI-response-16 specification amendments applied and the two MVP-0 build obligations
closed: **real ML-DSA-65** signing (R-CAP1) and a **deterministic-serialization HLL** for
coverage counting (R-MAT1).

## Layout & the layer boundary

```
crates/
  goat-protocol/    PROTOCOL layer — device-agnostic core. Depends on NO backend crate.
                    types, commit, pqsign (ML-DSA-65), capability (+F6), attestation_chain,
                    hll, maturity (accumulators/fraud proofs), verification (cross-class),
                    backend (the GoatHAL trait), conformance (D.1 runner)
  goat-backends/    DEVICE layer — two reference backends BELOW the trait. Depends on
                    goat-protocol. Excluded from the neutrality scan.
  goat-ledger/      PROTOCOL layer (MVP-1) — minimal mechanism ledger, epoch beacon
                    (commit-reveal, R-CAP3), and the fraud-proof adjudication loop.
                    Binary: goat-mvp1-demo (proves SC5 public verifiability locally).
  goat-neutrality/  Auditor binary — scans the protocol-layer crates for device-type
                    identifiers and content-policy tokens. A CI merge gate.
```

See `ARCHITECTURE.md` for the layer rule, mechanism map, and the MVP-1 fraud-loop data flow.

The protocol/device boundary is a **compile-time property**: `goat-protocol` has no
dependency on `goat-backends`, so a protocol module physically cannot `use goat_backends`.
The neutrality auditor enforces the lint-time half (`if it names a device type, it's wrong`).

## Amendments applied (design note 16)

- **A-1** `observed_compute_equiv` (renamed from the device-typed `observed_gpu_equiv`);
  the auditor now catches device terms as identifier sub-tokens.
- **A-2** density under-declaration is a hard validity failure; F6 is evaluated on the
  probe-observed value.
- **A-3** hash-chain commits to the signed record. **A-4** strict epoch monotonicity.
  **A-5** hard/soft checks. **A-6** device-blind commitment.
- **B-1** slash coupling = 1/3 (band → cap at `tol_width = tol_ref`). **B-2** directional
  fraud. **B-3** precise snap. **B-5** `V_c` denominator. **B-6/R-MAT2** the anomaly-burst
  snap is recomputable: receipts carry a `sub_window` bucket, the accumulator tallies
  anomalies per bucket (bound into the root), and `verify_posting` derives the burst itself —
  a withheld snap is provable fraud (`withheld_burst_snap`).
- **C-1** widened band capped by task bound (ineligible → same-class). **C-2** the fourth
  escalation outcome (C agrees with both → no attribution). **C-3** disjoint-and-pairable
  third executor. **C-5** tokens ∧ numerics.

## Build & test

```
cargo test --workspace                          # all tests (parity oracle + units)
cargo run  -p goat-neutrality -- crates/goat-protocol/src   # neutrality gate
cargo clippy --workspace --all-targets -- -D warnings       # lint gate
cargo fmt --all -- --check                                   # format gate
```

## Status

- **MVP-0 complete:** reference parity in Rust with R-CAP1 and R-MAT1 closed. ML-DSA-65
  sizes (pubkey 1952 B, sig 3309 B) flow through the length-prefixed wire format. The
  reference signer is gone — signing is genuinely post-quantum.
- **MVP-1 complete:** minimal mechanism ledger + commit-reveal epoch beacon (R-CAP3) + the
  fraud-proof adjudication loop. SC5 (public verifiability) is demonstrated locally by
  `goat-mvp1-demo`.
- **MVP-2 complete:** PQ-authenticated transport (ML-KEM-768 + AES-256-GCM + ML-DSA handshake
  auth), orchestrator with the executor-set spread rule and signed assignment logs,
  beacon-seeded lottery third-executor selection, and the distributed verification loop.
  `goat-mvp2-demo` shows honest settlement + a faulty submission escalated/slashed across nodes.
  Acceptance SC2/SC3/SC4/SC7/SC10 pass.
- **MVP-3 complete:** density probe + F6 evaluated on the probe-*observed* value, live class
  maturity (PROBATION→MATURE from genuine distributed work), and a co-located Sybil adversary
  correctly merged by F6 (coverage inflation prevented). `goat-mvp3-demo` on a 60-node network
  shows a class reaching MATURE, a 30-identity Sybil collapsed, and reproducible accumulator
  roots. Acceptance SC1/SC6/SC8 pass. **The full Testnet MVP (MVP-0…3) is now complete.**

CI enforces the neutrality + conformance + lint + format gates across all protocol-layer
crates. See `ACCESSIBILITY.md` for the standing broad-accessibility consideration.
