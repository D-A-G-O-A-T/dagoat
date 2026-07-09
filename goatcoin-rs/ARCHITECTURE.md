# goatcoin-rs — Architecture

Production Rust for the GoatCoin (GOAT) Phase 3 mechanisms. This note orients a new
contributor: the layers, the one rule that governs every module, and where each mechanism
lives.

## The one rule: the protocol / device boundary

> **"If it names a device type, it's wrong."**

Everything the network's fairness depends on — scheduling, verification, maturity, rewards —
must be **device-agnostic**. A device class is an opaque registry string (`"cls.a.v1"`); no
protocol code branches on it, and no protocol type can hold a model name, license, or content
policy (Core Principle 7). This is enforced two ways:

1. **Compile time.** `goat-protocol` (and `goat-ledger`) declare **no dependency** on
   `goat-backends`. A protocol module physically cannot `use goat_backends::…`. The device
   layer sits *below* the `GoatBackend` trait; the protocol layer sits *above* it and only
   ever calls trait methods.
2. **Lint time.** `goat-neutrality` scans every protocol-layer crate for device-type
   identifiers (as whole words *and* identifier sub-tokens, so `observed_gpu_equiv` is
   caught) and content-policy tokens, in code (comments/doc-comments stripped, string
   literals kept). It is a **blocking CI gate**.

If you find yourself wanting to special-case a device in protocol code, the design is telling
you the logic belongs below the trait, or that you need a measured, device-neutral signal
instead.

## Crates

```
goat-protocol   PROTOCOL layer — device-agnostic. Depends on no workspace crate.
goat-backends   DEVICE layer   — reference backends, BELOW the trait. Depends on protocol.
goat-ledger     PROTOCOL layer — MVP-1 minimal ledger + beacon + fraud loop.
goat-net        PROTOCOL layer — MVP-2 PQ transport + distributed verification.
goat-neutrality tooling        — the auditor binary (CI gate). Depends on nothing.
```

The neutrality gate scans `goat-protocol`, `goat-ledger`, and `goat-net` (all device-agnostic).

## Where each mechanism lives

| Mechanism | Module | Spec |
|---|---|---|
| Post-quantum signing (ML-DSA-65) | `goat-protocol/pqsign` | R-CAP1 |
| Device-blind output commitment | `goat-protocol/commit` | A-6 |
| Deterministic HLL coverage | `goat-protocol/hll` | R-MAT1 |
| CapabilityRecord + hash-chain + F6 density | `goat-protocol/capability` | A-1…A-6 |
| Rolling re-attestation / chain rules | `goat-protocol/attestation_chain` | A-3/A-4/A-5 |
| Maturity controller + accumulators + fraud proofs | `goat-protocol/maturity` | B-1…B-5 |
| Cross-class verification + escalation | `goat-protocol/verification` | C-1…C-5 |
| GoatHAL trait (the boundary) | `goat-protocol/backend` | Item 1 |
| D.1 conformance runner | `goat-protocol/conformance` | D-1…D-3 |
| Reference backends | `goat-backends/reference_a`, `reference_b` | Item 1 |
| Minimal ledger + adjudication | `goat-ledger/ledger` | WP-1.1/1.3 |
| Epoch beacon (commit-reveal) | `goat-ledger/beacon` | WP-1.2 / R-CAP3 |
| Orchestrator / Challenger actors | `goat-ledger/actors` | WP-1.4 |
| PQ transport (ML-KEM-768 + AES-GCM) | `goat-net/transport` | WP-2.1 |
| Orchestrator + spread + signed logs | `goat-net/distributed` | WP-2.2 |
| Beacon-seeded lottery C-selection | `goat-net/distributed` (`lottery_select`) | WP-2.4 |
| Distributed verification round | `goat-net/distributed` (`run_round`) | WP-2.5 |
| Density probe + F6 (observed value) | `goat-net/density` | WP-3.1 |
| Testnet driver (live maturity, Sybil, reproducibility) | `goat-net/testnet` | WP-3.2/3.3/3.4 |

## Data flow (MVP-1 fraud loop)

```
beacon (commit-reveal) ──> capability nonce + lottery seed
                                   │
orchestrator ──posts──> [ ledger: root + claimed transition + receipts manifest + bond ]
                                   │                         │
        challenger ──recompute──── │ ────────────────────────┘
        (published receipts +      │
         ledger's prior state)     ▼
                          ledger.challenge(id): INDEPENDENT re-run of verify_posting
                                   │
                    fraud? ── yes ─┴─> slash bond, void posting (challenger + ledger agree)
                              no ────> finalize, advance class state
```

The load-bearing property: **two independent recomputations** (challenger and ledger) reach
the same verdict from the same published data. Nobody is trusted; correctness is recomputable.

## The layers above MVP-1 (not yet built)

Distributed orchestrator + PQ P2P (MVP-2), density probe + live class maturity + Sybil
adversary (MVP-3). See the Testnet MVP work packages (design note 18) and MVP scope (17).

## Build & gates

```
cargo test --workspace
cargo run  -p goat-neutrality -- crates/goat-protocol/src crates/goat-ledger/src
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

All four are CI merge gates (`.github/workflows/ci.yml`). Neutrality and conformance are the
ones that protect the design's character; do not `#[allow]` around them.
