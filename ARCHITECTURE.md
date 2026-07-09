# GoatCoin (GOAT) — Node Crate Architecture (`src/`)

> **Audit orientation (V1.0, 2026-07-07).** This document maps the **consolidated node crate** built
> across Phases 3–5 — the module stack under `src/` that implements the sealed cryptographic,
> verification/consensus, and network planes of a GoatCoin participant. It is the artifact submitted
> for external cryptographic audit. It is distinct from, and layered above the concerns of, the
> earlier `goatcoin-rs/` Testnet-MVP workspace (whose mechanism map lives in
> `goatcoin-rs/ARCHITECTURE.md`); where the two overlap they share the same spec IDs (amendment
> `A-*`, risk `R-*`/`RECON-*`, success-criteria `SC*`).
>
> **Golden Goal (non-negotiable).** Any idle computer worldwide can contribute compute and earn
> rewards, and the system must *structurally prevent* large farms from monopolizing rewards.
> Anti-centralization is an engineering constraint on par with quantum resistance.
>
> **The one rule.** *If it names a device type, it's wrong.* Every fairness-bearing path
> (scheduling, verification, maturity, rewards, lottery) is device-agnostic; a device class is an
> opaque string the protocol never branches on.
>
> **Runtime reality.** This document describes the sealed-core *design* and the frozen-trait
> *contract*. On the current deploy path the crypto backends are **reference placeholders** (see §6.4);
> real ML-DSA-65 / ML-KEM-768 live off-path in `goatcoin-rs` pending Track C. For the authoritative
> shipped-vs-designed breakdown see [`RUNTIME_VS_SPEC.md`](RUNTIME_VS_SPEC.md); for the single-spine
> decision see [`ARCHITECTURE_CONVERGENCE.md`](ARCHITECTURE_CONVERGENCE.md).

---

## 1. Directory tree

```
src/
├── lib.rs         Crate root: #![no_std] + #![forbid(unsafe_code)]; declares the 6 modules;
│                  gates `extern crate alloc` behind the `alloc` feature.
│
├── types.rs       [SEALED V1.0 · zero-heap] Foundational layer. Fixed-point aliases
│                  (Ppm/Bp/MicroUsd/Epoch), capacity constants, the `BoundedVec<T,N>` stack
│                  container, opaque device-class tag, and every canonical wire struct
│                  (CapabilityRecord, ExecutionAttestation, SignedRecord<T>, SignedReceipt,
│                  AuthorizationSet, EscalationRecord, telemetry frames). Depends on nothing.
│
├── crypto.rs      [SEALED V1.0 · alloc-gated mirrors] Canonical-serialization contract
│                  (CanonicalSerialize / ByteSink / SliceSink), the domain-separation registry
│                  (15 × CTX_GOAT_*), the injected `SignatureVerifier` + `KeyRegistry` traits,
│                  the verified-attributed fold, largest-remainder weight normalization, and the
│                  symmetric-deviation predicate. Depends on: types.
│
├── state.rs       [SEALED V1.0 · zero-heap] Verification & consensus state machine. Capability
│                  ingestion + epoch replay guard, dispute resolution (unanimous/majority/total-
│                  divergence), the lagged-entropy beacon lottery (`derive_authorization_set`),
│                  fault deduplication + fail-closed slashing, and the inline FIPS-202 SHA3-256
│                  (`pub(crate) sha3_256`, reused by the network layer). Depends on: crypto, types.
│
├── transport.rs   [zero-heap hot path · alloc-gated mirrors] Hybrid post-quantum transport:
│                  ML-KEM-768 + ML-DSA-65 handshake, the RECON-11 stateless cookie and RECON-12
│                  single-use `CookieCache`, and the AES-256-GCM `SecureChannel` abstraction.
│                  Depends on: crypto, state (SHA3-256), types.
│
├── gossip.rs      [zero-heap] Epidemic gossip validation: the RECON-11 `MessageCache`
│                  (hash-before-verify dedup), strict verify-before-forward, and `PeerScore`.
│                  Depends on: crypto, state (SHA3-256), types.
│
└── daemon.rs      [zero-heap] The top-level `GoatNode` participant and the raw-byte ingress
                   multiplexer (`process_ingress_packet` → `demux` → route). Wires the cookie,
                   cache, verifier, and registry planes together. Depends on: crypto, gossip,
                   transport, types.
```

## 2. Layering & the compile-time neutrality perimeter

```
                         types            (no workspace deps — pure core)
                           ▲
                         crypto           (→ types)
                        ▲      ▲
                     state ────┤          (→ crypto, types)  ── provides sha3_256 ─┐
                    ▲     ▲    │                                                    │
            transport ◄──┘  gossip ◄──────────────────────────────────────────────┘
                    ▲          ▲          (→ crypto, state, types)
                    └────┬─────┘
                       daemon             (→ crypto, transport, gossip, types)
```

The DAG is acyclic and the direction is load-bearing for the audit: **`types` and `crypto` sit at
the base and depend on no consensus logic**, so the sealed serialization/domain-separation contract
cannot be perturbed by higher layers. No module names or branches on a device type; a device class is
carried only as an `OpaqueTag` (`types.rs`) and never inspected. This mirrors the `goatcoin-rs`
neutrality-gate discipline: fairness is device-agnostic by construction, not by policy.

### Mechanism → module → spec-ID map

| Mechanism | Module · item | Spec IDs |
|-----------|---------------|----------|
| Canonical, injective, length-prefixed signing preimage | `crypto::write_preimage` / `CanonicalSerialize` | A-CI4, SC-verifiability |
| Domain separation across 15 message classes | `crypto::CTX_GOAT_*`, `ALL_CONTEXTS` | A-CI4 |
| Sybil-resistant fold (verify + authorize before attribute) | `crypto::fold_verified_attributed` | RECON-06/07 |
| Floor-division-free reward split | `crypto::normalize_weights_largest_remainder` | RECON-06 |
| Epoch replay guard on ingestion | `state::ingest_capability`, `MAX_ATTESTATION_AGE` | RECON-08 |
| Cross-task escalation coherence | `state::verify_escalation_coherence` | RECON-08 |
| Withholding-resistant assignment lottery (lagged entropy) | `state::derive_authorization_set` | RECON-09/10 |
| Fair index extraction (64-bit, negligible modulo bias) | `state::draw_hash` + `derive_authorization_set` | RECON-10 |
| Double-jeopardy-free slashing (per-node fault dedup) | `state::deduplicate_epoch_faults`, `apply_epoch_penalties` | RECON-09/10 |
| Spoof-proof handshake admission (address-bound cookie) | `transport::issue_cookie` / `verify_cookie_echo` | RECON-11 |
| Replay-proof handshake admission (single-use cookie) | `transport::CookieCache`, `CookieReplayed` | RECON-12 |
| Signed, forward-secret key agreement | `transport::HandshakeInitiation/Response`, `verify_*` | A-CI4 |
| Broadcast-storm dedup (hash-before-verify) | `gossip::MessageCache`, `validate_gossip_message` | RECON-11 |
| Verify-before-forward + peer scoring | `gossip::validate_origin_signed`, `PeerScore` | RECON-11 |
| Ingress multiplexing & plane wiring | `daemon::process_ingress_packet`, `demux` | Phase 5 |

## 3. The security perimeter — `#[cfg(feature = "alloc")]`

**Feature declaration.**

```toml
[features]
default = ["alloc"]   # ergonomic heap mirrors enabled for tooling/host builds
alloc   = []          # opt-out to compile a zero-heap enclave binary
```

`lib.rs` links the allocator only when the feature is on:

```rust
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
```

**Zero-heap by default; heap is a convenience, never a dependency.** Every consensus, verification,
and network decision executes on the **stack-only path**: canonical preimages are built into a
fixed-size `[u8; N]` via `SliceSink` (`crypto.rs`), bounded working sets live in `BoundedVec`, and
all arithmetic is saturating and panic-free. The `alloc` feature adds **only** `Vec`-returning
mirrors that are useful off the hot path (host tooling, differential tests, non-enclave nodes). The
complete set of allocating surface is small and enumerable:

| Location | `#[cfg(feature = "alloc")]` item | Zero-heap equivalent (always available) |
|----------|----------------------------------|------------------------------------------|
| `crypto.rs` | `impl ByteSink for Vec<u8>` | `SliceSink` (fixed stack buffer) |
| `crypto.rs` | `CanonicalSerialize::to_canonical_vec` | `serialize_into<S: ByteSink>` |
| `crypto.rs` | `preimage(&T, ctx) -> Vec<u8>` | `write_preimage(&T, ctx, &mut SliceSink)` |
| `crypto.rs` | `CapabilityRecord/ExecutionAttestation::signing_preimage` | `write_signing_preimage(&mut S)` |
| `transport.rs` | `HandshakeInitiation/Response::signing_preimage` | `write_signing_preimage(&mut S)` |

**No other module allocates.** `types.rs`, `state.rs`, `gossip.rs`, and `daemon.rs` contain **zero**
`#[cfg(feature = "alloc")]` — they are heap-free in every configuration, including the SHA3-256 core,
the beacon lottery, the message/cookie caches, and the ingress pipeline.

**Enclave build.** A firmware or trusted-enclave host compiles with `--no-default-features`: no
`extern crate alloc` is linked, no global allocator is required, and the crate reduces to a
`#![no_std]`, `#![forbid(unsafe_code)]`, panic-free, statically-bounded binary. The invariant the
auditor should check: **disabling `alloc` removes exactly the five mirrors above and nothing that can
change a verdict.** This is enforced two ways in CI — the full test suite runs in *both*
configurations, and the `crypto::tests::heap_path_matches_stack` differential test pins the
`Vec` path byte-for-byte to the `SliceSink` path.

**Standing guarantees (both configs).** `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/panic on any
library path (fallible `Result` + saturating arithmetic); post-quantum-only primitives **by design** (ML-DSA-65,
ML-KEM-768, SHA3-256, AES-256-GCM — no classical fallback anywhere). **Maturity caveat:** SHA3-256 is
implemented inline, but the ML-DSA/ML-KEM/AEAD backends on the current runtime are **reference
placeholders** (§6.4, `RUNTIME_VS_SPEC.md` row 6) — "no classical crypto" is not "PQ crypto is
implemented & audited." Bounded memory (fixed `BoundedVec`/cache capacities, no unbounded growth).

## 4. The anti-DoS flow — lifecycle of a raw ingress packet

Every expensive operation (ML-KEM decapsulation, ML-DSA-65 verification) is gated behind a **cheap
proof**. A raw byte slice enters at `GoatNode::process_ingress_packet` and is routed by
`demux` on a single leading tag byte:

```
 raw bytes ──► demux(tag) ──► fail-closed parse (bounds-checked, no trailing bytes)
                 │
   ┌─────────────┼───────────────────────────┬──────────────────────────┐
   ▼             ▼                             ▼                          ▼
0x01          0x02                          0x03                       0x04
Initiation    CookieEcho                    Response                   SecureFrame
   │             │                             │                          │
issue_cookie  ① freshness  (CookieExpired)  verify_response         decrypt_frame
(0 crypto)    ② address MAC (InvalidCookie)  (1 ML-DSA verify)          │
   │          ③ single-use  (CookieReplayed) ◄── CookieCache            decode (GossipCodec)
ChallengeIssued  │  ALL cheap, BEFORE crypto                             │
   │             ▼                                              validate_gossip_message
 (reply       verify_initiation                                    ① SHA3-256 dedup ◄── MessageCache
  cookie)     (1 ML-DSA verify — only once per cookie)                 (DuplicateMessage, penalty 0)
                 │                                                  ② KeyRegistry authorize
           HandshakeEstablished                                        (UnauthorizedOrigin)
                                                                    ③ ML-DSA verify (SignatureSpam)
                                                                       │  + PeerScore on failure
                                                                  GossipAccepted (forward)
```

Three independent DoS classes are structurally defeated **before** any post-quantum cost:

1. **Address spoofing** — the cookie MAC (`HMAC-SHA3-256(node_secret ‖ observed_peer_addr ‖ ts)`) is
   bound to the *observed* source address, so a forged source cannot reach `verify_initiation`
   (RECON-11).
2. **Replay within the freshness window** — a MAC-valid cookie is consumed exactly once via the FIFO
   `CookieCache`; the 2nd…Nth replay is rejected as `CookieReplayed` with zero PQ work (RECON-12).
3. **Broadcast storm** — a gossip message's `SHA3-256` fingerprint is checked against the
   `MessageCache` *before* the ML-DSA-65 verification; a redundant epidemic copy is a penalty-free
   `DuplicateMessage`, collapsing the naïve O(N²) mesh re-verification (RECON-11).

Genuine failures decrement `PeerScore`; one strike reaches the drop threshold, so an abusive peer is
evicted rather than amplified. Caches are insert-**only-on-success**, so junk can neither pollute nor
evict a legitimate window entry. Nobody is trusted; every admission is recomputed from published
data.

## 5. Audit surface & merge gates

The crate is held to four blocking gates, each run in **both** feature configurations
(`default` and `--no-default-features`):

```
cargo build                                          # compiles, both configs
cargo clippy --all-targets -- -D warnings            # zero warnings, both configs
cargo fmt --all -- --check                            # canonical formatting
cargo test                                            # 72 tests (alloc) / 71 (no-alloc)
```

The single test-count delta is `heap_path_matches_stack` (the `alloc`-only differential parity
test). The cryptographic suite is post-quantum only: **ML-DSA-65** (FIPS 204, pk 1952 B / sig
3309 B), **ML-KEM-768** (FIPS 203, ek 1184 B / ct 1088 B / ss 32 B), **SHA3-256** (FIPS 202,
inline Keccak-f[1600]), **AES-256-GCM** (abstracted behind `SecureChannel`, Threat Model §0).
The genesis bootstrap that seeds the `KeyRegistry` and the first beacon lottery is specified in
[`genesis.json`](genesis.json).

---

## 6. Phase 7 addendum — the async daemon & type-level invariants

> Added after the Phase-7 build + AR75–AR77 operational patches. §1–§5 describe the sealed
> `#![no_std]` core; this section documents the constraints introduced by the production async
> runtime and the type-level guard that armors the ARC-01 economic invariant. Current gate status:
> **core** 91 tests (alloc) / 90 (no-default), four merge gates clean in both feature configs;
> **`goatd`** (std + tokio) 6 tests, build/clippy/fmt clean, verified live over UDP.

### 6.1 The `AdvisoryStakeFloor` type-level tripwire (ARC-01-M12)

`EpochPenaltyReport::adaptive_min_stake` (`state.rs`) is **not** a `u64`; it is
[`types::AdvisoryStakeFloor`](src/types.rs), a newtype that deliberately implements **no `Ord` /
`PartialOrd`, no arithmetic, no `Deref`, and no `From<AdvisoryStakeFloor> for u64`**. Consequently a
participation gate of the shape `node_stake >= floor` **does not type-check** — the compiler, not a
review comment, forbids it. The value is reachable only through two intentionally narrow accessors:

| Accessor | Returns | Purpose |
|----------|---------|---------|
| `fee_market_hint(self)` | `MicroUsd` (`u64`) | The *only* value readout — for fee-priority / telemetry consumers. Its narrow name makes any appearance at a participation/registration/challenge gate self-evident misuse and trivially greppable. |
| `is_raised(self)` | `bool` | Whether saturation raised a floor this epoch — a boolean signal only, so no magnitude can flow into a gating comparison. |
| `AdvisoryStakeFloor::NONE` | `Self` | The unsaturated sentinel. |

**Standing invariant (do not weaken).** Never derive `PartialOrd`/`Ord`, never add a `u64`/`MicroUsd`
`From`/`Into`/`Deref`, and never gate participation, registration, or challenge rights on this value —
doing so would re-introduce the plutocratic censorship the two-lane fair market (§ARC-01, H-3) exists
to prevent. Locked by the conformance test `state::tests::adaptive_min_stake_is_advisory_only`.

### 6.2 The production daemon `src/bin/goatd.rs` — the only `std`/`alloc`/async boundary

`goatd.rs` is a `tokio` UDP event loop and the **only** place `std`, the allocator, and async live;
it wraps the sealed core, whose consensus pipelines (`fold`, `agree`, `validate_gossip_message`,
cookie verification) remain synchronous and total. Updated file tree:

```
src/
├── (types|crypto|state|transport|gossip|daemon).rs   # the sealed #![no_std] core (§1)
└── bin/
    └── goatd.rs                                       # std + tokio + alloc; the async runtime only
```

The async boundary is engineered against **four guardrails**, each mapped to code:

| # | Guardrail | Mechanism in `goatd.rs` |
|---|-----------|-------------------------|
| 1 | **Bounded ingress concurrency** | The socket reader `try_send`s into a *bounded* `mpsc::channel(INGRESS_QUEUE_CAP = 1024)`; a full queue drops the datagram at the socket layer and bumps an atomic `dropped` counter — backpressure, never unbounded queue/task growth → OOM. |
| 2 | **Cancellation-safe consensus** | A **single consensus actor** owns all mutable state (`GoatNode` + the session map). `ConsensusActor::process` runs the whole demux/verify/state-mutation **synchronously — no `.await`, no lock held across a transition** — so a dropped/cancelled future can never leave the core half-mutated. The only `.await`s are `rx.recv`, `gc.tick`, and the egress `send_to`, none holding a consensus borrow. |
| 3 | **Session garbage collection** | Sessions live in `HashMap<SocketAddr, Session>` where `Session { channel: Aes256GcmChannel, last_seen }`. A GC-only `tokio::time::interval(GC_INTERVAL = 30 s)` calls `sweep_dead_sessions`, dropping any session idle past `SESSION_IDLE_TIMEOUT = 300 s` — plus the hard LRU cap of §6.3. Actor-model variant of an `Arc<RwLock>` + detached sweeper, chosen because single ownership is *strictly* cancellation-safe (no shared lock a dropped task could poison or hold across `.await`). |
| 4 | **Deterministic, message-driven time** | The `NetworkClock` is advanced **only** inside `process_ingress_packet` from an authenticated peer's *signed* `local_time`, on message arrival. `unix_now()` is read at arrival and handed to the core, which corrects it via the median clock — it never gates consensus directly. **No `tokio::time` timer feeds consensus timekeeping;** the GC interval is the sole timer and touches no consensus state. |

The cache-heavy `GoatNode` (`MessageCache<4096>` + `CookieCache<4096>` ≈ 380 KB) is **boxed** and
constructed **on a worker thread** (via `tokio::spawn`), keeping large temporaries off the OS
main-thread stack (a real overflow was observed and fixed during the AR76 live run).

### 6.3 Operational bounds — LRU session cap & the generic-codec actor

- **Hard session cap (AR77, Deliverable 1).** `MAX_SESSIONS = 8192`. `insert_session_bounded`
  synchronously evicts the least-recently-seen session (an `O(n)` scan bounded by the cap, run only on
  overflow) when a *new* address would exceed the cap; re-handshakes on an existing address replace in
  place and never evict. The session map is therefore **mathematically bounded at all times**, not
  merely after the 30 s sweep — closing a spoofed-`SocketAddr` burst window. Evictions are counted in
  `evicted` and surfaced by the GC log. While this O(n) scan is computationally trivial for the current
  cap, a production-grade linked-list LRU cache can be cleanly substituted in a future hardening pass if
  the connection cap is ever significantly scaled upward.
- **Backpressure visibility (AR77, Deliverable 2).** If more than `DROPPED_WARNING_THRESHOLD = 500`
  datagrams are shed in a single GC interval, the daemon emits a structured `WARN` line (shed count,
  interval, threshold, session/eviction/accept/reject counters) so an ongoing flood is never silent.
- **Generic actor over the wire codec.** `ConsensusActor<G: GossipCodec>` is generic over the gossip
  decoder, so the wire codec is a swappable, contract-tested backend: production wires
  `ReferenceGossipCodec`; the AR77 integration test injects a decoding codec. The ML-DSA verifier and
  key registry are likewise concrete, injected backends behind the sealed `SignatureVerifier` /
  `KeyRegistry` traits.

### 6.4 Reference backends & the frozen contract

The daemon's AEAD (`Aes256GcmChannel`), verifier (`ReferenceMlDsaVerifier`), codec
(`ReferenceGossipCodec`), and ML-KEM key derivation (`derive_session_key`) are **reference
placeholders** (the library-provided, out-of-audit-scope primitives, §0) that a Mainnet build MUST
replace with audited FIPS bindings. The swap procedure — which treats the `SecureChannel`,
`SignatureVerifier`, and `GossipCodec` trait surfaces as a **frozen API contract** — is specified in
[`DEPLOY.md`](DEPLOY.md) and gated on the `handshake_and_gossip_round_trip_api_contract` regression
test.
