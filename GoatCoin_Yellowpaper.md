# The GoatCoin (GOAT) Master Protocol Specification

> **Public note (2026-07-09).** This is a **protocol / engineering specification**, not a token offering
> or marketing whitepaper. Economic figures such as historical ~$20/month idle-earnings *targets* are
> **superseded by Vision v2.1** (Funded Public Good + No-Ponzi — see README.md (direction) and
> RUNTIME_VS_SPEC.md / README). Capability claims must match `RUNTIME_VS_SPEC.md`.

### *The Yellowpaper — Consolidated, Authoritative Reference*

> **Version 1.0 — Mainnet Specification Sealed (2026-07-06).** Parts I–VIII and Appendices A–D
> complete; the design record is consolidated through advisory GOAT-ARCH-RECON-03 (amendment passes
> 1–13; risk register R-C1…R-C20 dispositioned). The Specification Architecture phase is **closed**:
> subsequent changes enter only as numbered amendments against the owning sections under the §4
> discipline. Implementation status is unchanged by the seal — **[shipped]** remains the Testnet MVP
> surface, **[design]** the Phase-3 settlement/hardening surface; sealing the *specification* is not
> a claim that the **[design]** layers are built. This document
> executes Track **D1** of the Post-MVP
> Roadmap: it consolidates the fragmented Phase-3 design record — the guidance pack, the
> reference-implementation findings, specification amendments A-* / B-* / C-* / D-*, the risk
> register, and the Dynamic-CET oracle/settlement design (design notes 36–41) — into a single
> authoritative specification. Where a mechanism has been implemented in `goatcoin-rs`, this
> document is descriptive of shipped behavior; where a mechanism is Phase-3 design (the settlement
> and oracle layers), it is marked **[design]**. Nothing here changes a specification; it records
> the current, hardened state.
>
> **Naming.** Formal name **GoatCoin (GOAT)**; network brand **D.A. G.O.A.T.**; the familiar,
> relatable hook **GPUCoin**; the work unit **GCU = Goat Compute Unit**. These are used
> consistently throughout.
>
> **Status legend.** **[shipped]** implemented + tested in `goatcoin-rs` (Testnet MVP).
> **[design]** specified and mathematically hardened, not yet implemented (Phase-3).
> **[calibration]** parameter pending the F5 empirical study before economic go-live.

---

## Table of Contents

### Part I — Philosophy & Constitutional Invariants
- 1. The Golden Goal — maximizing idle consumer-hardware profitability
- 2. The Thin-Pool Principle (the central economic thesis)
- 3. The Constitutional Invariants (unamendable)
  - 3.1 The Calibration Law (idle priced in time, not energy)
  - 3.2 Power-Source Neutrality
  - 3.3 Core Principle 7 — Content Neutrality
  - 3.4 Measured-Work-Only GCU
  - 3.5 The Device-Agnosticism Axiom — *"if it names a device type, it's wrong"*
  - 3.6 Permissionless Entry (nodes *and* device classes)
  - 3.7 Post-Quantum & End-to-End security floors
  - 3.8 Fraud-Provable-by-Recomputation
- 4. Amendment discipline & how this document stays authoritative

### Part II — The Heterogeneous Device Layer
- 5. `GoatHAL` — the device-agnostic hardware abstraction trait
- 6. The Goat Compute Unit (GCU) — measured work, never spec-sheet
- 7. The Device Class Registry — permissionless, population-statistical
- 8. The D.1 Conformance Suite (the eight objective criteria)
  - 8.1 Fault-isolated execution & the opaque-payload DoS (**amendment D-5 / R-C12, Pass 11**);
    signed hardware exception logs vs. submitter-framing (**R-C16, Pass 12**); host-daemon
    Watchdog Tombstone for the hard-kill/OOM blind spot (**R-C19, Pass 13**)
- 9. The Neutrality Auditor (compile-time device/content gate)
- 10. Determinism profiles & the canonical output commitment (A-6)

### Part III — Identity, Capability & Anti-Sybil Physics
- 11. `CapabilityRecord` / `DeviceCapability` — signed, chained, measured
- 12. The attestation hash-chain (A-3/A-4) & rolling re-attestation (A-5)
- 13. Network-class attestation & the residential last-mile gate (`q_network`)
- 14. F4 density coupling & F6 cohort-merge (the anti-Sybil core) — incl. **CGNAT/shared-gateway
  resilience (R-C13, Pass 11)** and the device-neutral **memory-contention co-location probe
  (amendment D-6 / R-C17, Pass 12)**
- 15. Operator clustering & the density→clustering feedback

### Part IV — Cryptographic Provenance & Consensus Primitives
- 16. Post-quantum primitives (ML-DSA-65, ML-KEM-768, SHA3-256)
- 17. PQ-authenticated transport (handshake, channel, framing)
- 18. Receipt provenance chain (H1 / R-MAT2b)
  - 18.1 `SignedReceipt` & the executor-attributable core
  - 18.2 Key registry & authorization (assignment-log cross-binding)
  - 18.3 `EscalationRecord` & verifiable attribution
  - 18.4 Fold-time enforcement (`fold_verified_attributed`)
- 19. The epoch beacon (H2)
  - 19.1 Commit-reveal construction & last-revealer analysis
  - 19.2 Delay-sealed finalization (`BeaconMode`, VDF placeholder)
  - 19.3 Validator-Quorum Data-Availability attestation [design]
  - 19.4 Local-chain DA fallback — sustained-outage liveness (**R-C18, Pass 12**)

### Part V — Verification, Maturity & the Fraud-Proof Ledger
- 20. Cross-class verification (Spec C: `effective_profile`, `agree`, the four escalation outcomes)
- 21. The Verification Maturity Controller (Spec B)
  - 21.1 Accumulators, the gate, and the asymmetric ratchet
  - 21.2 Recomputable anomaly-burst snap (B-6 / R-MAT2)
  - 21.3 Slash sizing & the directional-fraud definition (B-1/B-2)
- 22. The minimal mechanism ledger & public verifiability (SC5)

### Part VI — Anti-Capture & Monopolization Defense
- 23. The anti-capture stack (idle premium, S_o, κ, spread rules)
- 24. Power-infrastructure capture defense (P_r, service-lane caps)
- 25. Device diversity & class-capture defense
- 26. Adversarial-simulation results (Q1 iterations 1–3)

### Part VII — Economics: Dynamic-CET Settlement & Oracle Layer **[design]**
- 27. The Dynamic Contributor Earnings Target (CET)
- 28. The Compute Market Index (CMI) — commodity-tier only
- 29. The Hexa-Index CPPI basket & localization
- 30. The Meta-Index Controller (adaptive rebalancing + bounded mutation) — incl. the
  **volatility-boost correction + liquid-anchor damping (R-C14, Pass 11)**
  - 30.1 The R-C2 volatility model — **finalized Symmetric Integer Deviation math (AR41)**:
    sMAPE-style `2·|v_t − v_{t-1}|·PPM / max(1, v_t + v_{t-1})` with the **`u128`
    cast-before-multiply hyperinflation guard**; mean-absolute-return-**from-parity** (not
    about-the-mean), so N=1 is a real reading, not zero.
  - 30.2 **Constitutionally tunable parameters** — `VOL_WINDOW_MIN_RETURNS` defined here as a
    constitution-band tunable (governs the cold-start floor / single unavoidable blind quarter),
    alongside `VOL_WINDOW_{DEFAULT,MAX}_QUARTERS`, `w_min`/`w_max`, `λ`, `boost_cap`,
    `SYMMETRIC_DEVIATION_MAX_PPM`.
- 31. Regional compute amortization (device-agnostic normalization) — incl. the **two-tier
  black-swan emergency release valve (R-C3 specified, Pass 11)** and **dynamic macro-coherence /
  frozen-feed drop (R-C15, Pass 12)**
  - 31.2 Regional onboarding — zero-history bootstrapping, **hardened against neighbor-region
    parity divergence (R-C7, Pass 6)**: k-nearest-median proxy, per-component parity-dispersion
    gate, ramp-referenced provisional clamp; **genesis-degradation cascade + Genesis Basket
    (R-C7 completion, Pass 7)**
- 32. Off-chain manifest index & state minimization
  - 32.1 Registry sunsetting (**R-C9, Pass 7**) — ledger-mechanical `DORMANT`→`ARCHIVED`
    lifecycle, O(1) archive-tree tombstones, re-entry by re-registration; registration bond +
    escalator + `PROBATION` verification budget (**R-C10, Pass 8**; Sybil-dilution hardening —
    seniority pricing, `r_net` burn-rate term — **Pass 9**)
- 33. The Emission Allocation Controller (gap-fill, decaying cap)
  - 33.2 The DA Fallback Rebate (**R-C20, Pass 13**) — the emission controller rebates the R-C18 7×
    premium to honest orchestrators, closing the economic liveness trap
  - 33.1 The Surplus Routing Rule (**R-C8, Pass 6**) — the CET as a two-sided target: surplus
    routed to non-attributable sinks (reserve-refill + burn), `u_ref` derived from escrow
- 34. The 7-day challenge window & ±5%/quarter clamp (anti-manipulation)

### Part VIII — Governance, Risk & Roadmap
- 35. The bounded algorithmic controller vs. the unamendable band
- 36. Consolidated risk register (R-VER / R-MAT / R-CAP / R-C1…R-C20)
- 37. Open calibration dependencies (the F5 study)
- 38. Phase roadmap & success criteria (SC1–SC10)

### Appendices
- A. Fixed-point conventions & pure-integer arithmetic contracts
- B. Amendment index (A-* / B-* / C-* / D-* → section map)
- C. Glossary (GCU, CET, CMI, CPPI, κ, S_o, P_r, F4/F6, GoatHAL, …)
- D. Reference-implementation ↔ specification cross-reference

---

# Part I — Philosophy & Constitutional Invariants

## 1. The Golden Goal

GoatCoin turns the **idle, sunk-cost compute capacity** already sitting in ordinary households
worldwide — unused while its owner sleeps, works, or is otherwise away — into **verified, useful
public-good compute.** *(Vision v2.1: the purpose is **sustainable value from otherwise-wasted idle
capacity**, funded by real external value under the **No-Ponzi Invariant / Funded Public Good** model
— **not** maximizing per-machine profit and **not** promising a monetary yield. Contributor reward
flows only from verified external inflow; see README.md (direction) and RUNTIME_VS_SPEC.md / README.)*

The emphasis on *idle* and *consumer* is not incidental; it is the entire thesis. A design that
merely paid for compute would be won by whoever could deploy the most compute most cheaply — an
industrial data center. GoatCoin instead is engineered so that the party best positioned to profit
is a dispersed individual contributing hardware they already own, and the party structurally
*unable* to profit is an entity deploying fresh capital to build dedicated capacity to farm the
network. Every mechanism in this document serves, directly or indirectly, that inversion.

**Historical note (superseded by Vision v2.1).** Earlier drafts set a concrete north-star of
~$20/month real earnings for ~8 h/day of idle contribution. **v2.1 retires this as a monetary
target** — a guaranteed yield is exactly the emissions death-spiral the No-Ponzi Invariant forbids.
Contributor value is now a *modest, externally-funded reward plus non-monetary participation
(game / status)*, and may be near-zero when no external inflow exists. **There is no promised $/month.**

## 2. The Thin-Pool Principle

The reward pool is deliberately kept **thin**: reward levels are calibrated to *sunk-cost idle
economics*, not to a return that would justify new capital. The consequence is structural and
self-enforcing:

- For hardware that **already exists** and would otherwise be idle, any positive payment above
  marginal running cost is pure gain — the capital cost is already sunk. Participation is rational.
- For hardware that must be **bought and hosted to farm the pool**, the payback period at thin-pool
  rates exceeds the hardware's depreciation life. Deploying fresh capital to capture the pool is a
  *structural, perpetual loss* — not a risk to be managed, an arithmetic certainty.

The thin pool is therefore itself a defense: capture must be bought at a loss, forever. This
principle is *upstream* of every anti-capture mechanism in Part VI — those mechanisms bound the
residual vectors, but the thin pool is why the dominant strategy is to *be* a dispersed household
rather than to *simulate* one.

## 3. The Constitutional Invariants

These are **unamendable**. The protocol contains a bounded algorithmic controller that may tune
parameters *within* constitution bands (Part VIII), but nothing — no vote, no controller, no
governance bloc — may move the bands themselves or suspend an invariant. A patron bloc that
captured every tunable parameter would still find little worth capturing, by design.

### 3.1 The Calibration Law — idle is priced in time, not energy

Idle-premium eligibility is governed by `I_max × (D_max / 24) ≤ 1`, which prices the *fleet-hours*
an always-on operator must sacrifice to credibly mimic idleness. This is denominated in **time and
capital utilization**, never in energy price. Free electricity does not change the arithmetic —
idling still wastes capital utilization — so a cheap-power advantage cannot weaken the idle
premium's no-arbitrage property. The pool pays for time and genuine idleness, not for joules.

### 3.2 Power-Source Neutrality

The network is **power-source agnostic on the cost side** (cheap power — including solar
households — is welcome, and is unattestable anyway) and **distribution-demanding on the reward
side**. Every anti-capture mechanism is denominated in time, capital utilization, and
physical/operator distribution — never in energy price. Control of power infrastructure earns
nothing in the idle pool, because the pool prices properties that must be *physically lived*, not
generated.

### 3.3 Core Principle 7 — Content Neutrality

The protocol performs **zero** legal, compliance, or content-filtering logic. It is designed as if
operating in a jurisdiction with no restrictions. `Task` carries an **opaque payload** and has *no*
model-name, license, or content field — there is nowhere in the type system to put a content
policy, by construction. This is a structural guarantee, not a policy choice: the protocol *cannot*
inspect content because the data to do so does not exist in its types. The associated risk is
accepted and participant-borne.

### 3.4 Measured-Work-Only GCU

A device's value is set exclusively by **measured benchmarks on real task classes** — never by
spec-sheet FLOPS/TOPS or any self-declared capability. The benchmark suite doubles as the hardware
fingerprint. Self-reported performance is never trusted; measurement is the only currency.

### 3.5 The Device-Agnosticism Axiom — *"if it names a device type, it's wrong"*

No protocol-layer logic may branch on, name, or privilege a device type. GPUs, CPUs, NPUs, TPUs,
FPGAs, and future hardware are treated identically: a device class is an **opaque registry string**
the protocol never interprets. This axiom is *itself unamendable* and is enforced **mechanically**
at compile time by the Neutrality Auditor (§9), which scans protocol-layer source for device-type
tokens as whole words *and* as identifier sub-tokens. A module that names a device type cannot
merge. Device heterogeneity is thereby reduced to a *measurement* problem, not a *mechanism*
problem.

### 3.6 Permissionless Entry

Both **nodes** and **device classes** enter without approval. A new device class registers via
population statistics (median-of-many independent submissions), so there is no committee, gatekeeper,
or table-owner to capture. Anyone may run a node; anyone may introduce a new class of hardware.

### 3.7 Post-Quantum & End-to-End Security Floors

Identity, signing, and transport are **post-quantum** (ML-DSA-65, ML-KEM-768; §16) — non-negotiable,
never to be silently downgraded to a classical stand-in. Data in transit is end-to-end protected.
These are floors, not targets.

### 3.8 Fraud-Provable-by-Recomputation

Every consequential state transition is **recomputable from published data**, so a wrong claim is
*provable* and a conservative claim is *never* punished (the directional-fraud property, B-2). This
extends from the maturity ledger (Part V) to the oracle postings (Part VII): if a value is posted,
its inputs must be available to recompute it (the data-availability requirement, §19.3). Trustless
means trustless-by-recomputation, not trusted-because-asserted.

## 4. Amendment discipline

This Yellowpaper is the consolidation point. The design record advanced by a disciplined loop:
build a spec → implement a reference → discover edge cases/contradictions during implementation →
formalize each as a numbered amendment (A-* capability, B-* maturity, C-* cross-class, D-*
conformance) with the finding that motivated it → periodically consolidate. Appendix B maps every
amendment to the section that now absorbs it. When this document and a scattered prior response
disagree, **this document governs**; prior responses are historical.

---

# Part II — The Heterogeneous Device Layer

The device layer is where the Device-Agnosticism Axiom (§3.5) meets physical hardware. Its job is
to let *any* capable device contribute verified work while ensuring the protocol above it never
learns, needs, or trusts what that device is.

## 5. `GoatHAL` — the device-agnostic hardware abstraction trait

`GoatHAL` (the `GoatBackend` trait in `goat-protocol`) is the sole interface between the
device-agnostic protocol and a device-specific implementation. A backend lives *below* the trait;
the protocol crate has **no compile-time dependency** on any backend crate, so a protocol module
*physically cannot* `use` device-specific code. The protocol/device boundary is thus a compile-time
property, not a convention.

The trait surface (device-agnostic throughout) covers:

- **Discovery** — enumerate available devices as opaque `DeviceDescriptor`s (`class_id`,
  `device_index`, `endpoint_id`); the protocol reads none of the internals.
- **Benchmarking (= fingerprinting)** — produce a `BenchmarkReport`: a timing-signature commitment
  (the hardware fingerprint) and measured `TaskClassCap`s. Measurement is the *only* source of
  capability (§3.4, §6).
- **Capability** — report per-task-class measured throughput, memory, batch limits.
- **Execution** — run a `Task` under an `ExecPolicy`, yielding an `ExecOutcome` (completed result or
  cooperative-preemption save-state).
- **Canonical output commitment** — produce a device-blind commitment to the result (§10, A-6).
- **Preemption** — cooperative yield within a declared p95 latency (D5), so contributing never makes
  the owner's machine unusable — an accessibility guarantee.
- **Telemetry & envelope enforcement** — report coarse telemetry and bind execution to a power/
  thermal envelope (D6), with the envelope binding *over* any per-task policy cap (execution uses
  the minimum).

Every method is expressed in task-semantic and measured-physical terms. None names a device type;
the Neutrality Auditor (§9) enforces this on the trait and every implementation's public surface.

## 6. The Goat Compute Unit (GCU) — measured work, never spec-sheet

The **GCU (Goat Compute Unit)** is the protocol's unit of verified useful work. Its cardinal rule
(§3.4): a device earns GCU at a rate set by **measured benchmarks on the actual task class**, never
by any declared or spec-sheet figure. Consequences:

- **Fair cross-device valuation.** Two devices that produce equally-good verified output on the same
  task class earn the same per-GCU rate, whatever their internal architecture. A CPU and an NPU that
  each complete a task class to spec are paid identically per GCU.
- **The benchmark is the fingerprint.** The same measurement that sets the rate also identifies the
  hardware (a timing-signature commitment), so a node cannot claim a capability it cannot reproduce
  under measurement — and drift in that fingerprint triggers re-benchmark (§12, A-5).
- **Self-report is never currency.** Declared capability may be *checked against* measurement to
  detect dishonesty, but it never *sets* a rate. This is the same posture the anti-Sybil physics
  (§14) applies to density: the probe is ground truth; declarations only expose lies.

## 7. The Device Class Registry — permissionless & population-statistical

A **device class** is an opaque `class_id` string. New classes register **permissionlessly**
(§3.6): rather than a governance-approved normalization table (a capturable object), a class's
normalization is established by **population statistics** — the median of many independent
measurement submissions from distinct operators. No committee approves a class; the network *measures*
it into existence.

To keep a young class from destabilizing verification while its determinism characteristics are
still being learned, a new class enters at **100% redundancy sampling** and matures out of it only
by demonstrated behavior (the Verification Maturity Controller, Part V). Unverifiable-work floods
from a novel class are thereby priced out until the class proves itself — an anti-flood tool that is,
again, device-agnostic (it keys on measured verification behavior, not on what the hardware is).

Permissionless entry also has a deterministic *dual* — permissionless **exit**: a class that stops
producing verified work is mechanically sunset (`DORMANT` → `ARCHIVED`) and its live ledger state
reduced to a 32-byte tombstone, so the registry's footprint stays bounded over decades of hardware
evolution while history remains verifiable (§32.1, R-C9) **[design]**. Registration itself is
priced, never approved: a crowd-posted bond, refunded when the class first earns `RELAX` and burned
on archival-before-`RELAX`, with a seniority-and-burn-rate escalator against churn and rotation
cycles (§32.1, R-C10) **[design]**.

### 7.1 The Pioneer Multiplier — bootstrapping heterogeneous liquidity **[design]**

A young device class faces a chicken-and-egg problem. Until it registers (population-statistically,
§7) and matures (Part V), its nodes run at **100% redundancy sampling** during the `PROBATION`
phase — every unit of work is fully re-verified, so the early adopter of a new hardware class bears
real overhead (more redundant compute per paid GCU) and thin early liquidity in its class. Left
alone, no rational contributor would be the *first* to bring a new class online, and heterogeneous
hardware liquidity would never bootstrap. The **Pioneer Multiplier** is the narrow, temporary
incentive that pays for that bootstrapping overhead — and it is engineered to do so **without
touching a single invariant**:

- **Temporary and self-extinguishing.** The multiplier decays as the class's adoption doubles, so
  it is an *early-adoption* incentive, not a standing subsidy. Once a class has liquidity, the
  reason for the bonus is gone and so is the bonus.
- **Hard per-class budget cap.** Each class draws at most ~0.5% of the remaining emissions reserve
  — a bounded, disclosed line item. The total cost of bootstrapping *all* classes over the network's
  life is therefore bounded, and no class can drain the reserve.
- **Idle-qualified only.** The multiplier applies exclusively to nodes that already pass the idle
  premium's physical gates (§13, §3.1). It cannot be earned by always-on industrial capacity
  pretending to pioneer — the Calibration Law still binds first.
- **Inside the full anti-capture stack.** The bonus sits *within* operator clustering, S_o, and the
  power-region factor (Part VI). A single entity that floods a new class with many identities to
  farm the pioneer bonus is clustered and capped exactly as anywhere else — the multiplier is
  applied to already-anti-capture-adjusted reward, not on top of it.
- **Device-agnostic by construction.** The mechanism keys on *a class's adoption curve and maturity
  state* — opaque `class_id`, measured verification behavior — never on what the hardware is
  (§3.5). It rewards *being early in any class*, not being a particular kind of device.

Net effect: pioneering a new device class pays *modestly* — enough to compensate the `PROBATION`
overhead and seed liquidity — while *farming* the pioneer bonus is structurally unprofitable
(bounded budget × decay × the full anti-capture stack). The invariants that make industrial capture
a losing game (§2, §3) are precisely the ones that make pioneer-farming a losing game; the
multiplier rides inside them rather than around them.

## 8. The D.1 Conformance Suite

A backend is admitted only by passing **eight objective, device-agnostic criteria** — the D.1
suite, run in CI as a merge gate **[shipped]**:

1. **D1 Interface completeness** — every `GoatHAL` method implemented.
2. **D2 Capability honesty** — reported caps reproduce under measurement.
3. **D3 Determinism holds empirically** — the declared determinism profile is met in practice.
4. **D4 Canonical commitment** — output commitment is correct and device-blind (§10).
5. **D5 Preemption within declared p95** — cooperative yield meets its latency claim.
6. **D6 Envelope enforcement binds over policy** — power/thermal envelope caps execution, over any
   task policy (requires a peak-power observable).
7. **D7 Telemetry fidelity** — reported telemetry matches observed behavior.
8. **D8 Neutrality** — two irreducible halves: **behavioral** (the commitment is device-blind, per
   A-6) and **static** (the source passes the Neutrality Auditor, §9).

D6 certifies that a backend *implementation* enforces envelopes; it does **not** make any running
node's self-reported power telemetry trusted (D-3 clarification). Runtime power trust remains
governed by population-level statistics only (§13).

**D-4 (amendment, Pass 8; verdict form refined Pass 9) [design].** Determinism profiles carry
declared component widths, dimension bounds, and accumulation schedules, and a profile is admitted
only if it passes the **static accumulation budget** (App. A.4): every intermediate of its declared
metric provably fits `u128`/`i128` — with verdict comparisons executed in the protocol's fixed
**exact 256-bit multiply-compare** (`wide_mul_128`), whose factors must each provably fit `u128` —
so no agreement computation can wrap, saturate, or truncate at runtime. The conformance runner
will not certify a backend against a profile that fails the budget. This closes the
high-dimensional-overflow hazard (R-C11) at registration time, before the D3 (empirical
determinism) and D4 (canonical commitment) criteria are ever exercised against it.

### 8.1 Fault-isolated execution & the opaque-payload DoS (amendment D-5, R-C12) **[design]**

<!-- PATCH 10 (Pass 11): opaque-payload worker exploitation (advisory GOAT-ARCH-RECON-01 V1.1,
     registered R-C12). CP7 makes the Task payload opaque and the boundary contains a corrupted
     runtime by "verification, not isolation" (§Threat-Model 2.2) — but that argument is about
     protocol STATE, not node LIVENESS. A payload crafted to trip an out-of-bounds/kernel bug in a
     consumer ML runtime (vLLM/TVM/Triton class) can panic honest executors at the OS/driver layer:
     an un-slashable, content-blind DoS on exactly the household nodes the network serves. Closed
     below the trait (execution robustness) + at the submitter (content-blind outcome pricing),
     never by inspecting the payload. -->

**The hazard.** Core Principle 7 (§3.3) makes the `Task` payload an opaque blob, and the
hardware-to-protocol boundary contains a corrupted *runtime* by verification, not isolation
(Threat Model §2.2). That containment argument is about protocol **state** — a wrong result is
detected, attributed, and slashed. It says nothing about node **liveness**. A payload engineered to
trigger a known out-of-bounds or unhandled-panic path in a popular consumer ML runtime (a
vLLM/TVM/Triton-class kernel bug) can crash the executor process itself. Broadcast at volume, such
payloads systematically panic honest household executors at the OS/driver layer — a widespread,
**un-slashable, content-blind Denial-of-Service** on precisely the accessible nodes the network
exists to serve (§1), without ever tripping a protocol invariant. Three device-agnostic,
CP7-preserving mechanisms close it; none inspects the payload.

- **Fault-isolated execution below the trait (amendment D-5; conformance requirement).** Every
  `GoatHAL` execution runs in a **fault-contained worker** — a disposable child process / sandbox
  whose failure blast radius is *itself only*. A payload that panics the runtime takes down one
  disposable worker, never the node daemon and never the consensus client (which shares no address
  space with execution — the §5 layer boundary, now extended from *compile-time* isolation to
  *runtime* fault isolation). This is a **backend-robustness** obligation enforced as a D.1
  conformance criterion, not protocol branching: it names no device type, and the isolation
  mechanism (OS process + namespace/seccomp, or a WASM/sandbox host) is the backend's choice.
  *Accessibility (§1, S1):* the requirement is *fault-containment*, deliberately satisfiable by a
  cheap OS-process boundary — **not** a heavyweight VM — so it adds negligible floor cost to a
  low-end node; a watch-item flag is raised if any conformant implementation path forces a heavy
  always-on isolation runtime.
  *(Amendment **D-5** is the fifth hyphenated Spec-D amendment; it is distinct from the unhyphenated
  conformance criterion **D5** (preemption, §8), which it complements — D5 governs cooperative
  yield, D-5 governs crash containment.)*
- **A crash is availability churn, not a fault (R-C5, extended).** A worker that dies emits **no
  receipt** — not a faulty one. Under churn ≠ fault (§21.3) an absent result can never trip the
  maturity gate or the ratchet, so the DoS **cannot manufacture attributable faults** and cannot
  slash the honest executor it crashed. The toxic payload wastes the node's time; it cannot take its
  bond or its trust. This is the existing offline-node semantics applied to an *induced* offline
  event.
- **Content-blind submitter throttling on cross-executor crash correlation.** The residual — wasted
  executor time — is a *task-submission* abuse, and it is priceable **without reading the payload**.
  The protocol observes only the outcome distribution: a submitter whose tasks cause **abnormal
  worker termination across many *independent, cluster/ASN-disjoint* executors** (§14) exhibits a
  device-agnostic, content-blind signal — a toxic payload crashes independent executors on the same
  input, whereas one node's flaky hardware crashes *uncorrelated*. That cross-executor crash/timeout
  correlation raises the submitter identity's required fee-escrow (§33.1) and throttles its dispatch
  rate, recomputably from published execution-outcome attestations (the receipt-provenance discipline
  of §18, extended to abnormal-termination outcomes) — so it is **fraud-provable** and keys strictly
  on the *rate of divergent execution termination across independent executors*, never on payload
  bytes. A timeout (D5 cooperative preemption exceeded) and a crash (abnormal worker exit) are both
  observable outcomes; the signal is their *correlation across disjoint executors*, which
  distinguishes an adversarial payload from honest hardware variance and from a legitimately
  long task.

<!-- PATCH 15 (Pass 12): submitter-framing counter-vector in R-C12 (advisory GOAT-ARCH-RECON-02,
     registered R-C16). The Pass-11 escrow-throttle keys on "cross-executor crash/timeout
     correlation" but did not specify how a crash is PROVEN. That let the mechanism run in reverse:
     a cohort of adversarial executors could FABRICATE crash/timeout attestations against an honest
     submitter's tasks to inflate its escrow and throttle it out — weaponising the anti-DoS defence
     into an anti-submitter frame. Closed by requiring a crash to carry an epoch-linked, signed
     hardware exception log from the fault-isolated worker; an unsubstantiated hangup is charged to
     the executor's own churn (R-C5), not to the submitter. -->

**Crashes must be proven, not asserted — the signed exception log (R-C16, Pass 12).** The throttle
above keys on cross-executor crash/timeout *correlation*, but left unspecified how a crash is
**evidenced**, it is symmetric in a dangerous way: a coordinated cohort of executors could *fabricate*
abnormal-termination reports against an honest submitter's tasks — no toxic payload required — to
inflate that submitter's escrow (§33.1) and throttle it off the network. The anti-DoS defence would
run backwards as a submitter-framing tool. The asymmetry is restored by requiring a crash to be
**cryptographically substantiated** before it can be charged to a submitter:

- **The epoch-linked signed exception log.** A crash/timeout counts toward a submitter's throttle
  **only if** accompanied by a `HardwareExceptionLog` — the fault-isolated worker's abnormal-exit
  record (fault class, isolation-boundary signal), bound to the **task's assignment** (`task_id`,
  `submitter_id`) and to the **current epoch beacon** (anti-replay, §19), and **ML-DSA-65-signed by
  the executor** under its registered key (§18.2) in a dedicated signing context
  (`CTX_GOAT_HW_EXCEPTION_LOG` — pairwise domain-separated from every other signature, per the Threat
  Model context registry). The signature makes the report *attributable*: an executor that signs a
  false exception log has committed a fraud-provable act against a recomputable record, exactly as a
  fabricated fault attribution is (§18.3).
- **Anonymous or unsubstantiated hangups default to the executor's own churn (R-C5).** A worker exit
  with **no** valid signed exception log — an anonymous hangup, an unsigned report, a stale-epoch or
  wrong-`task_id` log — is **not** charged to the submitter. It is treated as the executor's own
  **availability churn** (§21.3): the executor simply produced no receipt, which manufactures no
  fault for anyone and does not touch the submitter's escrow. This is the safe default: absent proof,
  the system attributes an abnormal exit to the node reporting it, never to the party it accuses.
- **Epoch-linkage defeats replay and log-farming.** Because the log commits to the epoch beacon and
  the specific assignment, a cohort cannot mint a library of exception logs and replay them across
  epochs to sustain a frame, nor reuse one crash against unrelated submitters. Each charged crash is
  a fresh, signed, epoch-bound, assignment-bound statement whose signer is accountable for it.
- **The correlation gate still binds on top.** The R-C12 requirement is unchanged and now stacks:
  even *validly signed* exception logs throttle a submitter only when they correlate across
  **independent, cluster/ASN-disjoint** executors (§14). A single cluster's signed logs — honest bug
  or coordinated frame — cannot throttle a submitter; only genuinely independent executors crashing
  on the same input can, which is the true signature of a toxic payload. Framing thus requires both
  forging accountable signatures *and* controlling disjoint clusters — the same conjunction the
  anti-Sybil layer already prices out (§14, §15).

<!-- PATCH 18 (Pass 13, advisory GOAT-ARCH-RECON-03, registered R-C19): the R-C16 hard-kill blind
     spot. R-C16 charges a submitter only on a worker-SIGNED HardwareExceptionLog. But a payload
     engineered to trigger a catastrophic OOM/SIGKILL destroys the fault-isolated worker BEFORE it
     can sign anything — so the most violent toxic payloads produce no log, default to the
     executor's own churn (R-C5), and escape the throttle entirely: the more effective the DoS, the
     more completely it erases its own evidence. Closed by moving the evidence outside the worker's
     blast radius: the host GoatHAL daemon (the parent supervising the disposable worker) signs a
     Watchdog Tombstone for an abnormal hard-kill, and a QUORUM of disjoint host daemons tombstoning
     the same assignment restores the R-C16 asymmetry against single-host framing. -->

**The hard-kill blind spot & the Watchdog Tombstone (R-C19, Pass 13).** R-C16 restored the
anti-framing asymmetry by requiring a crash to carry a **worker-signed** `HardwareExceptionLog`. That
is exactly right for a *soft* fault — a caught exception, a cooperative-preemption timeout — where the
fault-isolated worker (amendment D-5) survives long enough to sign its own abnormal-exit record. It
has a latent blind spot at the violent end of the spectrum: a payload engineered to induce a
**catastrophic hard-kill** — an out-of-memory kill by the OS OOM-killer, an uncatchable `SIGKILL`, a
memory-limit cgroup termination — destroys the worker *before* it can sign anything. Under R-C16 alone
that produces **no** valid log, defaults to the executor's own churn (R-C5), and never touches the
submitter. The perverse consequence: the *more effective* a toxic payload is at hard-killing honest
workers, the more completely it erases the very evidence needed to charge it — the throttle is blind
precisely where the DoS is most damaging. The gap is closed by relocating the evidence to a vantage
point the hard-kill cannot reach:

- **The tombstone is signed from outside the blast radius.** Fault-isolated execution (D-5) already
  runs each task in a disposable worker supervised by a **host `GoatHAL` daemon** that is *not* in the
  worker's failure domain — an OOM/SIGKILL of the worker cannot take down its parent. When the daemon
  observes an **abnormal hard-kill** of a worker (OS-level termination signal, OOM-score / cgroup
  memory-limit trip, non-cooperative exit with no cooperative log emitted), it generates and
  **ML-DSA-65-signs a `WatchdogTombstone`** under its registered key (§18.2) in a dedicated,
  pairwise-domain-separated context (`CTX_GOAT_WATCHDOG_TOMBSTONE`, per the Threat Model context
  registry). The tombstone is bound to the **assignment** (`task_id`, `submitter_id`, and the payload
  *commitment* — never the payload bytes) and to the **current epoch beacon** (anti-replay, §19). The
  evidence survives the exact event that erased the worker's own log.
- **Content-blind by construction (CP7, §3.3, §3.5).** A tombstone records the *fact and class* of
  abnormal termination — hard-kill taxonomy: `OomKill`, `Signal(SIGKILL)`, `MemLimit`, `Watchdog` — the
  assignment binding, and the epoch. It carries **no payload bytes and no device type**; the daemon
  names an opaque termination class, not what the hardware is or what the task contained. The tombstone
  path is neutrality-gated (§9) exactly as the exception-log path is.
- **A quorum of disjoint host daemons restores the R-C16 asymmetry.** A *single* host daemon's
  tombstone charges the submitter with **nothing** — one host, honest bug or coordinated frame, cannot
  throttle a submitter, precisely the R-C16/R-C12 discipline. A crash is charged to the submitter
  **only when ≥ `WATCHDOG_TOMBSTONE_QUORUM`** (strawman 3) **cluster/ASN-disjoint host daemons**
  (§14) each sign a tombstone for the **same** assignment / payload commitment within the correlation
  window. Independent hosts on distinct physical machines hard-killing on the *same* input is the true,
  hard-to-forge signature of a toxic payload — the same "correlate across disjoint executors" logic as
  R-C12, now carried by host-daemon tombstones for the case where no worker log can exist. Framing a
  submitter this way requires forging accountable signatures **and** controlling that many disjoint
  clusters — the conjunction §14–§15 already price out.
- **The churn default is preserved, and the tombstone only *adds* a charge path.** Absent a disjoint
  quorum, a hard-kill remains the reporting node's own **availability churn** (R-C5, §21.3) — it
  manufactures no fault and does not touch the submitter's escrow. The tombstone never removes the safe
  default; it only supplies the missing evidence path that lets a *corroborated* toxic-payload hard-kill
  reach the same content-blind submitter throttle (R-C12 escrow-escalation curve, §33.1) that a
  soft-crash quorum already reaches. Throttle, never slash: a submitter is not a bonded protocol
  participant.
- **Signed ⇒ fraud-provable, epoch-bound ⇒ un-replayable.** Because each tombstone commits to the epoch
  beacon and the specific assignment, a cohort cannot mint a library of tombstones and replay them, nor
  reuse one hard-kill against unrelated submitters; and a host daemon that signs a **false** tombstone
  has committed a fraud-provable act against a recomputable record, exactly as a false exception log
  (R-C16) or a false fault attribution (§18.3) is. Accountability, not trust.

Net effect: the throttle now covers the full crash spectrum — soft faults by worker-signed
`HardwareExceptionLog` (R-C16), hard-kills by disjoint-quorum `WatchdogTombstone` (R-C19) — with the
same content-blind, correlation-gated, fraud-provable discipline throughout, and the R-C5 churn
default intact at every point. `WATCHDOG_TOMBSTONE_QUORUM` and the hard-kill fault-class taxonomy are
**[calibration]** (testnet-operations tuning).

Net effect: a toxic-payload campaign panics only disposable workers (never node daemons or the
ledger client), manufactures **zero** slashable faults against its honest victims, and prices the
submitter's own escrow up in proportion to the cross-executor damage it causes — while the *reverse*
frame is closed, because only an epoch-linked, executor-signed, independently-corroborated crash can
touch a submitter's escrow, and everything else is charged to ordinary churn. All of this reads no
payload byte, so CP7 (§3.3) and device-agnosticism (§3.5) hold exactly. `ISOLATION_MODE` conformance
detail, the crash-correlation window, the escrow-escalation curve, and the `HardwareExceptionLog`
schema/fault-class taxonomy are **[calibration]** (F5-adjacent + testnet-operations tuning).

## 9. The Neutrality Auditor

The Auditor (`goat-neutrality`) mechanically enforces §3.5 and §3.3 at compile time **[shipped]**.
It scans protocol-layer source (code only — comments/docstrings and the auditor's own definition
file are exempt) for:

- **Forbidden device-type tokens** — matched both as whole words *and* as identifier sub-tokens,
  splitting on `_` and camelCase boundaries, so a field like `observed_gpu_equiv` is caught even
  though `\bgpu\b` would not match inside it (the A-1 finding). Substring false positives are
  avoided (e.g. `input` must not trigger on the sub-token `npu`).
- **Forbidden content/policy tokens** — `license`, `model_name`, and similar, enforcing CP7 (§3.3).

A violation fails CI; a feed, backend, or protocol module that names a device type or inspects
content can never bind, by construction. This is the mechanical backstop that makes the
Device-Agnosticism Axiom an enforced invariant rather than an aspiration.

## 10. Determinism profiles & the canonical output commitment (A-6)

Cross-device verification is only possible if two *different* devices computing the *same* task can
be compared. Two constructs make this work:

- **Determinism profiles** classify a task's reproducibility: `Exact` (bit-identical commitments
  required), `Tolerance` (agreement within a numeric band), or `Statistical` (agreement within a
  distribution at confidence α). A profile carries its metric (`l_inf`, etc.), bound, and version.
  Profiles are the vocabulary the cross-class verifier (Part V, Spec C) speaks.
- **The canonical output commitment (A-6)** is a function of **task semantics only** —
  `task_class_id`, tokens, numeric outputs, `engine_build_id` — and **carries no device identity**.
  Two device classes computing the same task therefore commit *identically*. This is precisely what
  makes cross-class verification and the D8-behavioral neutrality property possible at all: if the
  commitment embedded the device, no two classes could ever agree, and the protocol could not be
  device-blind. The commitment is a deterministic, field-ordered, length-prefixed serialization
  hashed with SHA3-256 **[shipped]**.

Together, Parts I and II establish the frame the rest of the Yellowpaper builds on: a network whose
purpose is to profit dispersed idle households, whose invariants make capture a structural loss, and
whose device layer admits all hardware on measured merit while guaranteeing — mechanically — that
nothing above it ever knows what the hardware is.

---

# Part III — Identity, Capability & Anti-Sybil Physics

Part II admitted any hardware on measured merit while hiding its type from the protocol. Part III
answers the adversarial question that immediately follows: if a device is an opaque, measured
string, what stops one operator from *minting many* such strings — a Sybil fleet — to capture the
network's distribution-weighted rewards? The answer is not a gatekeeper (that would violate
permissionless entry, §3.6) but **physics**: identities are bound to signed, measured capability,
and co-location is exposed by the one thing an operator cannot fake — sustained physical throughput
per network endpoint.

## 11. `CapabilityRecord` / `DeviceCapability` — signed, chained, measured **[shipped]**

A node advertises what it can do through a **`CapabilityRecord`**: an ML-DSA-65-signed, canonically
serialized wire structure describing, per device, its measured per-task-class capability
(`DeviceCapability`), its determinism-profile reference, availability, power/thermal envelope, a
**density witness**, and attestation references. Two properties are load-bearing:

- **Measured, never declared (§3.4).** A `DeviceCapability` reports capability that must *reproduce
  under measurement*; the benchmark that sets the figure is also the hardware fingerprint. A record
  claiming capability the node cannot reproduce fails validation.
- **Identity binding.** The record is signed with the operator's **ML-DSA-65** post-quantum identity
  key (§16). The signature binds the measured capability, the epoch, an anti-replay nonce drawn from
  the epoch beacon (§19), and the chain position (§12) to *one* cryptographic identity. Capability
  is therefore never anonymous free-floating data; it is an attested claim by a specific,
  post-quantum-authenticated key that stakes its reputation and (in the economic layer) its bond.

The validity predicate partitions checks into **hard** (a failure rejects the record — bad
signature, replayed nonce, non-monotone epoch, density under-declaration) and **soft** (a signal
that weights scheduling but never rejects — fingerprint drift, staleness), per amendment A-5. The
soft class exists because ordinary life — a node sleeping, a low-bandwidth uplink, a GPU swapped by
its owner — must not be indistinguishable from an attack.

## 12. The attestation hash-chain (A-3/A-4) & rolling re-attestation (A-5) **[shipped]**

Each node maintains a **hash-chain** of its own capability records: `prev_record` commits to the
SHA3-256 of the full *signed* prior record (amendment A-3 — the chain binds exactly the bytes that
were accepted, signature included, so two records differing only in signature cannot collide). The
chain enforces **strict epoch monotonicity** (A-4): a record whose epoch does not strictly exceed
the head's is rejected, independent of the beacon-nonce check, which defeats replay and reordering
within a node's own history even if a beacon nonce is contested.

Re-attestation is **rolling and forgiving** (A-5). Fingerprint drift is a *soft* signal: it triggers
re-benchmark and, if sustained, flags the node — but a single drift does not reject a record
(hardware genuinely changes). Capability past the node's declared attestation cadence is
**confidence-weighted down in scheduling, never penalized**. This is the accessibility posture made
concrete at the identity layer: intermittency and modest hardware are normal, not adversarial.

## 13. Network-class attestation & the residential last-mile gate **[shipped]**

The idle premium — the reward multiplier that makes dispersed household hardware the network's most
profitable participant — is gated on a **residential last-mile** attestation, expressed through the
network-score factor **`q_network`**. Network class (residential vs. datacenter vs. unknown) is a
*network* property, not a device property (§3.5): it is inferred from **probe-observed** signals —
coarse multilateration geography, grid-territory correlation, last-mile characterization — never
from a node's self-report. A warehouse, an orbital/beamed-power ground station, and a
nuclear-adjacent datacenter all fail the terrestrial residential test *by construction* and land in
the same bucket: they earn commodity rates under κ and S_o, or service-lane fees, but no idle
premium and no pioneer bonus. This single physical gate handles every exotic-infrastructure case
identically, with no special category and no gatekeeper.

## 14. F4 density coupling & F6 cohort-merge — the anti-Sybil core **[shipped]** / **[calibration]**

The decisive anti-Sybil mechanism is **physical throughput per endpoint**, because it is the one
quantity a co-located Sybil operator cannot fabricate: many identities behind one fat residential
pipe still push their *aggregate* work through that single last mile, and sustained aggregate
throughput per endpoint is passively observable.

- **F4 — density-coupled network score.** `q_network` degrades **sharply** once the probe-observed
  compute density behind an endpoint exceeds the residential-plausible device count. A home
  last-mile credibly hosts a small number of reference-device-equivalents; beyond that, the network
  score falls off (strawman `q_network = max(0.10, 0.85·(5/d)^1.5)`, `d` = observed
  reference-device-equivalents per endpoint). Density is measured as sustained throughput per
  endpoint divided by the reference-device throughput — **probe-observed, never declared** (Rev D/B6:
  the probe is ground truth; self-reports only detect dishonesty). This forces any
  residential-distributed Sybil toward genuinely low-density sites, multiplying its site count and
  infrastructure cost.
- **F6 — density feeds *clustering*, not merely the premium.** When a **residential** endpoint's
  *probe-observed* density exceeds the plausible count, the protocol emits a `CohortMerge` density
  signal and **collapses every node identity behind that endpoint into a single cluster** for
  coverage-counting and anti-capture purposes. Forty identities behind one warehouse pipe count as
  **one** cluster — they cannot inflate the distinct-cluster coverage that the maturity gate and the
  reward-distribution mechanisms reward. Crucially, F6 evaluates on the **observed** value: a node
  that *under-declares* its density both fails the hard validity check (A-2) *and* is still merged on
  the probe observation, so under-declaration dodges nothing.

**The endpoint is a multi-dimensional topological fingerprint, not an IP.** A naïve density probe
keyed on IP address would be trivially defeated by fronting each Sybil identity with its own VPN or
proxy. The F4/F6 "endpoint" is therefore *not* an IP; it is a **topological fingerprint** composed of
signals a rerouting layer cannot cheaply forge, because they are properties of the physical last mile
and the work itself:

| Dimension | What it captures | Why a VPN/proxy cannot mask it |
|---|---|---|
| **ASN / routing origin** | The autonomous system the traffic truly originates from | A proxy relocates the *exit* IP but the aggregate still funnels through one origin AS/last-mile |
| **Geographic latency clustering** | RTT multilateration to independent probes | Latency is set by physical distance + speed of light; a proxy *adds* latency, it cannot subtract the shared physical hop |
| **Bandwidth capacity ceiling** | Sustained aggregate throughput achievable at the endpoint | Many identities behind one pipe share one capacity ceiling; the pipe's physical bandwidth is invariant to how many IPs front it |
| **Uptime / availability overlap** | Correlated online/offline transitions across identities | Co-located hardware powers on, sleeps, and drops together; independent households do not |

Identities that co-locate on any strong combination of these dimensions are treated as one endpoint
for F4/F6, so a Sybil farm cannot buy back its distinct-cluster coverage by scattering IPs — it would
have to scatter the *physical topology*, which is exactly the genuine distribution the network wants
(and prices at ordinary market return). This is the §3.5-consistent form of the anti-Sybil claim: the
probe reads network *topology and physics*, never device type or self-report.

<!-- PATCH 2 (peer review): temporal smoothing of the topological fingerprint to reject transient
     network false positives (ISP outages, BGP route leaks, congestion). -->

**Temporal smoothing — no single-epoch reaction (anti-false-positive).** The internet is noisy:
regional ISP outages, BGP route leaks and hijack-recoveries, and transient congestion can transiently
distort *any* of the four dimensions — an ASN can appear to shift, latencies can spike, throughput can
collapse — for an honest household that has done nothing wrong. Reacting to a single-epoch anomaly
would mislabel these legitimate events as co-location and wrongly F4-penalize or F6-merge honest
nodes, an **accessibility** harm precisely for contributors on less-stable last miles (often the
emerging-market households the network most wants). The fingerprint therefore applies **temporal
smoothing**: every dimension is evaluated over a **trailing moving-average window (recommended 72
hours)**, and F4 penalties / F6 cohort-merges fire only on signals that **persist across the smoothing
window**. Short-lived disruptions that resolve within the window trigger nothing. This mirrors the
maturity ratchet's "measured over sustained behavior, not a single tick" posture (§21) and the A-5
soft-signal philosophy (§12): the network reacts to *durable physical co-location*, not to the
internet having a bad afternoon. The 72-hour window length is a **[calibration]** parameter (tunable
alongside the F5 density thresholds) — long enough to smooth routing/outage noise, short enough that a
genuine warehouse cohort is still merged within a few days of coming online.

<!-- PATCH 11 (Pass 11): CGNAT / shared-gateway mass false-positives (advisory GOAT-ARCH-RECON-01
     V3.1, registered R-C13). Temporal smoothing rejects TRANSIENT shared-origin noise; CGNAT is
     PERSISTENT shared origin, so smoothing does not help. The fix leans on the two fingerprint
     dimensions CGNAT cannot collapse (per-household throughput ceiling, uptime independence),
     declares shared ASN/IP insufficient ALONE, and adds a recomputable de-merge escape. -->

**CGNAT & shared gateways — shared origin is not co-location (R-C13).** Temporal smoothing (above)
handles *transient* shared-origin noise; it does **not** handle a *persistent* one. In many emerging
markets, dense high-rises, and mobile-first regions, residential ISPs deploy **Carrier-Grade NAT
(CGNAT)** or uniform 4G/5G gateways, so hundreds of genuinely independent households **permanently**
share an ASN, a public-IP pool, and a backhaul path — two of the four fingerprint dimensions,
durably. A naïve F6 keyed on ASN + latency clustering would cohort-merge an entire honest
neighborhood into one cluster and crush its collective earnings — an **accessibility** catastrophe
in exactly the populations the network most wants (§1). The resolution is already latent in the
four-dimension design: **CGNAT collapses shared-origin dimensions but cannot forge the two that
measure physical independence.**

- **Shared ASN / IP-pool is declared *insufficient alone* for a merge.** These are the
  CGNAT-collapsible dimensions; on their own they carry no co-location information in a CGNAT region,
  so F6 must never merge on them alone. (This does not weaken the anti-Sybil claim — a real
  co-located farm also trips the two dimensions below; it only stops merging on the dimensions a
  whole honest neighborhood *unavoidably* shares.)
- **Merge requires the CGNAT-non-collapsible conjunction.** A cohort merges only when it *also*
  exhibits the signals a single physical last mile produces and independent households do not:
  (a) **aggregate-throughput dependence** — identities whose *combined* sustained throughput is
  bounded by one last-mile ceiling (a warehouse pipe), as opposed to independent households whose
  combined throughput *exceeds* any single access link and scales with the count; and (b) **uptime
  co-transition** — correlated power/sleep/drop transitions (co-located hardware cycles together;
  independent homes do not). Genuinely independent CGNAT households fail *both*: their combined
  throughput out-scales one link, and their availability is de-correlated. The merge predicate is
  thus a conjunction dominated by the two dimensions physics ties to true co-location, exactly the
  §3.5 "read topology and physics, never self-report" posture.
- **A recomputable distinctness de-merge (the escape valve).** Because probes are statistical, F6
  carries a **de-merge path** that is fraud-provable, not a support ticket: a merged cohort is split
  when the published probe series shows **sustained aggregate throughput exceeding a single
  last-mile's plausible ceiling** *or* **de-correlated availability transitions** across the merged
  identities over the smoothing window — physical evidence of independence that a true co-located
  farm cannot fabricate (it *is* one pipe, cycling together). The predicate is a pure-integer
  function of anchored probe observations, so any observer recomputes the de-merge identically
  (§3.8) — no gatekeeper, no discretion, no appeal board.

This keeps F6 device-agnostic and physics-based while removing the CGNAT false-positive: the
mechanism now reacts to *durable physical co-location* evidenced by the dimensions a shared gateway
cannot manufacture, and mistaken merges are self-correcting on published data. The plausible
per-last-mile throughput ceiling and the availability-correlation threshold are **[calibration]**
(F5, alongside the density curve).

<!-- PATCH 16 (Pass 12): network-throttle mimicry of the F4/F6 fingerprint (advisory
     GOAT-ARCH-RECON-02, registered R-C17; amendment D-6). The R-C13 non-collapsible dimensions
     (aggregate-throughput, uptime) are NETWORK signals. A co-located farm can DOWN-THROTTLE its own
     bandwidth and stagger power to keep its network fingerprint under a residential ceiling —
     mimicking many low-throughput homes to dodge the density merge and harvest the residential
     premium. Closed by a COMPUTE-SIDE, device-neutral signal the network throttle cannot touch:
     shared-silicon memory-contention timing entropy, which reveals identities that co-reside on one
     physical machine. Framed strictly as a CO-LOCATION probe (are these identities the same
     silicon?), never a device-type classifier — it emits an opaque measured scalar and must pass
     the neutrality auditor. -->

**The compute-side co-location probe — throttling the pipe cannot throttle the silicon (R-C17,
amendment D-6).** F4 and the R-C13 conjunction read *network* topology (throughput ceiling, uptime,
ASN). That leaves one residual mimicry path: a co-located cohort that **deliberately down-throttles
its own bandwidth** and staggers its power cycling can hold its *network* fingerprint under a
residential ceiling — presenting as many independent low-throughput households to dodge the density
merge (§14) and harvest the idle-residential premium (§13). The throttle is cheap because the
constrained resource (bandwidth) is not the one the farm actually has in abundance (compute). The
closure is to measure a signal on the axis the throttle does not touch — the physical memory
hierarchy — and to do so **without ever classifying what the hardware is**:

- **What it measures (an opaque scalar, not a device type).** A standardized, bounded
  micro-benchmark induces controlled L1/L2/L3 cache contention and records a **timing-entropy
  signature** — a pure-integer distribution digest of memory-access latencies under load. This is a
  *measured physical observable* in the exact sense of the Measured-Work-Only invariant (§3.4, §6):
  the benchmark that produces it is of a piece with the capability fingerprint. It yields an opaque
  `Ppm`-scaled scalar; **the protocol never maps it to "server" / "consumer" / any device class**
  (§3.5), and the module carrying it must pass the Neutrality Auditor (§9) as identifier text and
  sub-tokens — it names a *contention-timing measurement*, never a device.
- **What it actually detects: co-residency, not "industrial-ness."** The load-bearing signal is not
  a device's absolute speed (which would be a capability/device signal and is irrelevant here); it is
  **cross-identity cache interference**. Multiple identities that claim to be independent households
  but in fact run as VMs/containers on **one physical machine** share that machine's L2/L3 hierarchy,
  so when the probe runs concurrently across them their contention signatures are **mutually coupled**
  — thrashing each other's cache lines in a way physically separate machines cannot. Independent
  silicon shows independent signatures; co-resident identities show correlated interference. The probe
  therefore answers the same question F6 always asks — *are these separate participants or one
  operator wearing many masks?* — on a channel (the memory bus) that a network throttle cannot mask.
- **It is a co-location input to F6, under the same conjunction discipline.** The signature feeds the
  §14 density/merge estimate as an **additional non-collapsible dimension**, not a standalone gate:
  correlated cross-identity cache interference is added to aggregate-throughput dependence and uptime
  co-transition as evidence of physical co-location. The recomputable **de-merge** (R-C13) applies
  unchanged — a cohort split on published evidence of *independent* silicon signatures — so an honest
  CGNAT neighbourhood of genuinely separate machines is never merged by this dimension either; it
  makes the anti-mimicry stronger *and* the false-positive escape stronger, symmetrically.
- **Accessibility (S1) — bounded, not always-on.** The probe is a **short, bounded** benchmark run
  during attestation/benchmarking windows, not a heavyweight always-on measurement — explicitly
  sized against the S1 verification-cost budget and the standing accessibility watch (§1,
  `ACCESSIBILITY.md`): it must add negligible floor cost to a low-end node, and a watch-item flag is
  raised if any conformant implementation forces continuous or resource-heavy profiling. It runs the
  *same* standardized micro-benchmark on every device, so a low-end home node is measured identically
  to any other — the signature is used only relationally (cross-identity correlation), never as an
  absolute bar to clear.

*(Amendment **D-6** adds this as a D.1 conformance-observable — a `contention_timing` measurement the
backend must expose under the standardized probe, §8 — the sixth hyphenated Spec-D amendment,
distinct from the unhyphenated conformance criteria D1–D8. Like every D.1 observable it is
device-agnostic and measured, never declared.)* The probe's parameters — working-set sizes, the
contention schedule, the cross-identity correlation threshold — are **[calibration]** (F5, alongside
the density curve). R-C17 closes the network-throttle mimicry residual of F4/F6 by adding one
device-neutral physical dimension the throttle cannot reach, with no device-type logic anywhere in
the path.

Together F4 and F6 close the residential-Sybil vector to *breakeven-at-best*: high-density endpoints
are simultaneously score-degraded (F4) and cohort-merged (F6), so the only non-negative operating
point is genuine low-density distribution across independent sites — at which point the "attacker"
has *become* dispersed residential infrastructure and earns ordinary market return with no excess.
Pure physics; no gatekeeper.

> **[calibration] — F5 dependency.** The exact F4 density curve and the F6 merge thresholds (the
> strawman "~1–5 plausible devices" and probe-slack values) are **not yet final**. They are set by
> the **F5 empirical household-distribution study**: the real-world cost of imitating genuine
> household statistical distributions at scale. F5 is non-blocking for the build but **blocking for
> the quantitative anti-capture guarantee** — until it lands, the density parameters here are
> reasoned strawmen validated in simulation (Part VI), not measured constants.

## 15. Operator clustering & the density→clustering feedback **[shipped]**

F6 is one input to a broader **operator-clustering** layer that groups identities the network has
reason to believe share an operator, so that anti-capture caps (κ, S_o, the power-region factor
P_r) apply to the *cluster*, not the individual identity. Beyond F6's physical-density merge,
clustering features include payout-flow convergence (on-chain earnings-share and splitter patterns),
deployment-cohort signatures (fingerprint homogeneity × geographic burst × client-build uniformity),
and cluster-level "subsidized-persistence" statistics (fleets that persist where independent
economics say quit). Fiat-settled off-chain sponsorship remains invisible to flow analysis — that
residual (patronage capture) is bounded by governance hardening (Part VIII), not detection. The
design stance throughout: **population-level statistical evidence, never per-node hard gates** on
anything a node could synthesize.

---

# Part IV — Cryptographic Provenance & Consensus Primitives

Parts II–III establish *who* a participant is and *what* they can do. Part IV establishes that every
consequential datum the protocol acts on is **cryptographically attributable to its source and
recomputable by anyone** — the concrete machinery behind the Fraud-Provable-by-Recomputation
invariant (§3.8). Nothing here trusts an intermediary; every trust relationship is replaced by a
signature or a recomputation.

## 16. Post-quantum primitives **[shipped]**

The protocol's cryptographic floor is post-quantum and non-negotiable (§3.7):

- **ML-DSA-65** (FIPS 204) for identity and signing — public key ~1952 B, signature ~3309 B. Used
  for capability records, signed receipts, assignment logs, DA attestations, and beacon commitments.
  The Ed25519 stand-in used during the Python reference (risk R-CAP1) is **gone**; signing is
  genuinely post-quantum.
- **ML-KEM-768** (FIPS 203) for key encapsulation — ciphertext 1088 B, encapsulation key 1184 B —
  establishing the transport's shared secret.
- **SHA3-256** for all hashing, commitments, Merkle roots, and accumulator roots.

The wire format length-prefixes signatures and keys, so the primitives' byte sizes are irrelevant to
serialization and a future primitive swap is localized. These sizes were deliberately validated for
low-bandwidth accessibility (SC10): a handshake is a few KB, then symmetric.

## 17. PQ-authenticated transport **[shipped]**

Nodes communicate only through a **PQ-authenticated channel**: an ML-KEM-768 encapsulation
establishes a shared secret; the initiator authenticates the handshake with its ML-DSA identity
signature over the ciphertext; a derived AES-256-GCM channel then carries length-prefixed,
role-separated frames (the two directions occupy disjoint nonce spaces, so a bidirectional channel
never reuses a key–nonce pair). Confidentiality and authenticity come from the AEAD channel; framing
is transport plumbing that names no device type. The design is intentionally lightweight — one KEM
ciphertext + one signature per handshake, then symmetric AEAD — so a bandwidth-constrained node
participates without a high-end-hardware assumption.

## 18. Receipt provenance chain (H1 / R-MAT2b) **[shipped]**

A **receipt** is the atom of verified work that feeds the maturity accumulators (Part V). Its
integrity determines whether the whole fraud-proof edifice rests on trust or on cryptography. The H1
work makes *every executor-attributable element of a receipt independently verifiable*, and binds
the one element an executor cannot self-attest — the fault verdict — to a recomputable escalation
record. The result eliminates orchestrator framing: an orchestrator can neither rewrite what an
executor did nor fabricate a fault against an honest node.

### 18.1 `SignedReceipt` & the executor-attributable core

An executor signs an **`ExecutionAttestation`** over its *attributable core* — `class_id`,
`task_class_id`, `window`, the intra-window `sub_window` bucket, `cluster_id`, `asn`, and a
**commitment to its own output** (`result_commit`, the device-blind A-6 commitment). The
`diverged`/`fault` outcome flags are **deliberately excluded** from the signed core: those are
*verification outcomes* the orchestrator determines after comparison, and — critically — an executor
cannot be asked to sign its own guilty verdict (a faulted node would simply refuse, making
attribution unproducible). So the executor signs everything it is responsible for; the orchestrator
attaches the outcome afterward without being able to alter any signed field.

This closes the R-MAT2b provenance gap for the anomaly-burst mechanism (B-6, Part V): the
`sub_window` bucket that the burst predicate reads is now **attested at the source** by the executor
that performed the work, not assigned unilaterally by the orchestrator. A party controlling the
orchestrator can no longer spread anomalies across buckets to suppress a burst snap — the buckets are
executor-signed.

### 18.2 Key registry & authorization (assignment-log cross-binding)

Two checks establish that a signed receipt is *legitimate*, not merely *well-formed*:

- **Identity** — a `KeyRegistry` maps each `node_id` to its registered ML-DSA-65 public key; a
  receipt must verify against the registered key of the node it claims to come from.
- **Authorization** — an `AuthorizationSet` records which nodes were *assigned* each task. It is
  built from the orchestrator's **signed assignment log** (the primary pair A, B) plus the
  **beacon-lottery-re-derived** escalation executor C (§19, verifiable from the beacon, so C's
  authorization is itself recomputable, not asserted). A receipt from a node that was never assigned
  the task is rejected even if its signature is valid.

### 18.3 `EscalationRecord` & verifiable attribution

The last trusted element — *which* executor faulted — is made recomputable by the **`EscalationRecord`**.
It carries the three participants' signed receipts and their **raw results** (each bound to its
receipt via `result_commit`), plus the two comparison determinism profiles. A recomputer re-runs the
agreement decision (`agree(C,A)`, `agree(C,B)`) from the executor-signed results and confirms that
the attributed `diverged`/`fault` flags are *exactly* what that decision produces. Because the
orchestrator cannot forge the executor-signed result commitments and the agreement rule is
deterministic, **it cannot frame an honest node**: any fabricated attribution re-derives to a
different verdict and is rejected.

### 18.4 Fold-time enforcement (`fold_verified_attributed`)

All of the above is enforced at the accumulator boundary. `fold_verified_attributed` accepts a
receipt into the maturity accumulators only if (a) its signature verifies against the registered key,
(b) its node was authorized for the task, and (c) any `diverged`/`fault` flag it asserts is backed by
a verified `EscalationRecord` that re-derives that exact attribution. Identity, bucket, authorization,
and outcome are thus *each* independently verifiable, so no element of a folded receipt is trusted
rather than checked. **Remaining (Phase-2, [design]):** making a provenance fault *slashable* (needs
the economic bond) and stamping *real completion-time* sub-windows (needs independent operators);
the cryptographic chain itself is complete.

## 19. The epoch beacon (H2)

The beacon supplies the two pieces of public randomness the protocol cannot let any participant
grind: the anti-replay **nonce** for capability records (§11) and the **seed** for lottery
third-executor selection (§18.2). Its integrity is therefore an anti-capture concern.

### 19.1 Commit-reveal construction & last-revealer analysis **[shipped]**

The base construction is commit-reveal: each participant commits to `H(r ‖ salt)` during a commit
phase (before any reveal is known), then reveals `(r, salt)`; the beacon is `H(epoch ‖ sorted
reveals)`. Because commits are **binding** and locked before any reveal, no participant can bias the
output *at commit time* (avalanche: one revealed bit flips the whole beacon). The residual weakness
is at **reveal time**: the participant who reveals last has observed every other reveal, so it can
compute the resulting beacon *before* deciding whether to reveal — a one-bit veto (reveal, or
withhold to force a re-roll / subset outcome). `k` colluding potential withholders raise this to a
choice among up to `2^k` outcomes. In the permissioned MVP this is mitigated *economically* (a
non-revealer is detected and slashable/excluded, with an offline re-roll) — acceptable for a trusted
set, but only economic, and it costs liveness.

### 19.2 Delay-sealed finalization **[shipped]** (placeholder VDF) / **[design]** (production VDF)

The H2 hardening passes the combined reveal-seed through a **Verifiable Delay Function** whose
evaluation takes *longer than the reveal/decision window*. The delayed output is then unknowable
within that window, so a would-be last revealer **cannot compute either outcome in time to decide
whether to withhold** — the "see-then-decide" capability that *is* the last-revealer bias is removed.
This also makes a graceful `NonRevealerPolicy::SubsetWithSlashing` fallback safe (liveness restored,
no forced re-roll) precisely *because* a withholder cannot predict the value it would forgo. A
`BeaconMode` strategy enum selects `CommitReveal` (permissioned), `DelaySealed{ delay_iterations }`
(public/adversarial), or `ThresholdVrf` (documented target, not yet implemented), and a calibration
helper sizes `delay_iterations` to exceed the reveal window.

**Testnet last-revealer scope (advisory GOAT-ARCH-RECON-01 V1.2 — disposition).** The concern that a
colluding orchestrator cohort could withhold reveals to steer the lottery is the last-revealer bias
analysed in §19.1, and it is **already addressed by mechanism, not left open**: even at the
permissioned MVP, `DelaySealed` mode plus `NonRevealerPolicy::SubsetWithSlashing` removes the
see-then-decide capability that *is* the bias, so the mitigation is a **deployment selection**
(enable `DelaySealed` on the testnet with a placeholder-VDF `delay_iterations` sized to the reveal
window — its O(iterations) verify is acceptable *for a permissioned set*, only R-C4-blocked for
public/low-power verifiers), not a design gap. The residual is purely the production-VDF succinct-verify
requirement (R-C4), already tracked. Net: no new mechanism; the advisory's "temporary deterministic
fallback for testnet entropy" is the already-specified `DelaySealed` mode, recommended as the
testnet default whenever the participant set is not fully trusted.

The current VDF (`delay_eval`) is a documented **placeholder**: iterated SHA3-256, which has the
required sequentiality/delay property but verifies in O(iterations) by re-execution. A public
deployment **must** replace it with a real VDF (Wesolowski/Pietrzak) whose proof verifies in
O(log T)/O(1), or move to a threshold VRF (drand-style, requiring a DKG and pairing crypto). This is
not merely a performance note: the O(iterations) verify is an **accessibility** hazard (risk R-C4) —
a low-power node must not need to re-execute a long delay to verify a beacon. Succinct verification is
therefore a *gating requirement* on the production beacon, and the `BeaconMode`/`DelayProof`/
`SealedBeacon` type shape is chosen so the swap is localized.

### 19.3 Validator-Quorum Data-Availability attestation **[design]**

The oracle/settlement layer (Part VII) publishes reporter submissions and historical series
**off-chain**, content-addressed, anchoring only a 32-byte Merkle root + CID on the ledger — an
O(1)-per-region-epoch footprint that keeps the settlement ledger as thin as the mechanism ledger.
This introduces a **data-withholding** hazard (risk R-C1): an adversary could anchor a corrupted root
and then withhold the underlying leaves so no challenger can fetch them to produce a fraud proof
before the challenge window expires.

The mitigation is the **Validator-Quorum DA Attestation**. The 7-day challenge window does **not**
begin when a manifest is anchored; it begins only when a **`QuorumCertificate`** is anchored —
≥ 2/3 (integer BFT majority `n·2/3 + 1`) of an independent validator set, each signing
`H(GDA\x01 ‖ epoch ‖ region ‖ CID)` under its registered ML-DSA-65 key to attest it has fetched and
replicated the leaf blob. With the data unavailable, the clock never starts, so withholding cannot
"win by timeout." A reporter that fails to broadcast its leaves within `DA_TIMEOUT_EPOCHS` (strawman
24) receives no attestations; the maintenance engine intercepts the state transition, deletes the
reporter's reputation, and **burns 100% of its locked bond**. Withholding is thereby converted from a
winning move into a strictly loss-making one, under the same directional-fraud logic as the maturity
ledger.

**Two distinct roles — Orchestrators post, Validators attest.** The DA scheme deliberately separates
the party that *proposes* state from the party that *vouches for availability*, so no single actor
both writes a manifest and certifies its data is fetchable:

| Role | What it does | What it stakes | Selection |
|---|---|---|---|
| **Orchestrator** | Assembles a manifest (Merkle root + CID), posts the claimed aggregate to the ledger, runs verification rounds | A bond slashable on a fraud proof (§18, §22) | Assigns work under the executor-set spread rule (§21) |
| **Validator** | Independently fetches the CID leaf blob, replicates it, and signs a DA attestation of possession | A registered ML-DSA-65 identity + (production) a bond | An independent **Validator Set** registered in the ledger |

The **Validator Set** is a registered, permissioned-for-the-testnet cohort of independent operators
whose ML-DSA-65 keys the ledger knows, and whose ≥ 2/3 signatures form the `QuorumCertificate` that
starts the challenge clock. Because the Validators are *not* the Orchestrator and *not* the reporters,
data availability is certified by parties with no stake in the manifest's content — the same
"transparent before trustless" posture as the signed assignment log (§18.2).

**New trust assumptions this introduces (for the Part-VIII threat model).** Shifting availability
onto a quorum is a genuine new trust boundary, stated plainly rather than hidden:

- **Liveness attack (≥ 1/3 collusion).** A colluding third-plus of the Validator Set can *withhold*
  attestations for an honest, available manifest, preventing the `QuorumCertificate` from forming and
  stalling that region-epoch's update. Bounded impact: no *false* state is admitted (the update
  simply does not finalize; the prior value stands under the ±5%/quarter clamp), but liveness for that
  region degrades. Mitigation: over-provision the set and treat chronic non-attestation as a
  registry-eviction/slashing signal.
- **Safety attack (≥ 2/3 collusion).** A colluding two-thirds could attest to data that is *not*
  actually replicated, letting an Orchestrator anchor a corrupt-and-withheld manifest whose clock
  nonetheless starts. This is the classic BFT ≥ 2/3 safety threshold; it is the *strongest*
  assumption the scheme makes and the reason validator-set **independence is a hard requirement**:
  distinct operators, ASNs, and regions (mirroring the executor-set spread rule, §21), so a 2/3
  quorum cannot be assembled cheaply behind one operator — the same F6/topology logic (§14) that
  defeats co-located Sybils applies to the Validator registry.

<!-- PATCH 17 (Pass 12): the DA-hostage liveness vector (advisory GOAT-ARCH-RECON-02 V3.2,
     registered R-C18). The QuorumCertificate gate (R-C1) defeats withhold-to-run-out-the-clock by
     never STARTING the clock without available data — but that same property means a total
     external-DA outage stalls fraud-proof liveness indefinitely: no certificate can form, so no
     challenge window opens, so no posting is adjudicable. The single-contested-feed on-chain
     fallback (above) covers a targeted withhold, not a sustained systemic outage. Closed by a
     recomputable sustained-failure predicate that temporarily forces inline on-chain manifests at
     a punitive fee, auto-reverting on recovery. -->

### 19.4 Local-chain DA fallback — sustained-outage liveness (R-C18) **[design]**

**The hazard.** The QuorumCertificate gate (§19.3, R-C1) makes withholding *safe* for the protocol —
the challenge clock never starts on unavailable data, so no false state finalizes. But safety is not
liveness: a **sustained, systemic** failure of the external DA layer (the validator set partitions,
the content-addressed network goes dark, or a ≥ 1/3 cohort withholds indefinitely) means no
certificate can ever form, no challenge window ever opens, and the settlement layer **stalls** — every
region-epoch frozen at its prior value under the ±5%/quarter clamp. The single-contested-feed on-chain
fallback (§19.3) answers a *targeted* withhold of one disputed feed; it does not answer a *total*
outage where nothing is fetchable at all. Fraud-proof liveness must not be hostage to the external
DA network's uptime.

**The fallback — a recomputable predicate, a punitive price, an automatic revert.** When the DA layer
fails a region for a sustained span, the protocol temporarily trades its state-minimization posture
(§32) for guaranteed liveness, on a fully mechanical trigger:

- **Trigger (recomputable, no vote).** If **no `QuorumCertificate` anchors for a region for
  `DA_FALLBACK_EPOCHS` consecutive epochs** (strawman **32**), that region enters `DaFallback`. The
  predicate reads only anchored certificate presence/absence — every observer computes the identical
  state transition at the identical epoch (§3.8); there is no "DA is down" oracle and no discretion.
- **Forced inline posting at an 8× fee.** In `DaFallback`, a region's oracle postings must carry
  their manifest **leaves inline on-chain** (the full reporter-submission blob, not merely the
  `submissions_root` + CID), so a challenger can recompute `median` + `clamp_move` (§32, §34)
  directly from ledger state with **no external fetch** — fraud-proof liveness is restored without
  the DA layer. Inline posting costs an **`8×` fee multiplier** (`DA_FALLBACK_FEE_MULT`) over the
  normal O(1)-anchor fee, which (a) funds the temporary on-chain storage expansion, (b) makes the
  fallback strictly a *degraded* mode no rational poster prefers, and (c) prices any attempt to
  *induce* the fallback (a cohort withholding certificates to force costly on-chain bloat pays the
  DA-attestation bond forfeiture of §19.3 *and* confers an 8× cost that lands on postings, not on the
  network's baseline). So the 8× does not trap an *honest* orchestrator into halting during a genuine
  outage, the Emission Allocation Controller rebates the 7× premium back to it (§33.2, R-C20) — the fee
  stays punitive for an *inducer* at point-of-posting while the mode is cost-neutral for the victim.
- **Bounded blast radius.** `DaFallback` is **per region**, not global: an outage localized to one
  validator neighborhood expands on-chain storage only for that region's postings, so the O(1)
  steady state holds everywhere else. The challenge window in fallback starts at inline-posting time
  (the data is *definitionally* available — it is on-chain), so the recompute-or-slash loop (§34,
  B-2) operates unchanged.
- **Automatic revert.** The moment DA recovers — the **first `QuorumCertificate` to anchor** for the
  region — it exits `DaFallback` at the next quarter boundary and returns to O(1) root+CID anchoring.
  No governance action re-enables the cheap path; recovery is self-detecting, exactly as the trigger
  is self-detecting. The fallback cannot become a standing state because its exit condition is the
  same signal whose *absence* is its entry condition.

The fallback preserves every invariant it touches: postings remain pure-integer and fraud-provable
(inline data is *more* available, not less), device- and content-agnostic (it prices bytes and
epochs, never payloads or device types), and the 8× multiplier keeps state-minimization the *default*
while guaranteeing that independent fraud-proof capability survives a total DA outage — the S2
"availability is a first-class requirement" posture (§36) extended from *withholding* to *outage*.

**Residual + calibration.** Validator-set independence must be a registry requirement (per above);
the DA thresholds/timeout (`DA_TIMEOUT_EPOCHS`), the 100%-burn severity, and the R-C18 fallback
parameters (`DA_FALLBACK_EPOCHS`, `DA_FALLBACK_FEE_MULT`) are **[calibration]** items pending
F5-adjacent grounding and testnet-operations tuning; and moving the Validator Set from permissioned
to permissionless is a Phase-2/3 **[design]** item tracked with the real-ledger backing (Part VIII).

---

# Part V — Verification, Maturity & the Fraud-Proof Ledger

Parts II–IV established *who* participates, *what* they can do, and that every datum is
attributable and recomputable. Part V is where those guarantees do economic work: it is the machinery
that decides whether a unit of claimed work is *correct*, how much *redundant* verification a device
class must bear, and how any of it can be *challenged by anyone*. This is the concrete expression of
the Fraud-Provable-by-Recomputation invariant (§3.8).

## 20. Cross-class verification (Spec C) **[shipped]**

Because the canonical commitment is device-blind (§10, A-6), two *different* hardware architectures
computing the same task can be compared directly — a CPU-class node can verify a GPU-class node's
work. The rule that makes this fair is the **effective determinism profile**:

| Pairing | Comparison band | Rationale |
|---|---|---|
| Same-class | that class's **own** profile | identical architectures should agree tightly |
| Cross-class | the **widened** `max(band_A, band_B)` | legitimate cross-vendor round-off must not be read as a fault |
| Either, band > task bound | **INELIGIBLE** → pin to same-class | a class whose error exceeds the task requirement cannot serve that task |

*Two EXACT classes cross-pair at EXACT.* This corrected rule (amendment **C-1**) strikes the word
"stricter" from the original spec: an EXACT verifier would *false-reject* a TOLERANCE executor's
legitimate round-off, so the union-widened band is mandatory.

**Agreement (`agree`, amendment C-5).** For an EXACT profile, the canonical commitments must be
bit-identical. For a TOLERANCE profile, agreement is **modality-appropriate** — the comparison
function is a property of the *task class*, declared in its determinism profile (§10), never of the
device (§3.5):

<!-- PATCH 3 (peer review): non-string output agreement (amendment C-6). Extends the original
     text-only TOLERANCE rule to non-textual modalities via a canonical binary representation +
     a modality-appropriate metric, all declared in the determinism profile. -->

| Output modality | Canonicalization | Agreement metric (TOLERANCE) |
|---|---|---|
| **Textual** (tokens) | pinned/greedy decoding | LCS ratio ≥ 0.98 **and** numeric `L∞(a,b) ≤ band` |
| **Vectors / tensors / embeddings** | standardized canonical binary encoding (fixed dtype, shape, byte order) | bounded **Euclidean** distance or **cosine similarity** ≥ threshold |
| **Images** | canonical raster encoding | **SSIM** (Structural Similarity Index) ≥ threshold, or equivalent |
| **Audio / other** | canonical PCM/feature encoding | modality-appropriate bounded distance (declared per class) |

The rule (amendment **C-6**) generalizes the original text-only formulation: **every** non-textual
output is first mapped to a **standardized canonical binary representation** — the same A-6
device-blind commitment discipline (§10), extended so that two architectures encode the *same* logical
tensor/image/audio to the *same* bytes before any comparison — and is then compared under the
**modality-appropriate function and tolerance declared in the task class's determinism profile**
(§10). This keeps cross-class verification meaningful for the full range of AI outputs (not just
generated text) while preserving device-blindness: the profile names a *metric and bound*, never a
device. Length-/shape-mismatched outputs compare as maximal distance (disagreement, never an error).

<!-- PATCH 3 REFINEMENT (Pass 5): the modality metrics MUST be pure-integer fixed-point, or the
     comparison itself becomes non-deterministic across FPUs and causes accidental slashing. -->

**Metrics are pure-integer fixed-point — the comparison must not itself be non-deterministic.** A
subtle trap: SSIM, Euclidean/cosine distance, and embedding comparisons are conventionally *floating
point*, and IEEE-754 results diverge across architectures (x86 vs. ARM vs. discrete GPU/FPU: fused
multiply-add, rounding-mode, and reduction-order differences). If the *verification metric* were
float, two honest nodes could compute *different* agreement verdicts on the *same* canonical bytes —
an accidental disagreement that escalates and **slashes an innocent executor**. Therefore, and
consistent with the pure-integer determinism invariant (§3.8, App. A):

- **All C-6 tolerance metrics are specified as pure-integer fixed-point implementations** (PPM-scaled),
  never IEEE-754 — integer SSIM, integer L2/`L∞`, integer cosine (dot-products and norms accumulated in
  `u128`/`i128`, compared against a PPM threshold).
- Reduction order, rounding, and accumulation width are **fixed by the determinism profile**, so the
  agreement verdict is **bit-identical on every architecture** — the metric is as recomputable as the
  commitment it compares.
- This makes the comparison itself fraud-provable: a challenger re-runs the exact integer metric and
  gets the exact same verdict, so a mis-adjudicated escalation is itself a provable fault, not an
  architecture artifact.

In short: C-6 canonicalizes the *output* to bytes **and** the *metric* to integers — both halves are
required, or cross-class verification of non-textual work would slash honest nodes on FPU noise.
The integer metrics are additionally **overflow-proof by construction**: every profile's component
width, dimension bound, and accumulation schedule must pass the static accumulation budget of
amendment **D-4** (App. A.4, R-C11) before the profile can register — high-dimensional embeddings
cannot wrap `u128` into a wrong verdict.

**Escalation — four outcomes.** When the primary pair (A, B) disagrees, the orchestrator escalates to
a third executor **C**, selected by the **beacon lottery** (§19) so C is never adversary-chosen, and
required to be cluster/ASN-disjoint from *and* pairable with both (amendment C-3). The
result-comparison then yields exactly four outcomes:

| # | Condition | Attribution | Reward / slash |
|---|---|---|---|
| 1 | C agrees with **A** only | B faulted | reward A; **slash B** at the coupled multiple |
| 2 | C agrees with **B** only | A faulted | reward B; **slash A** |
| 3 | C agrees with **both** (non-transitive tolerance) | none possible | settle primary; **no slash**; flag `profile_remeasure` (C-2) |
| 4 | C agrees with **neither** (3-way split) *or* no disjoint-pairable C exists | none | **quarantine** — no reward, no slash (C-4) |

Outcome 3 was *discovered during implementation*: tolerance bands are not transitive (with band 8,
results `A` and `A+14` disagree while `A+7` agrees with both), so a fourth, no-attribution outcome is
reachable and must settle safely rather than slash an innocent party. Outcome 4's dependence on a
disjoint-pairable C is why the **executor-set spread rule** (§21, §24) is not merely anti-capture but
also **escalation liveness**: spread is what *reserves a resolvable third executor at assignment
time*.

Verification outcomes are emitted **as maturity receipts** (§18) — the attribution "`D_num += 1` for
the faulted class" is exactly one diverged+fault receipt for the faulted executor plus clean receipts
for the others (amendment B-5), which is what feeds §21.

## 21. The Verification Maturity Controller (Spec B) **[shipped]**

A brand-new device class is untrusted: its determinism characteristics are unknown, so its work must
be heavily re-verified. But re-verifying *forever* would make a mature, proven class permanently
expensive and thin-margin. The Maturity Controller resolves this with a **per-class lifecycle** whose
every transition is recomputable from published receipts (§3.8).

### 21.1 Accumulators, the gate, and the asymmetric ratchet

Per class, the controller folds receipts into a **`ClassAccumulator`**: verified-work count `V_c`,
divergence count `D_num`, fault count `F_num`, and **deterministic-HLL coverage sketches** of distinct
clusters and ASNs (the HLL is deterministically serialized so accumulator roots reproduce
bit-identically across recomputers — amendment R-MAT1). A **gate predicate** passes when volume,
divergence rate (`< ε`), fault rate (`< φ`), and coverage (≥ x_clusters, x_asns) all clear their
thresholds.

#### 21.1.1 HLL input hardening — anti-saturation (R-MAT4) **[design]**

<!-- PATCH 1 (peer review): HLL saturation-attack protection. New hardening requirement on the
     coverage HLL inputs; amendment R-MAT4. -->

The deterministic HyperLogLog counters that estimate task-space / cohort coverage during a class's
PROBATION phase are, like any HLL, sensitive to **adversarial input crafting**. HLL cardinality is
inferred from the maximum leading-zero run of hashed inputs, so an adversary who can *pre-compute*
identifiers (cluster ids, ASNs, or task-space keys) to produce artificially long leading-zero runs can
**inflate the coverage estimate** — potentially pushing an unstable, insufficiently-diverse device
class through the gate (§21.1) toward MATURE prematurely, exactly the coverage guarantee the gate
exists to enforce.

The mitigation is to make the hash distribution **un-precomputable** by salting every HLL input with an
on-chain beacon value the adversary could not have known when crafting inputs. But the salt must be
chosen carefully:

<!-- PATCH 1 REFINEMENT (Pass 5): pin the salt to the probation-START beacon, not the sliding current
     beacon. A per-epoch rotating salt would re-hash the same coverage_key to a different value each
     epoch, breaking cross-epoch de-duplication over the 30-day probation window and INFLATING the
     unique-coverage estimate — the very failure R-MAT4 exists to prevent. -->

- **Wrong: the *current*, sliding beacon.** Salting with each epoch's beacon rotates the salt every
  epoch, so the *same* `coverage_key` (a given cluster/ASN/task-space key seen repeatedly across the
  30-day PROBATION window) hashes to a *different* value each epoch and is **counted as new every
  time**. That breaks cross-epoch de-duplication and *inflates* the unique-coverage estimate — it
  re-introduces the very saturation it was meant to stop.
- **Right: pin to the probation-start beacon.** The salt is fixed to the historical beacon hash of the
  **exact epoch the device class entered PROBATION**, and held constant for that class's entire
  probation window:

  ```
  hll.add( H( probation_start_beacon ‖ coverage_key ) )      // replaces H( coverage_key )
  ```

  This is simultaneously **un-precomputable** (the class could not have known its own future
  probation-start beacon when crafting payloads, and cannot grind it — §19) and **stable across the
  window** (the same `coverage_key` hashes identically all 30 days, so genuine repeats de-duplicate
  correctly). Because `probation_start_beacon` is a fixed, recomputable on-chain value, every
  recomputer salts identically and the accumulator root still reproduces bit-identically (R-MAT1
  preserved). Marked **[design]** — a specified hardening of the shipped deterministic-HLL path, to be
  folded into the accumulator implementation.

The state machine advances a per-class sampling probability `p_class`:

| Stage | `p_class` | Meaning |
|---|---|---|
| CANDIDATE | 1.0 | pre-registration; not yet diverse enough to register |
| PROBATION | 1.0 | registered; 100% redundancy sampling |
| RELAX | 0.5 → 0.25 → 0.15 | earning trust; sampling steps down |
| MATURE | 0.15 (`P_FLOOR`) | proven; minimum steady-state redundancy |

(Two further, terminal-side stages — `DORMANT` and `ARCHIVED`, for classes that stop producing
verified work — extend this machine in the settlement-era state-minimization design, §32.1
**[design]**. They are ledger-mechanical, never ratchet `p_class`, and inactivity is not a breach.)

The ratchet is deliberately **asymmetric** — *slow up, fast down*:

- **Relaxation is earned slowly:** at most **one step per fully-held 30-day window** (1.0 → 0.5 →
  0.25 → 0.15 = `P_FLOOR` → MATURE). Trust accrues only over sustained good behavior.
- **A breach snaps immediately:** any gate breach (or a recomputable anomaly burst, §21.2)
  **doubles `p_class`** at once (capped at 1.0), demoting the class. A breached MATURE class always
  re-enters at least RELAX. Distrust is instant.

This asymmetry is the anti-fraud posture: a class cannot cheaply "buy back" the sampling discount it
lost, so a cheating episode is expensive for a long time afterward.

### 21.2 Recomputable anomaly-burst snap (B-6 / R-MAT2) **[shipped]**

The gate reacts to *window-wide* rates, but an adversary could concentrate faults into a short
*intra-window* burst whose window-averaged rate still passes the gate. The **anomaly-burst snap**
catches this — and, per amendment **B-6**, it is now fully recomputable. Each receipt carries a
`sub_window` bucket (executor-attested at source, §18.1); the accumulator tallies anomalous receipts
per bucket into the root; and a pure integer predicate `anomaly_burst(acc)` fires when one bucket
holds a concentration of anomalies (≥ a floor count and ≥ half the window's total). Because the
predicate is derived from the published receipts, **both** the live controller and the fraud verifier
recompute it identically: a controller (or orchestrator) that *withholds* a burst-mandated snap is
now caught as provable fraud (`withheld_burst_snap`, §22). This closed the last non-recomputable
trigger in the maturity controller.

### 21.3 The R-C5 tension — ratchet vs. honest churn

**The concern (R-C5).** Low-power, intermittent consumer devices — the very hardware the network
exists to serve (§1) — churn far more than always-on industrial capacity: they sleep, drop offline,
resume, and occasionally return with drifted state. If that churn were read as instability, the
aggressive down-ratchet (§21.1) would repeatedly snap a legitimately low-power class up to high
sampling and pin it there, structurally penalizing exactly the accessible devices the mission
depends on — an **accessibility** and **device-neutrality** (§3.5) harm.

**Why the design already separates the two — and what must be verified:**

| Signal | What it means | How the controller treats it |
|---|---|---|
| **Divergence / fault** | a node returned a *wrong* result | counts in `D_num`/`F_num`; can trip the gate/burst → snap |
| **Availability churn** | a node went *offline* (no result) | produces **no receipt at all** — not a faulty one; cannot trip the gate |
| **Staleness / drift** | capability aged or fingerprint drifted | **soft**, confidence-weighted in scheduling, never penalized (A-5, §12) |

The load-bearing property is that **churn ≠ fault**: an offline node emits nothing, so absence can
never be mistaken for divergence. The ratchet keys strictly on *measured wrongness* (divergence/fault
rate), never on completion gaps or wall-clock uptime. The maturity gate accrues over **completed,
verified work**, not calendar time, so an intermittent device progresses toward MATURE across its
*actual* participation rather than being reset by idle gaps — and this is device-agnostic by
construction (it counts verified-work behavior, never a device type). The residual is a *validation*
task, not new mechanism: an invariant test that correlated honest dropout does not trip a snap, plus a
multi-epoch churn simulation to fix the relaxation-window parameters against realistic churn
distributions (roadmap A4). Recorded as **R-C5**, folded into the analysis track.

### 21.4 Slash sizing & directional fraud (B-1 / B-2)

- **Slash sizing (B-1).** The slash multiple scales with the class's tolerance width — a wider band
  implies more room to cheat, so the penalty rises toward a cap:
  `slash_mult = clamp(base·(1 + coupling·tol_width/tol_ref), 15×, 20×)` with `coupling = 1/3` (chosen
  because `coupling = 1` saturated the cap almost immediately). Combined with `P_FLOOR = 0.15`, the
  expected value of cheating is negative: `fault_ev_margin = slash_mult · p_effective ∈ [2.25×, 3.0×]`
  at the floor — cheating loses 2.25–3× its gain even at minimum sampling.
- **Directional fraud (B-2).** A window posting is fraudulent **iff it is *less safe* than the
  recomputable lower bound**: a wrong accumulator root, a wrong claimed prior, an under-sampled
  `p_class`, or an over-advanced stage. An orchestrator may always be *more* conservative (sample
  more, snap harder) without penalty. This directionality is essential — an exact-match fraud
  definition would slash honest conservatism.

## 22. The minimal mechanism ledger & public verifiability (SC5) **[shipped]**

The ledger is deliberately the **thinnest possible on-chain surface** — the one place the protocol
must anchor state so a fraud proof has a target. It stores *only*:

- the epoch **beacon** value (§19),
- per-window **accumulator roots** + the **claimed maturity transition**,
- orchestrator **bonds** and the **slash** action a valid fraud proof triggers.

Nothing else — no token, no rewards, no balances, no receipts. Raw receipts are published off-chain,
content-addressed; anyone fetches them and recomputes. This is what makes **public verifiability
(SC5)** real rather than asserted: a challenger folds the published receipts, recomputes the
accumulator root and the *legal* transition (via the **same** pure `evaluate_transition` the
controller uses), and — if the posting is less safe than that lower bound (B-2) — produces a fraud
proof that **slashes the orchestrator's bond**. The ledger then *independently* re-runs the same
recomputation; it never trusts the challenger. Two independent recomputations agreeing is the
trustless-by-recomputation property. Conversely a *conservative* posting is provably never slashed —
demonstrated across every fraud class in the shipped harness. The minimal ledger is thus the anchor
that turns Parts III–V from "signed claims" into "publicly adjudicable claims."

---

# Part VI — Anti-Capture & Monopolization Defense

Anti-capture is not a feature bolted onto GoatCoin; it is the reason the protocol exists in the form
it does (§1–§2). Part VI consolidates the *economic* defenses that sit atop the *physical* defenses of
Part III. The unifying claim, proven in simulation (§26), is that **capture must be bought at a
structural loss** (the Thin-Pool Principle, §2) — every mechanism here bounds a specific residual
vector around that central fact.

## 23. The core defense equations — S_o, κ, spread **[shipped]**

The reward paid for a unit of verified work is the base rate multiplied by an anti-capture stack.
Three terms carry the load; all apply to the **operator cluster** (§15), never the raw identity, so
Sybil-splitting cannot dodge them (§14):

| Term | Name | Form (strawman) | What it does |
|---|---|---|---|
| **S_o** | Concentration factor | reward share falls as an operator's share `s` of *recent network work* rises (diminishing-returns curve) | makes the marginal unit of a large operator worth **less** than a small operator's — the core "spread the work" incentive |
| **κ** | Assignment cap (floor) | `κ ≥ 1%` is an **unamendable floor** on any qualifying small node's assignment share | guarantees a small node is never starved of work by concentration; the floor is constitutional (§3) |
| **spread rule** | Executor-set diversity | a redundant set must span ≥ m distinct clusters/ASNs (≥ regions where latency allows) | anti-capture **and** escalation liveness (§20, C-4): no set collapses below m independent operators |

Because S_o is denominated in *share of recent work* and applies to the cluster, an operator that
grows its footprint drives its own marginal reward down — the diminishing-returns curve is the
mathematical expression of "the pool pays for distribution." Cross-reference: this is why F6's
cohort-merge (§14) is decisive — it forces a co-located Sybil's many identities into *one* cluster, so
S_o and κ see the true concentration rather than the faked spread.

## 24. Power-infrastructure capture defense — P_r & the Calibration Law **[shipped]** / **[calibration]**

A distinct vector is an operator that is *physically distributed but single-grid* — a "company-town"
deployment spread across a region but sitting on one cheap/free power source. The **Power-Region
Factor P_r** bounds it:

- **P_r** soft-caps any single grid/balancing-authority territory's share of idle-premium-qualified
  work (strawman threshold `ρ* ≈ 4%`, penalty `(ρ*/s_r)^γ_r` beyond it), applied **largest-cluster-
  first** within the over-concentrated region so genuine small locals keep full weight when a whale
  moves into their grid.
- **Service-lane caps** bound the same operator's alternative path: no cluster above ~25–30% of any
  lane's paid volume; every registry model seeded by ≥ 3 independent clusters; verification duty
  inherits the ≥ m-operator spread. Dumping below cost is then self-defeating — the caps prevent the
  take-the-lane endgame, so predatory pricing just burns money.

**Why free/cheap power buys *margin* but not *market share* (Power-Source Neutrality, §3.2).** This is
the sharpest statement of the invariant. Idle-premium eligibility is governed by the **Calibration
Law** (§3.1):

$$I_{max} \times \frac{D_{max}}{24} \le 1$$

which prices the **fleet-hours** an always-on operator must sacrifice to credibly *mimic* idleness.
The variable being priced is **time / capital utilization**, not energy. Therefore:

- **Cheap power lowers an operator's cost** → it keeps more of its reward as margin. The network is
  agnostic to this and neither rewards nor punishes it — cheap power (solar households included) is
  welcome, and unattestable anyway.
- **Cheap power does not change the Calibration Law's arithmetic.** Idling still wastes capital
  utilization regardless of the electricity price; a nuclear/solar/satellite operator that runs
  always-on to maximize output *fails the idle gate* (§13) exactly as a coal-powered one does, and one
  that idles to pass the gate sacrifices the same fleet-hours as anyone else. Free joules cannot buy
  back sacrificed time.

So an energy-advantaged operator earns *more margin per unit of the market share it legitimately wins*
— but its **share** is still bounded by S_o, κ, P_r, and the physical idle/residential gates, none of
which reference energy. Control of power infrastructure earns *nothing extra* in the idle pool because
the pool prices time, genuine idleness, and independent distribution — properties that must be
**physically lived, not generated**. An energy giant's only rational paths to GoatCoin revenue are the
(capped) service lanes or *genuinely distributing hardware into independent households it does not
control* — both of which strengthen the network.

## 25. Device diversity & class-capture defense **[shipped]**

Because every mechanism above prices *time, distribution, and verified work* — never a device type
(§3.5) — none needed modification for heterogeneous hardware. Exotic accelerator fleets (hyperscaler
TPU/ASIC) fail the residential last-mile test (§13) exactly as datacenter GPUs do. One-entity
domination of a single device *class* is covered by cross-class operator clustering + S_o and
monitored via a **device-class entropy** metric so the network does not drift mono-class or
mono-owner-per-class. The pioneer multiplier (§7.1) that bootstraps a class is itself inside this
stack, so pioneering pays but pioneer-farming does not.

## 26. Adversarial-simulation results (Q1 iterations 1–3)

The defenses above are not asserted; they are tested against active adversaries in the Q1 adversarial
simulation, run as a closed loop (simulate → find a hole → fix → re-simulate).

| Iteration | What it tested | Headline result |
|---|---|---|
| **1** | whale / power-giant / Sybil / patronage / pioneer-farming strategies vs. the reward engine | found two holes: the ratchet was +EV for cheating, and residential-Sybil was profitable → motivated fixes **F3** (`P_FLOOR = 0.15`, slash ≥ 15×) and **F4** (density-coupled `q_network`) |
| **2** (`q1_adversarial_sim_v2.py`) | the F3/F4 fixes + the discovery that density must feed *clustering* | datacenter / free-power / naive-Sybil strategies **fail decisively (~2% capture, −$160k to −$200k/mo)**; residential-Sybil closes to **breakeven-at-best** only after adding **F6** (density → clustering, §14); the reference small node's earnings target attainment stays **≥ 1.05** in every surviving configuration |
| **3** (500-round campaign, Wilson 95% CIs) | quantified cross-class collusion, band-edge gaming, and F6 detection on the live testnet data | **R-VER1:** net-profit framing requires **> 50% control of the ~20-candidate escalation pool** (≥ 11 disjoint sites, ~$770/mo), and C is beacon-lottery-chosen. **R-VER2:** band-edge gaming **backfires ~4.5×** more than it succeeds (46.8% attribution vs 10.4% no-attribution). **R-MAT3/F6:** **40/40** concentrated endpoints merged (100%), **0/200** home-endpoint false positives; coverage inflation prevented **2.38×** |

The trajectory is the important part: each iteration closed a hole and the next confirmed the fix
under active attack, converging on the central claim (§2) — in every surviving configuration, small
honest nodes remain viable (target attainment ≥ 1.05) and every capture strategy is at best breakeven
and usually a heavy loss. **[calibration]:** the *quantitative* guarantee's last free parameter is the
F5 study (§14): the real cost of imitating genuine household distributions at scale, which sets the
final F4 curve and F6 thresholds the simulation currently strawmans. The models are also just that —
models over an in-process transport (the crypto and role separation are real); field validation on a
public testnet is the corrective (Part VIII).

---

# Part VII — Economics: Dynamic-CET Settlement & Oracle Layer **[design]**

> **Scope.** This entire chapter is Phase-3 **[design]** — specified and mathematically hardened
> (design notes 36–41), **not** implemented in the shipped Testnet MVP, whose ledger deliberately
> holds no token or reward (§22). It is the deferred settlement layer (roadmap I4). Economic
> constants (`κ_thin`, base weights, clamp bands, decay, DA thresholds) are **[calibration]** pending
> the F5 study. Every quantity is **pure-integer**, so a mis-posted target is a fraud proof (§3.8).
> Fixed-point conventions (App. A): `PPM = 1_000_000` (1.0), `BP_FULL = 10_000` (100%), `MicroUsd`
> = µUSD, `Ppm`/`Bp`/`Epoch` = `u64`/`u32`/`u64`.

The economic layer answers one question honestly: *what is a fair, localized, honest wage for a unit
of idle compute, denominated so it holds its real value over a decade?* A static fiat peg cannot; the
Dynamic-CET pegs the wage to live commodity-compute markets and localizes it through a
purchasing-power basket, while the Thin-Pool coefficient (§2) keeps the wage structurally unprofitable
for industrial expansion.

## 27. The Dynamic Contributor Earnings Target (CET) **[design]**

The **CET** is the target net earnings for a unit of contributed idle work. It is computed as a
pipeline, each stage recomputable:

```
[ Compute Market Index ] --×κ_thin--> [ Thin-Pool Gross Rate ] --×CPPI--> [ Localized Net Target ]
      commodity µUSD/GCU-h                  µUSD/GCU-h (capped)              µUSD/GCU-h (localized)
```

- **Authoritative unit:** a **per-GCU-hour rate in µUSD**, thin-pool-discounted *before* anything
  downstream sees it (§28), so no code path ever handles an un-capped gross.
- **Monthly figure is display-only:** the familiar "8 h/day × 30 d" number is
  `CET_monthly_display = 240 × localized_target_ugcu_h`, derived *from* the already-capped per-hour
  target purely for the *D.A. G.O.A.T.* UI — never an independent settlement path. Keeping `κ_thin` inside
  the single per-hour rate guarantees the display and settlement paths cannot disagree.

## 28. The Compute Market Index (CMI) — commodity-tier only **[design]** / **[calibration]**

The CMI tracks the **global hourly clearing price of commodity/consumer-tier AI compute**, aggregating
live asks from decentralized/transparent markets (e.g. Akash, Vast.ai, Spheron spot pools). Its
single most important rule is a **filter**, not a formula:

- **Enterprise/hyperscaler tiers are excluded.** Commercial H100/B200-class enterprise cloud rates are
  filtered out; the index reads only commodity/consumer-tier asks. This is what holds the thin-pool
  cap intact — pegging to industrial rates would raise the wage to where industrial expansion clears.

The thin-pool gross rate applies the unamendable coefficient `κ_thin ∈ (0,1]` up front:

$$\text{CET}_{gross\_rate} = \frac{\text{median\_commodity\_rate} \times \kappa_{thin\_ppm}}{\text{PPM}} \quad (\mu\text{USD/GCU-h})$$

```rust
pub struct ComputeMarketIndex {
    pub commodity_rate_ugcu_h: AggregatedFeed, // median of commodity-tier asks, µUSD/GCU-h
    pub kappa_thin_ppm: Ppm,                    // thin-pool coefficient (PPM); UNAMENDABLE band
}
```

`κ_thin < 1` is why deploying fresh capital to farm the pool is a structural loss (§2): the pool pays
a *fraction* of the commodity clearing rate, below new-hardware payback, forever. `κ_thin` is
**[calibration]** (F5), but its *band* is a constitutional invariant.

## 29. The Hexa-Index CPPI basket **[design]**

The **Contributor Purchasing-Power Index (CPPI)** localizes the gross target through six components —
three direct operating costs, three real-value anchors — so the wage means the same real thing in
every region:

| # | Component | Kind | Why it protects the idle contributor |
|---|---|---|---|
| 0 | **Residential electricity** (µUSD/kWh) | Opex | the largest direct running cost; buffers net margin against local tariff shocks |
| 1 | **Broadband tariff** | Opex | data-transmission cost, decisive in metered/emerging-market last miles |
| 2 | **Digital PPP / cost-of-living** | Anchor | pegs token value to local digital-goods parity |
| 3 | **Local inflation (CPI)** | Anchor | keeps the nominal target rising with local prices between rebalances |
| 4 | **P2P stablecoin premium** | Anchor | captures the true off-ramp rate (USDT↔local fiat) in capital-controlled economies |
| 5 | **Local wage index** | Anchor | preserves the reward's *meaningfulness* vs. local labor |

Each component is normalized to an index level and combined by weight:

```rust
pub fn index_level(value: u64, base_ref: u64) -> Ppm {           // 1e6 == unchanged vs base epoch
    if base_ref == 0 { return PPM; }
    (value as u128 * PPM as u128 / base_ref as u128) as u64
}
pub fn cppi_multiplier(levels: &[Ppm; N_CPPI], weights: &[Bp; N_CPPI]) -> Ppm {
    let mut acc: u128 = 0;
    for k in 0..N_CPPI { acc += levels[k] as u128 * weights[k] as u128; } // Σ weights == 10_000
    (acc / BP_FULL as u128) as u64
}
```

## 30. The Meta-Index Controller — adaptive rebalancing **[design]**

Over a decade, a contributor's cost structure shifts; the basket must adapt **without** a governance
lever an adversary could capture (§35). The Meta-Index Controller reweights the basket
algorithmically, bounded by a constitution band.

### 30.1 The R-C2 volatility model — Symmetric Integer Deviation (finalized, AR41)

Opex components are buffered in proportion to their **trailing volatility**. Volatility is the
finalized **Symmetric Integer Deviation (sMAPE-style)** — chosen over log-returns (no exact integer
log) and over asymmetric ratio-returns (a 50→100 rise and 100→50 crash must weigh equally), with the
`u128` cast-before-multiply hyperinflation guard so trillion-scale fiat values cannot overflow `u64`:

```rust
pub const SYMMETRIC_DEVIATION_MAX_PPM: Ppm = 2_000_000; // ±200% structural bound (collapse/appearance)

/// d(prev,cur) = min( 2·|cur−prev|·PPM / max(1, prev+cur), 2·PPM ). Total & panic-free on all u64.
pub fn symmetric_deviation_ppm(prev: u64, cur: u64) -> Ppm {
    let abs_diff = cur.abs_diff(prev) as u128;          // cast FIRST -> no u64 overflow (hyperinflation)
    let sum      = prev as u128 + cur as u128;          // < 2^65
    let denom    = core::cmp::max(1u128, sum);          // zero-guard: only prev==cur==0 hits 1
    let num      = abs_diff * 2 * (PPM as u128);        // < 2^85, fits u128
    core::cmp::min(num / denom, SYMMETRIC_DEVIATION_MAX_PPM as u128) as Ppm
}
```

- **Symmetric:** `d(a,b) == d(b,a)`; equal-magnitude up/down opex shocks reweight identically.
- **Overflow-safe to `u64::MAX`:** the wide product is formed in `u128` (proven ~2^43 headroom even at
  the worst input), so a hyperinflating fiat feed cannot halt the chain.
- **Zero-safe & symmetric-denominator:** `max(1, prev+cur)` — the only zero case has a zero numerator.

The trailing measure is a **mean absolute return *from parity*** (not deviation about the sample mean —
a steady tariff climb must register as pressure, and a single return must not read 0):

```rust
pub fn symmetric_deviation_mar_ppm(finalized: &[u64], window: usize) -> Option<Ppm> {
    let w = window.clamp(1, VOL_WINDOW_MAX_QUARTERS);
    let series = &finalized[finalized.len().saturating_sub(w + 1)..]; // last w+1 values
    if series.len() < 2 { return None; }                             // Q1: 0 returns (see §30.2)
    let (mut sum, mut n): (u128, u128) = (0, 0);
    for p in series.windows(2) { sum += symmetric_deviation_ppm(p[0], p[1]) as u128; n += 1; }
    Some((sum / n) as Ppm)
}
```

### 30.2 Cold-start progressive window, `VOL_WINDOW_MIN_RETURNS`, and the ±5% circuit breaker

- **Progressive fold (no Year-1 blindness).** Volatility is averaged over `min(available_returns, W)`,
  emitting as soon as one return exists — buffering is live in a class/region's **2nd** finalized
  quarter, not after `W+1`. The single unavoidable blind quarter is Q1 (one data point → no return).
- **`VOL_WINDOW_MIN_RETURNS` is a constitutional parameter.** It sets the cold-start floor (minimum
  returns before a reading is emitted). Its band is constitutional; its value is **[calibration]**:

| Constant | Value (strawman) | Governs | Status |
|---|---|---|---|
| `VOL_WINDOW_MIN_RETURNS` | 1 | cold-start floor (buffer from Q2 vs. more smoothing) | **[calibration]**, constitutional band |
| `VOL_WINDOW_DEFAULT_QUARTERS` | 4 | default trailing window | **[calibration]** |
| `VOL_WINDOW_MAX_QUARTERS` | 8 | window upper bound | constitutional band |
| `SYMMETRIC_DEVIATION_MAX_PPM` | 2_000_000 | per-tick structural cap | fixed (structural) |

- **±5%/quarter circuit breaker.** Independently of any reweight, the *output* multiplier moves at
  most ±5%/quarter via `clamp_move`, so even a saturated volatility cannot jump the target — the
  reweighter and the clamp compose. This is the flash-manipulation breaker (§34).

```rust
pub fn rebalance(ctl: &MetaIndexController) -> [Bp; N_CPPI] {
    let mut raw = [0u64; N_CPPI];
    for k in 0..N_CPPI {
        let base = ctl.base_weights[k] as u64;
        raw[k] = if ctl.is_opex[k] {
            let sigma = symmetric_deviation_mar_ppm(ctl.history[k].valid(),
                                                    ctl.vol_window_quarters as usize).unwrap_or(0);
            let boost = (ctl.buffer_lambda_ppm as u128 * sigma as u128 / PPM as u128)
                .min(ctl.boost_cap_ppm as u128) as u64;
            base * (PPM + boost) / PPM
        } else { base };
        raw[k] = raw[k].clamp(ctl.w_min as u64, ctl.w_max as u64);
    }
    normalize_bp(&raw, ctl.w_min, ctl.w_max) // Σ == 10_000 by largest remainder
}
```

<!-- PATCH 13 (Pass 11): the "volatility weight-boosting paradox" (advisory GOAT-ARCH-RECON-01
     V2.1). The premise as stated is incorrect for the current design and is corrected here; a
     genuine but BOUNDED residual is then addressed with an optional inverse-volatility damping for
     designated liquid anchors (R-C14). -->

**On the volatility-boost / liquid-anchor concern (R-C14, Pass 11).** A raised concern held that the
controller would *boost the weight* of a speculative, noisy component — naming the P2P stablecoin
premium — letting erratic streams destabilise the target. **As stated this does not occur, by
construction:** the volatility boost applies **only to `is_opex` components** (`raw[k] = if
is_opex[k] { …boost… } else { base }`), and only residential electricity and broadband are opex
(`is_opex = [true, true, false, false, false, false]`). The P2P stablecoin premium is component 4,
an **anchor** (§29) — it is *never* boosted; its weight sits at `base` regardless of its volatility.
The boost is deliberately reserved for *sticky infrastructure* costs, exactly to avoid amplifying a
liquid asset.

A **bounded residual** does remain, and is worth closing: a noisy liquid anchor, though unboosted,
still enters the multiplier at its fixed base weight, so speculative noise in it passes through
(diluted by weight and bounded by the ±5%/quarter output clamp, §34). The optional refinement is
**inverse-volatility damping for designated liquid anchors**: a flagged liquid anchor's weight is
*reduced* in proportion to its own trailing symmetric deviation (§30.1) — reusing the same integer
primitive — so speculative noise **lowers** the chaotic stream's influence rather than leaving it
flat:

```rust
// For an anchor flagged is_liquid: damp (never boost) by trailing volatility.
//   damp_ppm = min(damp_lambda · σ_k / PPM, damp_cap_ppm);  w' = base · (PPM − damp_ppm) / PPM
// Directionally safe: high σ ⇒ LOWER weight; re-normalised by largest remainder (Σ == 10_000).
```

This is strictly a *containment* of an already-clamp-bounded exposure, not a fix for a live paradox:
it can only shrink a noisy component's weight, is symmetric-integer and deterministic, composes with
the ±5%/quarter clamp, and re-normalises exactly. `is_liquid` designation, `damp_lambda`, and
`damp_cap_ppm` are **[calibration]**; the damping is **[design]** and optional (the correction above
stands on its own without it).

Bounded component **mutation** (swapping a dead feed) is a mechanical state machine gated by an
on-chain co-movement correlation ≥ θ (overflow-safe integer Pearson), the neutrality scan (§9), and
the challenge window — no vote (detailed in the risk chapter, Part VIII).

## 31. Regional compute amortization & regional onboarding **[design]**

### 31.1 Regional compute amortization

The global CMI is dominated by low-cost regions, understating the commodity value of a GCU-hour where
import taxes / capital controls raise real replacement cost. A **tightly-clamped, device-agnostic**
per-region scalar normalizes for this — a *normalization*, never a capital subsidy (it keys on
`region_id` and GCU units, applies uniformly to every contributor in the region, and is clamped to a
narrow band, strawman `[0.85, 1.30]`). It flows through the same ±5%/quarter clamp and challenge
window as any feed.

<!-- PATCH 12 (Pass 11): the triple-clamp hysteresis trap (advisory GOAT-ARCH-RECON-01 V2.2).
     This is R-C3, previously only "design intent recorded" in §36. Promoted here to a specified
     two-tier mechanism: the routine ±5%/quarter clamp is kept for anti-manipulation, and a
     separate, larger EMERGENCY slew unlocks only on sustained, multi-feed, multi-epoch
     corroboration of a genuine macro shock — recomputable, cross-checked against the global
     median, and self-re-locking. -->

**The black-swan release valve — two-tier, corroboration-gated (R-C3, specified Pass 11).** The
routine ±5%/quarter clamp (§34) is a deliberate *anti-manipulation* choice: it will not chase a fast
move, because most fast moves are manipulation. But a genuine macro shock (hyperinflation, currency
collapse, a capital-control step) can move a region's real replacement cost and purchasing power by
multiples in weeks — far beyond both the amortization band and the slew limit. Left at one tier, the
three backward-looking dampeners (input clamp, weight band, output clamp) compose into **hysteresis**:
the target takes many quarters to recognize the shock, underpaying households in the affected region
exactly when their earnings matter most (an **accessibility** failure, §1). Widening the *routine*
clamp to compensate would reopen the manipulation vector. The resolution is not a wider clamp but a
**second tier that unlocks only for a corroborated shock**:

- **Routine tier (default).** ±5%/quarter, unchanged. Governs all normal movement and every
  single-feed anomaly.
- **Emergency tier (gated).** A wider slew `EMERGENCY_SLEW_BP` (strawman ±25%/quarter) unlocks for a
  region **only** while a pure-integer, recomputable predicate holds: **multiple independent basket
  components breach an emergency threshold together for ≥ `CORROBORATION_EPOCHS` consecutive epochs**
  — e.g. residential electricity ∧ local CPI ∧ the P2P stablecoin premium (§29) all exceeding
  `EMERGENCY_DEVIATION_PPM` in the same direction. Cross-feed corroboration is the anti-manipulation
  core: a single captured or noisy feed **cannot** unlock the tier (that is what the routine clamp is
  for), because independent components rarely move together *except* in a real macro event — and
  forging correlated movement across electricity, CPI, and the off-ramp rate simultaneously is far
  harder than nudging one feed.
- **Global cross-check.** The unlock is additionally confirmed against the *global-median* and
  neighbouring-region series (§31.2): a breach isolated to one region with no corroboration in its
  economic neighbourhood is treated as suspect and stays routine, guarding against a region-local
  feed-capture masquerading as a shock.
- **Bounded and self-re-locking.** Even unlocked, movement is *clamped* (to the emergency slew, not
  unbounded), still challengeable in the 7-day window (§34), and the tier **re-locks automatically**
  the moment corroboration lapses — so the emergency path cannot become a standing loophole. The
  unlock predicate, the slew, and the re-lock are all recomputable from published feeds, so an
  emergency-tier posting is fraud-provable exactly like a routine one (§22, B-2): the valve widens
  *what the honest value may be*, never *who may assert it*.

`EMERGENCY_SLEW_BP`, `EMERGENCY_DEVIATION_PPM`, `CORROBORATION_EPOCHS`, and the corroborating-feed
set are **[calibration]** (F5-adjacent macro-data grounding). This promotes R-C3 from a recorded
design intent to a specified mechanism; the deliberate limitation is stated openly — routine tracking
prioritises anti-manipulation over shock-chasing, and extreme moves are handled by this bounded,
corroboration-gated path, never by loosening the routine clamp.

<!-- PATCH 14 (Pass 12): dynamic macro-coherence for the R-C3 emergency valve (advisory
     GOAT-ARCH-RECON-02, registered R-C15). The Patch-12 valve requires a CONJUNCTION of independent
     feeds breaching together — which a state actor defeats by freezing one feed. A government
     tariff-freeze pins residential electricity artificially flat during hyperinflation, so the
     electricity∧CPI∧premium conjunction never completes and the valve stays shut exactly when the
     region needs it. Fix: detect a feed that has DECOUPLED from the basket (electricity vs CPI
     divergence > threshold, sustained) as state-manipulated, and drop it from the conjunction — but
     floor the surviving corroboration set so the valve cannot be opened by dropping feeds until one
     remains. -->

**Dynamic macro-coherence — a frozen feed must not jam the valve (R-C15, Pass 12).** The
corroboration conjunction of the previous mechanism has a state-actor blind spot. Its
anti-manipulation strength — *independent feeds rarely move together except in a real shock* — becomes
a weakness when an actor can hold one feed *still*: a **government tariff-freeze** pins residential
electricity (an `is_opex` infrastructure feed) artificially flat precisely during a hyperinflation,
so electricity never breaches `EMERGENCY_DEVIATION_PPM`, the conjunction never completes, and the
valve stays **shut** in the exact scenario it exists for — households underpaid while local prices
run away (§1). The freeze is not noise to be smoothed; it is *signal*: a policy-suppressed feed has
**decoupled from the real economy**, and that decoupling is itself recomputably detectable.

- **Decoupling detector (pure-integer, recomputable).** An infrastructure feed is flagged
  `state_suppressed` for a region when its trailing movement diverges from the region's cost-of-living
  anchor (local CPI, §29) by more than `MACRO_DECOUPLING_PPM` (strawman **400_000**) for
  `≥ DECOUPLING_EPOCHS` consecutive epochs (strawman **2 quarters**) — reusing the §30.1
  `symmetric_deviation_ppm` primitive between the feed's index level and the CPI index level. A feed
  held flat while CPI multiplies is the textbook signature; so is a feed forced to move while CPI
  does not. The flag is a function of anchored feed history only — every observer computes it
  identically (§3.8).
- **A suppressed feed is dropped from the conjunction, not from the basket.** While
  `state_suppressed` holds, the feed is **removed from the emergency-corroboration requirement**, so
  the valve can complete on the *remaining* independent feeds (CPI ∧ stablecoin premium) that the
  actor did not freeze. The feed continues to contribute to the routine CPPI at its clamped value —
  suppression changes only whether it can *veto the emergency tier*, never its ordinary weight
  (dropping it from the basket would hand the actor the opposite win: erasing a real cost signal).
- **The anti-manipulation floor — dropping cannot itself open the valve.** Because removing feeds
  *loosens* the unlock, the conjunction carries a hard floor: **at least `MIN_CORROBORATING_FEEDS`
  independent feeds (strawman 2) must remain and breach together**; the emergency tier can never be
  unlocked once suppression has pruned the set below the floor. So an actor cannot *manufacture* an
  emergency unlock by getting feeds flagged — flagging only ever *removes* a feed's veto, and the
  surviving feeds must still independently corroborate a genuine shock. The global cross-check (§31.2
  neighbourhood median) still applies to the survivors.
- **Self-relocking, fraud-provable.** `state_suppressed` clears the moment the feed re-couples to CPI
  within the band, and the whole predicate (flag, drop, floor, unlock, slew, re-lock) is a
  pure-integer function of published feeds — an emergency posting under a pruned conjunction is
  fraud-provable exactly like any other (§22, B-2). The valve still widens *what the honest value may
  be*, never *who may assert it*.

`MACRO_DECOUPLING_PPM`, `DECOUPLING_EPOCHS`, and `MIN_CORROBORATING_FEEDS` are **[calibration]**
(F5-adjacent macro data). R-C15 hardens R-C3 against single-feed state suppression without widening
the routine clamp or lowering the corroboration floor below two independent survivors.

### 31.2 Regional onboarding — the zero-history bootstrapping protocol **[design]** / **[calibration]**

**The problem.** A newly activated sovereign region has *no history* for its CPI or electricity
vectors, so `base_ref = 0` and `index_level` is undefined — the Meta-Index Controller cannot compute a
CPPI multiplier for it. A region cannot be blind on day one, nor can it be a free-for-all an oracle
poster games while unmapped.

**The state machine.** A region moves through three deterministic states:

| State | Baseline source | Reweighting | Clamp | Exit condition |
|---|---|---|---|---|
| `Unmapped` | none | — | — | onboarding transaction posts an anchor selection |
| `Provisional` | **proxy baseline** (below) | **disabled** (weights pinned to `base_weights`) | **tighter** (strawman ±2.5%/qtr) | `local_quarters ≥ PROVISIONAL_MIN_QUARTERS` |
| `Active` | region's own finalized medians | enabled (§30) | normal ±5%/qtr | — |

**Establishing the provisional proxy baseline (deterministic).** At onboarding, `base_ref` is set from
a proxy chosen by a *fixed, recomputable rule* — never a poster's choice.

<!-- PATCH 4 (Pass 6): neighbor-region parity divergence (R-C7). The original rule anchored to THE
     single nearest Active region, and the provisional clamp was referenced to the prior finalized
     value. Geographic adjacency does not imply purchasing-power parity, and the prior-referenced
     clamp mechanically fought the proxy→local ramp, locking any initial proxy error in for the
     whole provisional phase. Three deterministic fixes: k-nearest-MEDIAN proxy, a per-component
     parity-dispersion gate, and a ramp-referenced provisional clamp (below). -->

**The parity-divergence hazard (R-C7).** The first draft of this rule anchored to *the* single
nearest `Active` region. That is fragile in exactly the dimension the CPPI exists to correct:
**geographic adjacency does not imply purchasing-power parity.** Adjacent sovereign regions routinely
diverge by large factors on precisely the basket's components — electricity across a subsidy border,
the P2P stablecoin premium across a capital-control border, wages across a development gradient.
Because `index_level = value·PPM/base_ref` (§29), a divergent single-neighbor baseline propagates
*multiplicatively* into the provisional CPPI: a too-high proxy under-pays the new region for its
entire provisional phase (an **accessibility** failure, §1 — onboarding collapses in exactly the
regions localization exists to serve), and a too-low proxy over-pays it (a **thin-pool** exposure,
§2). The anchor rule is therefore hardened in two ways, and the provisional clamp in a third (below):

1. **k-nearest-median proxy (preferred).** The proxy for each component is the **median of the k
   nearest already-`Active` regions'** finalized baselines (strawman `k = 3`), per the deterministic,
   on-chain **region-adjacency/proximity table** (geographic + economic proximity, fixed at genesis
   and itself mutation-gated, §35). Median-of-neighbors is the same capture-resistant population
   statistic the protocol uses everywhere else (§7 class registration, §32 reporter medians): no
   single divergent — or single captured — neighbor can set the new region's baseline. When fewer
   than `k` `Active` neighbors exist, the comparison set is **padded to size k with the global
   anchor** — the single rule that degrades gracefully all the way to network genesis (the cascade
   note below this list).
2. **Per-component parity-dispersion gate.** Before a neighbor median is adopted for a component, the
   neighborhood must *demonstrate* parity rather than have it presumed: compute
   `disp = max_i symmetric_deviation_ppm(b_i, median(b))` over the (padded) comparison set — reusing
   the finalized R-C2 primitive (§30.1) unchanged. If `disp > NEIGHBOR_PARITY_MAX_PPM` (strawman
   `300_000` ≈ ±30%), the neighbors disagree *with each other*, proximity carries no parity
   information for that component, and that component falls back to the global anchor. The gate is
   evaluated **per component**: neighbors that agree on broadband but diverge on electricity yield a
   mixed proxy vector, each component on its best-supported anchor. Pure-integer and recomputable —
   a proxy posted against the gate's verdict is fraud-provable like any other wrong posting (§34).
3. **Global anchor (fallback of last resort).** The **global median** of the component across all
   `Active` regions — a Big-Mac-Index-style global PPP anchor — at the onboarding epoch, **provided
   `|Active| ≥ G_MIN`** (strawman 3); below that floor, the **Genesis Basket** (cascade note below).
   The global anchor is also the destination for any component that fails the parity-dispersion gate.

<!-- PATCH 6 (Pass 7): the k-nearest GENESIS problem (R-C7 completion). The Pass-6 rule left two
     degenerate cases undefined: fewer than k Active neighbors (a median of one re-introduces the
     single-neighbor fragility, and the dispersion gate passes vacuously), and ZERO Active regions
     anywhere (the "global median" itself is undefined — the fallback chain bottomed out at genesis
     and the first region could never onboard). One padding rule + one disclosed genesis constant
     close both. -->

**Genesis degradation — the cascade never bottoms out undefined (R-C7 completion, Pass 7).** The
rule above, as first drafted in Pass 6, left two degenerate cases undefined. With `n < k` `Active`
neighbors, "use those that exist" quietly re-introduced the fragility R-C7 was fixing — a median of
one *is* the single-neighbor anchor — and made the dispersion gate vacuous (one value has zero
dispersion; the gate passes without demonstrating anything). And at network genesis, with **zero**
`Active` regions anywhere, the "global median" was itself undefined: the fallback chain bottomed out
with no value at all, so the *first* region could never onboard. Two constructions close both cases
without adding a code path:

- **The padded comparison set.** For an onboarding region with `n ≤ k` `Active` neighbors, the
  comparison set is `B = { the n nearest Active baselines } ∪ { (k − n) copies of the global anchor
  g }` — always exactly `k` values. `median(B)` reduces *exactly* to the Pass-6 rule at `n = k` and
  leans progressively toward `g` as `n` falls: a sparse neighborhood is automatically conservative
  rather than automatically trusted. The parity-dispersion gate runs over `B` unchanged and is never
  vacuous (`|B| = k` always) — with a thin neighborhood the set is already `g`-heavy, so a single
  outlier neighbor is *detected against the global prior* instead of silently adopted.
- **The global-anchor floor and the Genesis Basket.** `g` is the global median only while it is
  actually global: `|Active| ≥ G_MIN` (strawman 3). Below the floor — including the empty network at
  genesis — `g` is the **Genesis Basket**: a constitution-fixed, fully disclosed per-component
  baseline vector, set from published pre-launch reference data (F5-adjacent grounding) and anchored
  in the genesis block alongside the base weights and the adjacency table. This is honest about its
  epistemic status: at genesis there is no measured data, so the anchor is a **named genesis
  constant** (§35.2) — an auditable input, not a lever — and a one-region "global median" would not
  be global at all (it would be that region, arbitrarily unrepresentative; the disclosed prior is
  the safer anchor).

The first onboarding regions therefore run `Provisional` against the Genesis Basket, and any
genesis-prior error washes out by the *same* machinery that removes proxy error everywhere else: the
region's own finalized medians accrue, the deterministic ramp carries `base_ref` toward them, and
the ramp-referenced clamp (part 3 above) lets that correction through. Nothing about genesis is a
special code path — the full cascade (`n = k` → `n < k` → `n = 0`, `|Active| ≥ G_MIN` → below) is
one deterministic function of on-chain state (`Active`-set membership, the genesis-fixed adjacency
table, the genesis-fixed basket), so anchor selection remains rule-fixed, poster-discretion-free,
and fraud-provable at **every network age**.

The chosen anchor values are pinned to the **onboarding-epoch beacon** (like the R-MAT4 probation-start
salt, §21.1.1), so they are *fixed, recomputable* values for the whole provisional phase.
Onboarding-*timing* games are bounded, not merely hoped away: every neighbor baseline itself moves
under the ±5%/quarter clamp (§34), so waiting for a favorable snapshot buys at most a few percent —
and against a median-of-k anchor, a majority of the neighborhood would have to be simultaneously
favorable.

**Scaling out of provisional (the progressive window does the work).** As the region accrues its own
finalized medians, the baseline transitions proxy → local by a deterministic integer ramp, and the
R-C2 progressive fold (§30.2) means the region's own volatility buffering comes online from its **2nd**
local quarter — no full-window wait:

```
base_ref(t) = ( proxy_base · (RAMP − p) + local_base · p ) / RAMP        // p = min(local_quarters, RAMP)
```

At `local_quarters ≥ PROVISIONAL_MIN_QUARTERS` (strawman = `RAMP`, ~4–8 quarters) the proxy term is
zero and the region enters `Active`.

**The provisional clamp is ramp-referenced — the clamp must not fight the ramp (R-C7, part 3).** A
subtlety the first draft missed: raw feed medians (µUSD/kWh, tariffs) do not depend on `base_ref`,
but **index levels do** (§29) — so as the ramp moves `base_ref(t)` from proxy toward local, the
*output multiplier* moves mechanically even with unchanged raw inputs. If the provisional clamp were
referenced to the **prior finalized multiplier**, it would cap exactly that mechanical correction: a
large initial parity error wanting ~10%/quarter of convergence against a ±2.5%/quarter clamp could
never converge inside the provisional window, and the region would exit `Provisional` still carrying
most of the error — the clamp holding in place the very mispricing the ramp exists to remove. During
`Provisional` the output-multiplier clamp is therefore referenced to the **ramp-predicted
multiplier**: the prior quarter's finalized raw component medians re-evaluated against this quarter's
ramped `base_ref(t)`. Both inputs are on-chain/DA-published, so the predicted value is itself
recomputable by any challenger; the ±2.5%/quarter provisional clamp then bounds only the *posted
deviation from the deterministic trajectory* — genuine market movement — while the mechanical
proxy→local correction passes through unimpeded, whatever its size. The anti-manipulation property is
preserved exactly (a poster still cannot move the target more than ±2.5%/quarter *relative to what
the recomputable trajectory dictates*), and the initial parity error is fully removed by the end of
the ramp. Per-feed raw-median clamps are unaffected (raw values never reference `base_ref`).

**Anti-gaming the unmapped/provisional epochs.** The danger is a poster exploiting sparse early data.
Five properties close it, all recomputable:

- **The proxy baseline is itself on-chain and recomputable** (a pinned neighbor/global value), so the
  provisional CPPI is **fraud-provable exactly like a mature one** — a poster cannot invent a baseline;
  a wrong provisional post is slashable under the same directional-fraud loop (§34, §22).
- **Anchor selection is rule-fixed, not poster-chosen** (median of the k nearest `Active` regions,
  parity-dispersion-gated per component, else the global median) — no discretion to game, and no
  single neighbor to lean on (R-C7).
- **Beacon-pinned anchor** (onboarding-epoch beacon) — the poster could not pre-position for a value it
  could not predict or grind (§19).
- **Reweighting disabled + tighter clamp during `Provisional`** — no volatility-driven reweight on
  sparse data, and any residual error moves the target ≤ ±2.5%/quarter.
- **Full oracle stack applies from epoch 0** — multi-reporter median, the 7-day challenge window
  (§34), and the Validator-Quorum DA attestation (§19.3) are all live immediately.

`PROVISIONAL_MIN_QUARTERS`, `RAMP`, the provisional clamp width, the adjacency table, `k`,
`NEIGHBOR_PARITY_MAX_PPM`, `G_MIN`, and the Genesis Basket vectors are **[calibration]** items
(F5-adjacent; the basket is additionally a disclosed genesis constant, §35.2).

## 32. Off-chain manifest index & state minimization **[design]**

Per-region, per-feed reporter submissions are heavy and must never hit the ledger. The ledger anchors
only **32-byte roots + finalized scalars**; raw leaves and historical series live off-chain,
content-addressed, fetched by CID for recomputation — the same posture as the shipped receipt path
(§22).

```rust
pub struct FeedManifest {          // ~200 B, INDEPENDENT of reporter count
    pub feed_id: u16, pub region_id: u32, pub epoch: Epoch,
    pub submissions_root: [u8; 32], // Merkle root over sorted reporter leaves
    pub submissions_cid: [u8; 32],  // content address of the canonical leaf blob (off-chain)
    pub n_leaves: u32,
    pub posted_median: u64, pub prior_accepted: u64, pub proposed: u64, // clamp_move(prior, median)
}

pub struct OracleWindowPosting {   // the per-region-epoch anchored posting (~2 KB total, 8 feeds)
    pub epoch: Epoch, pub region_id: u32,
    pub feeds: Vec<FeedManifest>,           // fixed cardinality (1 CMI + 6 CPPI + regional adj.)
    pub cppi_multiplier_ppm: Ppm,
    pub localized_target_ugcu_h: MicroUsd,
    pub history_root: [u8; 32], pub history_cid: [u8; 32], // trailing series for the co-movement gate
    pub challenge_deadline: Epoch,          // set when the DA QuorumCertificate anchors (§19.3)
    pub poster: String, pub poster_sig: Vec<u8>, pub finalized: bool,
}
```

**State bound:** on-chain footprint per region-epoch is **O(1)** — ~2 KB regardless of whether 10 or
10⁴ reporters contributed. A challenger fetches leaves by CID, verifies they hash to
`submissions_root`, recomputes `median` + `clamp_move`, and — on mismatch — posts a fraud proof. Data
availability is guaranteed by the Validator-Quorum DA attestation (§19.3): the challenge window does
not even start until a ≥ 2/3 quorum certifies the leaves are fetchable, defeating withhold-to-run-out
(R-C1).

### 32.1 Registry sunsetting — bounded class-lifecycle state (R-C9) **[design]**

<!-- PATCH 7 (Pass 7): device-class registry state bloat (R-C9). Permissionless class entry (§3.6,
     §7) had no exit: every class ever registered held live ledger state (registry entry,
     accumulator, HLL sketches) forever. The sunset is a ledger-MECHANICAL DORMANT→ARCHIVED
     lifecycle keyed on verified-work volume — device-agnostic, recomputable by construction, and
     O(1) total archival footprint via a single archive-tree root. -->

**The hazard.** Permissionless entry (§3.6) is deliberately one-way-open: anyone may register a
class (§7), and nothing may gatekeep entry. But the document as of Pass 6 specified no *exit*: every
class ever registered — abandoned experiments, superseded hardware generations, stillborn
registrations — held a live registry entry, a live `ClassAccumulator`, and live HLL sketches (§21.1)
forever. Over a decade of permissionless hardware evolution that is unbounded ledger growth, cutting
directly against the state-minimization posture that governs everything else on the ledger (§22,
§32). It is also an **accessibility** cost: modest challengers must hold the live class set to
recompute (§3.8, S1), so an unbounded set narrows who can verify.

**The lifecycle extension.** Two terminal-side stages extend the §21.1 state machine, entered and
exited **mechanically by the ledger** at window boundaries. Like `decay_cap` (§33), these
transitions are pure functions of *already-anchored* state — the per-window accumulator roots the
ledger holds (§22) — so nothing is posted, no one is trusted, and there is no fraud vector to
adjudicate: every observer derives the identical lifecycle state from the identical public inputs.

| Stage | Entered when (recomputable predicate) | Live state | Exit |
|---|---|---|---|
| `DORMANT` | `V_c == 0` for `DORMANT_AFTER_WINDOWS` consecutive windows (strawman 6 ≈ 180 days) | unchanged — stage and `p_class` preserved; deliberately inert | **one verified receipt** folds → the class returns to its prior stage; the counter resets |
| `ARCHIVED` | `DORMANT`, then `V_c == 0` for `ARCHIVE_AFTER_WINDOWS` further windows (strawman 12 ≈ 360 more days) | **deleted** — replaced by a 32-byte tombstone leaf | none — terminal (re-entry below) |

The design decisions, each pinned to the invariant that forces it:

- **Inactivity is measured as verified-work volume — never wall-clock age, never device identity.**
  The predicate reads `V_c` per anchored window root, data the ledger already holds (§21.1, §22):
  sunsetting adds **no new measurement, no new trust surface, and no device-type knowledge** (§3.5 —
  an opaque `class_id` with zero folded receipts is all the ledger ever sees).
- **Dormancy is not a breach — churn ≠ fault, extended to classes.** Entering `DORMANT` never
  ratchets `p_class` (§21.3): inactivity produces *no* receipts, not *faulty* ones, so a seasonal or
  intermittent class — exactly the accessible hardware of §1 — cycles in and out of `DORMANT`
  without penalty, resuming at its earned stage. Post-dormancy divergence needs no special
  machinery: the gate and burst snap (§21.1–§21.2) exist precisely to catch measured wrongness the
  moment work resumes, and node-level fingerprint drift already triggers re-benchmark (§12, A-5).
- **Archival is a tombstone, not an erasure.** The class's final state — registry record, final
  accumulator root, stage, archive epoch — folds into one leaf,
  `H(class_id ‖ final_accumulator_root ‖ final_stage ‖ archive_epoch)`, appended to a single
  ledger-anchored **archive tree**; the raw final state is published off-chain, content-addressed
  (the §22/§32 posture). On-chain, the network's *entire archival history* is **one 32-byte root**:
  per-class live state goes to zero and total archival state is O(1). History stays verifiable
  forever — any observer proves any past class's final state against the root — it just stops being
  *live*.
- **Re-entry is re-registration, never resurrection.** An archived `class_id` is permanently
  retired; its tombstone is the terminal record. The hardware population behind it re-enters through
  the ordinary permissionless path (§7): fresh registration, fresh accumulator chain, `PROBATION` at
  100% sampling. This is deliberate, not incidental: after a dormancy measured in years, a class's
  determinism profile and earned trust are *stale* (drivers, firmware, and populations drift), and
  the asymmetric-ratchet philosophy (§21.1) prices stale trust at zero — trust is re-demonstrated,
  not restored from cold storage. Permissionless entry (§3.6) is fully preserved; only *state
  resurrection* is excluded. (Registry strings are conventionally versioned — `"cls.a.v2"` succeeds
  an archived `"cls.a.v1"` — but that is operator convention; the protocol never interprets the
  string, §3.5.) Re-registration also grants no fresh pioneer advantage: the pioneer multiplier
  (§7.1) is paid to *nodes* through the full anti-capture stack, and the returning population is
  still the same F6-merged operator cluster (§14–§15) it was before.
- **The sunset is also the registration-spam backstop.** The dual hazard of permissionless entry is
  an adversary minting junk classes to bloat state at the *front* door. Registration already
  requires a genuinely distributed population (median-of-many independent, cluster-merged operators
  — §7, §14); the sunset adds the missing half: every registered class must *keep earning its
  state*. A junk class pays 100% `PROBATION` redundancy while alive (§7) and self-deletes to a
  32-byte leaf on the same clock as any other quiet class — and idle *declarations* cannot keep it
  alive, because dormancy keys on **verified** volume only (§3.4). State occupancy is priced in
  exactly the currency the network wants.
- **No forced-archival vector.** An adversary cannot sunset a competitor class it does not control:
  archival requires ~18 months of *zero verified receipts network-wide* for that class, any single
  verified receipt resets the clock, and the κ assignment floor (§23) guarantees qualifying small
  nodes keep receiving work. Suppressing every node of a living class for that long, network-wide,
  is not cheaper than the capture strategies already priced out in Part VI.

`DORMANT_AFTER_WINDOWS` and `ARCHIVE_AFTER_WINDOWS` are **[calibration]** — long enough that
seasonal usage and regional connectivity patterns never archive a living class (an accessibility
constraint, §1), short enough that dead state does not linger for a hardware generation.

<!-- PATCH 8 (Pass 8): the resurrection exhaustion vector (R-C10). Pass 7 bounded the STATE cost of
     junk registrations (the R-C9 sunset) but left REPETITION unpriced: a cohort could cycle
     register → idle → archive → re-register at no escalating cost, each turn drawing 100%
     PROBATION redundancy for workloads that will never earn trust. Three mechanical prices close
     it: a crowd-posted registration bond (refunded at RELAX, burned at archival-before-RELAX), a
     per-cluster re-registration escalator recomputable from the archive tree, and a hard
     network-wide PROBATION verification budget. Entry remains permissionless — priced and paced,
     never approved. -->

**Resurrection exhaustion & the registration bond (R-C10, Pass 8).** The analysis above bounded
what a junk registration can *hold* (live state → a 32-byte tombstone) but not how often the cycle
can *repeat*: register → minimal activity → archive → fresh registration carried no escalating
cost, and every turn of the wheel obliges the network to run 100% `PROBATION` redundancy (§7,
§21.1) on workloads that will never earn the trust that would retire the overhead. The grief scales
with the work the cohort actually performs — which costs it real compute for cluster-merged,
S_o-capped rewards (§14–§15, §23) — but the *repetition itself* was free. Three mechanical prices
close the vector. None introduces approval, discretion, or a gatekeeper: §3.6 is unamendable, so
entry is **priced and paced, never approved** — the same posture under which bonds elsewhere never
gate posting (§19.3, §35.1):

- **The registration bond — refunded at trust, burned at abandonment.** A class registration posts
  a bond, **crowd-posted** across the founding submissions (registration is already a collective,
  median-of-many act, §7, so the per-operator share stays small — an accessibility property, §1).
  The bond is **refunded in full the first time the class reaches `RELAX`** (the earliest
  earned-trust milestone, §21.1) and **burned** — a non-attributable sink, §33.1 — **if the class
  is `ARCHIVED` without ever having reached `RELAX`**. One derived bit per live class
  (`ever_reached_relax`, folded into the tombstone) makes the outcome ledger-mechanical, like the
  sunset itself. This is the B-2 directional pattern applied to registration: an honest founding
  cohort's expected cost is ≈ 0 — it recovers the bond on the road it was already taking — while a
  junk cycle forfeits the full bond every turn.
<!-- PATCH 8 REFINEMENT (Pass 9): Sybil-dilution of the crowd-posted bond. Keying the escalator
     ONLY on per-cluster history left a rotation loophole: freshly minted clusters always carry
     r = 0, so a griefer could co-sign every junk registration with new Sybil clusters and never
     meet the exponential penalty. The escalator's target moves from the UNLINKABLE (identity) to
     the UNFAKEABLE: newcomer pricing on clusters without verified-work seniority, a network
     burn-rate term (2^r_net) on newcomer shares, and clustering-merge back-propagation of
     history. Refund-on-RELAX keeps all of it lockup-only for honest fresh cohorts. -->

- **The re-registration escalator — priced on what rotation cannot refresh (hardened, Pass 9).**
  The first draft priced a founding *cluster's* share at `base_share × 2^{r_c}`, with `r_c` its own
  archived-without-`RELAX` count — per-cluster deliberately, to deny a poison-pill against honest
  founders. Per-cluster keying alone, however, is **rotation-soluble**: a freshly minted cluster
  always carries `r = 0`, so a griefer could co-sign every junk registration with new Sybil
  clusters and never meet the exponent. The hardened rule prices the two things rotation cannot
  refresh — *demonstrated work history* and the *network-wide consequences of the campaign itself*.
  Each founding cluster `c`, posting fraction `f_c` of the base bond (`Σ f_c = 1`), pays
  `share_c = base_bond × f_c × mult_c`, where:

  | Cluster standing | `mult_c` | Rationale |
  |---|---|---|
  | **Seasoned** — verified-work volume ≥ `SENIORITY_MIN` over a trailing window | `2^{r_c}` | genuine history exists, so its own record is the fair price; per-cluster keying still denies the poison-pill |
  | **Newcomer** — below `SENIORITY_MIN` | `NEWCOMER_MULT × 2^{r_net}` | no history to price, so freshness itself is priced — and priced *harder while a burn campaign is running* |

  - **Seniority is verified work, not wall-clock.** A cluster's standing is its accumulated
    *verified* volume (receipts, F6-merged upstream — §14, §21.1): device-agnostic, already
    anchored, and not fakeable by parking idle identities — pre-aging a cluster means doing real
    verified work at cluster-merged, S_o-capped rewards, which *is* honest participation.
  - **`r_net` — the network burn-rate term.** `r_net` counts network-wide
    archived-without-`RELAX` events above a disclosed baseline rate within the trailing
    `ESCALATOR_WINDOW` — congestion pricing on junk burn. Identities rotate; **the burn record the
    campaign itself creates does not**. A sustained rotation campaign therefore prices itself
    exponentially out of its own strategy, with no per-identity linkage needed. Both `r_c` and
    `r_net` remain **derived state** (App. A, contract 6): registration records bind founding
    clusters, tombstones bind the never-`RELAX` bit and archive epoch, all anchored — anyone
    recomputes both with no new live state.
  - **Clustering-merge back-propagation.** "Fresh" is a judgment of the *current* clustering
    assignment, and §15's signals — deployment-cohort signatures (fingerprint homogeneity ×
    geographic burst × client-build uniformity) and payout-flow convergence — are precisely what
    later merges a minted founding cohort into its true operator cluster. Because `r_c` and
    seniority are recomputed under the clustering assignment current at each *new* registration,
    history follows the merge automatically: no retroactive debt on bonds already posted, but the
    next cycle is priced with the merged record. Outrunning this indefinitely requires fresh
    *physical* topology every cycle — exactly the F5-priced cost the anti-Sybil layer already
    stands on (§14).
  - **Honest parties stay whole.** Refund-on-`RELAX` applies to every share, so newcomer pricing
    and even an elevated `r_net` are **lockup-only** for an honest fresh cohort whose class earns
    trust — the burn lands solely on cohorts whose classes never do. A seasoned cluster co-signing
    someone else's registration is a *voucher with skin in the game*: if the class archives
    pre-`RELAX` it loses its share and increments its own `r_c`. And a rich adversary cannot
    usefully grief honest newcomers by inflating `r_net`: driving the burn rate up requires
    burning `base_bond × NEWCOMER_MULT × 2^{r_net}` per event — a self-escalating, exponentially
    unsustainable spend — while its honest victims lose only lockup and can wait out the window.
  - (Record *laundering* — abandoning a degraded but once-trusted class for a fresh identity —
    remains the pre-existing R-MAT3 surface, §14, §26; the bond and full re-`PROBATION` price it,
    and the escalator deliberately does not count classes that legitimately earned `RELAX`.)
- **The PROBATION verification budget.** Independently of anything an adversary spends, the
  network's exposure is bounded structurally: aggregate `PROBATION`-class redundancy may consume at
  most `PROBATION_BUDGET_BP` of per-window verification capacity (strawman 1_000 bp = 10% — the
  §7.1 bounded-line-item pattern). Within the budget, sampling allocation is pro-rata to each young
  class's **distinct-cluster coverage** (the HLL estimate the accumulator already maintains, §21.1
  — device-agnostic and F6-hardened, §14): genuinely diverse cohorts bootstrap fastest; thin,
  Sybil-founded registrations queue behind them. Over-budget demand is **paced, never rejected** —
  a queued class matures later, but entry is never denied, so §3.6 holds to the letter.

Net effect: a junk cycle now costs a burned bond every turn — escalated by the cluster's own record
if it keeps an identity, by `NEWCOMER_MULT × 2^{r_net}` if it rotates, and by fresh physical
topology if it tries to outrun the clustering layer — plus real compute at 100% redundancy for
capped rewards, while the grief it can inflict stays capped at a disclosed budget line. An honest
cohort, fresh or seasoned, pays ≈ nothing net and bootstraps fastest precisely by being what the
network wants: genuinely distributed. `base_bond`, `ESCALATOR_WINDOW`, `SENIORITY_MIN`,
`NEWCOMER_MULT`, the `r_net` baseline rate, and `PROBATION_BUDGET_BP` are **[calibration]**
(F5-adjacent economic tuning).

## 33. The Emission Allocation Controller — deterministic gap-fill **[design]**

Emissions exist only to bridge the gap between organic usage revenue and the CET floor, per effective
unit of work, under a hard **decaying** cap so emissions disinflate and hand off to usage:

$$M_E = \text{clamp}\big(N_{eff} \cdot (\text{CET}_{gross} - u_{ref}),\; 0,\; M_{cap}(t)\big)$$

```rust
pub struct EmissionController {
    pub epoch: Epoch, pub reserve_remaining: u64,
    pub m_cap_current: u64, pub m_cap_floor: u64, pub decay_ppm: Ppm, // hard disinflation schedule
}
impl EmissionController {
    pub fn decay_cap(&mut self) { // m_cap <- max(floor, m_cap · decay_ppm / PPM); monotone
        self.m_cap_current = ((self.m_cap_current as u128 * self.decay_ppm as u128 / PPM as u128) as u64)
            .max(self.m_cap_floor);
    }
}
/// Saturating throughout: non-negative, cap-bounded, reserve-bounded; no overflow, no panic.
pub fn compute_epoch_gap_fill(n_eff: u64, cet_gross: u64, u_ref: u64, m_cap: u64, reserve: u64) -> u64 {
    let gap_per_unit = cet_gross.saturating_sub(u_ref);              // 0 if usage already meets target
    let raw = (n_eff as u128).saturating_mul(gap_per_unit as u128);
    (raw.min(m_cap as u128) as u64).min(reserve)
}
```

| Term | Meaning | Anti-capture property |
|---|---|---|
| `N_eff` | **effective** work units, clustering/F6-discounted upstream (§14–15) | a Sybil cannot inflate the gap-fill — its identities are already merged |
| `CET_gross − u_ref` | the per-unit gap between target and realized usage revenue | when usage meets/exceeds target, the gap is 0 → **emissions vanish** (usage-funded); the excess above the target is routed by §33.1, never into the wage |
| `M_cap(t)` | monotone-decaying hard cap | no epoch, gap, or captured input can mint beyond the disinflation schedule |

`decay_ppm`, `m_cap_floor`, and the reserve schedule are **[calibration]** (F5).

### 33.1 The Surplus Routing Rule — the CET as a two-sided target (R-C8) **[design]**

<!-- PATCH 5 (Pass 6): organic surplus extraction (R-C8). §33 specified the shortfall direction
     (emissions bridge UP to the target) but was silent when usage revenue EXCEEDS the gross target.
     An unspecified surplus either drifts the wage above thin-pool (pass-through) or becomes a
     discretionary orchestrator margin (extraction). The surplus is now routed deterministically to
     non-attributable sinks — reserve-refill up to the genesis ceiling, burn the overflow — and
     u_ref is made a derived on-ledger quantity so it cannot be under-reported. -->

**The hazard.** `compute_epoch_gap_fill` fully specifies the *shortfall* regime: when
`u_ref < CET_gross`, emissions bridge the gap. It was silent about the opposite regime —
`u_ref > CET_gross`, organic usage revenue above the gross target. Left unspecified, the surplus
must go *somewhere*, and both defaults are failures:

- **Pass-through** (contributors keep it): the effective wage tracks demand spikes above the
  thin-pool target. Sustained high demand pushes per-unit revenue toward and past new-hardware
  payback, and the Thin-Pool Principle (§2) — the structural-loss guarantee every anti-capture
  argument in Part VI leans on — fails precisely when the network is most worth capturing. A
  one-sided target is not thin; it is thin-until-popular.
- **Discretionary capture** (the routing party keeps it): the surplus becomes an unaccounted
  orchestrator margin — an extraction and centralization vector (parties compete to route high-fee
  work and skim the residual) and a mis-reporting incentive (post `u_ref = CET_gross`, settle the
  rest off the books).

**The rule.** The CET becomes **two-sided**: emissions lift a shortfall *up* to the target (§33);
the Surplus Routing Rule skims the excess *down* to the target. Contributor settlement per effective
unit is `min(u_ref, CET_gross)` plus gap-fill — never more than the target, from either direction.
The per-epoch surplus is routed in the same saturating pure-integer discipline as everything else:

```rust
pub struct SurplusRouting { pub to_reserve: u64, pub burned: u64 }

/// Saturating throughout; both sinks are non-attributable. `reserve_ceiling` is the genesis
/// reserve schedule's current value: refill may RESTORE spent reserve, never grow it past the
/// disclosed cap. Contributor settlement per effective unit is min(u_ref, cet_gross) + gap-fill.
pub fn route_surplus(n_eff: u64, u_ref: u64, cet_gross: u64,
                     reserve_remaining: u64, reserve_ceiling: u64) -> SurplusRouting {
    let per_unit   = u_ref.saturating_sub(cet_gross);            // 0 in the shortfall regime (§33)
    let surplus    = (n_eff as u128).saturating_mul(per_unit as u128);
    let headroom   = reserve_ceiling.saturating_sub(reserve_remaining) as u128;
    let to_reserve = surplus.min(headroom);
    let burned     = (surplus - to_reserve).min(u64::MAX as u128); // exact: to_reserve ≤ surplus
    SurplusRouting { to_reserve: to_reserve as u64, burned: burned as u64 }
}
```

| Property | Why it holds |
|---|---|
| **Thin-pool binds in both regimes** | under-demand: emissions bounded by the decaying cap (§33); over-demand: the wage is capped at `CET_gross` and the excess leaves the wage channel — fresh capital faces the structural loss (§2) in every market condition |
| **Counter-cyclical, mint-free** | reserve-refill means high-demand epochs replenish the same reserve low-demand epochs draw down — extending the emission runway toward the usage-funded handoff *without minting*; bounded by `RESERVE_CEILING(t)` so the reserve is restored, never grown past its disclosed genesis cap |
| **Non-attributable sinks ⇒ wash-trade-proof** | no participant's payoff increases with the surplus it generates: a cohort self-dealing tasks at `u_ref > CET_gross` pays the full fee and receives back at most `CET_gross`/unit — the difference leaves its control (reserve/burn). Self-generated surplus is a strict loss |
| **Deterministic, no honeypot** | the split is a pure integer function of on-chain quantities; there is no allocator, no vote, and nothing discretionary to capture (§35) |

**`u_ref` is derived, never declared.** The mis-reporting vector is closed structurally, not
economically: consumer fees are **escrowed on-ledger at task acceptance** and released at verified
settlement, so per-epoch usage revenue is the recomputable sum of escrow releases over settled work.
`u_ref` is thereby *derived state* — like `σ_k` (§30) — and a posting that disagrees with the escrow
ledger is a fraud proof in either direction (§34). A pair that settles off-protocol has not
extracted the surplus; it has left the protocol — no escrow, no verification, no receipts, no GCU —
which is non-participation, not extraction (and the work forgoes everything the network sells:
verification, provenance, settlement assurance).

**What the ceiling does not do.** `CET_gross` is not a frozen number: it is `κ_thin ×` the live
commodity median (§28) and tracks a sustained demand move under the ±5%/quarter clamp (§34). The
rule removes only the *super-target residual per epoch*, never the market trend — so the ceiling
does not starve the pool of contributors in a hot market; it holds the idle pool at the thin-pool
fraction of that market. Capacity that wants spot-market upside has the designed path: the
(separately capped) service lanes (§24). The idle pool prices idleness; the lanes price the spot
market; the Surplus Routing Rule keeps the two from blurring exactly when demand would otherwise
blur them.

`RESERVE_CEILING(t)` (the refill schedule) — and whether a fixed fraction should bypass the reserve
and burn unconditionally — are **[calibration]** (F5-adjacent economic tuning).

### 33.2 The DA Fallback Rebate — closing the economic liveness trap (R-C20) **[design]**

<!-- PATCH 19 (Pass 13, advisory GOAT-ARCH-RECON-03, registered R-C20): the R-C18 economic liveness
     trap. §19.4 forces inline posting at an 8× fee during DaFallback to fund bloat and price out
     INDUCED fallback. But the same punitive fee, applied to an HONEST orchestrator during a GENUINE
     outage it did not cause, makes halting operations the rational choice — which itself stalls the
     settlement layer, the exact liveness failure §19.4 exists to prevent. The Emission Allocation
     Controller (§33) rebates the 7× premium from the gap-fill reserve, rendering the mode
     fee-NEUTRAL for honest operators while leaving the 8× charged at point-of-posting (anti-induction
     economics unchanged). The rebate is a protocol-imposed-cost offset, NOT surplus and NOT profit —
     so R-C8's non-attributable-sink rule is not violated. -->

**The hazard (R-C18 residual).** The `DaFallback` mode (§19.4) forces a region's orchestrator to post
manifest leaves **inline on-chain at an `8×` fee** during a sustained DA outage, so fraud-proof
liveness survives even when the external DA layer is dark. That 8× is deliberately punitive — it funds
the temporary on-chain bloat and prices out any cohort trying to *induce* the fallback. But the fee
does not distinguish the *inducer* from the *victim*: an **honest** orchestrator facing a genuine
outage it did not cause now confronts an 8× operating cost merely to keep settling. Its rational move
is to **halt** until DA recovers — and a halted orchestrator produces no postings, which is *precisely
the settlement stall* §19.4 was built to prevent. The anti-induction penalty, applied to the honest
majority case, becomes an anti-liveness incentive. This is an economic-liveness trap: the mechanism is
technically live but economically self-defeating.

**The rebate — neutral for the honest operator, unchanged for the inducer.** The Emission Allocation
Controller (§33) is authorized to **automatically rebate the punitive premium** — the
`(DA_FALLBACK_FEE_MULT − 1) = 7×` difference over the normal O(1)-anchor fee — from the gap-fill
emission reserve directly to the orchestrator's address, so an honest operator's *net* fallback cost is
`1×`, identical to normal mode. The 8× is still **charged at point-of-posting**, so every anti-induction
property of §19.4 holds at the moment a would-be inducer would pay it; the rebate is a *separate,
downstream, mechanically-gated* settlement that returns an honest operator — and only an honest operator
— to cost-neutrality:

```rust
/// Rebate = the punitive premium only (base fee is never rebated). Saturating, reserve-bounded,
/// paid ONLY for a fraud-surviving inline manifest in a recomputable DaFallback region-epoch.
/// DA_FALLBACK_FEE_MULT = 8  ⇒  premium multiple = 7.
pub fn da_fallback_rebate(base_fee: u64, reserve_remaining: u64) -> u64 {
    let premium = base_fee.saturating_mul(DA_FALLBACK_FEE_MULT.saturating_sub(1)); // 7 × base_fee
    premium.min(reserve_remaining)                                                 // reserve-bounded
}
```

Every property is pinned to an existing invariant:

- **Gated on the recomputable, un-inducible trigger.** The rebate is payable **only** in a region-epoch
  whose `DaFallback` state holds under the §19.4 predicate — no `QuorumCertificate` for
  `DA_FALLBACK_EPOCHS` — an outage an orchestrator **cannot manufacture**: withholding *validator*
  certificates is the validator set's action, and a withholding validator forfeits **100% of its bond**
  (§19.3). The party that is paid-and-rebated (the orchestrator) is structurally distinct from the party
  that could cause the outage (the validators), by the §19.3 role separation. Rebating the orchestrator
  therefore never rewards the outage's *cause*.
- **Paid only against real, fraud-surviving work.** The rebate attaches to a **validly posted inline
  manifest that survives its challenge window** (§34, B-2) — of which there is exactly **one per
  region-epoch**. A fraudulent inline posting is slashed and forfeits the rebate with its bond, so the
  rebate cannot be farmed by spamming postings; it reimburses genuine liveness-preserving work, once.
- **Bounded by the same disinflation budget as gap-fill.** The rebate draws from the `EmissionController`
  reserve under the identical saturating, reserve-bounded discipline as `compute_epoch_gap_fill` (§33)
  and cannot mint beyond `M_cap(t)`/reserve. It is an emission *allocation* competing inside the bounded,
  monotone-decaying budget — not a new mint. Total exposure is `7 × base_fee ×` (fallback region-epochs),
  itself bounded by the fallback being **rare, per-region, and auto-reverting** (§19.4).
- **Thin-pool untouched — a cost-offset, not a wage or a profit (and why R-C8 still holds).** The rebate
  reimburses a cost the *protocol itself imposed* (the 8× penalty), returning the orchestrator to
  neutrality; it never flows into the CET wage (§27–§28) or to contributors as reward, so the thin-pool
  arithmetic (§2) is unaffected. It may look like it contradicts the R-C8 **non-attributable-sink** rule
  (§33.1), which forbids routing value *to its generator* — but the two are precisely distinguished:
  R-C8 forbids returning **surplus** (revenue *above* target) to its generator because that would be
  *profit* and enable wash-trading. The rebate is **neither surplus nor profit**: it is capped at exactly
  the premium the operator already paid, gated on an outage it cannot induce, so the best an entity that
  *did* collude to induce fallback can achieve is `−(validator bond burn, §19.3) + (net-zero on the fee)`
  — a **strict net loss**. There is no positive-EV extraction to wash-trade; the rebate's ceiling is
  cost-neutrality, never gain.
- **Deterministic and fraud-provable.** `da_fallback_rebate` is a pure integer function of the anchored
  base fee, the constant multiplier, and the recomputable `DaFallback` state. Any observer recomputes it;
  an over-rebate, a rebate outside a genuine `DaFallback` region-epoch, or a rebate on a slashed posting
  is a fraud proof exactly like a mis-posted gap-fill (B-2, §22). The controller is *more* conservative
  by paying *less*, never more (the B-2 direction).

Net effect: during a genuine DA outage the honest orchestrator keeps settling at *normal* cost (the trap
is closed), while an operator that tries to *induce* the outage still pays the full 8× at posting **and**
forfeits validator bond for the withholding that caused it — the anti-induction economics of §19.4 are
fully preserved. The rebate multiple is definitionally `DA_FALLBACK_FEE_MULT − 1`; whether to rebate the
full premium or leave a small honest-cost haircut as a mild anti-abuse margin is **[calibration]**.

## 34. The 7-day challenge window & ±5% quarterly clamp **[design]**

Every oracle update is *proposed*, not final, and doubly bounded:

- **±5%/quarter clamp (`clamp_move`).** The finalized value moves at most ±5% vs. the prior accepted
  value (for a `Provisional` region's output multiplier, vs. the recomputable ramp-predicted value —
  §31.2) — the **flash-manipulation circuit breaker**. A captured feed, even a captured *quorum*, can
  perturb the localized target by at most 5%/quarter and is challengeable; a genuine sustained move is
  tracked over several quarters (the routine anti-manipulation vs. black-swan tension is R-C3,
  Part VIII).
- **7-day challenge window (recompute-or-slash).** Any party recomputes `median` + `clamp_move` from
  the DA-certified leaves and, on mismatch, posts a fraud proof that slashes the poster's bond and
  reverts to `prior_accepted` — the **identical directional-fraud pattern** as the maturity ledger
  (§22, B-2): the honest value is recomputable, so a wrong post is provable and an over-conservative
  post is never punished. Crucially (R-C1, §19.3) the window starts only when the DA `QuorumCertificate`
  anchors, so a withheld manifest cannot win by timeout.

Together, §32–§34 make the economic layer as trustless-by-recomputation as the mechanism layer: only
roots and bounds on-chain, every localized wage recomputable, every wrong post slashable, and the
whole thing device-agnostic and content-blind by construction (§3.3, §3.5).

---

# Part VIII — Governance, Risk & Roadmap

Parts I–VII specify a protocol deliberately hostile to discretion: every consequential value is
measured, recomputed, or clamped, and nothing fairness depends on is decided by anyone. Part VIII
consolidates what that leaves for governance (very little, by design), indexes every risk the design
record has raised against the section that now owns it, collects the open calibration dependencies
into one table, and records the road from the completed Testnet MVP to economic go-live.

## 35. The bounded algorithmic controller vs. the unamendable band

**Governance-minimization is itself the anti-capture design.** The project's governance model is not
a voting scheme bolted onto the protocol; it is the deliberate *absence* of levers. Every parameter
lives in one of exactly two lanes:

| Lane | Contents | Who can move it |
|---|---|---|
| **Unamendable invariants** (§3) | the Calibration Law, power-source neutrality, content neutrality (CP7), measured-work-only GCU, the device-agnosticism axiom, permissionless entry, the PQ floors, fraud-provable-by-recomputation — plus every constitution *band* in the row below | **No one.** No vote, no controller, no quorum. Enforced mechanically where possible: the Neutrality Auditor (§9) **[shipped]** and the compile-time layer boundary (§5) **[shipped]** make two of the invariants physically unviolatable rather than merely forbidden |
| **Constitution-band tunables** | parameter *values* inside disclosed bands: `κ_thin` (§28), `w_min`/`w_max`/`λ`/`boost_cap` (§30), `VOL_WINDOW_*` (§30.2), the clamp widths (§34, §31.2), the DA thresholds (§19.3), `k`/`NEIGHBOR_PARITY_MAX_PPM` (§31.2), `RESERVE_CEILING(t)` (§33.1), the F4/F6 thresholds (§14) | the **bounded algorithmic controller** — algorithmically, recomputably, challengeably. Never a vote. The κ ≥ 1% assignment floor (§23) sits in the *first* lane: it is a floor, not a tunable |

The composition is the point: a captured tunable is worth at most its band width; the band composes
with the ±5%/quarter output clamp (§34) and the challenge window, so the **maximum extractable value
of total parameter capture is small, disclosed, and temporary**. This is the governance expression of
the Thin-Pool Principle (§2): make capture not worth buying. It is also the answer to the one capture
vector the clustering layer cannot see — fiat-settled patronage (§15): a patron bloc that acquired
influence over every tunable would still find **no discretionary lever to point that influence at**.
The residual it *could* buy — a band-width, clamp-bounded, challengeable perturbation — is priced,
bounded, and reversible.

### 35.1 The bounded component-mutation state machine **[design]**

The one structural change the economic layer ever needs — replacing a dead or obsolete feed over a
decade of operation — runs as the mechanical lifecycle promised in §30, not as governance:

```
Propose (permissionless, bonded)
   └─▶ Probation — shadow mode, ≥ probation_quarters (strawman 2): ingested in parallel,
        accumulated alongside the historical utility curve, ZERO effect on the CET
        └─▶ Certify — three gates, all mechanical, all must pass
             └─▶ Activate — atomic swap at a quarter boundary; the first post under the
                  new feed is still ±5%-clamped (§34)
```

The three certification gates:

1. **Co-movement gate.** The candidate's shadow series must correlate with the realized utility
   curve at `correlation_ppm ≥ θ` (strawman `850_000`) — an **overflow-safe integer Pearson**
   (integer square roots taken *individually before* the variance product, so the computation cannot
   exceed `u128` under any market input; the same cast-before-multiply discipline as §30.1).
2. **Neutrality gate.** The candidate adapter's source must pass the `goat-neutrality` scan (§9): a
   feed that names a device type or inspects content can never bind, by construction. The shipped
   auditor is reused unchanged.
3. **Challenge gate.** Activation itself is subject to the 7-day window (§34): a challenger who shows
   the co-movement statistic was miscomputed from the published shadow series reverts the slot and
   slashes the proposer's bond.

No privileged actor exists anywhere in the loop. The worst an adversarial proposer achieves is a
bounded, challengeable, ≤ ±5%/quarter perturbation that costs it a bond — and a *silent/dead* feed
cannot exploit its own death: a starving history yields **zero** volatility boost (§30.2), and
liveness failure escalates to this state machine rather than into the weights.

### 35.2 The residual human surface — named, not hidden

Three objects remain human-made. The design posture is to name them as trust boundaries and track
them by ID, not to pretend construction dissolved them:

- **Genesis constants.** The constitution bands, base weights, and the region-adjacency/proximity
  table (§31.2) are set once at genesis, disclosed in full, and thereafter frozen or mutation-gated
  (§35.1). They are auditable inputs, not levers.
- **The Validator Set (§19.3)** is permissioned for the testnet. Its independence requirements
  (distinct operators/ASNs/regions, the same F6-topology logic as §14) are registry rules; moving it
  to permissionless registration is a Phase-2/3 **[design]** item sequenced with the real ledger
  (§38). Until then it is a stated ≥ 2/3-honest assumption, carried openly in §19.3.
- **Software supply** (client releases, CI). Bounded — not eliminated — by the mechanical merge
  gates (D.1 conformance + neutrality, §8–§9 **[shipped]**) and by the Spec-D maintenance-bounty
  design intended to sustain ≥ 2 competing implementation teams per critical backend. Whether the
  bounty economics actually sustain that competition is open item **A5** (§38).

## 36. Consolidated risk register

Every risk ID raised anywhere in the design record, its current disposition, and the section that now
owns it. Severity analysis and mitigation detail live in the owning section; this table is the index.
(IDs: R-CAP* capability/identity, R-MAT* maturity, R-VER*/R-CC* verification, R-C1…R-C20 the
settlement-era + operational register. F3 predates the ID scheme.)

**Closed / resolved:**

| ID | Risk | Disposition | Owner |
|---|---|---|---|
| F3 | ratchet parameters made faults +EV (p_floor 0.10, 5× slash) | **RESOLVED** — `P_FLOOR = 0.15`, slash 15–20×; fault-EV margin 2.25–3.0× verified **[shipped]** | §21.4 |
| R-CAP1 | reference signer was not post-quantum | **CLOSED** — real ML-DSA-65; the classical stand-in is gone **[shipped]** | §16 |
| R-CAP3 | beacon nonce supplied by context; on-chain beacon unbuilt | **CLOSED** — commit-reveal beacon + delay-sealed finalization **[shipped]**; production VDF gated by R-C4 | §19 |
| R-MAT1 | coverage counting must reproduce bit-identically | **CLOSED** — deterministic-serialization HLL **[shipped]** | §21.1 |
| R-MAT2 | a withheld anomaly-burst snap was undetectable | **CLOSED** — amendment B-6: accumulator-derived burst; `withheld_burst_snap` is provable fraud **[shipped]** | §21.2 |
| R-MAT2b | receipt stamps trusted from the orchestrator | **CLOSED (cryptographic chain)** — H1: `SignedReceipt`/`EscalationRecord`/`fold_verified_attributed` **[shipped]**; slashable provenance faults + real completion-time buckets are Phase-2 **[design]** | §18 |
| R-CC2 | conflating D6 conformance with runtime power trust | **RESOLVED** — normative Spec-D text (D-3) | §8 |
| R-C2 | integer volatility model unspecified (no integer log) | **CLOSED** — Symmetric Integer Deviation, finalized AR41 | §30.1 |

**Accepted with design:**

| ID | Risk | Disposition | Owner |
|---|---|---|---|
| R-CAP2 | F6 probe-observation trust boundary | **ACCEPTED** — the probe is ground truth; declarations only detect dishonesty (A-2); no trusted self-report exists | §14 |
| CP7 exposure | zero content/compliance logic is a structural choice | **ACCEPTED, participant-borne** — recorded as a constitutional consequence, not a gap | §3.3 |

**Quantified — watch items (Iteration-3 results, §26):**

| ID | Risk | Disposition | Owner |
|---|---|---|---|
| R-VER1 (+ R-CC1) | cross-class framing collusion | **QUANTIFIED** — net-profit framing needs > 50% of the ~20-candidate escalation pool (≥ 11 disjoint sites); C is beacon-lottery-chosen. F5 refines the per-site cost assumption | §20, §26 |
| R-VER2 | band-edge gaming toward no-attribution | **QUANTIFIED** — backfires ~4.5× more than it succeeds; `profile_remeasure` frequency is the monitored statistic | §20, §26 |
| R-MAT3 | registration-diversity gaming | **VALIDATED** — F6 merged 40/40 concentrated endpoints, 0/200 false positives; final thresholds await F5 | §14, §26 |

**Design-track (settlement layer + hardening):**

| ID | Risk | Disposition | Owner |
|---|---|---|---|
| R-MAT4 | HLL saturation via crafted inputs | **DESIGNED** — probation-start-beacon salt (stable across the window, un-precomputable) | §21.1.1 |
| R-C1 | off-chain data withholding; ≥ 2/3 validator collusion degrades fraud-proofs to permissioned BFT (advisory V3.2) | **DESIGNED** — Validator-Quorum DA attestation; challenge window gated on the quorum certificate; publish-or-forfeit with 100% burn; the ≥ 2/3 safety bound is stated openly (§19.3, Threat Model V3b) and the production hardening is external, erasure-coded DA sampling (property specified; platform is roadmap decision **D3**, not hard-committed) | §19.3, §32 |
| R-C3 | black-swan regional macro moves outrun the clamp (advisory V2.2 hysteresis trap) | **DESIGNED (specified Pass 11)** — two-tier band: routine ±5%/quarter kept for anti-manipulation + a wider **emergency slew** unlocked only on sustained, multi-feed, multi-epoch corroboration, global-cross-checked and self-re-locking; recomputable/fraud-provable; widths/thresholds **[calibration]** | §31.1, §34 |
| R-C4 | VDF/PQC verification tax on modest hardware | **GATING REQUIREMENT** — succinct-verify VDF (or threshold VRF) is mandatory for the production beacon; batch ML-DSA verification at fold time; the non-verifying light path is preserved; budget tracked as S1 | §19.2 |
| R-C5 | asymmetric ratchet vs. honest device churn | **VALIDATION ITEM** — churn ≠ fault by construction (an offline node emits no receipt); invariant test + multi-epoch churn simulation folded into A4 | §21.3 |
| R-C6 | content-filter interference with adversarial analysis | **STANDING (process)** — neutral-framing guidelines institutionalized; S3 | process |
| **R-C7** | **neighbor-region parity divergence** (single-neighbor proxy; clamp fought the ramp; fallback chain undefined at genesis) | **DESIGNED (Pass 6; completed Pass 7)** — k-nearest-median proxy + per-component parity-dispersion gate + ramp-referenced provisional clamp; padded comparison set + `G_MIN` floor + Genesis Basket close the low-`Active`/genesis degenerate cases | §31.2 |
| **R-C8** | **organic surplus extraction** (`u_ref > CET_gross` unspecified) | **DESIGNED (Pass 6)** — two-sided CET: payout capped at the target; surplus → reserve-refill + burn (non-attributable sinks); `u_ref` derived from on-ledger escrow | §33.1 |
| **R-C9** | **registry state bloat** (permissionless class entry had no exit; live per-class state grew unboundedly) | **DESIGNED (Pass 7)** — ledger-mechanical `DORMANT`→`ARCHIVED` sunset keyed on verified-work volume (churn ≠ fault preserved); O(1) archive-tree tombstones; re-entry by re-registration, never resurrection | §32.1 |
| **R-C10** | **resurrection exhaustion** (register→archive→re-register cycles drew 100% `PROBATION` redundancy at no escalating cost; per-cluster escalator alone was rotation-soluble via fresh Sybil clusters) | **DESIGNED (Pass 8; Sybil-dilution hardened Pass 9)** — crowd-posted registration bond refunded at `RELAX` / burned at archival-before-`RELAX`; escalator priced on what rotation cannot refresh: verified-work seniority (`NEWCOMER_MULT` on unseasoned shares), the network burn-rate term `2^{r_net}`, and clustering-merge history back-propagation; hard `PROBATION_BUDGET_BP` verification budget with coverage-pro-rata pacing (entry priced and paced, never approved — §3.6 preserved) | §32.1 |
| **R-C11** | **high-dimensional intermediate overflow** (C-6 integer metrics could exceed `u128` on 1536–4096-dim embeddings; cross-multiplied cosine checks worst) | **CLOSED at specification (Pass 8; verdict form refined Pass 9)** — amendment **D-4**: static accumulation budget checked at profile registration; i32 canonical components; verdicts compare squares **exactly** via `wide_mul_128` (replacing the floored-isqrt form, whose ≤ 1/√N relative error made low-norm thresholds arbitrary and whose zero-norm degenerate case agreed with everything); no runtime saturation | §8, §20, App. A.4 |
| **R-C12** | **opaque-payload worker DoS** (advisory V1.1) — a CP7-opaque payload crafted to crash consumer ML runtimes panics honest executors; un-slashable, content-blind | **DESIGNED (Pass 11)** — amendment **D-5**: fault-isolated execution below the trait (crash blast-radius = one disposable worker); a crash is availability churn, **not** a fault (R-C5) so it manufactures no slash; content-blind submitter throttling on *cross-executor* crash/timeout correlation (never on payload bytes — CP7 preserved) | §8.1 |
| **R-C13** | **CGNAT / shared-gateway mass false-positives** (advisory V3.1) — honest neighbourhoods behind CGNAT durably share ASN/IP and risk F6 cohort-merge | **DESIGNED (Pass 11)** — shared ASN/IP declared insufficient alone; merge requires the CGNAT-non-collapsible conjunction (aggregate-throughput dependence + uptime co-transition); recomputable distinctness **de-merge** on published probe evidence of independence | §14 |
| **R-C14** | **liquid-anchor volatility passthrough** (advisory V2.1) — premise (boosting the stablecoin premium) **corrected**: the boost is opex-only; the premium is an unboosted anchor | **CORRECTED + REFINED (Pass 11)** — bounded residual (unboosted noise at fixed weight, clamp-limited) optionally closed by inverse-volatility **damping** of designated liquid anchors (noise *lowers* weight); optional **[design]** | §30 |
| **R-C15** | **macro-coherence / frozen-feed valve jam** (advisory RECON-02) — a government tariff-freeze pins one emergency-corroboration feed flat, so the R-C3 conjunction never completes during a real shock | **DESIGNED (Pass 12)** — `symmetric_deviation`-based decoupling detector flags a feed `state_suppressed` when it diverges from CPI by > `MACRO_DECOUPLING_PPM` over `DECOUPLING_EPOCHS`; a suppressed feed is dropped from the emergency conjunction (never the basket), with a hard `MIN_CORROBORATING_FEEDS` floor so pruning cannot itself open the valve | §31.1 |
| **R-C16** | **submitter-framing via fabricated crashes** (advisory RECON-02) — the R-C12 crash-correlation throttle could be run in reverse: a cohort fabricates crash/timeout reports to inflate an honest submitter's escrow | **DESIGNED (Pass 12)** — a crash charges a submitter only with an epoch-linked, assignment-bound, ML-DSA-65-signed `HardwareExceptionLog` (context `CTX_GOAT_HW_EXCEPTION_LOG`); anonymous/unsubstantiated hangups default to the executor's own churn (R-C5); the cross-disjoint-executor correlation gate still stacks on top | §8.1 |
| **R-C17** | **network-throttle mimicry of F4/F6** (advisory RECON-02) — a co-located farm down-throttles bandwidth + staggers uptime to hold a residential *network* fingerprint and dodge the density merge | **DESIGNED (Pass 12)** — amendment **D-6**: a device-neutral memory-contention **timing-entropy probe** (opaque `Ppm` scalar, no device-type logic, neutrality-gated) detects cross-identity cache interference = co-residency on one physical machine, an axis the network throttle cannot touch; feeds F6 as a non-collapsible dimension under the same de-merge discipline; bounded/not-always-on (S1) | §14, §8 |
| **R-C18** | **DA-hostage liveness / sustained outage** (advisory V3.2) — the R-C1 QuorumCertificate gate makes withholding *safe* but a total external-DA outage stalls all fraud-proof liveness (no certificate → no challenge window) | **DESIGNED (Pass 12)** — recomputable per-region `DaFallback`: no certificate for `DA_FALLBACK_EPOCHS` (32) → forced inline on-chain manifests at an `8×` fee (funds bloat, prices out induced fallback), challenge loop runs on definitionally-available data, auto-reverts on the first recovered certificate; O(1) preserved elsewhere | §19.4 |
| **R-C19** | **hard-kill blind spot** (advisory RECON-03) — a payload engineering a catastrophic OOM/`SIGKILL` destroys the fault-isolated worker before it can sign an R-C16 `HardwareExceptionLog`, so the most damaging toxic payloads erase their own evidence and escape the throttle | **CLOSED at specification (Pass 13)** — the **host `GoatHAL` daemon**, outside the worker's blast radius, ML-DSA-65-signs a `WatchdogTombstone` (context `CTX_GOAT_WATCHDOG_TOMBSTONE`, epoch- and assignment-bound); a **quorum of `WATCHDOG_TOMBSTONE_QUORUM` (3) cluster/ASN-disjoint** host daemons on the same assignment restores the R-C16 anti-framing asymmetry; content-blind (CP7); R-C5 churn default preserved (single/absent tombstone charges nobody) | §8.1 |
| **R-C20** | **economic liveness trap** (advisory RECON-03) — the R-C18 `8×` fallback fee, applied to an honest orchestrator during a genuine (non-induced) outage, makes halting the rational choice, re-stalling settlement | **CLOSED at specification (Pass 13)** — the Emission Allocation Controller rebates the `(DA_FALLBACK_FEE_MULT − 1) = 7×` premium from the gap-fill reserve to the honest orchestrator (net cost `1×`); charged 8× still lands at point-of-posting (anti-induction intact); gated on the recomputable `DaFallback` state + a fraud-surviving posting; reserve/disinflation-bounded; a cost-offset not surplus, so R-C8 holds (inducer EV strictly < 0 after §19.3 bond burn) | §33.2 |

**Standing cross-cutting items:**

- **S1 — per-node verification-cost budget.** One accessibility metric that R-C4, R-C5, and the
  density-probe weight all report against: the CPU/bandwidth cost for a modest node to participate
  *and* to independently verify. Any change that raises it is an accessibility deviation to justify
  explicitly (`ACCESSIBILITY.md`).
- **S2 — data availability as a first-class requirement.** Any content-addressed surface that is
  externalized must ship with an availability proof + bond (the §19.3 pattern), never a bare
  commitment — including the shipped receipt path if it is ever externalized (Phase-2 threat model).
- **S3 — content-neutral framing as permanent discipline** (R-C6): node + observable condition,
  never actor + intent; established terms of art retained.

**Residual trust boundaries (from §35.2):** genesis constants (disclosed, frozen/mutation-gated);
the permissioned Validator Set (≥ 2/3-honest assumption, permissionless registration a Phase-2/3
design item); software supply (bounded by the merge gates + Spec-D bounty economics, open A5).

## 37. Open calibration dependencies — the F5 study

The quantitative anti-capture guarantee ultimately rests on one externally measured quantity: **F5,
the real-world cost of imitating genuine household statistical distributions at scale.** F5 is
non-blocking for any build, but **blocking for parameter finalization and for economic go-live** —
until it lands, every value below is a reasoned strawman validated in simulation (§26), not a
measured constant. It is external and slow, so it is commissioned early and runs alongside all
phases.

Consolidated **[calibration]** index (the owning section holds the reasoning):

| Parameter | Strawman | Owner | Set by |
|---|---|---|---|
| F4 density curve / F6 merge thresholds | `max(0.10, 0.85·(5/d)^1.5)`; ~1–5 plausible devices | §14 | **F5 proper** |
| Topological-fingerprint smoothing window | 72 h | §14 | F5 (with the density thresholds) |
| `DA_TIMEOUT_EPOCHS` / burn severity | 24 / 100% | §19.3 | F5-adjacent + testnet operations |
| `κ_thin` (value; its band is constitutional) | — | §28 | **F5 economic study** |
| `VOL_WINDOW_MIN_RETURNS` / `_DEFAULT_QUARTERS` | 1 / 4 | §30.2 | F5-adjacent macro backtests |
| Regional amortization band | `[0.85, 1.30]` | §31.1 | F5-adjacent |
| `PROVISIONAL_MIN_QUARTERS` / `RAMP` / provisional clamp | ~4–8 / = / ±2.5% | §31.2 | F5-adjacent |
| `k` / `NEIGHBOR_PARITY_MAX_PPM` (R-C7, Pass 6) | 3 / 300_000 | §31.2 | F5-adjacent |
| `G_MIN` / Genesis Basket vectors (R-C7, Pass 7) | 3 / disclosed genesis constants | §31.2 | pre-launch reference data (F5-adjacent) |
| `DORMANT_AFTER_WINDOWS` / `ARCHIVE_AFTER_WINDOWS` (R-C9, Pass 7) | 6 / 12 (30-day windows) | §32.1 | F5-adjacent usage-pattern data |
| `base_bond` / `ESCALATOR_WINDOW` / `PROBATION_BUDGET_BP` (R-C10, Pass 8) | — / ~8 quarters / 1_000 bp | §32.1 | F5-adjacent economic tuning |
| `SENIORITY_MIN` / `NEWCOMER_MULT` / `r_net` baseline rate (R-C10 hardening, Pass 9) | — / 4× / — | §32.1 | F5-adjacent economic tuning |
| `ISOLATION_MODE` / crash-correlation window / escrow-escalation curve (R-C12, Pass 11) | process-isolation / — / — | §8.1 | F5-adjacent + testnet operations |
| CGNAT per-last-mile throughput ceiling / availability-correlation threshold (R-C13, Pass 11) | — / — | §14 | F5 (with the density curve) |
| `EMERGENCY_SLEW_BP` / `EMERGENCY_DEVIATION_PPM` / `CORROBORATION_EPOCHS` (R-C3, Pass 11) | ±2_500 bp / — / — | §31.1 | F5-adjacent macro data |
| `is_liquid` set / `damp_lambda` / `damp_cap_ppm` (R-C14, Pass 11) | {stablecoin premium} / — / — | §30 | F5-adjacent |
| `MACRO_DECOUPLING_PPM` / `DECOUPLING_EPOCHS` / `MIN_CORROBORATING_FEEDS` (R-C15, Pass 12) | 400_000 / 2 / 2 | §31.1 | F5-adjacent macro data |
| `HardwareExceptionLog` schema / fault-class taxonomy (R-C16, Pass 12) | — | §8.1 | testnet-operations tuning |
| `contention_timing` probe: working-set sizes / schedule / cross-identity correlation threshold (R-C17, Pass 12) | — | §14, §8 | F5 (with the density curve) |
| `DA_FALLBACK_EPOCHS` / `DA_FALLBACK_FEE_MULT` (R-C18, Pass 12) | 32 / 8× | §19.4 | F5-adjacent + testnet operations |
| `WATCHDOG_TOMBSTONE_QUORUM` / hard-kill fault-class taxonomy (R-C19, Pass 13) | 3 / — | §8.1 | testnet-operations tuning |
| DA-fallback rebate multiple / honest-cost haircut (R-C20, Pass 13) | `DA_FALLBACK_FEE_MULT − 1` (= 7×, derived) / 0 | §33.2 | F5-adjacent + testnet operations |
| `decay_ppm` / `m_cap_floor` / reserve schedule | — | §33 | **F5 economic study** |
| `RESERVE_CEILING(t)` refill schedule (R-C8, Pass 6) | genesis schedule | §33.1 | F5-adjacent |
| Emergency-band width / corroboration threshold & `N` (R-C3) | — | §36 | F5-adjacent macro data |
| Co-movement `θ` / `probation_quarters` | 850_000 / 2 | §35.1 | shadow-mode backtests |
| Pioneer multiplier decay / per-class budget | ~0.5% of reserve | §7.1 | **F5 economic study** |

The former north-star earnings target (~$20/month real for ~8 h/day of idle, §1) is **retired as a
monetary target by Vision v2.1** (No-Ponzi / Funded Public Good) — it was always F5-dependent, never a
promise, and v2.1 removes the yield target entirely. The discipline: **[calibration]** never blocks mechanism
correctness — every formula above is total, integer, and fraud-provable at *any* in-band parameter
value — it blocks only the claim that the chosen value achieves the economic goal.

## 38. Phase roadmap & success criteria

### 38.1 The Testnet MVP is complete — SC1–SC10 **[shipped]**

| SC | Property proven |
|---|---|
| SC1 | a new device class registers Stage-1 and progresses PROBATION → RELAX → MATURE, driven only by genuine distributed work |
| SC2 | honest cross-class settlement between two real backends under the widened-tolerance rule; strict tasks pin to same-class |
| SC3 | a faulty submission is detected, escalated to a lottery-selected disjoint C, slashed at the coupled multiple, and attributed to the correct class |
| SC4 | all four escalation outcomes observed on the live network, including C-agrees-both → no attribution + `profile_remeasure` |
| SC5 | an illegal posting is caught by independent third-party recomputation producing a valid fraud proof; a conservative posting is never falsely slashed (B-2) |
| SC6 | a co-located high-density cohort is merged by F6 on probe-observed density; class registration and coverage inflation prevented |
| SC7 | the executor-set spread rule holds under load; escalation never quarantines for lack of a disjoint executor under normal diversity (C-4 liveness) |
| SC8 | any observer recomputing from published receipts + anchored roots reaches bit-identical accumulator roots (R-MAT1) |
| SC9 | D.1 conformance + the neutrality scan run green in CI as merge gates for both backends |
| SC10 | PQ handshake + ML-DSA signatures work end-to-end at realistic sizes without excluding low-bandwidth nodes |

Explicit non-goals of the MVP — throughput, latency, cost, earnings realism — remain non-goals of
this document's **[shipped]** claims.

### 38.2 The phase sequence

The ordering principle, unchanged since the MVP: **prove the riskiest property before adding surface
that depends on it.**

- **Phase 1 — validation & hardening** (parallelizable; needs no public network). Deepen the
  adversarial analysis (A1) and multi-epoch dynamics incl. the R-C5 churn simulation (A4); commission
  the crypto-integration audit (A3 — longest external lead, front-loaded; the target is the
  *integration*: nonces, domain separation, serialization, replay, fraud-proof soundness) and the F5
  study (A2); H1 receipt provenance **landed**; H2 beacon hardening landed at protocol/type level
  with deeper work **deliberately held** pending the R-C4 verification-budget analysis and a concrete
  H3 target; this consolidation (D1).
- **Phase 2 — public-testnet preparation.** The two structural changes: real-ledger backing (H3) and
  networked deployment (H4); then operations tooling, distributed release/CI, additional real
  backends (I1–I3), and the post-MVP threat model (D2) — which inherits §35.2's residual trust
  boundaries and §19.3's validator assumptions as its starting inventory. Gated on Phase 1's
  hardening and the audit clearing.
- **Phase 3 — economic layer & broad accessibility.** Implementation of this document's Part VII
  (I4), whose design-blocking closures — R-C1, R-C2, and now R-C7/R-C8 — are met *in specification*;
  plus the consumer surface: D.A. G.O.A.T. onboarding, earnings dashboard, electricity-cost-aware
  scheduling, low-bandwidth modes. This is where the standing accessibility goal moves from
  designed-for to built.
- **Cross-cutting:** F5 (external, slow — commissioned at Phase 1 start); the S1–S3 standing items.

### 38.3 Gating decisions

Seven forks gate the sequence (recommendations recorded in the Post-MVP Roadmap): **D1** public-
testnet timing (recommend: Phase 1 unconditionally; Phase 2 go/no-go on the audit + H1/H2); **D2**
audit scope/vendor (recommend: external, integration-focused, commissioned at Phase 1 start); **D3**
real-ledger platform — purpose-minimal BFT set vs. existing chain/rollup vs. sequenced public log
(the largest Phase-2 architectural decision); **D4** beacon approach — production VDF vs. threshold
VRF, now coupled to the R-C4 verification budget; **D5** the analysis-depth bar before public
exposure (set an explicit CI/scenario target); **D6** reference-oracle policy — update the Python
reference for B-6 or retire it (the Rust implementation is authoritative for Spec B as amended);
**D7** the content-filter process (S3, resolved in principle, applied continuously).

The document's own discipline closes the loop (§4): this Yellowpaper is the consolidation point;
future findings enter as numbered amendments against these sections, and when a scattered prior
record disagrees with this document, **this document governs**.

---

# Appendices

## Appendix A — Fixed-point conventions & pure-integer arithmetic contracts

Everything consequential the protocol computes is **pure integer**. This is not a style preference;
it is what makes §3.8 real: a value recomputed on any architecture must be **bit-identical**, or a
mismatch would be noise instead of proof. IEEE-754 floating point diverges across FPUs (fused
multiply-add, rounding modes, reduction order), so a float anywhere in a consensus path would turn
honest divergence into accidental slashing — the trap the C-6 refinement closed for the verification
metrics themselves (§20). The contracts below bind every formula in this document; a snippet that
violates one is wrong even if numerically plausible.

### A.1 Fixed-point types & scales

| Type | Width | Scale | Used for |
|---|---|---|---|
| `Ppm` | `u64` | `PPM = 1_000_000` = 1.0 | parts-per-million multipliers: CPPI levels, deviations, `κ_thin`, correlation thresholds |
| `Bp` | `u32` | `BP_FULL = 10_000` = 100% | basis-point weights: CPPI basket weights, clamp widths |
| `MicroUsd` | `u64` | 1 = 10⁻⁶ USD | money rates: CMI, CET targets, escrow sums |
| `Epoch` | `u64` | 1 = one beacon epoch | all protocol time |
| wide intermediates | `u128` / `i128` | — | every product and running sum before division |

### A.2 The six contracts

1. **No floating point in any consensus-relevant path** — including the verification *metrics*:
   SSIM, L2/`L∞`, and cosine are integer fixed-point with fixed accumulation width and reduction
   order, declared in the determinism profile (C-6, §20).
2. **Cast before multiply.** Every product widens its operands to `u128`/`i128` *before*
   multiplying (the §30.1 hyperinflation guard). Where even `u128` could overflow — a product of two
   large aggregates — **reduce first**: integer square roots are taken individually before the
   Pearson variance product (§35.1). For high-dimensional accumulations this contract is necessary
   but not sufficient — the static accumulation budget of amendment **D-4** (A.4) binds there.
3. **Total and panic-free on all inputs.** Saturating add/sub/mul throughout; zero-guards with
   defined semantics (`max(1, denom)` where the only zero-denominator case has a zero numerator,
   §30.1); structural caps on unbounded ratios (`SYMMETRIC_DEVIATION_MAX_PPM = 2·PPM`). A hostile or
   hyperinflating feed produces a *clamped reading*, never a halt.
4. **Deterministic division and normalization.** Floor division everywhere; weight vectors
   renormalize to `Σ == BP_FULL` by **largest remainder** (§30.2), so rounding is order-free and
   exact.
5. **Canonical serialization and ordering.** Every hashed or compared structure is field-ordered
   and length-prefixed (the A-6 commitment, §10; sorted beacon reveals, §19.1; sorted reporter
   leaves, §32). No map-iteration order, locale, or platform byte quirk ever reaches a hash.
6. **Derived state over posted state.** Anything computable from anchored inputs is recomputed,
   never trusted: `σ_k` (§30), `u_ref` (§33.1), lifecycle stages (§32.1). What must be posted is
   clamp-bounded and challengeable (§34).

**Corollary — the point of all six:** two independent recomputations agree **bit-identically**, so
disagreement with a posting is a fraud proof, not an architecture artifact (§3.8, §22).

### A.3 Reference idioms (worked examples in the main text)

`symmetric_deviation_ppm` (§30.1) — cast-before-multiply + zero-guard + structural cap;
`cppi_multiplier` (§29) — weighted accumulation in `u128` with exact normalization;
`compute_epoch_gap_fill` (§33) and `route_surplus` (§33.1) — saturating, reserve-bounded allocation;
`correlation_ppm` (§35.1) — reduce-before-multiply under `u128` (the *statistics* idiom);
`cosine_agree` (A.4) — the exact `wide_mul_128` squared comparison, zero truncation at every norm
(the *verdict* idiom, Pass 9).

### A.4 High-dimensional accumulation budgets — amendment D-4 (R-C11) **[design]**

<!-- PATCH 9 (Pass 8): intermediate overflow in high-dimensional integer metrics (amendment D-4,
     registered R-C11). Contract 2's cast-before-multiply is necessary but NOT sufficient for the
     C-6 metrics: sums of squares over 1536–4096-dimensional embeddings — and above all the
     CROSS-MULTIPLIED threshold checks (cosine) — can exceed u128. Safety is made STATIC: every
     profile declares component width, dimension bound, and accumulation schedule, and a
     registration-time budget check proves every intermediate fits u128/i128. Overflow becomes
     impossible by construction; runtime saturation (semantics-bearing in a verdict) never
     engages. -->

**The hazard, concretely.** Contract 2 (cast before multiply) protects a *single* product; it does
not bound an *accumulation across thousands of dimensions* or a *product of two large aggregates*.
With canonical `i32` components (magnitude < 2³¹) at `D = 4096`, the squared-difference sum needs
only ~76 bits — safe. But the naive cosine threshold check, cross-multiplied to avoid division —
`(a·b)²·PPM² ≥ θ²·‖a‖²·‖b‖²` — squares two ~76-bit aggregates into ~190 bits: **silently past
`u128`**, on realistic embedding sizes (1536–4096 dims). With `i64` components even the plain sum
of squares (~138 bits) overflows. An overflow here is not an economics glitch; it is a wrong
**agreement verdict** — an honest executor slashed by arithmetic wraparound.

**The rule (amendment D-4).** Every TOLERANCE determinism profile declares, as part of its
canonical binary representation (§10, C-6): the component **width** `B` (magnitude < 2^B — the
normative canonical width for tensor/embedding comparison is **`i32`, `B ≤ 31`**; wider source
dtypes are canonically quantized down, identically everywhere, as part of the representation), the
**dimension bound** `D ≤ 2^d`, and the **exact accumulation and comparison schedule** (linear
left-to-right order, accumulator width, comparison form). At **profile registration** a mechanical
budget check proves every declared intermediate fits with margin — a profile that fails is rejected
at registration, exactly as the neutrality scan rejects at CI (§9):

| Intermediate | Worst-case bits | Budget |
|---|---|---|
| squared-difference sum `Σ(a_i−b_i)²` | `2B + 2 + d` | ≤ 126 |
| dot product / norm sums `a·b`, `‖a‖²`, `‖b‖²` | `2B + d` | ≤ 126 |
| cosine verdict factors `(a·b)·PPM`, `θ·‖a‖²`, `θ·‖b‖²` — each a `wide_mul_128` operand (Pass 9) | `2B + d + ~21` | ≤ 126 |

With the normative `B ≤ 31` and `d ≤ 24` (over 16 million dimensions — far above any practical
embedding), the worst row is ~107 bits: every intermediate clears `u128` with ≥ 20 bits of headroom,
and the check is trivially verifiable by anyone.

<!-- PATCH 9 REFINEMENT (Pass 9): the floored-isqrt verdict is replaced by an EXACT squared
     comparison via a fixed 128×128→256 multiply-compare primitive. Floor-isqrt has relative error
     up to 1/√N — ~42% at ‖a‖² = 3 — making the effective threshold norm-dependent and arbitrary
     at low magnitudes (loosening the bar at tiny norms; and once a threshold is calibrated
     against truncated behavior, exposing honest low-norm outputs to wrongful disagreement). The
     analysis also surfaced a latent verdict bug: a zero-norm output made both sides degenerate
     (RHS = 0, dot = 0) and AGREED WITH EVERYTHING. Both are eliminated: the wide-compare verdict
     is exact for every norm, and zero norms get an explicit rule. isqrt reduction is retained
     only for certification STATISTICS (§35.1), never verdicts. -->

**Compare squares exactly — the wide-compare verdict (Pass 9; supersedes the floored-isqrt form).**
The first draft of this rule reduced norms with floor `isqrt` before the cross-multiply. That kept
every intermediate inside `u128`, but at an unacceptable price for a *verdict*: floor-isqrt's
absolute error is ≤ 1, so its **relative** error is up to `1/√N` — **~42% at `‖a‖² = 3`** — and the
effective threshold `θ·(na·nb)/(‖a‖‖b‖)` became norm-dependent and arbitrary at low magnitudes
(systematically looser at tiny norms; and a threshold calibrated against that truncated behavior
over-tightens against honest low-norm outputs — wrongful-escalation exposure in exactly the verdict
that must never be arbitrary). Worse, the floored form had a degenerate hole: a zero-norm output
zeroed both `na·nb` *and* `a·b`, so `0 ≥ 0` held and a zero vector **agreed with everything**. Both
defects vanish by removing the root altogether and comparing **squares, exactly**, with one fixed
primitive:

```rust
/// Exact 128×128 → 256-bit product as (hi, lo) limbs — schoolbook on u64 halves.
/// Total, panic-free, no division; the ONLY arithmetic wider than u128 in the protocol.
pub fn wide_mul_128(a: u128, b: u128) -> (u128, u128) { /* 4-limb schoolbook */ }

/// Cosine agreement, EXACT for every norm (θ in PPM, θ > 0):
///   zero norms:  agree ⇔ both norms are zero (identical zero outputs); else disagree
///   dot < 0:     disagree (cos < 0 < θ/PPM)
///   otherwise:   agree ⇔ (dot·PPM)² ≥ (θ·‖a‖²)·(θ·‖b‖²)   — compared in 256 bits
pub fn cosine_agree(dot: i128, theta_ppm: u64, n2a: u128, n2b: u128) -> bool {
    if n2a == 0 || n2b == 0 { return n2a == 0 && n2b == 0; }
    if dot < 0 { return false; }
    let lhs = wide_mul_128(dot as u128 * PPM as u128, dot as u128 * PPM as u128);
    let rhs = wide_mul_128(theta_ppm as u128 * n2a, theta_ppm as u128 * n2b);
    lhs >= rhs                                   // lexicographic (hi, lo) compare
}
```

For `dot ≥ 0` this is *algebraically identical* to `cos(a,b) ≥ θ/PPM` — no approximation, no ulps,
no threshold-semantics contortions: **zero truncation at every norm**, including `‖a‖² = 3`. Each
`wide_mul_128` factor provably fits `u128` under the D-4 budget (`dot·PPM` ≤ `2B + d + ~21` bits;
`θ·‖·‖²` likewise — ~107 bits at the normative `B ≤ 31`, `d ≤ 24`), and the 256-bit product needs no
division, no reduction, and no rounding rule. The zero-norm rule is explicit and deterministic:
identical zero outputs agree; a zero output never agrees with a non-zero one (the C-6
mismatch-is-disagreement posture). Every recomputer reaches the identical bit (§3.8).

**Where isqrt reduction still lives — statistics, never verdicts.** The §35.1 Pearson discipline
(integer square roots taken *individually first*, bounding the variance product) remains the
contract for **certification statistics** — the co-movement gate — where a sub-ulp truncation is
immaterial to a thresholded correlation over a whole shadow window and width is precious. The
dividing line is the same one A.4 already draws for saturation: anything that decides an
**agreement verdict** must be exact; anything that feeds a slow, challengeable *statistic* may
reduce first.

**Why static, not saturating.** In the economic layer a clamped reading is a *defined semantic* —
§30.1's structural cap is a legitimate "±200%" reading. In a **verification verdict**, saturation is
semantics-bearing: a saturated distance could flip agree/disagree and slash an innocent executor.
D-4 therefore forbids runtime saturation in agreement metrics entirely: safety is proven **once, at
registration**, and the runtime arithmetic is plain, provably-non-overflowing `u128`/`i128`. A
component outside its declared width is a **canonical-encoding validity failure** and compares as
maximal distance — disagreement, never an error, never a panic — the existing C-6 mismatch rule
extended to range.

## Appendix B — Amendment index

Every numbered amendment in the design record, one line each, mapped to the section that absorbs it.
Per the amendment discipline (§4): **this document governs**; the amendment record is history.

| ID | One-line content | Absorbed in |
|---|---|---|
| **A-1** | `observed_compute_equiv` rename; the auditor catches device terms as identifier sub-tokens | §9 |
| **A-2** | density under-declaration is a **hard** validity failure; F6 evaluates the probe-observed value | §11, §14 |
| **A-3** | the attestation chain commits to the SHA3-256 of the full *signed* prior record | §12 |
| **A-4** | strict epoch monotonicity, independent of the beacon-nonce check | §12 |
| **A-5** | hard/soft check partition; rolling, forgiving re-attestation (drift and staleness are soft) | §11–§12 |
| **A-6** | the canonical output commitment is device-blind — task semantics only | §10 |
| **B-1** | slash multiple couples to tolerance width: `clamp(base·(1 + ⅓·tol/tol_ref), 15×, 20×)` | §21.4 |
| **B-2** | fraud is **directional** — less safe than the recomputable lower bound; conservatism is never slashed | §21.4, §22 |
| **B-3** | precise snap: `p_class` doubles (capped 1.0); a breached MATURE re-enters at least RELAX | §21.1–§21.2 |
| **B-4** | `force_snap` split: recomputable triggers are fraud-enforced, declared bursts voluntary (residual closed by B-6) | §21.2 |
| **B-5** | `V_c` counts all verified-completed work; escalation emits clean receipts for clean parties | §20, §21.1 |
| **B-6** | the anomaly burst is accumulator-derived (`sub_window` buckets); a withheld snap is provable fraud — closes R-MAT2 | §21.2 |
| **C-1** | cross-class band is the **widened** `max(band_A, band_B)`, capped by the task bound (ineligible → same-class) | §20 |
| **C-2** | fourth escalation outcome: C agrees with both → no attribution, settle, flag `profile_remeasure` | §20 |
| **C-3** | the third executor must be cluster/ASN-disjoint **and** pairable; lottery-chosen, never adversary-chosen | §20 |
| **C-4** | no disjoint pairable C → quarantine; spread is escalation *liveness*, not only anti-capture | §20, §23 |
| **C-5** | TOLERANCE agreement = tokens **∧** numerics; length mismatch is disagreement, never an error | §20 |
| **C-6** | non-textual outputs: canonical binary representation + modality-appropriate metric, both pure-integer | §20 |
| **D-1** | D6 requires a peak-power observable; the envelope binds **over** any per-task policy cap | §8 |
| **D-2** | D8 has two irreducible halves: behavioral (device-blind commit) and static (source scan) | §8, §9 |
| **D-3** | a passed D6 does **not** make runtime power telemetry trusted (population statistics only; was R-CC2) | §8, §13 |
| **D-4** | profiles must pass the **static accumulation budget** — declared width × dimension × schedule provably fit `u128`; verdicts compare squares **exactly** via `wide_mul_128` (Pass 9 — no isqrt, no truncation, explicit zero-norm rule); no runtime saturation in verdicts | §8, §20, App. A.4 |
| **D-5** | execution runs **fault-isolated** below the trait (crash blast-radius = one disposable worker); a runtime crash is availability churn, not a fault; distinct from the unhyphenated D5 preemption criterion (Pass 11, R-C12) | §8.1 |
| **D-6** | backends expose a device-neutral `contention_timing` measurement under a standardized memory-contention probe (co-residency detection, not device typing; neutrality-gated); distinct from the unhyphenated D6 envelope criterion (Pass 12, R-C17) | §14, §8 |

Hardening and fix IDs (the risk-register IDs double as design labels once closed):

| ID | One-line content | Absorbed in |
|---|---|---|
| **F3** | `P_FLOOR = 0.15` + 15–20× slash → fault EV of −2.25…−3.0× at the floor | §21.4, §26 |
| **F4** | density-coupled `q_network` on probe-observed density | §14 |
| **F6** | density feeds *clustering*: cohort-merge behind one endpoint | §14, §15 |
| **H1** | receipt provenance chain (`SignedReceipt`, `EscalationRecord`, fold-time enforcement) — closes R-MAT2b | §18 |
| **H2** | beacon hardening: delay-sealed finalization, `BeaconMode`; production VDF pending (gated by R-C4) | §19 |
| **R-MAT4** | HLL inputs salted with the probation-**start** beacon (stable across the window, un-precomputable) | §21.1.1 |
| **R-C1…R-C20** | the settlement-era + operational-hardening register (through advisory RECON-03) — dispositions and owning sections indexed in §36 | §36 |

## Appendix C — Glossary

Terse; the owning section holds the full definition. All numeric symbols are integer-scaled per
Appendix A. Note the two distinct kappas.

**Naming & units**

| Term | Meaning |
|---|---|
| GoatCoin (GOAT) / D.A. G.O.A.T. / GPUCoin | formal name / consumer-UI brand / familiar hook |
| GCU | Goat Compute Unit — measured verified work; never spec-sheet (§6) |
| PPM / BP | fixed-point scales: 1_000_000 = 1.0 / 10_000 = 100% (App. A) |

**Device layer**

| Term | Meaning |
|---|---|
| GoatHAL | the device-agnostic backend trait; the protocol/device boundary (§5) |
| device class / `class_id` | opaque registry string; the protocol never interprets it (§3.5, §7) |
| determinism profile | Exact / Tolerance / Statistical + metric + bound, per task class (§10) |
| canonical output commitment | device-blind SHA3-256 over task semantics only (A-6, §10) |
| D.1 conformance suite | the eight objective backend admission criteria (§8) |
| Neutrality Auditor | compile-time scan: no device-type or content tokens in protocol source (§9) |
| static accumulation budget | D-4: registration-time proof that a profile's metric intermediates fit `u128` (App. A.4) |

**Identity & anti-Sybil**

| Term | Meaning |
|---|---|
| `CapabilityRecord` | ML-DSA-signed, hash-chained, measured capability claim (§11) |
| attestation chain | per-node record chain; strict epoch monotonicity (§12) |
| `q_network` | network-score factor; the residential last-mile gate (§13) |
| F4 | density-coupled degradation of `q_network` (§14) |
| F6 / `CohortMerge` | identities behind one endpoint collapse to one cluster (§14) |
| endpoint | a multi-dimensional topological fingerprint, not an IP (§14) |
| operator cluster | the identity group all anti-capture caps apply to (§15) |

**Verification, maturity & ledger**

| Term | Meaning |
|---|---|
| effective profile | the comparison band for a pairing: own / widened / ineligible (§20) |
| third executor C | the beacon-lottery-chosen escalation verifier (§20) |
| quarantine | no-attribution settlement when no disjoint pairable C exists (C-4, §20) |
| `ClassAccumulator` | per-class `V_c`/`D_num`/`F_num` + deterministic-HLL coverage (§21.1) |
| `p_class` / `P_FLOOR` | per-class redundancy sampling probability / its 0.15 floor (§21.1) |
| asymmetric ratchet | relax one step per held 30-day window; snap doubles `p_class` instantly (§21.1) |
| anomaly-burst snap | recomputable intra-window fault-concentration trigger (B-6, §21.2) |
| `DORMANT` / `ARCHIVED` | ledger-mechanical sunset stages; archived classes are tombstoned (§32.1) |
| directional fraud | fraudulent iff *less safe* than the recomputable lower bound (B-2, §21.4) |
| fraud proof | a published-data recomputation that slashes a poster's bond (§22) |
| accumulator root | anchored digest every recomputer must reproduce bit-identically (§22) |

**Randomness, transport & availability**

| Term | Meaning |
|---|---|
| epoch beacon | commit-reveal public randomness: capability nonces + lottery seeds (§19) |
| delay-sealed / VDF | finalization slower than the reveal window; removes last-revealer bias (§19.2) |
| `QuorumCertificate` | ≥ 2/3 validator DA attestation that starts the challenge clock (§19.3) |
| ML-DSA-65 / ML-KEM-768 | the post-quantum signature / KEM primitives, FIPS 204/203 (§16) |

**Anti-capture & economics**

| Term | Meaning |
|---|---|
| Thin-Pool Principle | rewards priced to sunk-cost idle economics; capture is a structural loss (§2) |
| Calibration Law | `I_max × D_max/24 ≤ 1` — idleness priced in time, never energy (§3.1) |
| idle premium | the multiplier gated on genuine idleness + residential last mile (§13) |
| S_o | concentration factor: diminishing returns on an operator's recent work share (§23) |
| **κ** | the ≥ 1% *assignment floor* for qualifying small nodes — constitutional (§23) |
| **κ_thin** | the *thin-pool coefficient* on the CMI — a different symbol entirely (§28) |
| P_r | power-region factor: per-grid soft cap on idle-premium work (§24) |
| spread rule | executor sets span ≥ m clusters/ASNs — anti-capture **and** liveness (§23) |
| pioneer multiplier | decaying, budget-capped bootstrap bonus for young classes (§7.1) |
| registration bond | crowd-posted at class registration; refunded at `RELAX`, burned at archival-before-`RELAX` (R-C10, §32.1) |
| CET | Contributor Earnings Target — the localized per-GCU-h wage target (§27) |
| CMI | Compute Market Index — commodity-tier clearing price only (§28) |
| CPPI | Contributor Purchasing-Power Index — the six-component localizer (§29) |
| Meta-Index Controller | bounded algorithmic reweighting + feed mutation (§30, §35.1) |
| symmetric integer deviation | the sMAPE-style R-C2 volatility primitive (§30.1) |
| `clamp_move` | the ±5%/quarter output clamp (±2.5% and ramp-referenced in `Provisional`) (§34, §31.2) |
| `Provisional` / `Active` | the region-onboarding states (§31.2) |
| Genesis Basket | constitution-fixed pre-launch baseline vectors; the genesis anchor (§31.2) |
| gap-fill / `M_cap(t)` | the emission bridge up to the CET floor / its decaying hard cap (§33) |
| Surplus Routing Rule | wage capped at the target; excess → reserve-refill + burn (R-C8, §33.1) |
| `u_ref` / `N_eff` | derived per-unit usage revenue / F6-discounted effective work units (§33) |
| challenge window | the 7-day recompute-or-slash period, DA-gated (§34) |
| F5 study | the empirical household-distribution study gating all calibration (§37) |

## Appendix D — Reference-implementation ↔ specification cross-reference

The Rust workspace **`goatcoin-rs`** is authoritative for every **[shipped]** claim in this
document. Module ↔ section ↔ ID map:

| Module | Yellowpaper | IDs |
|---|---|---|
| `goat-protocol/pqsign` | §16 | R-CAP1 |
| `goat-protocol/commit` | §10 | A-6 |
| `goat-protocol/hll` | §21.1 | R-MAT1 |
| `goat-protocol/capability` | §11, §13–§14 | A-1…A-6, F4/F6 |
| `goat-protocol/attestation_chain` | §12 | A-3/A-4/A-5 |
| `goat-protocol/maturity` | §21 | B-1…B-6 |
| `goat-protocol/verification` | §20 | C-1…C-5 |
| `goat-protocol/provenance` | §18 | H1 / R-MAT2b |
| `goat-protocol/backend` (the GoatHAL trait) | §5 | Item 1 |
| `goat-protocol/conformance` | §8 | D-1…D-3 |
| `goat-backends/reference_a`, `reference_b` | §8 — *below* the trait; excluded from the neutrality scan | Item 1 |
| `goat-ledger/ledger` | §22 | WP-1.1/1.3 |
| `goat-ledger/beacon` | §19 | WP-1.2, R-CAP3, H2 |
| `goat-ledger/actors` | §22 | WP-1.4 |
| `goat-net/transport` | §17 | WP-2.1 |
| `goat-net/distributed` | §20, §23 (spread rule, lottery C-selection, verification rounds) | WP-2.2/2.4/2.5 |
| `goat-net/density` | §14 | WP-3.1 |
| `goat-net/testnet` | §26, §38.1 | WP-3.2–3.4 |
| `goat-neutrality` (auditor binary; CI merge gate) | §9 | A-1, D-2, CP7 |

Demo binaries ↔ success criteria: `goat-mvp1-demo` → SC5; `goat-mvp2-demo` → SC2/SC3/SC4/SC7/SC10;
`goat-mvp3-demo` → SC1/SC6/SC8; `goat-collect` → the WP-3.5 live-data pipeline feeding §26. The
neutrality gate scans `goat-protocol`, `goat-ledger`, and `goat-net`; `goat-backends` sits below the
trait and is deliberately out of scan scope (§5, §9).

**What has no implementation anywhere:** all of Part VII, the Validator-Quorum DA attestation
(§19.3), the R-MAT4 salt (§21.1.1), and the sunset lifecycle (§32.1) are **[design]** — the Rust
snippets in those sections are *normative specification*, not excerpts from the workspace. The
production VDF / threshold VRF for §19.2 is likewise pending (decision D4, gated by R-C4).

**The Python reference (`reference/goathal`)** is the frozen behavioral oracle the Rust port
maintains parity against. It lags the specification in one known place — it still models the
anomaly burst as a *declared* input (pre-B-6) — so it is authoritative for nothing; it is retained
or retired per decision D6 (§38.3). New mechanisms land in `goatcoin-rs` only.
