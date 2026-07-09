# GoatCoin (GOAT) — Cryptographic Boundary & Protocol Threat Model

### *Audit-Staging Security Specification — Tracks A3 / D2 (Phase 1)*

> **Version 1.3 (draft, 2026-07-06), aligned to Yellowpaper v1.0 — Mainnet Specification Sealed
> (advisory GOAT-ARCH-RECON-03 disposition — R-C19 / R-C20; adds the RECON-03 vector dispositions
> in §3.3 and the `CTX_GOAT_WATCHDOG_TOMBSTONE` signing context in Part V). Supersedes v1.2 (RECON-02
> / R-C15…R-C18 / amendment D-6, §3.2) and v1.1 (RECON-01 / R-C12–R-C14, §3.1).** This document is
> the
> primary security blueprint for the external third-party audit (Post-MVP Roadmap, tracks **A3**
> crypto-integration audit and **D2** threat model; decision **D2**: external, integration-focused).
> It defines the cryptographic boundaries, trust transitions, adversarial vectors, and the explicit
> assertion scope the auditing firm is asked to fuzz, formally verify, or structurally stress-test.
>
> **Defensive purpose statement.** This is defensive validation of a decentralized compute
> network's verification and settlement mechanisms; the goal is hardening prior to public
> exposure. Per the project's defensive-language convention (adversarial-node framing),
> this document describes **nodes and observable conditions, never actors and intents**, and every
> adversarial condition is paired with the mechanism's response.
>
> **Audit target discipline.** The post-quantum primitives (ML-DSA-65 / FIPS 204, ML-KEM-768 /
> FIPS 203, SHA3-256) are **library-provided and out of scope as algorithms**. The audit target is
> the **integration**: signing contexts and domain separation, nonce and replay discipline,
> canonical serialization injectivity, key/authorization binding, fraud-proof soundness and
> completeness, and pure-integer arithmetic totality.
>
> **Numeric convention.** No floating point exists anywhere in scope, and none appears in this
> document: all bounds are pure-integer, PPM-scaled (`PPM = 1_000_000` = unity) or
> basis-point-scaled (`BP_FULL = 10_000` = 100%), per Yellowpaper Appendix A. Where the Yellowpaper
> uses a conventional decimal (e.g. "0.15"), the normative value is the integer form
> (`P_FLOOR = 150_000 PPM`).
>
> Cross-references (`§`) are to `GoatCoin_Yellowpaper.md` v1.0 (sealed). Status tags carry over:
> **[shipped]** = implemented + tested in `goatcoin-rs`; **[design]** = specified, not built;
> **[calibration]** = parameter pending the F5 study.

---

## 0. Configuration scope — what exists in code vs. on paper

The audit must not conflate the three system configurations. Each row states what the auditors are
looking at and how to treat it:

| # | Configuration | Status | Audit treatment |
|---|---|---|---|
| C1 | **Testnet MVP** — in-process transport, permissioned ledger, two reference backends, ~81 tests, 4 CI gates | **[shipped]** | **Primary code-audit target.** Every assertion in Part III marked C1 is testable against the workspace today |
| C2 | **Public testnet** — real ledger (H3), networked deployment (H4), independent operators, permissioned Validator Set | Phase-2 target | **Forward-scoped threat model.** Boundaries that change at C2 are explicitly marked; audit findings should state C1/C2 applicability |
| C3 | **Settlement & oracle layer** — Yellowpaper Part VII (CET/CMI/CPPI, DA attestation, emission/surplus controllers, registry bonds) | **[design]** | **Specification review only.** No code exists; the deliverable is validation of the *math and closure arguments*, and of the normative Rust snippets as specifications |

Known-open items the audit should treat as documented, not discover: the placeholder VDF is
**not production** (iterated SHA3, O(iterations) verify — gated by R-C4, §19.2); the Python
reference (`reference/goathal`) is a frozen oracle **lagging B-6** (models the anomaly burst as a
declared input) and is authoritative for nothing; all F5-dependent constants are **[calibration]**
strawmen — audit the mechanism, not the constant.

---

# Part I — The Cryptographic Boundary Map

## 1. The State-Transition Perimeter

The perimeter is the ordered sequence of trust-state transitions a unit of work traverses, from an
unauthenticated consumer payload to a recomputable ledger anchor. Each transition names its guard
and what a node in an adversarial condition at that stage can and cannot cause.

```
 UNTRUSTED-OPAQUE          AUTHENTICATED CHANNEL            DEVICE SPACE (untrusted)
┌──────────────────┐   ┌───────────────────────────┐   ┌────────────────────────────┐
│ P0 Task payload  │──▶│ P1 ML-KEM-768 + ML-DSA-65 │──▶│ P3 GoatHAL execution below │
│ (opaque bytes,   │   │    handshake → AES-256-GCM │   │    the trait; envelope D6  │
│  CP7: no content │   │    channel, role-separated │   │    binds over ExecPolicy   │
│  fields exist)   │   │    nonce spaces (§17)      │   │    (§5, §8)                │
└──────────────────┘   └───────────────────────────┘   └────────────┬───────────────┘
          ▲                        ▲                                 │ trait-shaped data only
          │                        │                                 ▼
┌─────────┴────────┐   ┌───────────┴───────────────┐   ┌────────────────────────────┐
│ P2 Assignment:   │   │ P7 Ledger anchor: window  │◀──│ P4 A-6 device-blind commit │
│ signed log →     │   │ root + claimed transition │   │ P5 ExecutionAttestation    │
│ AuthorizationSet;│   │ + bond; challenge = inde- │   │    (ML-DSA-65, attributable│
│ C re-derived from│   │ pendent recomputation     │   │    core incl. sub_window)  │
│ beacon lottery   │   │ (§22, SC5)                │   │ P6 fold_verified_attributed│
│ (§18.2, §19)     │   └───────────────────────────┘   │    (§18.4)                 │
└──────────────────┘                                   └────────────────────────────┘
```

### 1.1 Transition table with audit assertions

| Stage | Boundary crossed | Cryptographic guard | An adversarial node here can / cannot | Audit focus |
|---|---|---|---|---|
| **P0 → P1** | untrusted consumer space → PQ-authenticated space | ML-KEM-768 encapsulation (ct 1088 B); initiator ML-DSA-65 signature **over the ciphertext**; derived AES-256-GCM; disjoint per-direction nonce spaces; length-prefixed frames (§16–17) | *can:* submit arbitrary opaque payloads. *cannot:* read/modify channel traffic, splice roles, or replay frames across directions — key–nonce pairs never repeat by construction | Handshake transcript binding (is every handshake element covered by the signature? unsigned-field injection); nonce-space disjointness under bidirectional load; downgrade paths (assert none exist: PQ-only, §3.7) |
| **P0 forever** | payload content → protocol logic | **structural absence**: `Task` has no model/license/content field (CP7, §3.3); protocol never parses payload bytes | *cannot:* trigger content-dependent protocol behavior — the data to branch on does not exist in the types | Type-level assertion: no protocol decision reads payload bytes; payload parsing surface exists only below the trait |
| **P1 → P2** | transport → authorization | orchestrator-**signed assignment log** → `AuthorizationSet`; escalation executor C **re-derived** from the epoch-beacon lottery, never asserted (§18.2, §19) | *cannot:* have an unassigned node's receipt accepted (valid signature ≠ authorized); *cannot:* substitute a chosen C — a recomputer re-derives the lottery from the anchored beacon | Beacon→lottery derivation determinism; assignment-log signature contexts; C's disjoint-and-pairable predicate (C-3) |
| **P2 → P3** | protocol space → device space | the `GoatHAL` trait — the *only* aperture; `ExecPolicy` capped by the D6 envelope (envelope **binds over** policy, D-1) | *can:* compute anything it likes below the trait (device space is untrusted by design). *cannot:* pass device identity, content policy, or unmediated state upward — only trait-shaped values return | See §2 (hardware-to-protocol boundary) |
| **P3 → P4** | raw device output → consensus-visible data | **A-6 canonical commitment**: deterministic, field-ordered, length-prefixed serialization over task semantics only (`task_class_id`, tokens, numerics, `engine_build_id`), SHA3-256 (§10) | *cannot:* embed device identity in the commitment (D8-behavioral); *cannot:* later swap results — `result_commit` binds the raw result to the receipt (§18.3) | **Serialization injectivity** (no two semantically distinct outputs share an encoding; no ambiguous variable-length encoding without length prefix); commitment covers every consensus-relevant field |
| **P4** | unsigned work → executor-attributable record | `ExecutionAttestation` (ML-DSA-65) over the **attributable core**: `class_id`, `task_class_id`, `window`, `sub_window`, `cluster_id`, `asn`, `result_commit` (§18.1). Outcome flags **deliberately excluded** — a node cannot be required to sign its own fault verdict | *cannot* (as orchestrator): rewrite what an executor did, or re-bucket `sub_window` to suppress a burst snap (R-MAT2b closed) | `KeyRegistry` binding (receipt verifies against the **registered** key of the claimed node); replay: window/sub_window binding; domain separation vs. other ML-DSA contexts |
| **P4 → P5** | claims → adjudicated outcome | `agree()` under the **effective profile** (C-1/C-5/C-6, D-4 exact integer metrics); `EscalationRecord` carries all three signed receipts + raw results bound by `result_commit`; attribution must **re-derive** (§18.3, §20) | *cannot:* attribute a fault an independent recomputation of `agree(C,A)`/`agree(C,B)` does not produce — fabricated attribution re-derives to a different verdict and is rejected | Verdict-math exactness (Part III, A-PF2/3); the four escalation outcomes; quarantine path (C-4) never slashes |
| **P5 → P6** | adjudicated receipts → accumulator state | `fold_verified_attributed`: (a) signature vs. registered key, (b) authorization, (c) any fault flag backed by a verified `EscalationRecord` (§18.4) | *cannot:* fold an unauthorized, mis-signed, or unbacked-fault receipt — **no element of a folded receipt is trusted rather than checked** | Fold-boundary completeness: enumerate every field consumed downstream; assert each is signature-covered or recomputed |
| **P6 → P7** | node-local state → public anchor | window **accumulator root** + claimed transition + bond on the minimal ledger; deterministic-HLL serialization (R-MAT1) makes roots bit-identical across recomputers (§21.1, §22) | *cannot:* post a less-safe-than-recomputable transition without creating a valid fraud proof (B-2); *can:* always be **more** conservative without penalty | **Two independent recomputations** (challenger and ledger) reach the same verdict from the same published data (SC5) — the load-bearing property; soundness *and* completeness in Part III |

**Perimeter-wide audit item — the signing-context inventory.** Enumerate every ML-DSA-65 signing
context in the workspace (capability records §11, attestation chain §12, execution attestations
§18.1, assignment logs §18.2, beacon commitments §19.1, transport handshake §17; at C3:
DA attestations `H("GDA\x01" ‖ epoch ‖ region ‖ CID)` §19.3, oracle postings §32). Assert **pairwise
domain separation** (no signature valid in one context verifies in another) and that every signed
structure is canonically serialized (injective, length-prefixed) *before* signing. Any two contexts
sharing a byte-compatible preimage space is a finding.

## 2. The Hardware-to-Protocol Boundary

The boundary's claim, stated precisely so it can be audited rather than admired: **a corrupted
device runtime (GPU/NPU driver, backend implementation) is contained as an adversarial *data
source*, never as a *privileged principal*.** It holds through three independent layers plus one
honest non-guarantee.

### 2.1 The three enforcement layers

1. **Compile-time absence of a channel [shipped].** `goat-protocol` (and `goat-ledger`,
   `goat-net`) declare **no dependency** on `goat-backends`. A protocol module *physically cannot*
   `use` backend code; the device layer sits below the `GoatBackend` trait and the protocol layer
   only calls trait methods. There is no language-level path — no linkage, no shared mutable
   state — by which backend code executes inside protocol modules.
   *Audit:* verify the dependency graph mechanically (`cargo metadata`); confirm no `dev-` or
   transitive edge from a protocol-layer crate to `goat-backends`; confirm no `unsafe` aperture or
   dynamic-loading path re-introduces one.
2. **Lint-time vocabulary exclusion [shipped].** The Neutrality Auditor (`goat-neutrality`) scans
   protocol-layer source for device-type identifiers — whole words *and* identifier sub-tokens
   (`observed_gpu_equiv` is caught, A-1) — and content/policy tokens (CP7). A blocking CI gate: a
   protocol module that names a device type cannot merge, so no future patch can quietly
   special-case (and thereby trust) a device class.
   *Audit:* fuzz the tokenizer for **false negatives** (unicode confusables, split-token evasion,
   string-literal placement — literals are scanned, comments exempt); attempt to land a
   device-branching patch past the gate.
3. **Data-shape reduction at the trait [shipped].** Everything returning above the trait is
   trait-shaped and measured: opaque `DeviceDescriptor`s, measured `BenchmarkReport`/`TaskClassCap`
   (capability is **measured, never declared** — §3.4, D2-honesty), `ExecOutcome`, and the A-6
   **device-blind commitment**. The protocol cannot receive device identity because no trait type
   carries it (D8-behavioral).
   *Audit:* enumerate the trait surface; assert no field can smuggle stable device-identifying
   bytes into consensus-relevant data; assert no protocol decision consumes backend-supplied bytes
   that are not either (a) inside the A-6 commitment or (b) population-statistically treated
   (D-3: runtime telemetry is never trusted per-node).

### 2.2 The honest non-guarantee — and why containment still holds

The boundary does **not** sandbox a corrupted runtime at execution time: below the trait, a
backend can compute whatever it wants. Containment is by **verification, not isolation**:

| A corrupted runtime attempts | What actually happens | Mechanism |
|---|---|---|
| return a divergent result | redundant/cross-class verification detects; escalation attributes; slash at 15–20× (coupling `1/3`), `fault_ev_margin ∈ [2_250_000, 3_000_000] PPM` (2.25–3.0×) net-negative at `P_FLOOR = 150_000 PPM` | §20, §21.4, F3 |
| claim capability it cannot reproduce | measurement is the only currency — the benchmark *is* the fingerprint; hard validity failure on non-reproduction | §3.4, §6, §11 |
| under-declare density / inflate coverage | A-2 hard failure **and** F6 merges on the **probe-observed** value regardless | §14 |
| flood via a novel class | 100% `PROBATION` sampling until matured; `PROBATION_BUDGET_BP` caps aggregate exposure | §7, §21.1, §32.1 |
| escalate into ledger state | no path exists: the ledger accepts only signed, authorized, recomputable data (Part I §1.1, P6–P7) | §18.4, §22 |

The consensus ledger is therefore reachable from device space **only through data that is
signature-bound, authorization-checked, and independently recomputable** — a corrupted runtime's
entire influence reduces to "submit results," and wrong results are the system's *normal,
already-priced* adversarial condition. Harm to the node owner's own machine by malicious backend
*software* is a conventional supply-chain concern, out of protocol scope and tracked as a named
residual trust boundary (§35.2; D.1 + neutrality gates bound what a certified backend build may
contain).

---

# Part II — The Core Threat Vector Matrix

Four vectors in audit depth, then the register index. Every row pairs the adversarial condition
with the neutralizing mechanism and its quantitative bound; **[design]** rows are C3
specification-review scope.

## 3. Primary vectors

| # | Vector | Adversarial profile & precondition | Attack mechanics | Neutralizing mechanisms (Yellowpaper) | Quantitative bound / residual | Status |
|---|---|---|---|---|---|---|
| **V1** | **Orchestrator collusion / framing** (R-VER1, R-MAT2b) | non-compliant orchestrator, possibly coordinating with executor cohort; controls assignment and posting | (a) rewrite an executor's receipt fields; (b) re-bucket `sub_window` to spread anomalies and suppress a burst snap; (c) fabricate a `diverged`/`fault` attribution against a compliant node; (d) steer escalation to a coordinated third executor C; (e) post an under-sampled / over-advanced transition | (a) attributable core is **executor-signed**, orchestrator cannot alter any signed field (§18.1); (b) `sub_window` is **inside the signed core** — R-MAT2b closed — and the burst predicate is accumulator-derived and recomputable, so a *withheld* snap is provable fraud (`withheld_burst_snap`, B-6, §21.2); (c) attribution must **re-derive** from the `EscalationRecord`'s executor-signed results under the deterministic `agree()` — a fabricated verdict re-derives differently and is rejected (§18.3); (d) C is **beacon-lottery-selected**, cluster/ASN-disjoint and pairable (C-3), re-derivable by anyone (§18.2, §19); (e) B-2 directional fraud → any less-safe posting yields a fraud proof; bond slashed (§21.4, §22) | Iteration-3 (500 rounds, Wilson 95% CI): net-profit framing requires **> 50% of the ~20-candidate escalation pool** (≥ 11 cluster-disjoint sites); a conservative orchestrator is **never** falsely slashed (tested). *Residual:* provenance faults become economically slashable only at C2 (bond); completion-time-stamped buckets need independent operators (Phase-2) | **[shipped]** (C1) |
| **V2** | **Sybil registry flooding with rotation** (R-C9 / R-C10) | operator cohort minting junk device classes; rotates freshly-minted clusters (`r = 0`) to dodge per-identity escalation | register low-effort classes via rotating Sybil founders → force 100% `PROBATION` redundancy on workloads that never mature → archive → re-register; goal: exhaust verification throughput | registration is **population-statistical** (median-of-many, F6-merged founders — §7, §14); **bond** refunded at `RELAX`, burned at archival-before-`RELAX`; **seniority pricing**: unseasoned founders pay `NEWCOMER_MULT × 2^{r_net}` shares — `r_net` is congestion pricing on the network-wide archived-without-`RELAX` rate: *identities rotate, the burn record does not*; clustering-merge **back-propagates history** (§15 signals) at each new registration; `PROBATION_BUDGET_BP` (strawman 1_000 bp) **hard-caps aggregate exposure**, paced pro-rata to distinct-cluster coverage; R-C9 sunset bounds state to one 32-B tombstone per class under a single archive root (§32.1) | grief per epoch ≤ `PROBATION_BUDGET_BP` of verification capacity **regardless of adversary spend**; each cycle burns `base_bond × NEWCOMER_MULT × 2^{r_net}` (self-escalating); honest fresh cohorts lose lockup only (refund-on-`RELAX`). *Residual:* parameters **[calibration]** (F5); the budget cap is the parameter-independent backstop | **[design]** (C3) |
| **V3** | **Validator data-withholding / epoch stalling** (R-C1) | colluding subset of the DA Validator Set (§19.3) | **(V3a) liveness, ≥ 1/3 collusion:** withhold attestations for an honest, available manifest → `QuorumCertificate` (integer BFT majority `n·2/3 + 1`) never forms → challenge clock never starts → region-epoch update stalls. **(V3b) safety, ≥ 2/3 collusion:** attest possession of an unfetchable blob → a corrupt-and-withheld manifest's challenge clock starts and can expire unchallenged | window **gated on the certificate** — withholding can never "win by timeout" because with data unavailable the clock never starts; stalled region: prior value stands, exposure bounded by the ±500 bp/quarter clamp (§34); chronic non-attestation = registry-eviction/slashing signal; **publish-or-forfeit**: no leaves within `DA_TIMEOUT_EPOCHS` (strawman 24) → reputation deleted, **100% bond burn**; on-chain fallback posts the *single contested feed's* leaves (~KB, O(1) preserved); validator-set **independence is a registry requirement** (distinct operators/ASNs/regions — the F6-topology logic applied to the registry) so a 2/3 quorum cannot be assembled behind one operator cheaply | V3a admits **no false state** — cost is liveness only, bounded to one region-epoch at ±500 bp/quarter drift; V3b is the classic BFT ≥ 2/3 bound — the scheme's strongest stated assumption, carried openly. *Residual:* permissioned set at C2 (§35.2); permissionless registration + erasure-coded DA sampling are Phase-2/3 design items | **[design]** (C3) |
| **V4** | **Verification arithmetic exploits** (R-C11 / D-4) | adversarial node crafting extreme-coordinate high-dimensional outputs (1536–4096-dim embeddings) | engineer components so metric intermediates wrap or truncate → flip an `agree()` verdict → cause a wrongful slash of a compliant executor, or force false agreement on a divergent result | **static accumulation budget** at profile registration: declared width `B ≤ 31` (normative i32 canonical components; wider dtypes canonically quantized down identically everywhere), dimension `D ≤ 2^d`, `d ≤ 24`, fixed accumulation schedule — every intermediate provably ≤ 126 bits (worst row `2B + d + ~21 ≈ 107`), so an unbudgeted profile **cannot register**; verdicts compare squares **exactly** via `wide_mul_128` (128×128→256) — zero truncation at every norm, explicit zero-norm rule (identical zeros agree; zero never agrees with non-zero); out-of-range components = canonical-encoding validity failure → **maximal distance** (disagreement — never an error, never a panic); **no runtime saturation in verdicts** (saturation is semantics-bearing where a flipped bit slashes a compliant node) | overflow is **impossible by construction**, verified once at registration; ≥ 20 bits of headroom at normative bounds; the verdict is algebraically identical to `cos ≥ θ/PPM` — no approximation exists to exploit | **[design]** (App. A.4, §8, §20; verdict math is C3-spec + Part III assertion targets) |

## 3.1 Advisory-derived vectors (GOAT-ARCH-RECON-01, Pass 11)

Two vectors added from the engineering advisory; both are **new mechanism** (Yellowpaper Pass 11),
in audit scope as C1-adjacent code obligations (V5 execution isolation) and C1 protocol behaviour
(V6 F6 predicate).

| # | Vector | Adversarial profile & precondition | Attack mechanics | Neutralizing mechanisms (Yellowpaper) | Quantitative bound / residual | Status |
|---|---|---|---|---|---|---|
| **V5** | **Opaque-payload worker DoS** (R-C12 / amendment D-5) | task submitter; CP7 makes payloads opaque so no pre-scan is possible | broadcast payloads crafted to trip out-of-bounds / unhandled-panic paths in consumer ML runtimes (vLLM/TVM/Triton-class) → crash honest executors at the OS/driver layer → un-slashable, content-blind DoS on household nodes | **fault-isolated execution below the trait** (D-5 conformance): a crash's blast radius is one disposable worker, never the node daemon or ledger client (§5 boundary extended from compile-time to runtime isolation); a crash is **availability churn, not a fault** (R-C5) — emits no receipt, so **zero** slashable faults are manufactured against the victim; **content-blind submitter throttling** on *cross-executor* crash/timeout correlation (keys on the rate of abnormal termination across cluster-disjoint executors, never on payload bytes — CP7 preserved) raising the submitter's escrow (§33.1) recomputably (§8.1) | crash blast-radius = one worker; slashable faults induced = 0; submitter escrow rises ∝ cross-executor damage. *Residual:* isolation must stay lightweight (OS process, not VM) — accessibility watch-item S1; `ISOLATION_MODE`/window/curve **[calibration]** | **[design]** (C1 code obligation) |
| **V6** | **CGNAT / shared-gateway mass false-positives** (R-C13) | *not* an adversary — honest households behind Carrier-Grade NAT / shared 4G-5G gateways in emerging markets, high-rises, mobile-first regions | hundreds of independent households **permanently** share ASN, public-IP pool, backhaul path → a naïve F6 keyed on ASN+latency cohort-merges the whole neighbourhood into one cluster → collective earnings crushed (accessibility catastrophe, §1) | shared ASN/IP declared **insufficient alone** for a merge; merge requires the **CGNAT-non-collapsible conjunction** — aggregate-throughput dependence (one last-mile ceiling vs. independent links that out-scale it) **and** uptime co-transition (co-located hardware cycles together; homes do not); **recomputable de-merge**: a merged cohort splits on published probe evidence of independence (throughput exceeding one last-mile's ceiling, or de-correlated availability), fraud-provable and gatekeeper-free (§14) | false-positive merge of independent CGNAT households → **self-correcting on published data**; a true co-located farm still trips both physical dimensions and is merged. *Residual:* per-last-mile ceiling + availability-correlation threshold **[calibration]** (F5) | **[design]** (refines C1 §14) |

**Dispositions for the advisory's already-covered vectors** (no new mechanism — auditors should
treat these as resolved-by-reference):

| Advisory vector | Disposition |
|---|---|
| **V1.2 Testnet last-revealer entropy** | Already the §19.1 last-revealer analysis; the fix is a **deployment selection** — enable `BeaconMode::DelaySealed` + `NonRevealerPolicy::SubsetWithSlashing` on the testnet (placeholder-VDF verify is acceptable for a *permissioned* set; only R-C4-blocked for public/low-power verifiers). No new mechanism; the "temporary deterministic fallback" the advisory requests already exists as `DelaySealed`. |
| **V2.2 Triple-clamp hysteresis** | This **is** R-C3, now **specified** (not merely intent-recorded) as the two-tier corroboration-gated emergency release valve (§31.1): routine ±500 bp/quarter kept, a wider emergency slew unlocks only on sustained multi-feed multi-epoch corroboration, global-cross-checked and self-re-locking, fraud-provable. |
| **V2.1 Volatility weight-boosting** | Premise **corrected**: the boost is `is_opex`-only (electricity, broadband); the P2P stablecoin premium is an unboosted **anchor** — it is never weight-boosted (§30, R-C14). Bounded residual (unboosted noise at fixed weight, clamp-limited) optionally closed by inverse-volatility **damping** of designated liquid anchors. |
| **V3.2 Fraud-proof → BFT collapse** | This is the **V3b** ≥ 2/3 safety bound already stated openly (above; §19.3). The advisory's remediation (external sharded DA, e.g. Celestia) is the already-listed production path; the **property** (external, erasure-coded, sampling-verifiable DA) is specified while the **platform** stays roadmap decision **D3** — deliberately not hard-committed to a single external dependency, consistent with the minimal-trust posture. |

## 3.2 Advisory-derived vectors (GOAT-ARCH-RECON-02, Pass 12)

Four vectors from the second engineering advisory. Each **hardens a Pass-11 or earlier disposition
against a latent counter-vector**; all are audit-scoped as marked. The lead-with-defense discipline
holds — each adversarial condition is paired with the mechanism's recomputable response.

| # | Vector | Adversarial profile & precondition | Attack mechanics | Neutralizing mechanism (Yellowpaper) | Quantitative bound / residual | Status |
|---|---|---|---|---|---|---|
| **V7** | **Frozen-feed emergency-valve jam** (R-C15) | state-level actor with policy control over one basket feed (a tariff-freeze authority) | pin residential electricity artificially flat during a real hyperinflation → the R-C3 emergency conjunction (electricity ∧ CPI ∧ premium) never completes → the black-swan valve stays shut and households are underpaid exactly when it matters (§1 accessibility failure) | **decoupling detector**: a feed diverging from local CPI by > `MACRO_DECOUPLING_PPM` (400_000) for ≥ `DECOUPLING_EPOCHS` (2) is flagged `state_suppressed` (reusing `symmetric_deviation_ppm`, §30.1) and **dropped from the emergency conjunction** — not the basket — so the valve completes on surviving independent feeds; a hard **`MIN_CORROBORATING_FEEDS` floor (2)** ensures pruning can never itself open the valve; global cross-check + self-relock unchanged (§31.1) | valve triggers on genuine shock even under single-feed suppression; unlock still requires ≥ 2 independent survivors corroborating — dropping feeds cannot manufacture an unlock. *Residual:* thresholds **[calibration]** (F5 macro data) | **[design]** (C3) |
| **V8** | **Submitter-framing via fabricated crashes** (R-C16) | cohort of coordinated executors targeting an honest task submitter | run the R-C12 crash-correlation escrow-throttle **in reverse**: fabricate crash/timeout reports against an honest submitter's tasks to inflate its escrow (§33.1) and throttle it off the network — no toxic payload needed | a crash charges a submitter **only** with an epoch-linked, assignment-bound, **ML-DSA-65-signed `HardwareExceptionLog`** (context `CTX_GOAT_HW_EXCEPTION_LOG`, §V below) from the fault-isolated worker; **anonymous/unsubstantiated hangups default to the executor's own churn (R-C5)** and never touch the submitter; the cross-disjoint-executor correlation gate (§14) still stacks on top (§8.1) | framing now requires forging accountable signatures **and** controlling cluster/ASN-disjoint executors — the conjunction the anti-Sybil layer already prices out; a signed false log is itself fraud-provable | **[design]** (C1 code obligation) |
| **V9** | **Network-throttle residential mimicry** (R-C17 / amendment D-6) | co-located compute farm seeking the idle-residential premium | **down-throttle own bandwidth** + stagger power cycling to hold the F4/F6 *network* fingerprint (throughput ceiling, uptime) under a residential bar → present many co-resident VMs as independent low-throughput households → dodge the density merge and harvest the premium (§13) | a **device-neutral memory-contention timing-entropy probe** (D-6): a standardized bounded micro-benchmark measures cross-identity L1/L2/L3 cache interference — co-resident identities on one physical machine thrash a shared hierarchy (correlated signatures) that separate silicon cannot; an axis the *network* throttle does not touch. Feeds F6 as a **non-collapsible dimension** under the same recomputable de-merge (R-C13). **Emits an opaque `Ppm` scalar; names no device type; neutrality-gated (§9)** (§14) | mimicry defeated on the compute axis while F4/F6 stay device-agnostic; bounded/not-always-on (S1 budget). *Residual:* probe params **[calibration]**; must not force heavy always-on profiling (accessibility watch) | **[design]** (C1 §14 refinement + D.1 obligation) |
| **V10** | **DA-hostage sustained outage** (R-C18) | total external-DA failure — validator partition, content-network dark, or ≥ 1/3 indefinite withhold | the R-C1 `QuorumCertificate` gate makes withholding *safe* (no false state) but not *live*: with no certificate ever forming, no challenge window ever opens → the settlement layer **stalls** indefinitely, every region-epoch frozen. The single-contested-feed fallback (§19.3) covers a targeted withhold, not a systemic outage | **recomputable per-region `DaFallback`**: no certificate anchors for `DA_FALLBACK_EPOCHS` (32) → forced **inline on-chain manifest leaves** at an **`8×` fee** (funds bloat; prices out *induced* fallback; strictly a degraded mode); the recompute-or-slash loop (§34, B-2) runs on definitionally-available on-chain data; **auto-reverts** on the first recovered certificate; O(1) preserved in every non-outage region (§19.4) | fraud-proof liveness survives a total DA outage; blast radius is one region; no vote, no discretion — trigger and revert are both anchored-certificate presence/absence. *Residual:* fallback params **[calibration]**; extends S2 from *withholding* to *outage* | **[design]** (C3) |

## 3.3 Advisory-derived vectors (GOAT-ARCH-RECON-03, Pass 13 — final seal)

The two final vectors, each closing a **residual of a RECON-02 disposition** (V11 hardens R-C16's
worker-signed-log requirement against the hard-kill case; V12 closes the honest-operator liveness
trap left by R-C18's punitive fallback fee). Their disposition seals the Specification Architecture
phase at Yellowpaper v1.0. Lead-with-defense discipline holds.

| # | Vector | Adversarial profile & precondition | Attack mechanics | Neutralizing mechanism (Yellowpaper) | Quantitative bound / residual | Status |
|---|---|---|---|---|---|---|
| **V11** | **Hard-kill evidence erasure** (R-C19) | submitter crafting a CP7-opaque payload that reliably hard-kills executor workers (OOM-killer / `SIGKILL` / cgroup memory-limit trip) | exploit the R-C16 requirement that a charge needs a **worker-signed** `HardwareExceptionLog`: engineer a catastrophic termination that destroys the fault-isolated worker (D-5) *before* it can sign — the crash defaults to executor churn (R-C5), the submitter is never charged, and the more damaging the DoS the more completely it erases its own evidence | the **host `GoatHAL` daemon** — outside the worker's failure domain, so an OOM/`SIGKILL` cannot silence it — ML-DSA-65-signs a **`WatchdogTombstone`** (context `CTX_GOAT_WATCHDOG_TOMBSTONE`, §V; epoch-beacon + assignment-bound; opaque hard-kill class, **no payload bytes / no device type**, neutrality-gated §9); a submitter is charged only on a **quorum of ≥ `WATCHDOG_TOMBSTONE_QUORUM` (3) cluster/ASN-disjoint** host daemons tombstoning the same assignment (§14); a single/absent tombstone charges nobody — R-C5 churn default preserved (§8.1) | full crash spectrum now covered (soft → worker log R-C16; hard-kill → disjoint-quorum tombstone R-C19) with the same content-blind, correlation-gated, fraud-provable discipline; framing needs forged accountable signatures **and** disjoint-cluster control — the §14–§15 conjunction. *Residual:* quorum + taxonomy **[calibration]** | **[design]** (C1 code obligation) |
| **V12** | **Fallback economic liveness trap** (R-C20) | honest orchestrator in a region suffering a genuine, un-induced DA outage (validator partition / content-network dark) | not an attack but a rational-halt failure mode the design must not create: the R-C18 `8×` inline-posting fee, meant to price out *induced* fallback, applies identically to the honest victim of a *real* outage → halting to avoid the 8× is the rational choice → the settlement layer re-stalls, defeating §19.4 | the Emission Allocation Controller **rebates the `(DA_FALLBACK_FEE_MULT − 1) = 7×` premium** from the gap-fill reserve to the orchestrator (net cost `1×`); the 8× is still **charged at point-of-posting** so anti-induction economics are intact for a would-be inducer; rebate gated on the **recomputable `DaFallback` state (§19.4)** + a **fraud-surviving inline manifest** (one per region-epoch); reserve/`M_cap(t)`-bounded; **cost-offset, not surplus** — so R-C8's non-attributable-sink rule holds (§33.2) | honest operators keep settling at normal cost (trap closed); an *inducer* nets `−(§19.3 validator bond burn) + (net-zero fee)` = **strict loss**, so no wash-trade EV; emission exposure bounded by the fallback being rare, per-region, auto-reverting. *Residual:* rebate haircut **[calibration]** | **[design]** (C3) |

## 4. Register index — vectors covered by reference

The full consolidated register is Yellowpaper §36; the following are in audit scope through their
owning sections and the Part III assertions rather than re-derived here:

| Vector | Bound | Owner |
|---|---|---|
| Beacon last-revealer bias (one-bit veto; `2^k` outcomes for `k` colluding withholders) | delay-sealed finalization removes see-then-decide; **placeholder VDF is not production** (R-C4 gates the swap) | §19.1–19.2 |
| Band-edge gaming toward no-attribution (R-VER2) | backfires ~4.5× (46.8% attribution vs 10.4% no-attribution, Iteration 3); `profile_remeasure` is the monitored statistic | §20, §26 |
| Co-located Sybil / density (R-MAT3, R-CAP2) | F4 degradation + F6 cohort-merge on **probe-observed** density; 40/40 merged, 0/200 false positives; endpoint = topological fingerprint, not IP; 72 h smoothing | §14 |
| HLL coverage saturation via crafted inputs (R-MAT4) | probation-start-beacon salt: un-precomputable, stable across the window, roots still bit-identical | §21.1.1 |
| Oracle feed manipulation / flash moves | multi-reporter median + ±500 bp/quarter `clamp_move` + 7-day recompute-or-slash window, DA-gated | §32, §34 |
| Organic-surplus extraction / wash-trading (R-C8) | two-sided CET; non-attributable sinks — Part III §7 assertions | §33.1 |
| Ratchet vs. honest churn (R-C5) | churn ≠ fault: offline nodes emit *no* receipt, never a faulty one; invariant test in A4 scope | §21.3 |
| Patronage capture (fiat-settled, off-chain) | bounded by governance-minimization — no discretionary lever exists to capture; **not** detectable by flow analysis (stated openly) | §15, §35 |

---

# Part III — Audit Validation & Assertions Scope

Assertions are numbered for the audit report. **Method key:** F = fuzzing, P = property-based
testing, D = differential testing vs. independent implementation, V = formal verification
candidate (small pure functions), S = static/structural analysis, M = protocol model checking.

## 5. Panic-free & totality invariants (arithmetic core)

| ID | Assertion | Domain | Method |
|---|---|---|---|
| **A-PF1** | `symmetric_deviation_ppm(prev, cur)` is **total and panic-free on all of `u64 × u64`**: no division by zero (`max(1, prev+cur)`; the only zero-sum case has a zero numerator), no overflow (`abs_diff` cast to `u128` **before** `× 2 × PPM` — worst product < 2^85), output ≤ `SYMMETRIC_DEVIATION_MAX_PPM = 2_000_000`; symmetry `d(a,b) == d(b,a)`; identity `d(a,a) == 0` | full `u64 × u64`; boundary corpus {0, 1, 2^k ± 1, `u64::MAX`} | F, P, **V** |
| **A-PF2** | `wide_mul_128(a, b)` is exact on **all of `u128 × u128`**: `(hi, lo)` equals `a·b` in ℤ (arbitrary-precision oracle); limb-carry correctness at `u64::MAX` boundaries; total, panic-free, no division; lexicographic `(hi, lo)` compare is a correct 256-bit ≥ | full `u128 × u128`; limb-boundary corpus | F, D, **V** |
| **A-PF3** | `cosine_agree(dot, θ, n2a, n2b)`: total on the full typed domain; for budget-conforming inputs with `dot ≥ 0` the verdict is **algebraically equivalent** to `cos(a,b) ≥ θ/PPM` (exact-rational oracle); `dot < 0 ⇒ false`; zero-norm rule (`n2a == 0 ∨ n2b == 0 ⇒ verdict = (n2a == 0 ∧ n2b == 0)`); **no input reaches a saturating or wrapping operation** | typed domain × budget-conforming subdomain; adversarial low-norm corpus (`‖·‖² ∈ {0,1,2,3,4,8}`) | F, P, D |
| **A-PF4** | **Static accumulation budget** (D-4): the registration check itself — for every declared `(B, d, schedule)`, computed worst-case bit-lengths match the A.4 table (`Σ(a_i−b_i)²` ≤ `2B+2+d`; dots/norms ≤ `2B+d`; verdict factors ≤ `2B+d+~21`); a profile exceeding 126 bits **cannot register**; attempt bypass via boundary declarations (`B = 31, d = 24`), non-normative widths, and schedule ambiguity | profile-registration surface | F, S |
| **A-PF5** | `compute_epoch_gap_fill` and `route_surplus`: saturating throughout; outputs non-negative, cap-bounded, reserve/ceiling-bounded on **all** `u64` inputs; `route_surplus` conservation: `to_reserve + burned == surplus` exactly (no unit lost or minted), `to_reserve ≤ ceiling − remaining` | full input space | F, P, **V** |
| **A-PF6** | Basket arithmetic: `cppi_multiplier` accumulates in `u128` with no overflow for all `Ppm × Bp` inputs; `rebalance` output **always** satisfies `Σ weights == 10_000` exactly (largest-remainder) with every weight in `[w_min, w_max]`; `clamp_move` never exceeds ±500 bp/quarter (±250 bp provisional, referenced to the **ramp-predicted** value in `Provisional`, §31.2) | full input space; degenerate histories (all-zero, single-return, `u64::MAX` feeds) | F, P |
| **A-PF7** | Deterministic-HLL: serialization is canonical and injective; fold order invariance where specified; **bit-identical roots across two independent implementations** folding the same receipt stream (R-MAT1 / SC8) | recorded testnet streams + fuzzed streams | D, F |

## 6. Cryptographic-integration invariants

| ID | Assertion | Method |
|---|---|---|
| **A-CI1** | **Signing-context inventory & domain separation** (Part I §1.1): every ML-DSA-65 context enumerated; pairwise cross-context verification fails; every signed structure canonically serialized (injective, length-prefixed) before signing | S, F |
| **A-CI2** | **Replay matrix**: capability records rejected on replayed beacon nonce *and independently* on non-monotone epoch (A-4 — the two checks do not share a failure mode); receipts bound to `window`/`sub_window`; transport frames unreplayable across role/direction (disjoint nonce spaces) | F, M |
| **A-CI3** | **Key/authorization binding**: a receipt verifying under a key not registered for its claimed `node_id` is rejected; a valid-signature receipt from an unassigned node is rejected; C's authorization is accepted only when the beacon-lottery re-derivation reproduces it | F, P |
| **A-CI4** | **Handshake**: ML-DSA signature covers the ML-KEM ciphertext (no unsigned handshake element influences the derived key); key-schedule domain separation; no classical fallback path exists (§3.7) | S, F |
| **A-CI5** | **Beacon**: commit binding (`H(r ‖ salt)` — no second-preimage flexibility at the protocol level); reveal set determinism (sorted); avalanche (any single reveal bit flips the output); delay-seal interface localizes the VDF swap (`BeaconMode`/`DelayProof`/`SealedBeacon`) and the placeholder is **compile-time distinguishable** from production modes | F, M, S |
| **A-CI6** | **Fraud-proof soundness *and* completeness** (SC5): *soundness* — no conservative posting (higher sampling, voluntary snap, B-2 direction) is ever slashable, across the full fraud-class harness; *completeness* — for every less-safe posting class (wrong root, wrong prior, under-sampled `p_class`, over-advanced stage, withheld burst snap) an independent challenger produces a valid proof from published data alone, and the ledger's independent recomputation agrees | P, M, D |
| **A-CI7** | **Layer boundary** (Part I §2): dependency-graph assertion (no protocol→backend edge, including dev/transitive); neutrality-auditor false-negative fuzzing (sub-token, unicode, literal placement); trait-surface review for device-identifying bytes | S, F |

## 7. Non-attributable economic sinks (R-C8) — wash-trade net-negativity **[design / C3]**

The assertion set proving that self-generated organic surplus cannot return to its generator. All
quantities `u64`/`u128`, PPM/BP-scaled; `X` denotes any operator cluster (F6/§15-merged, so
identity-splitting cannot redefine `X`).

**Definitions (per epoch, from Yellowpaper §33–§33.1):** `u_ref` = escrow-derived per-unit usage
revenue (never declared — the recomputable sum of on-ledger escrow releases over settled, verified
work); `payout/unit = min(u_ref, CET_gross) + gap_fill/unit`; `surplus = N_eff × (u_ref −
CET_gross)` when positive, routed `to_reserve = min(surplus, RESERVE_CEILING(t) −
reserve_remaining)`, `burned = surplus − to_reserve`.

| ID | Assertion | Method |
|---|---|---|
| **A-EC1** | **Structural non-attributability**: no identity-, cluster-, address-, or region-typed value flows into `route_surplus` or its callers' sink writes — provable by type/dataflow analysis of the (future) implementation against the normative signature `route_surplus(n_eff, u_ref, cet_gross, reserve_remaining, reserve_ceiling)`, which admits **no identity input**. The reserve is drawn down only by `compute_epoch_gap_fill`, whose per-unit payments are identity-uniform and F6-discounted upstream | S |
| **A-EC2** | **Ceiling before gap-fill**: contributor settlement per effective unit is computed as `min(u_ref, CET_gross)` **before** gap-fill is added; no code path pays a per-unit amount exceeding `CET_gross` when `u_ref > CET_gross` | S, P |
| **A-EC3** | **Wash-trade net-negativity (surplus regime)**: for any cohort `X` self-dealing at `u_ref > CET_gross`: `Δ_X = N_eff,X × (CET_gross − u_ref) − C_compute,X < 0` **strictly** — `X` pays `u_ref` into escrow per unit and receives back at most `CET_gross`; the difference exits to sinks `X` cannot draw from except as an identity-uniform, F6-discounted participant. Assert over a pure-integer parameter sweep (all quantities `u128` intermediates); include the boundary `u_ref = CET_gross` (surplus = 0, no path flips sign) | P, simulation |
| **A-EC4** | **Gap-fill farming bound (shortfall regime)**: self-dealing at `u_ref < CET_gross` to farm emissions is bounded by (a) `N_eff` being cluster-merged and S_o-capped upstream (a Sybil cannot inflate its effective units), (b) the monotone-decaying `M_cap(t)` and reserve bound, and (c) the work requirement — receipts must be *verified* work through the full Part-V loop at real compute cost. Assert the composed bound in the same integer simulation; confirm no epoch can mint beyond `min(M_cap(t), reserve)` | P, simulation |
| **A-EC5** | **`u_ref` fraud-provability**: a posted `u_ref` differing from the recomputable escrow sum (either direction) is rejected/challengeable; off-protocol settlement yields no escrow, no receipts, no GCU — assert no partial-participation path credits unescrowed revenue into `u_ref` | S, M |
| **A-EC6** | **Reserve conservation**: `reserve_remaining` changes only by gap-fill draw-down and surplus refill; refill never exceeds `RESERVE_CEILING(t)`; `RESERVE_CEILING(t)` is monotone per the genesis schedule — no path grows the reserve past its disclosed cap | P, **V** |

*Status honesty:* the R-C8 layer is **[design]** — A-EC1/A-EC2/A-EC5 are specification-conformance
assertions against the normative snippets (and become code assertions in Phase 3); A-EC3/A-EC4/A-EC6
are validated now by pure-integer simulation and formal argument over the spec.

## 8. Deliverables requested from the auditing firm

1. **Findings register** keyed to assertion IDs (A-PF*, A-CI*, A-EC*) and configuration (C1/C2/C3),
   with reproduction inputs for every arithmetic finding (exact integer inputs — no lossy repro).
2. **Signing-context inventory** (A-CI1) as a standalone artifact — it becomes normative Appendix
   material in the Yellowpaper under the §4 amendment discipline.
3. **Formal-verification reports** for the V-marked targets (`symmetric_deviation_ppm`,
   `wide_mul_128`, `route_surplus` conservation, reserve conservation) — these are small, pure,
   loop-free or simply-looped integer functions selected for tractability.
4. **C2 delta-assessment**: which C1 assurances weaken at the public-testnet boundary (real ledger
   H3, real network H4, external operators, permissioned Validator Set) — feeding the Phase-2
   go/no-go (roadmap decision D1).
5. **Explicit re-confirmation of the two known-open items**: the placeholder VDF (R-C4) must not
   ship, and the Python reference must not be used as an oracle for B-6-touched behavior (D6
   decision pending).

---

# Part IV — The Formal Cryptographic Boundary Map

This is the **audit-final** boundary map: the ordered transmutation of a datum from untrusted
consumer space into post-quantum-secured consensus space, with the explicit enforcement guard at
every interface. It consolidates and supersedes the §1 sketch, incorporating the Pass-11/12 runtime
boundaries (the isolated worker, the co-location probe). Each `P`-stage is a **trust
transmutation** — the point at which a datum's trust status changes — and each is labelled with the
one guard that effects the change. Nothing crosses a boundary except through its guard.

```
        UNTRUSTED SPACE                    │            POST-QUANTUM CONSENSUS SPACE
                                           │
  P0 ── P1 ──────── P2 ───────────────────┼──── P3 ──── P4 ──── P5 ──── P6 ──── P7
 opaque  KEM        probe                  │   isolated  canon.  ML-DSA  fold     anchor
 payload transport  (network+compute)      │   worker    binary  signing enforce  (root+bond)
                                           │
 ◀─────────── content-blind ──────────────┼──────── attributable & recomputable ────────▶
```

## 9. Boundary transmutation table

| Stage | Transmutation | Trust before → after | **Enforcement guard** | Invariant held |
|---|---|---|---|---|
| **P0 — Opaque Payload** | consumer submits a `Task` | untrusted, uninspected → untrusted, *structurally uninspectable* | **CP7 structural absence** (§3.3): the `Task` type carries no model/license/content field; there is no place in the type system for a content policy, so the protocol *cannot* branch on payload bytes | Content-neutrality (CP7) — enforced by construction + the neutrality auditor (§9) |
| **P1 — KEM Transport** | payload enters the wire | plaintext-untrusted → E2E-encrypted, peer-authenticated | **ML-KEM-768 encapsulation + ML-DSA-65 signature over the ciphertext** → AES-256-GCM channel; disjoint per-direction nonce spaces; length-prefixed frames (§16–17). No classical fallback exists (§3.7) | PQ-only confidentiality + authenticity; no key–nonce reuse |
| **P2 — Probe** | endpoint & device measured before trust is extended | self-asserted → **measured** | **network fingerprint** (F4/F6 topological probe — ASN, latency multilateration, aggregate-throughput ceiling, uptime co-transition; §14, R-C13) **+ compute co-location probe** (device-neutral memory-contention timing entropy; amendment D-6, R-C17). Both are *probe-observed, never declared* (§3.4); the probe emits opaque scalars and names no device type (§3.5, neutrality-gated) | Measured-work-only; device-agnosticism; anti-Sybil physics |
| **P3 — Isolated Worker** | execution runs below the trait | protocol space → **fault-contained device space** | **the `GoatHAL` trait is the only aperture** (compile-time: no protocol→backend dependency, §5) **+ fault-isolated execution** (amendment D-5, R-C12: a disposable worker whose crash blast-radius is itself only) **+ envelope binds over policy** (D-1). A crash is churn, not a fault (R-C5); a submitter is charged only via a signed `HardwareExceptionLog` (R-C16), or — for a hard-kill/OOM that erases the worker's log — a disjoint-quorum host-daemon `WatchdogTombstone` (R-C19) | Layer boundary (compile + runtime); node liveness; no privilege escalation into consensus |
| **P4 — Canonical Binary Representation** | raw device output → consensus-visible datum | device-specific → **device-blind, canonically serialized** | **A-6 commitment** (§10): deterministic, field-ordered, length-prefixed serialization over task semantics only, SHA3-256; carries no device identity (D8-behavioral). Non-textual outputs canonicalized + compared by pure-integer metrics under the D-4 static accumulation budget (§20, App. A.4) | Serialization injectivity; device-blindness; overflow-proof verdicts |
| **P5 — ML-DSA-65 Domain-Separated Signing** | canonical datum → executor-attributable record | anonymous → **cryptographically attributed** | **ML-DSA-65 signature over the attributable core** in a **dedicated domain-separation context** (Part V registry); `KeyRegistry` binds the key to the `node_id`; `AuthorizationSet` (signed assignment log + beacon-lottery-re-derived C) binds authorization (§18.1–18.2) | Attributability; domain separation; authorization ≠ mere validity |
| **P6 — Fold Enforcement** | attributed receipts → accumulator state | asserted → **each element checked or recomputed** | **`fold_verified_attributed`** (§18.4): (a) signature vs. registered key, (b) authorization, (c) any fault flag backed by a re-deriving `EscalationRecord` (§18.3). No folded element is trusted rather than checked | Fraud-provable-by-recomputation; no orchestrator framing |
| **P7 — Anchoring** | node-local state → public ledger anchor | private → **publicly adjudicable** | **minimal ledger**: window accumulator root + claimed transition + bond; deterministic-HLL bit-identical roots (R-MAT1); **two independent recomputations** (challenger + ledger) must agree (§22, SC5). At C3: DA availability gated on the `QuorumCertificate`, with the R-C18 `DaFallback` preserving liveness under outage (§19.3–19.4) | Public verifiability; directional-fraud (B-2); data availability |

**The two half-planes.** Everything left of P3 is **content-blind** — the protocol acts without ever
reading a payload byte (P0's structural guarantee carried through). Everything from P3 rightward is
**attributable and recomputable** — every datum is signature-bound and independently re-derivable.
The boundary is where an opaque, untrusted input becomes a measured, isolated, canonically-committed,
signed, folded, anchored fact. **No stage trusts the stage before it**: each re-establishes its
property by measurement (P2), isolation (P3), canonicalization (P4), signature (P5), recomputation
(P6), or independent agreement (P7).

---

# Part V — Key Context Inventory & Domain Separation

The single most consequential integration-audit target (A-CI1). Every ML-DSA-65 signature in the
system must be **domain-separated**: a signature produced for one purpose must be cryptographically
invalid for every other, or a signed structure from one context could be replayed as authorization
in another. This is achieved by a mandatory per-purpose **context string**, bound into the signature,
combined with a canonical serialization that guarantees the signed preimage is injective.

## 10. The Authorized Domain Context Registry

Every signing site binds a distinct, versioned context byte-string. The context is supplied as the
ML-DSA `ctx` parameter (FIPS 204 §5.2 supports a context of up to 255 bytes) **and** prepended to
the serialized message before hashing — belt-and-suspenders domain separation, so separation holds
even under a primitive swap whose `ctx` semantics differ. All strings are ASCII, **length-prefixed**
(one leading `u8` length byte; every string ≤ 255 bytes), and versioned (`/v1`) so a future context
revision is itself a distinct domain.

**Scheme:** `CTX = len_u8 ‖ "GOAT/v1/" ‖ <domain-tag> ‖ 0x01`. The trailing `0x01` is a
separation sentinel; `<domain-tag>` is unique per row. No tag is a prefix of another (the
length-prefix + fixed sentinel already guarantee non-ambiguity, but tags are kept prefix-free as
defence in depth).

| Context constant | Byte-string (`"GOAT/v1/" ‖ tag ‖ 0x01`) | Signed structure | Yellowpaper | Status |
|---|---|---|---|---|
| `CTX_GOAT_CAPABILITY_RECORD` | `GOAT/v1/cap\x01` | `CapabilityRecord` (measured capability + density witness) | §11 | **[shipped]** |
| `CTX_GOAT_ATTESTATION_CHAIN` | `GOAT/v1/attchain\x01` | rolling re-attestation chain link (`prev_record` binding) | §12 | **[shipped]** |
| `CTX_GOAT_EXEC_ATTESTATION` | `GOAT/v1/exec\x01` | `ExecutionAttestation` attributable core (incl. `sub_window`) | §18.1 | **[shipped]** |
| `CTX_GOAT_ASSIGNMENT_LOG` | `GOAT/v1/assign\x01` | orchestrator signed assignment log → `AuthorizationSet` | §18.2 | **[shipped]** |
| `CTX_GOAT_ESCALATION_RECORD` | `GOAT/v1/escal\x01` | `EscalationRecord` (three receipts + raw results) | §18.3 | **[shipped]** |
| `CTX_GOAT_BEACON_COMMIT` | `GOAT/v1/beacon\x01` | commit-reveal beacon commitment `H(r ‖ salt)` | §19.1 | **[shipped]** |
| `CTX_GOAT_TRANSPORT_HS` | `GOAT/v1/tls-hs\x01` | transport handshake auth (signature over the KEM ciphertext) | §17 | **[shipped]** |
| `CTX_GOAT_HW_EXCEPTION_LOG` | `GOAT/v1/hwexc\x01` | `HardwareExceptionLog` (epoch + assignment-bound crash proof) | §8.1 (R-C16) | **[design]** (Pass 12) |
| `CTX_GOAT_DA_ATTESTATION` | `GOAT/v1/gda\x01` | validator DA attestation over `(epoch, region, CID)` | §19.3 | **[design]** |
| `CTX_GOAT_ORACLE_POSTING` | `GOAT/v1/oracle\x01` | `OracleWindowPosting` / `FeedManifest` poster signature | §32 | **[design]** |
| `CTX_GOAT_ENTROPY_PROBE` | `GOAT/v1/probe\x01` | signed `contention_timing` probe attestation | §14 (D-6, R-C17) | **[design]** (Pass 12) |
| `CTX_GOAT_WATCHDOG_TOMBSTONE` | `GOAT/v1/wdog\x01` | host-daemon `WatchdogTombstone` (epoch + assignment-bound hard-kill proof) | §8.1 (R-C19) | **[design]** (Pass 13) |

> **Migration note.** The §19.3 text uses the legacy prefix `H("GDA\x01" ‖ epoch ‖ region ‖ CID)`.
> The audit should treat `CTX_GOAT_DA_ATTESTATION` above as the harmonized form; reconciling the
> in-text `GDA\x01` to the versioned scheme is a **pre-C3 spec fix** (enters as a §4 amendment). No
> shipped signature uses the legacy prefix — the DA layer is **[design]**.

**Audit assertions (extend A-CI1):**

| ID | Assertion | Method |
|---|---|---|
| **A-CI1a** | **Exhaustiveness**: every ML-DSA sign/verify call site in `goatcoin-rs` maps to exactly one registry row; no call site signs with an empty or defaulted context | S (call-graph enumeration) |
| **A-CI1b** | **Pairwise separation**: for every ordered pair of contexts `(X, Y), X ≠ Y`, a signature valid under `X` fails verification under `Y` — including the design contexts once implemented; fuzz across near-collision tags | F, P |
| **A-CI1c** | **Version isolation**: a `/v1` signature never verifies against a hypothetical `/v2` context (forward-separation for the revision path) | S, F |
| **A-CI1d** | **Replay across sites**: no serialized signed structure from one site is a valid preimage at another (e.g. an `ExecutionAttestation` replayed as an `EscalationRecord` element) | F, M |

## 11. The Canonical Serialization Invariant

Domain separation is necessary but not sufficient: two *distinct* logical structures that serialized
to the *same* bytes under the same context would still be confusable. Injective serialization closes
this — the signed preimage uniquely determines the logical structure.

**The invariant (binding on every signed structure).** Serialization is **canonical, length-prefixed,
and byte-aligned**:

1. **Fixed field order.** Fields are serialized in a single, spec-declared order; no map-iteration
   order, locale, or platform quirk reaches the encoder (App. A, contract 5).
2. **Length-prefixed variable fields.** Every variable-length field (signatures, keys, CIDs, token
   sequences, reporter-leaf blobs) is preceded by a fixed-width `u32` length. No delimiter-scanning,
   no ambiguous concatenation — `A ‖ B` can never be reparsed as `A' ‖ B'` (the property that makes
   the A-3 chain binding, §12).
3. **Fixed-width, fixed-endian integers.** All integers are little-endian fixed-width (`u32`/`u64`);
   no variable-length integer encoding whose byte boundaries could shift.
4. **Byte-aligned, no padding ambiguity.** No sub-byte packing; no optional padding a second encoder
   could add or omit. The encoding of a structure is **unique** — one logical value, one byte-string.
5. **Serialize-then-sign, never sign-then-describe.** The signature covers the canonical bytes
   directly; every consensus-relevant field is *inside* the signed region (the P4→P5→P6 chain), so
   no unsigned field influences a downstream decision.

**Why injectivity is load-bearing.** Injective + length-prefixed serialization is exactly what makes
the receipt-provenance chain (§18) and the accumulator roots (§22, R-MAT1) reproduce bit-identically
across independent recomputers — the property the whole fraud-proof edifice rests on (§3.8). A
non-injective encoding would let two different receipts share a commitment, breaking attribution; an
unprefixed concatenation would let a boundary shift forge a different structure with the same bytes.

**Audit assertions:**

| ID | Assertion | Method |
|---|---|---|
| **A-CS1** | **Injectivity**: no two distinct logical structures (across all signed types) serialize to identical bytes; fuzz adjacent field-boundary cases (empty vs. absent variable fields; max-length fields) | F, P |
| **A-CS2** | **Round-trip determinism**: `serialize` is a total function; `deserialize∘serialize == id` on all valid structures; `serialize` output is byte-identical across platforms (x86/ARM) and across the two reference implementations | D, P |
| **A-CS3** | **No unsigned consensus field**: every field consumed by a downstream protocol decision is inside the signed/committed region — enumerate the fold-boundary consumers (A-CI, Part III §6) and confirm coverage | S |
| **A-CS4** | **Length-prefix soundness**: no parser accepts a frame whose declared lengths do not exactly tile the buffer (no trailing bytes, no overlap, no length-field overflow) | F |

---

*Maintained under the Yellowpaper §4 amendment discipline: findings enter as numbered amendments
against the owning sections; this document tracks the Yellowpaper by version (currently v0.2,
amendments through Pass 12) and is superseded section-by-section as C2/C3 surfaces become code.*

---

# Part VI — Accepted Post-Testnet Realities

> **Intellectual-honesty disclosure for the external audit.** The vectors in Parts I–V are *closed*
> (mitigated in code with conformance vectors). This part documents risks we are **intentionally
> accepting** for the Testnet as long-term governance/calibration challenges rather than code fixes.
> Each is stated plainly, with its status, why it is accepted, how it is managed, and — where
> applicable — the **exit criterion that must clear before a Mainnet launch carrying real economic
> value**. None of these is a cryptographic defect; all three are socio-economic or roadmap items.

## 12. R-NEUT1 — The Neutrality Paradox (Goodhart's Law) **[accepted trade-off]**

**Statement.** The Golden Goal forbids the protocol from naming a device type (Core Principle 7;
*"if it names a device type, it's wrong"*). Fairness is therefore evaluated on *abstract measured
telemetry* (the parts-per-million density/availability/envelope signals). By Goodhart's Law, once a
proxy metric becomes the reward target it ceases to measure what it proxied: a well-capitalized
adversary can engineer hardware and network topology that maximize *our exact formulas* — approaching
the appearance of diverse consumer participation while centralizing rewards.

**Why accepted.** This is **inherent to neutrality**, not a fixable bug. The only "cure" — whitelisting
"consumer" hardware — is centralizing, unenforceable, philosophy-violating, and worse than the
disease. Critically, reward is **not** `f(performance)`: assignment is a lagged-entropy **lottery**
(`state::derive_authorization_set`), not a race, and reward is **topology-discounted** via
`density_witness_ppm` / the F5 endpoint-density reductions (device-neutral yet structurally anti-farm).
The residual is the *Sybil-with-diversity* adversary (paying for residential-IP / ASN diversity); the
density mechanism raises its cost without making it infinite.

**Management (ARC-01-M1–M4, ongoing calibration program).**
- **M1** — concave (sub-linear) per-endpoint/-ASN/-cluster reward, so co-location has sharply
  diminishing returns.
- **M2** — moving-target verification (rotate the measured challenge each epoch via
  `CTX_GOAT_ENTROPY_PROBE` / `contention_timing`) so a farm cannot pre-optimize to a static formula.
- **M3** — the `p_class` maturity ratchet as an anti-blitz brake (identity churn forfeits accrued
  maturity).
- **M4** — a standing adversarial-ML red-team: each calibration epoch, fit a cost-minimal telemetry
  that maximizes reward and re-tune the `[calibration]` curves.

Operational mitigations for R-NEUT1 are detailed in ARCHITECTURE.md §6.3 and the ongoing ARC-01-M1–M4
calibration program.

**Exit criterion.** None in the absolute sense — this is a permanent managed risk inherent to device
neutrality. However, parameter governance retains the ability to tighten diversity curves, maturity
ratchet speed, and challenge rotation during each calibration epoch. The residual Sybil-with-diversity
adversary is bounded but never eliminated.

## 13. R-NEUT2 — Patronage & Coordinated Subsidy **[open, governance-bounded]**

**Statement.** The on-chain economics cannot distinguish *organic* small-actor participation from
*subsidized* participation: an external patron (a whale, a state actor, an exchange) can inject
off-protocol capital to fund thousands of home-appearing nodes at a deliberate operating loss, in
order to accumulate influence, rewards, or governance weight — defeating the **Thin-Pool Principle**
(the bounded gap-fill yield reserve, `M_reserve`/`M_cap`, whose solvency was stress-tested in Track
E3). Because the subsidy is off-chain, no purely on-chain rule can detect it directly.

**Status.** **Open and governance-bounded** — *not* code-solvable at V1.0. It is the economic dual of
the Sybil-with-diversity vector (R-NEUT1): where R-NEUT1 games the *metric*, R-NEUT2 pays to *sustain
uneconomical honesty-shaped participation*.

**Management.** Monitored via concentration telemetry (endpoint/ASN density trends, reward-share
Gini, sudden participation surges) and responded to through **parameter governance** — tightening
diversity requirements, adjusting the gap-fill cap, or introducing a stake-cost curve for concentrated
identities. A future proof-of-diversity or superlinear stake-cost mechanism is a candidate code fix
but is out of V1.0 scope.

> **Critical Architecture Rule:** The response playbook for R-NEUT2 monitoring must remain strictly
> out-of-band and human-governed. Future maintainers must never attempt to automate token
> concentration responses via an on-chain state transition loop, as doing so introduces external
> network dependencies that violate core state determinism.

**Exit criterion (pre-real-value Mainnet).** A documented monitoring dashboard **and** a written
governance-response playbook must exist and be exercised on Testnet before Mainnet carries real
economic value. The residual (a patron willing to burn capital indefinitely) is acknowledged as
irreducible and bounded only by the patron's finite budget vs. the reserve's solvency envelope.

## 14. R-C4 — The VDF Placeholder (last-revealer bias hardening) **[roadmap blocker for real-value Mainnet]**

**Statement.** The epoch entropy beacon (`CTX_GOAT_BEACON_COMMIT`, `prior_epoch_entropy`) uses a
commit-reveal scheme with **lagged** entropy: the seed for epoch `E` is the *finalized* entropy of
`E-1` (RECON-09), which defeats last-revealer **withholding** — the last revealer cannot bias epoch
`E`'s assignment because its seed is fixed before `E` opens. However, complete last-revealer **bias**
hardening *within* the reveal window (grinding on reveal ordering/inclusion to steer the aggregated
output) requires a **Verifiable Delay Function** so the final beacon value is unpredictable-yet-
verifiable even to the participant who acts last. **The current beacon integrates a VDF placeholder,
not a production VDF.**

**Status.** **Accepted for Testnet** (no real economic value at stake, so the marginal
grinding-advantage is not worth an attacker's cost). Risk register ID **R-C4**.

**Exit criterion (hard Mainnet gate).** A production, audited VDF — e.g., a class-group Wesolowski/
Pietrzak construction or a threshold-VRF drand-style beacon — MUST replace the placeholder **before**
any Mainnet launch that carries real economic value. Until then, the lagged-entropy design bounds the
exposure to *reveal-ordering grinding within one epoch*, not to *withholding*.

## 15. Post-Testnet risk register index

| ID | Risk | Class | Status | Mainnet-with-value gate |
|----|------|-------|--------|--------------------------|
| **R-NEUT1** | Neutrality Paradox (Goodhart) | Socio-economic | Accepted trade-off | None — perpetual ARC-01-M1–M4 calibration |
| **R-NEUT2** | Patronage & Coordinated Subsidy | Economic | Open, governance-bounded | Monitoring dashboard + exercised response playbook |
| **R-C4** | VDF placeholder | Cryptographic roadmap | Accepted for Testnet | **Blocker** — production audited VDF required |

*These three are the only knowingly-accepted residuals at the V1.0 freeze. R-C4 is a hard gate for a
real-value Mainnet; R-NEUT1/R-NEUT2 are standing governance programs. All are disclosed to the
auditing firm per Part III §8.*
