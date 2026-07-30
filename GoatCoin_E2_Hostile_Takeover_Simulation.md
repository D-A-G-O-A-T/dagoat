# GoatCoin (GOAT) — E2 Industrial-Consolidation Stress Test

### *Track E2: the S_o Concentration Factor Campaign — regional capture economics under the physical anti-capture stack*

> **Version 1.0 (draft, 2026-07-07), aligned to `GoatCoin_Yellowpaper.md` v1.0 (sealed),
> `GoatCoin_Threat_Model.md` v1.3, the F5 study design (as amended F5-A1/A2), and the E1
> simulation record (as amended E1-A1/A2).** This document specifies **E2**, the second Phase-2
> economic campaign (colloquially the *takeover simulation*; this document uses the project's
> node-and-condition vocabulary throughout): a deterministic, pure-integer stress test proving
> that a well-capitalized industrial operator attempting to capture a regional orchestrator pool
> and its localized Contributor Earnings Target cannot do so at positive yield — that **capture
> must be bought at a structural loss** (the Thin-Pool Principle, §2), now demonstrated against
> the *strongest evasion tactics the F5 reference arm calibrates* (conditions M3/M4) and on top
> of the E1-patched settlement dynamics.
>
> **Defensive purpose statement.** This is defensive validation of a decentralized compute
> network's anti-monopolization mechanisms, conducted so that dispersed household contributors
> retain viable earnings under industrial consolidation pressure. Per
> `goatcoin-rs/CONTENT_FILTER_GUIDELINES.md`, the document describes **operator clusters and
> observable conditions** (a *consolidation condition*, a *capture cohort*, a *masquerade
> condition*), never actors and intents, and every condition is paired with the mechanism's
> recomputable response and its quantitative bound.
>
> **Numeric convention.** Pure-integer per Yellowpaper Appendix A: `Ppm`/`Bp`/`MicroUsd`/`Epoch`,
> `u128` cast-before-multiply, floor division, saturating arithmetic. Every worked number is
> floor-exact from the stated strawmen and is the expected value the assertion register (§6)
> pins. Cost-side constants are **pre-F5 placeholders** (the F5 `C_SITE` manifest replaces them;
> §7): E2's *inequalities and grid structure* are the deliverable, the margins recompute when F5
> lands.

---

## 0. Scope and inputs

### 0.1 What E2 proves

Three claims, one per output-assertion family:

1. **The Thin-Pool inequality (A-E2-1):** the fully-loaded cost of the F6-evading deployment
   (sole-tenant silicon, independent last miles, idle-duty scheduling — the F5 M4 endpoint and
   its cheaper interior variants) exceeds the maximum extractable value from the regional
   reward pool, per identity-month, across the entire consolidation grid — with the sharpest
   form: **hardware amortization plus idle-duty power alone exceed the revenue ceiling** at
   new-capital strawmen.
2. **The pincer (A-E2-2):** cost-saving consolidation (grouping identities onto shared silicon
   or shared last miles beyond the plausible-density band) triggers the F4 degradation /
   F6 cohort-merge / R-C17 coupling stack, collapsing the effective multiplier faster than the
   consolidation saves cost — **both branches of the trade are negative; the grid has no
   profitable interior point.**
3. **Capture failure independent of spend (A-E2-5):** even at cost-breakeven boundary
   assumptions, the cluster-level `S_o` concentration factor hard-plateaus any single operator's
   aggregate take, and the `κ ≥ 1%` constitutional floor plus the honest-attainment invariant
   keep small nodes viable — **monopolization fails structurally even where yield reaches
   zero.**

### 0.2 System configuration and inputs

| Input | Source | Status |
|---|---|---|
| F4 density curve, F6 merge conjunction (incl. R-C17 coupling), operating characteristics | §14 / Track A2 (F5) | strawman placeholders until the F5 manifest lands (§26.3 F5 doc); E2 re-runs mechanically on the manifest |
| M-condition evasion cost structure (M0–M4) | F5 §14.3 reference arm / `C_SITE` | pre-F5 placeholders (§2.2) |
| Localized CET / settlement dynamics (incl. valve + E1-A2 overshoot envelope) | Part VII as stressed by E1 | E1-patched harness reused as the settlement backdrop |
| S_o, κ, spread rule, P_r | §23–24 | S_o normative strawman formalized below (§1.1) |
| Verification-layer integrity (assignment logs, beacon lottery, escalation) | Part IV–V **[shipped]**; Q1/R-VER1 results | consumed as proven — E2 does not re-litigate verification, it prices the economics on top |

Harness placement mirrors E1 (§0.2 E1 doc): Rust normative crate + Python mirror, bit-identical
`e2stats.json` (A-E2-8), fully deterministic, verbatim-port mandate inherited (E1-A1), predicates
ported from the `goat-protocol/src/verification.rs` ground truth where shipped (the q1-script
convention).

---

## 1. The system under test, formalized

### 1.1 The S_o concentration factor — normative harness strawman

§23 specifies S_o as "reward share falls as an operator's share `s` of recent network work rises
(diminishing-returns curve)" without pinning the curve. E2 formalizes the harness strawman
(entering the Yellowpaper as the S_o reference form by amendment if E2 closes green):

```rust
pub const S0_KNEE_PPM: Ppm = 50_000;    // 5% of recent network verified work  [calibration]

/// Concentration factor, cluster-level (F6/§15-merged cluster share s_ppm).
/// Full weight below the knee; hyperbolic beyond. Pure integer, total.
pub fn s_o_ppm(s_ppm: Ppm) -> Ppm {
    if s_ppm <= S0_KNEE_PPM { PPM }
    else { (S0_KNEE_PPM as u128 * PPM as u128 / s_ppm as u128) as u64 }
}
```

**The plateau property (load-bearing):** a cluster's aggregate take rate is
`s · s_o_ppm(s) / PPM = min(s, S0_KNEE_PPM)` — beyond the knee, the marginal reward of
additional share is **exactly zero**. Growth buys nothing; the knee is the structural ceiling on
any single operator's fraction of the pool. (A softened `γ`-family `S_o = (knee/s)^γ`, `γ ∈
(0,1]`, is the **[calibration]** generalization; the harness runs `γ = 1` and sweeps the family
in §7.)

### 1.2 The composed reward pipeline (per identity, per month)

```
revenue/id-month = GCU_h_month × localized_target × q_network(d) × s_o_ppm(s) × gates
```

- `GCU_h_month = 240` (8 h/day × 30 d — the **Calibration Law duty gate**, §3.1/§24: idle-premium
  eligibility prices *time*; a machine that could deliver 720 h delivers 240, tripling effective
  CapEx per delivered GCU-h. Free power does not change this arithmetic.)
- `localized_target = 83_333 MicroUsd/GCU-h` (the §1 north-star: ≈ $20/month for the reference
  contributor; κ_thin already inside it, §27–28).
- `q_network(d)` — the F4 strawman `max(100_000, 850_000·(5/d)^1.5)` as a monotone `Ppm` table
  (F5-A2 operative frame): `d ≤ 5 → 850_000+premium ⇒ full ceiling`; `d = 8 → 420_000`;
  `d = 16 → 148_495`; `d ≥ 21 → 100_000` floor.
- `gates` — residential last-mile attestation (§13: a datacenter fails *by construction* → no
  idle premium, commodity/service lanes only, which are themselves capped at 25–30% per cluster,
  §24); F6 merge state (merged ⇒ one cluster for S_o/κ/coverage); P_r if single-grid.

### 1.3 The cost side — the consolidation grid

The single decision variable the operator controls is the **consolidation factor `c`** —
identities per physical site — traded against detection:

| Resource | Can it consolidate? | Enforcing mechanism |
|---|---|---|
| Silicon (one identity per physical machine) | **No** below detection — co-resident VMs couple in the contention probe | R-C17 / D-6 (F5-calibrated ≥ 99% detection at ≤ 0.1% FP) |
| Last mile (identities per access line) | Only within the plausible-density band `d ≲ 5` | F4 degradation + F6 merge on the topological fingerprint; F5-A1 peak estimator closes the micro-burst escape; R-C13 conjunction closes the CGNAT excuse |
| Uptime schedule | No — co-transition is a merge dimension; staggering is priced ops labor | §14 conjunction + F5 M2 cost measurement |
| Duty cycle | No — idleness is the eligibility gate itself | Calibration Law (§3.1, §24) |

**Pre-F5 cost placeholders (new capital, per identity-month, `MicroUsd`):**

| Term | Value | Basis |
|---|---|---|
| `HW_AMORT` | 16_666_666 | $600 consumer node / 36-month straight line |
| `LINE` | 35_000_000 / c | $35 independent residential access, shared per site up to the density band |
| `POWER_IDLE` | 5_400_000 | 150 W × 8 h/d × 30 d × $0.15/kWh (duty-gated) |
| `OPS` | 10_000_000 / c | per-site labor/logistics, amortized across co-sited identities |

---

## 2. Worked canonical grid — W-1 (the masquerade branch)

Cohort holds the residential masquerade (M3/M4 tactics: sole-tenant silicon per identity,
bandwidth shaping at 1-s granularity per F5-A1, staggered uptime) and sweeps `c`:

| c (ids/site) | cost/id-month | `d` | `q_network` | revenue/id-month | **yield/id-month** |
|---|---|---|---|---|---|
| 1 (= M4) | 67_066_666 | 1 | full | 19_999_920 | **−47_066_746** |
| 4 | 33_316_666 | 4 | full | 19_999_920 | **−13_316_746** |
| **5** | **31_066_666** | 5 | full (band edge) | 19_999_920 | **−11_066_746** ← grid minimum loss |
| 8 | 27_691_666 | 8 | 420_000 | 8_399_966 | **−19_291_700** |
| 16 | 24_879_166 | 16 | 148_495 | 2_969_876 | **−21_909_290** |

Worked check at the optimum (`c = 5`): `16_666_666 + 35_000_000/5 + 5_400_000 + 10_000_000/5 =
16_666_666 + 7_000_000 + 5_400_000 + 2_000_000 = 31_066_666`; revenue at the full ceiling
`240 × 83_333 = 19_999_920`; yield `= −11_066_746` µUSD/id-month. **Cost floor / revenue ceiling
= 1.553×** at the evasion-optimal point.

**The hardware-plus-power lemma (A-E2-1's sharpest form).** At new-capital strawmen,
`HW_AMORT + POWER_IDLE = 16_666_666 + 5_400_000 = 22_066_666 > 19_999_920` — the deployment is
net-negative **even with free connectivity, free labor, and perfect evasion** (ratio 1.103).
The two irreducible terms are exactly the two quantities the protocol prices by design: capital
time (the Calibration Law — 240 of a possible 720 GCU-h) and the physical footprint of genuine
distribution. This is §24's "cheap power buys margin, not share" made arithmetic: zeroing the
power term still leaves `16_666_666 < 19_999_920` only if CapEx amortization alone is the cost —
at which point the operator is buying consumer hardware and placing it on independent residential
last miles at 8 h/day duty, i.e. **it has become the dispersed residential infrastructure the
network wants**, earning ordinary market return (§14's breakeven-at-best endpoint).

**The used-capital boundary (honest edge, pinned not hidden).** Depressed hardware costs
($200/node → `HW_AMORT = 5_555_555`) shift the `c = 5` total to
`5_555_555 + 7_000_000 + 5_400_000 + 2_000_000 = 19_955_555` vs `19_999_920` — **breakeven
within 0.2%** (+44_365 µUSD/id-month). This reproduces the sealed spec's own claim verbatim
(§26: residential-Sybil closes to *breakeven-at-best*, iteration 2). At breakeven: zero excess
return, and §1.1's plateau still caps the aggregate share at the knee — see A-E2-5. The
breakeven boundary's location is the single most F5-sensitive number in E2 (§7).

## 3. Worked consolidation branch — W-1c (grouping to save cost)

The cohort abandons per-identity silicon (`c = 40` VMs on shared industrial servers behind one
warehouse line, condition M0/M1):

- **Cost falls:** `8_000_000_000/40/36 + 60_000_000/40 + 2_000_000 + 250_000 ≈ 9_305_555`
  µUSD/id-month.
- **Detection composes:** R-C17 contention coupling (co-resident VMs, F5 OC ≥ 99%) **and** F4
  density (`d = 40 → q = 100_000` floor) **and** F6 merge (40 identities → **one** cluster for
  S_o/κ/coverage) **and** the §13 residential gate fails on the warehouse last mile → **no idle
  premium at all**: the cohort earns commodity/service-lane rates under the lane caps — the Q1
  iteration-2 measured regime (**≈ 2% capture, −$160k to −$200k/month at fleet scale**, §26),
  which E2 consumes as the branch's established result rather than re-deriving.
- Even granting the masquerade rates counterfactually: `19_999_920 × 100_000/PPM = 1_999_992`
  revenue vs `9_305_555` cost → **−7_305_563**/id-month before the merge collapses coverage.

**The pincer, stated:** every cost saving from consolidation is purchased with a detection
dimension the physics reads directly (silicon coupling, one-pipe throughput, co-transition), and
the multiplier collapse is steeper than the cost curve at every grid point. The full
(c × N × region-share) sweep — A-E2-2 — asserts `max yield < 0` over the masquerade branch and
`yield ≪ 0` over the consolidation branch, with the sole non-negative cell being the used-capital
breakeven boundary where the operation is economically indistinguishable from genuine
distribution.

## 4. Capture mechanics beyond yield — W-2, W-3, W-4

### W-2 — Orchestrator-pool concentration (assignment share ≠ reward share)

The cohort acquires regional orchestrator capacity (runs orchestrator roles for a large fraction
of regional assignments). Asserted decoupling:

- **Verification integrity holds at any assignment share** — consumed from Part IV/V closures:
  signed assignment logs, beacon-lottery third-executor re-derivation, `verify_attribution`
  (V1 dispositions; R-VER1: net-profit framing needs > 50% of the ~20-candidate escalation pool
  across ≥ 11 cluster-disjoint sites — sites the W-1 grid has just priced at negative yield).
- **Reward share stays S_o-bound:** orchestrating does not change whose cluster the *work*
  settles to; the knee plateau (§1.1) caps the cohort's take regardless of assignment routing;
  the spread rule (≥ m distinct clusters/ASNs per redundant set) forces disjoint executor supply,
  asserted as a **liveness margin** (C-4: no quarantine-for-lack-of-disjoint-executor while
  honest regional diversity ≥ m + margin).
- **`κ ≥ 1%` floor:** every qualifying honest small node's assignment share never falls below
  the constitutional floor under maximum consolidation pressure (A-E2-4).

### W-3 — Valve interaction (composition with E1)

The cohort times entry to an E1 S-1 emergency window (localized target temporarily elevated) and
the E1-A2 overshoot tail: ceiling transiently `× 1.25 × 1.075 ≈ × 1.34` → `26_871_892`
µUSD/id-month — **still below the 31_066_666 evasion-optimal cost floor**, and transient
(quarters) against 36-month amortization: no grid cell flips sign in NPV (integer quarterly NPV,
`DISC_PPM = 980_000`/quarter, 12-quarter horizon, all `u128`). Asserted as A-E2-6: the emergency
tier widens *tracking*, never *extractability*.

### W-4 — Subsidized persistence (loss-funded starvation)

The cohort operates at the measured loss indefinitely to starve honest participation. Bounds
asserted: honest reference-node attainment `≥ 1_050_000 Ppm` in every W-4 configuration (the Q1
surviving-configuration invariant, continuity assertion A-E2-3); the κ floor guarantees work
allocation; the burn rate is the W-1 yield table (§2) times fleet size — **the mechanism converts
capture spend into household subsidy** (S_o-diluted rewards flow outward; the cohort's loss is
the pool's gain). The residual — externally-funded patronage that never needs positive yield —
is **not detectable by flow analysis and is bounded by governance minimization, not economics**
(§15, §35.2): stated openly, consumed as the standing residual it already is in the sealed spec.

## 5. Scenario matrix (summary)

| ID | Condition | Expected outcome |
|---|---|---|
| W-0 | honest baseline (no cohort) | reference attainment `[990_000, 1_010_000]`; no merges (F5 OC false-positive bound); the control for A-E2-3 |
| W-1 | masquerade grid `c ∈ {1, 4, 5, 8, 16}` × `N ∈ {40, 200, 400}` × region share | yield table §2 exactly; minimum loss `−11_066_746` at `c = 5`; no positive cell at new-capital costs |
| W-1u | used-capital boundary | breakeven within ±0.5% at `c = 5`; share still knee-capped (A-E2-5) |
| W-1c | consolidation branch `c = 40` | merge + gate failure; commodity-lane regime (Q1 it-2 consumed); `≪ 0` |
| W-2 | orchestrator concentration | assignment/reward decoupling; spread-rule liveness margin; κ floor |
| W-3 | valve-window timing (E1 composition) | transient ×1.34 ceiling < cost floor; NPV sign invariant |
| W-4 | subsidized persistence | honest invariant holds; burn = §2 yields × fleet; patronage residual stated |
| W-5 | totality torture | full `u64` boundary grid through §1.1–§1.3 arithmetic; `u128` discipline; no panic |

## 6. The assertion register

| ID | Assertion | Expected | Method |
|---|---|---|---|
| **A-E2-1** | Thin-Pool inequality: `min` over the W-1 grid of cohort yield `< 0` strictly at new-capital strawmen (grid min exactly `−11_066_746` µUSD/id-month at `c = 5`; ratio 1.553×); the hardware-plus-power lemma holds (`22_066_666 > 19_999_920`) | exact grid | P, D |
| **A-E2-2** | The pincer: no profitable interior — every `c` above the density band composes q-degradation/merge/coupling collapse steeper than its cost saving; W-1c consumed at the Q1 iteration-2 bound | exhaustive grid, `max < 0` | P, D |
| **A-E2-3** | Honest continuity: reference small-node attainment `≥ 1_050_000 Ppm` in **every** surviving configuration of every scenario (the Q1 invariant carried into E2) | invariant | P, D |
| **A-E2-4** | κ floor: qualifying honest nodes' assignment share `≥ 100_000 Ppm` (1%) under maximum W-2/W-4 pressure | invariant | P, M |
| **A-E2-5** | Capture failure at any spend: cluster aggregate take `= min(s, 50_000 Ppm)` of network work — the knee plateau — including at the W-1u breakeven boundary; marginal reward beyond the knee exactly 0 | algebraic + grid | **V**, P |
| **A-E2-6** | Valve non-extractability: no W-3 cell flips NPV-positive during emergency/overshoot windows (peak transient ceiling `26_871_892 < 31_066_666`) | exact | P, D |
| **A-E2-7** | Gate composition: W-1c cohort earns zero idle premium (residential gate) and its lanes respect the 25–30% caps; merged cluster counts once for coverage/κ/S_o | invariant | M, S |
| **A-E2-8** | Determinism/totality: `e2stats.json` bit-identical across implementations; W-5 panic-free; A-Q2-5b conformance vectors inherited | bit-equality; 0 panics | D, P |

## 7. Calibration outputs — the constraint surface handed back to F5

E2's margins are placeholder-backed; its *inequalities* are the durable output. Emitted:

1. **The κ_thin constraint:** thin-pool holds iff
   `min_c [ HW_AMORT + LINE/c + POWER_IDLE + OPS/c ]` (over the undetected band `c ≤ d_max`)
   `> GCU_h_month × localized_target_max` — with `localized_target_max` at the amortization-band
   and emergency-tier maxima. Solved for the κ_thin band edge given measured `C_SITE`: the
   **calibration inequality the F5 economic study must satisfy**, replacing guesswork with a
   surface.
2. **Breakeven-boundary sensitivity:** the used-capital edge (W-1u) as a function of
   (hardware price, line cost, power tariff, `d_max` band) — the F5 `C_SITE` rows that matter
   most, ranked.
3. **S_o family sweep:** knee ∈ {2%, 5%, 8%} × `γ` ∈ {½, 1} — capture-share plateau vs
   honest-attainment trade, feeding the S_o **[calibration]** row.
4. **Composition margins:** the W-3 transient-ceiling gap and the W-2 spread-rule liveness
   margin as explicit reserves against parameter drift.

## 8. Acceptance, findings, exit

- **Green bar:** all A-E2 assertions in both implementations, bit-identical, as a deterministic
  CI gate; the S_o strawman (§1.1) then enters the Yellowpaper §23 as the reference form by
  amendment, and the W-1 grid tables join the §26 adversarial-results record as the Q-series'
  third campaign.
- **Findings protocol:** failures are filed against owning sections and resolved by amendment,
  never by weakening assertions; the E1-A1/A2 verification-before-editing discipline applies to
  any future review of this record.
- **Exit → E3:** multi-region capture (P_r composition, correlated-region entry) and the
  patronage-capture residual's governance-hardening interaction (§35) — the two residuals this
  campaign consumed as stated bounds rather than re-proving.

---

*Maintained under the Yellowpaper §4 amendment discipline. E2 consumes F5's cost calibration as
input placeholders and E1's patched settlement dynamics as its backdrop; it re-runs mechanically
when the F5 `C_SITE` manifest lands (calibration provenance, F5 §26.3). Its durable claims are
structural: the plateau property of S_o, the hardware-plus-power lemma, the pincer's absence of
a profitable interior, and the breakeven-at-best boundary at which a capture cohort has become
the genuine distribution the network exists to reward.*
