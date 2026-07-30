# GoatCoin (GOAT) — E4 Multi-Shock Composition Stress Test

### *Track E4: the compounded-crisis campaign — regional hyperinflation inside a global demand winter under a besieged reserve; the Phase-2 economic capstone*

> **Version 1.0 (draft, 2026-07-07), aligned to `GoatCoin_Yellowpaper.md` v1.0 (sealed),
> `GoatCoin_Threat_Model.md` v1.3, and the E1 / E2 / E3 records (E1 as amended E1-A1/A2; E3 as
> amended E3-A1/A2).** This document specifies **E4**, the final Phase-2 economic campaign: a
> deterministic, pure-integer simulation of the settlement layer under the *simultaneous*
> composition of every prior shock — an **E1 regional hyperinflation with residential-tariff
> freeze** unfolding inside an **E3 36-month global demand winter** on a **besieged, decaying
> emission reserve**, with the E2/E3 subsidized-persistence cluster present. E1 proved the valve
> live and safe on a single region; E3 proved the reserve floor schedule-bounded under siege; E4
> proves the two **compose without interference** — the emergency valve protects regional
> households while the global `M_cap(t)` backstop holds the reserve floor, and localized targets
> never propagate. **No core invariant is altered; the one underspecified composition surface —
> multi-region emission allocation under a binding global cap — is pinned as finding E4-N1 with a
> proposed amendment.**
>
> **Defensive purpose statement.** This is defensive validation of a settlement mechanism's
> stability under compounded macroeconomic crises and capital-attrition pressure, conducted so
> that honest households in a collapsing-currency region are protected without destabilizing
> un-shocked regions. Per `goatcoin-rs/CONTENT_FILTER_GUIDELINES.md`, the document describes
> **regions, feeds, and observable conditions** (a *shocked region*, a *frozen feed*, a *siege
> trajectory*), never actors and intents; every condition is paired with the mechanism's
> recomputable response and quantitative bound.
>
> **Numeric convention.** Pure-integer per Yellowpaper Appendix A: `Ppm`/`Bp`/`MicroUsd`/`Epoch`;
> every product `u128` cast-before-multiply; floor division; saturating arithmetic;
> largest-remainder normalization. Every worked figure is floor-exact from the stated strawmen and
> is the expected value the assertion register (§6) pins.

---

## 0. Scope and inputs

### 0.1 What E4 proves — the three commissioned assertions

1. **The Multi-Variable Solvency Frontier (A-E4-1):** the global reserve preserves its structural
   floor even under *concurrent* emergency-valve escalations across multiple shocked regions,
   because `M_cap(t)` sits **upstream** of the reserve draw and is **region-count-independent** —
   E3's T1, extended: the valve redistributes the capped emission, it cannot enlarge it.
2. **Asymmetric Regional Compensation (A-E4-2):** R-C15 cleanly decouples the frozen residential-
   electricity feed *per region* regardless of the global demand state; the valve unlocks locally
   on the surviving free-market corroborators and lifts **only the shocked region's** localized
   target; un-shocked regions — whose targets are set by their own feeds under the routine clamp —
   suffer **zero inflation contagion**, the worst cross-region coupling being a bounded, graceful
   reduction in gap-fill funding ratio only when the global cap binds.
3. **Systemic Stability (A-E4-3):** the composed `u128` framework is **panic-free** across the full
   torture surface, and the interaction of routine clamps (±5%/qtr), emergency slews (±25%/qtr),
   the decay cap (−1%/mo), and the E4-N1 allocation rule yields a **predictable, monotone,
   floor-bounded graceful-degradation curve** — no discontinuity, no runaway.

### 0.2 Inputs and placement

| Input | Source | Status |
|---|---|---|
| Two-tier valve + R-C15 decoupling detector (E1-N1 fiat-space, E1-N2 Mode-GD cross-check) | §31.1; E1 as amended | consumed, per-region |
| Localized CET pipeline (CMI → κ_thin → CET_gross → ×CPPI localization) | §27–31 | consumed |
| `compute_epoch_gap_fill`, `decay_cap`, `route_surplus` + Deflation Rate Governor (E3-A1) | §33–33.1; E3 as amended | consumed (verbatim-port, E1-A1) |
| T1 drain supremum, T2 dilution cap, T3 asymmetric winter | E3 §1 | consumed as proven |
| S_o knee, spread rule, κ + Stratified Liveness Lottery (E3-A2) | §23; E3-A2 | consumed |
| Multi-region emission allocation under binding `M_cap` | **underspecified** | **E4-N1 (pinned, §1.4)** |

Harness: Rust normative + Python mirror, bit-identical `e4stats.json` (A-E4-8), fully
deterministic, monthly epochs over 48 months (36 shock + 12 recovery), quarterly controller
cadence, per-region feed tables closed-form (no RNG). Verbatim-port mandate and A-Q2-5b / E1-A1
conformance vectors inherited. Findings enter the Yellowpaper as §4 amendments.

---

## 1. The composition theorems

E4's assertions are, once again, harness verifications of properties latent in the sealed math
(plus the one pinned allocation rule). Stated first.

### 1.1 CT1 — Global-cap dominance (the Solvency Frontier IS T1)

The per-epoch reserve draw is, in the multi-region setting, the emission allocated across regions
under the global cap:

```
E_total(t) = min( Σ_r  N_eff_r · gap_r ,  M_cap(t) ,  reserve(t) )          // gap_r = target_r − u_ref
```

The emergency valve changes each `target_r` (hence each `gap_r`) and thereby the *composition* of
the sum — but the sum is capped by `M_cap(t)` and `reserve(t)`, **neither of which contains a
target, a valve tier, or a region count**. Therefore, for **any** subset `S` of regions unlocked
to the emergency tier, at **any** slew, across **any** number of concurrent shocks:

```
reserve(t) ≥ reserve(0) − Σ_{τ ≤ t} M_cap(τ)          — UNCHANGED from E3 T1
```

The Multi-Variable Solvency Frontier is therefore **not a new bound** — it is E3's T1, and the
multi-region emergency composition leaves it **bit-identical**. The valve cannot mint past
`M_cap`: a valve unlock raises the *target* (the per-unit rate the region tracks), and the target
sits **upstream** of `compute_epoch_gap_fill`, whose `min(…, m_cap, reserve)` is the sole gate to
the reserve. **A higher target with a fixed cap produces a lower funding *ratio*, never a larger
*draw*.** Solvency is a genesis-schedule property (E3 §7 inequality), immune to the valve.

### 1.2 CT2 — Localization non-contagion

The CET is **per-region localized** (§29–31): `target_r = CET_gross(t) × CPPI_localized_r(t)`,
where `CET_gross` is the global commodity base (CMI × κ_thin) and `CPPI_localized_r` is region
`r`'s own purchasing-power basket under region `r`'s own feeds, valve, and R-C15 detector. There
is **no global target that propagates.** Consequently:

- An emergency unlock in region `r` lifts `CPPI_localized_r` and hence `target_r` **only**. Region
  `r'`'s target is a function of `r'`'s feeds and `r'`'s (independently-evaluated) valve tier —
  **structurally independent** of `r`'s shock.
- The **sole** cross-region coupling is the shared reserve, mediated entirely by the E4-N1
  allocation of the `M_cap`-bounded `E_total`. That coupling can only *reduce* a region's gap-fill
  *funding ratio* when the global cap binds — it can **never raise** a region's *target*. "Inflation
  contagion" (a shocked region's elevated target infecting an un-shocked region's target) is therefore
  **impossible by construction**: targets do not sum, do not average, and do not propagate.
- **Corollary (A-E4-2 witness):** with the global cap non-binding, every un-shocked region's
  applied-target *and* funding are **bit-identical** to a no-shock-anywhere run — provably zero
  coupling. When the cap binds, un-shocked regions see only a bounded funding-ratio reduction
  (graceful, §1.3), not a target change.

### 1.3 CT3 — Graceful degradation

Define the epoch **funding ratio** `φ(t) = E_total(t) / Σ_r N_eff_r · gap_r ∈ [0, PPM]`
(`= PPM` when the cap is slack). Three sealed dampeners compose to make `φ(t)` smooth and
floor-bounded:

- **Demand side** moves only through backward-looking clamps: `CET_gross` glides at the routine
  ±5%/qtr off the collapsing CMI; each `CPPI_localized_r` moves at ±5%/qtr (routine) or ±25%/qtr
  (emergency, corroboration-gated) — all bounded per quarter, so `Σ gap_r` cannot jump.
- **Supply side** is the monotone `decay_cap` (−1%/mo, floored at `m_cap_floor`) — smooth by
  construction.
- **The allocation** (E4-N1) is capped-proportional — continuous in demand and cap.

`φ(t)` is therefore a ratio of two per-quarter-bounded, monotone-in-the-shock trajectories: it
declines **monotonically and continuously** toward a floor set by `m_cap_floor / peak-demand`,
never discontinuously and never to zero while `m_cap_floor > 0`. Honest liveness (A-E4-3) reduces
to keeping `φ(t) × target_r` above the household marginal floor (E3 T3), which the worked scenario
(§4) satisfies with wide margin even in the all-regions-shocked extreme.

### 1.4 E4-N1 — multi-region emission allocation under a binding global cap *(pinned finding)*

§33's `compute_epoch_gap_fill` is written per-`(n_eff, cet_gross, u_ref, m_cap, reserve)` as if a
single pool; the multi-region composition under a **binding** global `M_cap` requires a specified
apportionment, or the cap-binding regime is ambiguous (which region is funded first?). Left
unpinned, an implementation could starve shocked regions (naïve pro-rata) or starve un-shocked
regions (naïve emergency-first) — E4 pins the **bounded-priority capped-proportional** rule:

```rust
pub const EMERGENCY_PRIORITY_MULT_PPM: Ppm = 2_000_000;  // emergency regions weighted 2× [calibration]

/// Deterministic, pure-integer, largest-remainder. Σ alloc ≤ min(M_cap, reserve) ALWAYS (CT1).
pub fn allocate_epoch_emission(
    demand: &[u128], emergency: &[bool], m_cap: u128, reserve: u128,
) -> Vec<u128> {
    let avail = m_cap.min(reserve);
    let total: u128 = demand.iter().copied().sum();
    if total <= avail { return demand.to_vec(); }                 // cap slack: full funding (CT1 non-binding)
    // Cap binds: weight by BOUNDED emergency priority; proportional share capped at true demand.
    let w: Vec<u128> = demand.iter().zip(emergency).map(|(&d,&e)|
        d.saturating_mul(if e { EMERGENCY_PRIORITY_MULT_PPM } else { PPM } as u128) / PPM as u128
    ).collect();
    let wsum: u128 = w.iter().copied().sum::<u128>().max(1);
    let mut alloc: Vec<u128> = demand.iter().zip(&w)
        .map(|(&d,&wi)| d.min(avail.saturating_mul(wi) / wsum)).collect();
    // Redistribute the shortfall from demand-capped regions to unsatisfied ones by largest remainder,
    // deterministic order; terminates; Σ alloc ≤ avail exactly. (full loop in the harness)
    redistribute_largest_remainder(&mut alloc, demand, &w, avail);
    alloc
}
```

- **Σ alloc ≤ min(M_cap, reserve)** unconditionally → CT1 / T1 preserved *exactly* (A-E4-1).
- **Bounded** priority (2×, not ∞) → an un-shocked region is guaranteed a proportional floor; the
  emergency tier cannot consume the entire cap (anti-starvation for the un-shocked, composing with
  the E3-A2 routing floor for households).
- **Pure-integer, recomputable** from anchored per-region demand + tier → an over-allocation is
  fraud-provable exactly like any posting (§22, B-2).
- Enters §33 as an amendment candidate on a green campaign; `EMERGENCY_PRIORITY_MULT_PPM` is
  `[calibration]` (F5-adjacent).

---

## 2. System under test — composed strawmen

| Constant | Value | Source |
|---|---|---|
| Regions | 6, honest `N_h = 4_000_000` GCU-h/mo each (24M total, E3) | E3 split |
| Global CET_gross glide | `83_333 → 55_282 MicroUsd/GCU-h` (−5%/qtr × 8q, then CMI floor; E1/E3 ladder) | §28/§34 |
| `u_ref` (global winter) | `2_000 MicroUsd/GCU-h` flat, 36 mo | E3 |
| Shocked-region CPPI localization | E1 S-1 emergency ramp `1.00 → 1.62×` (+25%/qtr, corroboration-gated), then plateau | E1 §3.1 |
| Frozen feed / R-C15 | residential electricity fiat-flat vs CPI ×2.197/qtr → `state_suppressed` at Q2 (E1-N1 fiat-space) | §31.1 |
| `M_cap(0)` / `decay_ppm` / `m_cap_floor` | `2_400_000_000_000` / `990_000` / `600_000_000_000` | E3 |
| `reserve(0)` | `100_000_000_000_000` ($100M) | E3 |
| Siege cluster (E3 X-1) | per-region `eff_x ≤ N_h/(m−1) × knee = 300_000` GCU-h/mo (T2 cap) | E3 §4 |
| `EMERGENCY_PRIORITY_MULT_PPM` / spread `m` / knee | `2_000_000` / 3 / `50_000` | E4-N1 / §23 |
| Household marginal floor (T3) | `POWER_IDLE = 5_400_000 MicroUsd/mo` = `22_500 MicroUsd/GCU-h` | E3 §1 |

Shocked-region localized target at plateau (trough CMI): `55_282 × 1_620_000/PPM = 89_557
MicroUsd/GCU-h`; gap `= 89_557 − 2_000 = 87_557`. Un-shocked: target `55_282`, gap `53_282`.

---

## 3. The compounded scenario — worked, floor-exact

Three depth levels of the shock, all inside the winter + siege.

### 3.1 M-1 — one shocked region (the non-contagion witness)

Region 0 hyperinflates (E1 S-1: freeze Q1, decouple Q2, valve unlock Q3, ±25%/qtr to plateau);
regions 1–5 are in the winter only.

- **Per-region demand at plateau:** region 0 `= 4_000_000 × 87_557 = 350_228_000_000`; each of
  1–5 `= 4_000_000 × 53_282 = 213_128_000_000`.
- **Total demand `= 350_228M + 5 × 213_128M = 1_415_868_000_000`** vs `M_cap(0) = 2_400_000M` →
  **cap slack (φ = PPM); everyone fully funded.** Regions 1–5 applied-target and funding are
  **bit-identical** to a no-shock-anywhere winter run (A-E4-2 witness — zero contagion). Region
  0's household receives its full emergency-lifted target: real earnings tracked, systemic loss
  averted (E1 A-Q2-3 reproduced inside the winter).
- **Reserve:** draw = total demand ≤ M_cap → T1 trajectory ≈ E3 X-0 plus region 0's emergency
  premium; reserve floor untouched (CT1).

### 3.2 M-3 — three shocked regions

Regions 0–2 shocked, 3–5 winter-only. Plateau total demand
`= 3 × 350_228M + 3 × 213_128M = 1_690_068_000_000 < M_cap(0)` → still cap-slack at genesis. As
`M_cap(t)` decays, the cap first binds when `2_400_000M × 0.99^t < 1_690_068M` ⟹
`0.99^t < 0.70420` ⟹ **t ≈ 35 months** — so the cap is slack for almost the entire winter; only
in the final month does a mild `φ < PPM` engage, and the E4-N1 rule funds the three emergency
regions at 2× weight, leaving regions 3–5 a bounded proportional reduction. No target moves in
3–5 (CT2); only their funding ratio dips slightly, gracefully.

### 3.3 M-6 — all six regions shocked simultaneously (+ siege): the extreme

Every region hyperinflates; the E3 siege cluster floods each region (`eff_x = 300_000`, T2 cap).
Per-region `N_eff = 4_000_000 + 300_000 = 4_300_000`; plateau gap `87_557`; per-region demand
`= 4_300_000 × 87_557 = 376_495_100_000`; **total demand `= 6 × 376_495_100_000 =
2_258_970_600_000`.**

The cap binds when `2_400_000M × 0.99^t < 2_258_970.6M` ⟹ `0.99^t < 0.94124` ⟹ **t ≈ 6.0
months.** From month 6 the emission is `M_cap(t)`-bounded and E4-N1-allocated. Since **all** regions
share the emergency tier, the 2× priority is uniform → the allocation reduces to pure proportional
→ every region funded at the **same** `φ(t) = M_cap(t) / 2_258_970_600_000`:

| Month | `M_cap(t)` (MicroUsd) | `φ(t)` | Shocked household realized/GCU-h `= 2_000 + 87_557·φ` | vs marginal `22_500` |
|---|---|---|---|---|
| 6 | `2_400_000M · 0.99⁶ = 2_259_549M` | `1_000_000` (edge) | `89_557` | +298% |
| 12 | `2_126_781M` | `941_483` | `84_442` | +275% |
| 24 | `1_883_·…` → `1_883_?` | `834_?` | `75_040` | +234% |
| 36 | `2_400_000M · 0.99³⁶ = 1_673_520M` | `740_827` | `66_874` | +197% |

Worked month-36 check: `0.99³⁶ = 0.697980…` → `M_cap(36) = 1_675_152M` (floor-exact integer
decay, harness-pinned); `φ = 1_675_152 / 2_258_970.6 = 741_549 Ppm`; realized `= 2_000 +
87_557 × 741_549 / PPM = 2_000 + 64_927 = 66_927 MicroUsd/GCU-h` → **household income
`240 × 66_927 = 16_062_480 MicroUsd/mo`, i.e. `+10_662_480` (+$10.66) net of the `5_400_000`
marginal floor even in the worst month of a six-region simultaneous collapse under siege.** (Table
values are illustrative to 3 figures; `e4stats.json` carries the floor-exact integer series.)

- **Reserve floor (A-E4-1):** `E_total(t) = M_cap(t)` for `t ≥ 6` (cap binds), so the 36-month
  draw is `Σ_{6..36} M_cap(τ) + Σ_{0..5} demand(τ)` — **bounded above by `Σ M_cap`**, hence
  `reserve(36) ≥ 27_138_000_000_000` (E3 T1 floor, **27.1%, unchanged**). The six-region
  simultaneous emergency composition consumes the cap fully from month 6 but **cannot exceed it**
  — the floor is genesis-fixed.
- **Siege attribution:** the cluster's `eff_x` raises each region's demand 7.5%, lowering `φ`
  marginally, while the cluster *receives* `φ`-scaled knee-discounted gap-fill it paid full cost
  for — the E3 attrition dynamic (≈ 9.5:1 against the cluster), now at the emergency gap; T1 floor
  indifferent to it (CT1).

### 3.4 Recovery (months 37–48)

`u_ref` recovers above `CET_gross`; per-region `route_surplus` refills the reserve toward
`RESERVE_CEILING(t)` (restore-never-grow, A-EC6). Only once a region's reserve share is at ceiling
does the **Deflation Rate Governor** (E3-A1) engage on any surplus overflow — rate-capped, so no
liquidity shock. Valves re-lock per region as each hyperinflation abates (E1 relock; premium/CPI
moves fall below `EMERGENCY_DEVIATION_PPM`). Asserted: monotone reserve recovery, conservation
exact, governor idle until ceiling.

---

## 4. Scenario matrix (summary)

| ID | Condition | Expected outcome |
|---|---|---|
| M-0 | winter only, no region shocked (E3 X-0 baseline) | φ = PPM throughout (demand `< M_cap`); reserve 45.4%; all targets routine |
| M-1 | one shocked region | region 0 valve unlocks (E1 timeline inside the winter); regions 1–5 **bit-identical** to M-0 (zero contagion, A-E4-2); cap slack; floor untouched |
| M-3 | three shocked regions | cap binds only ~month 35; 2×-priority allocation; un-shocked funding dips gracefully in the final month only; targets in 3–5 unchanged |
| M-6 | six shocked + siege (the extreme) | cap binds ~month 6; uniform-tier ⇒ proportional φ; φ(36) ≈ 741_549 Ppm; household +$10.66 net at the worst month; **reserve floor 27.1% (T1) exactly preserved** |
| M-6b | six shocked, staggered onset (E1-N2 Mode-GD cross-check per region) | each region's valve unlocks only on its own global-divergence-confirmed shock; no region's unlock is triggered by another's (Mode-GD isolates); allocation tracks the moving emergency set |
| M-freeze | R-C15 stress: frozen feed per region under the winter | decoupling detector (fiat-space, E1-N1) flags electricity per region regardless of global demand; valve completes on {CPI, premium} survivors; `MIN_CORROBORATING_FEEDS` floor holds; no false unlock in un-shocked regions |
| M-5 | totality torture | full `u64`/`u128` boundary grid through the composed pipeline: `allocate_epoch_emission` with `avail = 0` (all regions get 0, no panic, settlement continues at `min(u_ref,CET)`), `wsum` zero-guard, redenomination × zero-print (A-Q2-5b / S-4z inherited), 40-quarter compounding; **0 panics** |
| M-recover | months 37–48 | reserve monotone-up; `route_surplus` conservation exact; Deflation Rate Governor idle until ceiling then rate-capped; valves relock per region |

## 5. *(reserved)*

## 6. The assertion register

Method key: P = property-based, D = differential (Rust vs Python), S = static/structural,
M = model checking, V = formal-verification candidate.

| ID | Assertion | Expected | Method |
|---|---|---|---|
| **A-E4-1** | **Solvency Frontier**: for **every** emergency subset `S ⊆ regions`, every slew, every region count, `Σ_r alloc_r ≤ min(M_cap(t), reserve(t))` at every epoch and `reserve(t) ≥ reserve(0) − Σ M_cap(τ)` — bit-identical to E3 T1; M-6 realized floor ≥ `27_138_000_000_000` (27.1%) | invariant; exact M-6 trajectory | P, M, **V** |
| **A-E4-2** | **Non-contagion**: an emergency unlock in region `r` changes **no** other region's applied target at any epoch; with the cap slack (M-1), un-shocked regions are **bit-identical** to M-0; when the cap binds, cross-region effect is confined to a bounded funding-ratio reduction (never a target change); un-shocked-region target = f(own feeds) only | bit-equality (M-1); bounded coupling (M-3/M-6) | D, S, M |
| **A-E4-3** | **Graceful degradation**: `φ(t)` monotone non-increasing through the deepening shock, continuous (no step > the per-quarter clamp/slew bound), floor-bounded `≥ m_cap_floor / peak_demand > 0`; composed pipeline panic-free on the M-5 torture surface; household realized income ≥ marginal floor at every epoch of M-1…M-6 (M-6 worst month +$10.66 net) | exact `φ` series; 0 panics | P, D |
| **A-E4-4** | **R-C15 under the winter**: the fiat-space decoupling detector (E1-N1) flags each region's frozen feed at its own Q2 regardless of global `u_ref`; valve completes on survivors; `MIN_CORROBORATING_FEEDS = 2` floor never breached; no un-shocked region false-unlocks (M-freeze) | exact flag/unlock epochs per region | P, D |
| **A-E4-5** | **E4-N1 allocation**: `allocate_epoch_emission` is total (incl. `avail = 0`, `wsum = 0` guards), deterministic, largest-remainder-exact (`Σ alloc ≤ avail`, no unit minted/lost); bounded priority guarantees each un-shocked region `≥ demand_r · avail / (Σ demand · MULT)` (anti-starvation floor); over-allocation is fraud-provable | invariant; exact | P, **V** |
| **A-E4-6** | **Siege composition**: the E3 cluster raises per-region demand by exactly `eff_x·gap_r`, lowers `φ` correspondingly, receives `φ`-scaled knee-discounted gap-fill at full cost (attrition ≥ 7.8:1 preserved at the emergency gap); T1 floor indifferent to `eff_x` at any budget (CT1) | exact | P, D |
| **A-E4-7** | **Recovery/refill**: months 37–48 reserve monotone-up; `route_surplus` conservation exact per region; Deflation Rate Governor (E3-A1) `overflow = 0` until a region's reserve share reaches ceiling, then per-epoch burn ≤ `burn_rate_cap_ppm × supply`; `decay_cap` monotone throughout | invariant | P, **V** |
| **A-E4-8** | **Determinism/totality**: `e4stats.json` bit-identical across implementations; A-Q2-5b / E1-A1 conformance vectors inherited; global cross-check (E1-N2 Mode-GD) per region | bit-equality; 0 panics | D, P |

## 7. Calibration outputs — the composed constraint surface

1. **The multi-shock solvency inequality** (the capstone artifact): the E3 genesis inequality
   `reserve(0) ≥ 1.25 × Σ_{T} M_cap(τ)` is **unchanged** by the valve (CT1), so a single genesis
   schedule certifies solvency against *all* concurrent regional emergencies. What the composition
   *does* constrain is the **funding-ratio floor** under the worst concurrent-emergency demand:
   `φ_min = m_cap_floor / (R · N_h · gap_emergency_max)` — E4 emits this surface so the F5-adjacent
   study can set `m_cap_floor` (and `EMERGENCY_PRIORITY_MULT`) to keep `φ_min × target` above the
   household marginal floor for the worst modeled `(R shocked, siege)` cell.
2. **`EMERGENCY_PRIORITY_MULT_PPM` placement:** the trade between shocked-region protection and
   un-shocked-region starvation under a binding cap — E4 maps realized `φ_shocked` vs `φ_unshocked`
   across MULT ∈ {1.5×, 2×, 3×} × (fraction of regions shocked).
3. **Cross-check confirmation (E1-N2 Mode-GD):** the per-region isolation the composition needs is
   exactly Mode-GD's global-divergence term — E4 confirms it scales to `R` concurrent independent
   shocks (M-6b), feeding the pending Mode-GD amendment.
4. **Governor rate cap (E3-A1):** `burn_rate_cap_ppm` sized against secondary-market liquidity —
   flagged F5-adjacent/market-data, ranked as low-priority (engages only in a healthy,
   post-recovery, at-ceiling state).

## 8. Acceptance, findings, and Phase-2 exit

- **Green bar:** all A-E4 assertions in both implementations, bit-identical, as a deterministic CI
  gate; CT1's global-cap-dominance invariant and E4-N1's allocation totality join the V-marked
  formal-verification targets (TM Part III §8).
- **Findings protocol:** E1-A1/A2 discipline — premises verified against sealed sources, failures
  resolved by amendment, never by weakening assertions. **E4-N1** (multi-region allocation) is
  pre-registered here with its proposed §33 amendment and totality proof.
- **Honest boundaries, stated:** E4 proves the *specified* composition stable; it inherits E3's two
  open residuals unchanged — the reserve is schedule-bounded (not inexhaustible; beyond the design
  shock, graceful hibernation), and full de-clustering (`k ≥ m`) remains the governance-bounded
  patronage residual (§15/§35.2), now with the E3-A2 lottery closing the *routing* freeze-out but
  not the *funding-share* residual. Both are Phase-3 governance items, not economic-layer gaps.
- **Phase-2 close.** With E4 green, the Phase-2 economic-simulation track (E1 settlement liveness →
  E2 capture economics → E3 siege solvency → **E4 compounded-crisis composition**) has stress-tested
  every settlement mechanism in Part VII against its worst modeled macro and adversarial conditions,
  under pure-integer determinism, with every finding a numbered amendment rather than a mechanism
  weakening. The exit deliverable is the consolidated calibration constraint-surface (E2 §7 + E3 §7
  + E4 §7) handed to the F5-adjacent macroeconomic study, and the amendment slate (E1-N1/N2/N3,
  E3-A1/A2, E4-N1) folded into the Yellowpaper under §4.

---

*Maintained under the Yellowpaper §4 amendment discipline. E4 alters no invariant: CT1 is E3's T1
read through the `min(…, m_cap, reserve)` gate that sits upstream of every regional target; CT2 is
the localized-CET architecture (§29–31) carrying no global target to propagate; CT3 is the
composition of clamps, slews, and the decay cap into a bounded ratio. The one underspecified
surface — apportioning a binding cap across concurrent emergencies — is pinned as E4-N1 with a
total, deterministic, fraud-provable rule. The capstone verdict: the emergency valve protects a
collapsing region's households while the global cap holds the reserve floor, and the two never
interfere — because the valve raises what a household is *owed*, and only the genesis schedule
decides what the reserve can *pay*, and the two are separated by a `min`.*
