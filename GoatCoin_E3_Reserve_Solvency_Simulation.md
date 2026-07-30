# GoatCoin (GOAT) — E3 Reserve Solvency Stress Test

### *Track E3: the Thin-Pool Yield Reserve Campaign — emission-pool solvency under cyclical demand collapse and budget-unconstrained subsidized persistence*

> **Version 1.0 (draft, 2026-07-07), aligned to `GoatCoin_Yellowpaper.md` v1.0 (sealed),
> `GoatCoin_Threat_Model.md` v1.3, the E1 record (as amended E1-A1/A2), and the E2 campaign
> design.** This document specifies **E3**, the third Phase-2 economic campaign: a deterministic,
> pure-integer, multi-year solvency simulation of the Emission Allocation Controller (§33) and
> Surplus Routing Rule (§33.1) under the composition of (a) a 36-month global demand collapse
> (`u_ref → ε`) and (b) the E2 W-4 residual taken to its limit — a **budget-unconstrained
> subsidized-persistence condition**: an operator cluster that does not seek yield at all, but
> spends toward reserve exhaustion and honest starvation. E2 proved the *rational* consolidation
> grid is net-negative everywhere; E3 prices the *irrational* siege and proves its damage is
> schedule-bounded. **No core invariant is altered anywhere in this campaign — every theorem is
> a property of the already-sealed §33/§23/§14 math, verified by harness.**
>
> **Defensive purpose statement.** This is defensive validation of a settlement mechanism's
> long-horizon solvency, conducted so that honest household contributors retain viable earnings
> through a multi-year demand winter under capital-attrition pressure. Per
> `goatcoin-rs/CONTENT_FILTER_GUIDELINES.md`, the document describes **operator clusters and
> observable conditions** (a *subsidized-persistence condition*, a *flood condition*, a
> *siege trajectory*), never actors and intents; every condition is paired with the mechanism's
> recomputable response and its quantitative bound.
>
> **Numeric convention.** Pure-integer per Yellowpaper Appendix A: `Ppm`/`Bp`/`MicroUsd`/`Epoch`;
> every product `u128` cast-before-multiply; floor division; saturating arithmetic. Every worked
> number below is derived floor-exact from the stated strawmen and is the expected value the
> assertion register (§6) pins; the harness computes the full epoch tables.

---

## 0. Scope and inputs

### 0.1 What E3 proves

1. **The Reserve Solvency Bound (A-E3-1):** the reserve is non-negative *by construction* and
   its worst-case depletion trajectory is a **pure function of the genesis emission schedule,
   independent of adversary budget** — with the genesis strawmen satisfying the design-shock
   solvency inequality, the reserve ends the 36-month siege at ≥ 27.1% (schedule worst case)
   and ≈ 41.3% (siege-realized), never at zero.
2. **The Patronage Burn Rate (A-E3-2):** the exact integer capital the siege consumes —
   `12_733_000_000_000 / 25_771_000_000_000 / 38_977_000_000_000 MicroUsd` net at 12/24/36
   months (≈ $12.73M / $25.77M / $38.98M) — against damage of ≈ $4.09M in accelerated
   depletion and **zero** honest-attainment reduction at strawmen: an attrition ratio of
   **≈ 9.5 : 1 against the sieging cluster**.
3. **Honest Liveness (A-E3-3):** throughout the winter, honest small nodes settle at the full
   *scaled* target (the published, pro-rata funded footprint), their cash flow stays above the
   household marginal-cost floor at every epoch, and the worst-case dilution floor — if the
   emission cap ever binds — is `930_232 Ppm` of scaled target **at any adversary budget**.

### 0.2 Inputs and placement

| Input | Source | Status |
|---|---|---|
| `compute_epoch_gap_fill`, `decay_cap`, `route_surplus`, `u_ref` derivation | §33–33.1 (verbatim-port mandate, E1-A1) | normative snippets |
| S_o knee plateau, spread rule, κ floor, F6/§15 cluster merge | §23, §14–15; E2 §1.1 formalization | consumed |
| Industrial cost bases; W-4 framing | E2 §1.3/§4 | pre-F5 placeholders |
| CET pipeline + routine clamp dynamics | §27–30, §34; E1 harness | E1-patched backdrop |
| Wash-trade non-attributability (R-C8) | §33.1; TM A-EC1–A-EC6 | consumed as proven assertions |

Harness: Rust normative + Python mirror, bit-identical `e3stats.json` (A-E3-8), fully
deterministic, monthly epochs over a 48-month horizon (36 shock + 12 recovery), quarterly
controller cadence. Findings enter the Yellowpaper as §4 amendments; the base campaign alters no
mechanism.

### 0.3 Amendment log — RECON-04 interventions

> Advisory **GOAT-ARCH-RECON-04** raised two feedback-loop vectors against the E3 residuals X-2
> (surplus/fee mechanics) and X-3 (de-clustered lottery dilution). Per the verification-before-
> editing discipline (see E1-A1 in the Q2 hyperinflation simulation), each premise was checked against §33.1
> and §23 mechanics before patching. Neither amendment alters a core invariant; both attach to
> residuals E3 already carried openly. Emitted constants are `[calibration]` (F5-adjacent).

#### E3-A1 — Surplus-burn weaponization *(premise overstated; rate residual closed)*

- **Reported hazard.** An irrational, well-capitalized cluster dumps fee capital to force
  `u_ref` into a **perpetual surplus regime** (`u_ref > CET_gross`), driving `route_surplus`'s
  100%-burn path continuously → a permanent deflationary contraction of circulating supply →
  "systemic ecosystem illiquidity and structural economic collapse."
- **Premise verification (three corrections against §33.1).** The collapse framing does not
  survive the sealed mechanics:
  1. **Reserve-refill-*first*, burn only the ceiling overflow.** `route_surplus` routes
     `to_reserve = min(surplus, reserve_ceiling − reserve_remaining)` **before** burning
     (`burned = surplus − to_reserve`). During the E3 winter the reserve is *depleted*
     (`reserve_remaining ≪ reserve_ceiling`), so headroom is large and **`burned = 0`** — every
     surplus µUSD is pure counter-cyclical *reserve refill*. A fee-dumping cluster during a siege
     **heals the very reserve it is besieging** (A-EC6, restore-never-grow). The burn path only
     engages once the reserve is at ceiling — i.e. in a *healthy* state, never during the winter.
  2. **The burn is self-financed, pro-holder deflation.** The surplus burned is fee capital the
     cluster *paid in* (escrowed → `u_ref`, derived-not-declared, §33.1); contributors settle at
     `min(u_ref, CET_gross) = CET_gross`. To burn at scale the cluster must **buy-and-burn** —
     acquire tokens, pay them as fees, watch them destroyed. Supply reduction is *bullish* for
     every remaining holder including honest nodes; the "attack" is a wealth transfer from the
     cluster to all holders (the E3 attrition motif: adversary spend → network gain).
  3. **Contributor real earnings are supply-immune by construction.** The CET is
     **µUSD-denominated** (CPPI/§27–31); a household's target is a purchasing-power figure, not a
     token count. Token deflation cannot starve contributors — they receive the µUSD-equivalent
     regardless of supply. Debt-deflation has no surface here (no GOAT-denominated obligations in
     the settlement path).
- **The genuine residual (closed).** One real concern survives: the **burn *rate***. An
  above-ceiling burst could remove circulating supply faster than secondary-market liquidity
  absorbs it — a flow/liquidity shock (not a solvency event, not "collapse"). Closure preserves
  the R-C8 anti-wash invariant exactly while capping only the rate: the **Deflation Rate
  Governor** — a deferred-burn queue.
  ```rust
  // Rate-limit the route_surplus BURN path; never the reserve-refill path. Non-attributable:
  // no identity input, so R-C8 (A-EC1) wash-trade-proofness is preserved bit-for-bit.
  pub struct BurnGovernor { pub queue: u128, pub burn_rate_cap_ppm: Ppm }  // cap = [calibration]
  impl BurnGovernor {
      /// `overflow` = route_surplus.burned this epoch (already ceiling-net). Returns supply removed.
      pub fn step(&mut self, overflow: u128, circulating_supply: u128) -> u128 {
          self.queue = self.queue.saturating_add(overflow);
          let cap = circulating_supply.saturating_mul(self.burn_rate_cap_ppm as u128) / PPM as u128;
          let now = core::cmp::min(self.queue, cap);      // total, panic-free
          self.queue -= now;                              // exact: now <= queue
          now
      }
  }
  ```
  - **Total eventual burn unchanged** (the queue drains completely) → the anti-wash deflationary
    pressure R-C8 relies on is intact; only its *velocity* is bounded.
  - **Per-epoch supply removal ≤ `burn_rate_cap_ppm × supply`** → graceful, predictable
    deflation; no liquidity shock (the reported consequence, closed).
  - **Idle during the winter:** while `reserve_remaining < reserve_ceiling`, `overflow = 0` →
    the governor never engages → surplus is 100% solvency refill. The governor is a healthy-state
    rate limiter, orthogonal to the siege.
  - *Rejected alternative (recorded):* redirecting overflow to a new non-attributable
    "accessibility endowment" sink — rejected as adding a governance surface for no solvency
    benefit; the deferred queue caps the rate without a new value destination or discretionary
    lever (§35 minimization).
- **Sections touched:** §3.3 (X-2 framing), §5 (X-2 row), register A-E3-9. **No Yellowpaper
  change to `route_surplus` itself** — the burn semantics are unchanged; the governor is a
  downstream rate limiter on the already-computed `burned`, and enters §33.1 as an additive
  amendment candidate on a green campaign.

#### E3-A2 — Lottery freeze-out under de-clustered flooding *(valid; new allocation mechanism)*

- **Reported hazard.** A budget-unconstrained actor running `k ≥ m` disguised clusters (the X-3
  full-de-cluster residual) floods the beacon-lottery candidate pool with millions of
  Sybil-disguised nodes. Even with the `κ ≥ 1%` floor "on paper," per-node selection probability
  `→ 1/|pool| → 0` for an honest household, which is then **starved of task routing** and
  churns offline (R-C5) from lack of work.
- **Premise verification (valid, with the existing layers named).** The vector is real for a
  *naïve uniform* lottery, but three shipped layers already blunt it — and E3-A2 closes the
  residual they leave:
  1. **Registry-flood pricing (V2 / R-C10).** Reaching the lottery requires registration under
     seniority bond pricing `NEWCOMER_MULT × 2^{r_net}`; minting millions of fresh identities is
     not free — the burn record does not rotate.
  2. **Cluster-granular anti-capture (§14–15, §23).** F6/§15 merge collapses physically
     co-located Sybils into clusters; S_o/κ/coverage operate on the *cluster*. Uniform-per-
     identity lottery dilution is the residual only under **full de-clustering** (`k ≥ m`,
     genuinely-independent-looking identities), which itself demands real physical distribution
     at the E2 M4 negative-yield cost — or fiat-settled patronage (the stated §15/§35.2 residual).
  3. **κ ≥ 1% is nominal, not allocated.** The gap the advisory correctly finds: κ was specified
     as an assignment-*share* floor, not a *reserved routing lane* — so a flooded uniform pool can
     satisfy "1% in expectation" while delivering ≈ 0 routed work to any individual honest node.
- **Closure — the Stratified Liveness Lottery (makes κ a *real reserved allocation*).** A
  protocol-fixed fraction of each epoch's assignments is drawn **only** among an
  established-residential stratum whose membership a flood cannot cheaply enter:
  ```
  RESERVED_LIVENESS_BP = 3_000            // 30% of assignments reserved   [calibration]
  Q(epoch) = { nodes : residential-attested (§13)                          // device-neutral gate
                     ∧ verified_work_count ≥ SENIORITY_MIN_UNITS (R-C10)    // accrued over ACTUAL
                                                                            //   verified work, not
                                                                            //   wall-clock → R-C5-robust
                     ∧ F6-distinct (one seat per merged cluster, §14–15) }
  reserved lane : beacon-lottery over Q only        → pool = |Q|, INDEPENDENT of the flood
  general  lane : (BP_FULL − RESERVED_LIVENESS_BP)  → open to all, incl. the flood & newcomers
  newcomer lane : existing PROBATION_BUDGET_BP onboarding allocation (R-C10) — unchanged
  ```
  - **Freeze-out closed:** an established honest node's reserved-lane selection probability is
    `≥ RESERVED_LIVENESS_BP/BP_FULL × 1/|Q|` — floored by the *honest established stratum size*,
    which the flood cannot inflate. Millions of Sybils win only *general-lane* tickets (where
    their E2/E3 economics are negative); they cannot dilute the reserved lane.
  - **To dilute `|Q|`, a node must reach `SENIORITY_MIN` = perform real verified work at real
    cost over time = *become an honest participant*** — the recurring self-defeat. A patronage
    fleet willing to do that has bought genuine standing, not a freeze-out.
  - **Invariants preserved:** device-agnostic (stratum keys on *measured verified-work* +
    residential attestation, never a device type — "if it names a device type, it's wrong");
    permissionless entry (the newcomer lane is untouched — a genuine newcomer is never blocked,
    it enters via onboarding then accrues into `Q`); accessibility (`SENIORITY_MIN` accrues over
    verified-work volume, not wall-clock, so an intermittent low-power household qualifies across
    its real participation — R-C5); fraud-provable (the stratified draw is a pure-integer function
    of anchored verified-work counts + the epoch beacon → any observer recomputes the lane
    assignment, §3.8). κ ≥ 1% is now *realized as routed work*, strengthening the floor from
    nominal to allocated — no invariant weakened.
- **Sections touched:** §3.4 (X-3), §5 (X-3 row), register A-E3-10. Enters §23 (the κ mechanism)
  as an amendment candidate on a green campaign; `RESERVED_LIVENESS_BP` / `SENIORITY_MIN_UNITS`
  are `[calibration]`.

---

## 1. The three structural theorems

E3's assertions are harness verifications of three properties already latent in the sealed math.
Stated first, so the scenario tables read as witnesses rather than discoveries.

### Theorem 1 — the drain supremum is adversary-independent

Per epoch, the reserve draw is `min(N_eff·(CET_gross − u_ref), M_cap(t), reserve)` (§33). The
middle term does not contain any adversary-controllable quantity: **no value of `N_eff`, at any
budget, in any number of regions, can push the epoch drain above `M_cap(t)`** — and `M_cap(t)`
is the monotone genesis decay schedule (`decay_cap`, §33). Therefore:

```
reserve(t) ≥ reserve(0) − Σ_{τ ≤ t} M_cap(τ)          — for ALL adversary strategies
```

The right-hand side is a genesis constant. A budget-unconstrained cluster can buy **timing
toward a floor the schedule already fixes** — the gap between the honest-demand drain and the
cap — and nothing more. Solvency through a design shock of length `T` is therefore a **genesis
calibration inequality**, not a battlefield outcome:

```
reserve(0) ≥ SOLVENCY_MARGIN_PPM × Σ_{τ ≤ T} M_cap(τ) / PPM      (strawman margin 1_250_000 = 1.25×)
```

Non-negativity is unconditional (`.min(reserve)` — A-PF5). *Strict* positivity through the shock
is this inequality, which E3 emits as the `RESERVE_CEILING(t)` / `decay_ppm` calibration
constraint (§7). If a shock ever outlasted the schedule's coverage, exhaustion is **graceful by
construction**: gap-fill tends to zero, settlement continues at `min(u_ref, CET)`, no invariant
breaks (ledger, fraud proofs, maturity all demand-independent), and the first recovery surplus
refills the reserve toward its ceiling (§33.1) — hibernation, not collapse. The inequality
exists precisely so the design shock never reaches that regime.

### Theorem 2 — the dilution cap: spread × S_o composes to a floor

Dilution — inflating `N_eff` so the capped emission spreads thinner over honest units — only
operates **when the cap binds** (`N_eff·gap > M_cap`; below the cap every effective unit
receives the full gap). Its magnitude is structurally bounded by two shipped mechanisms
composing:

1. **The spread rule caps raw share.** F6/§15 merge the cluster into **one** cluster; every
   redundant executor set must span ≥ `m` distinct clusters (§23) — the merged cluster holds at
   most one slot per set, so its raw executed volume obeys
   `raw_x ≤ (N_h + raw_x)/m ⟹ raw_x ≤ N_h/(m−1)`. At `m = 3`: **at most half the honest
   volume, at any budget** — to flood more, it must hire honest executors for the remainder
   (§3.3).
2. **S_o discounts what that share counts for.** At the spread-cap share `s = 1/m = 333_333
   Ppm`, `s_o_ppm = 50_000·PPM/333_333 = 150_000 Ppm`, so effective units
   `eff_x = raw_x × 150_000/PPM`. At strawmen: `raw_x ≤ 12_000_000` GCU-h/mo ⟹
   `eff_x ≤ 1_800_000` against `N_h = 24_000_000` honest.

**Worst-case honest per-unit floor if the cap binds:**
`N_h/(N_h + eff_x) = 24_000_000/25_800_000 = 930_232 Ppm` — an honest contributor keeps
≥ 93.02% of the undiluted per-unit gap-fill **at any adversary budget**. (At the E3 strawmen the
cap never binds — §4 — so realized dilution is exactly **zero**; the floor is the bound for
parameterizations where it does.)

### Theorem 3 — the asymmetric winter: marginal cost vs full cost

The demand collapse tightens the thin-pool asymmetry rather than loosening it. An honest
household's *marginal* cost is power only (hardware and line are sunk):
`POWER_IDLE = 5_400_000 MicroUsd`/month. The sieging cluster pays a *full-cost* basis (E2 §1.3:
≥ `31_066_666`/identity-month at the evasion optimum; industrial commodity basis
`c_x = 100_000 MicroUsd`/GCU-h here). The scaled target never falls below the household marginal
floor at any point in the strawman trajectory (§4: trough income `13_267_680` vs `5_400_000`),
so **sunk-cost households outlast fresh capital by construction** — the winter starves the
besieger, not the besieged.

---

## 2. System under test — constants and strawmen

| Constant | Value | Source / status |
|---|---|---|
| `N_h` (honest volume) | `24_000_000` GCU-h/mo (100_000 nodes × 240) | scenario strawman |
| `CET_gross(0)` | `83_333 MicroUsd`/GCU-h | §1 north-star |
| CET glide (CMI collapse) | −5%/quarter (routine clamp, §34) for 8 quarters → `55_282`, then CMI floor | E1 pipeline; floor-exact ladder `83_333 → 79_166 → 75_207 → 71_446 → 67_873 → 64_479 → 61_255 → 58_192 → 55_282` |
| `u_ref` (shock) | `2_000 MicroUsd`/GCU-h flat (fees collapse, volume thins) | scenario strawman |
| `M_cap(0)` | `2_400_000_000_000 MicroUsd`/mo ($2.4M) | genesis strawman **[calibration]** |
| `decay_ppm` | `990_000`/mo (−1%/mo); `m_cap_floor = 600_000_000_000` | genesis strawman **[calibration]** |
| `reserve(0)` | `100_000_000_000_000 MicroUsd` ($100M) | genesis strawman **[calibration]** |
| `S0_KNEE_PPM` / `m` (spread) | `50_000` / 3 | E2 §1.1 / §23 |
| `c_x` (cluster marginal cost) | `100_000 MicroUsd`/GCU-h (collapsed-CMI opportunity cost), swept {50k, 100k, 300k} | pre-F5 placeholder |
| Horizon | 36-month shock + 12-month recovery (`u_ref` recovers past `CET_gross`) | scenario |

Schedule integral (Theorem 1 constant):
`Σ_{36 mo} M_cap = 2.4e12 × (1 − 0.99³⁶)/0.01 = 72_862_000_000_000 MicroUsd` ($72.86M) —
`reserve(0)/Σ = 1.372×`, satisfying the 1.25× solvency margin. **Schedule worst-case floor:
`reserve(36) ≥ 27_138_000_000_000` ($27.14M, 27.1%), unconditionally.**

## 3. The siege model — strategy space and its self-defeats

### 3.1 X-FARM (execute the thin organic flow at a loss)

The E2 W-4 baseline: knee-capped receipts against full-cost basis; burn = the E2 W-1 yield
tables × fleet. Adds nothing to drain (organic `N_eff` unchanged); consumed from E2.

### 3.2 X-FLOOD-0 (zero-fee wash tasks, the maximal-drain strategy)

The cluster submits zero-fee wash tasks and executes what the assignment layer allows, to
maximize `N_eff` and pull the epoch drain up toward `M_cap`. Structural frictions, all shipped:

- **Spread leak:** ≥ `(m−1)/m` of every wash task's redundant execution is assigned to honest
  clusters (Theorem 2.1) — **the flood hires the honest network**; those units are honest-paid
  at the same per-unit settlement.
- **S_o discount:** the cluster's own executed share settles at `150_000 Ppm` weight.
- **Verified-work floor:** every wash unit is real compute through the full Part-V loop at
  `c_x` — fake work is a slashing event at 15–20×, consumed from Part V as closed.

### 3.3 X-FLOOD-F (fee-bearing wash — the self-funding paradox)

Fees escrow on-ledger and release into `u_ref` (derived, never declared — §33.1). Raising
`u_ref` **shrinks the gap** `CET − u_ref`, *reducing* the reserve drain the strategy exists to
maximize, while paying honest executors real usage revenue through the front door (and R-C8's
A-EC3 already proves the round trip strictly negative). Fee-bearing flooding is
**anti-correlated with its own objective**; the harness includes it to pin the sign (A-E3-5),
not because it is rational even by siege logic.

### 3.4 X-3 (multi-region de-clustering robustness)

The composition above assumes §15 clustering correctly merges the cluster. The robustness arm
assumes it *partially fails*: the cluster presents as `k` pseudo-independent clusters
(region-sharded, payout-flow-obscured). The spread cap loosens to `k` slots per set; at the
worst modeled case `k = m − 1 = 2`: `raw_x ≤ 2·N_h`, `s = 2/3`, `S_o = 75_000 Ppm`,
`eff_x ≤ 3_600_000` → dilution floor degrades to `24/27.6 = 869_565 Ppm` — **still bounded,
at roughly double the burn**. Full de-clustering (`k ≥ m`) is the **patronage residual**,
already stated openly in the sealed spec (§15, §35.2: fiat-settled sponsorship is not detectable
by flow analysis; bounded by governance minimization, not economics) — E3 consumes it as stated,
consistent with E2 W-4.

## 4. The canonical siege — worked, floor-exact

**X-1: maximal zero-fee flood at the spread cap, all 36 months.** `raw_x = 12_000_000`,
`eff_x = 1_800_000`, `N_eff = 25_800_000` GCU-h/mo.

**The cap never binds at strawmen.** Peak requirement `N_eff × gap(Q1) = 25_800_000 × 81_333 =
2_098_391_400_000 < M_cap(0) = 2_400_000_000_000`; thereafter the need declines at ≈ −1.7%/mo
(CET glide) against the cap's −1%/mo — the margin only widens (month 35:
`1_374_676_560_000` vs `1_688_280_000_000`). Consequences, all asserted:

- **Zero realized dilution:** every effective unit — honest and cluster — receives the full
  per-unit gap at every epoch. Honest attainment vs scaled target = `1_000_000 Ppm`
  throughout (A-E3-3a). Theorem 2's `930_232` floor is the cap-binding worst case, verified in
  the A-E3-4 parameter sweep, not the strawman trajectory.
- **The entire adversary effect is drain acceleration equal to its own receipts:** the flood
  adds exactly `eff_x × gap(t)` to the epoch drain — which is precisely the gap-fill paid *to
  the cluster*. The siege "damage" is the reserve buying the cluster's S_o-discounted work at
  the same identity-uniform rate as everyone else (A-EC1), nothing else.

**Reserve trajectories (monthly Σ, quarterly-constant gap ladder; Σ_gap over 36 months =
`2_274_237 MicroUsd`·(GCU-h/mo)⁻¹·months):**

| Trajectory | 36-month drain (`MicroUsd`) | `reserve(36)` | % remaining |
|---|---|---|---|
| X-0 honest-only downturn | `24_000_000 × 2_274_237 = 54_581_688_000_000` | `45_418_312_000_000` | **45.4%** |
| X-1 maximal siege | `+ 1_800_000 × 2_274_237 = 4_093_626_600_000` → `58_675_314_600_000` | `41_324_685_400_000` | **41.3%** |
| Theorem-1 schedule worst case (any strategy, any budget) | `72_862_000_000_000` | `27_138_000_000_000` | **27.1% floor** |

**The patronage burn table (A-E3-2), net of receipts** (gross = `raw_x × c_x ×` months; receipts
= `eff_x × Σ(gap + u_ref)`):

| Horizon | Gross compute burn | Receipts (gap-fill + `u_ref` share) | **Net capital burned** | Extra reserve drained | Attrition ratio |
|---|---|---|---|---|---|
| 12 mo | `14_400_000_000_000` | `1_669_421_000_000` | **`12_730_579_000_000`** (≈ $12.73M) | `1_626_221_000_000` | 7.8 : 1 |
| 24 mo | `28_800_000_000_000` | `3_029_175_000_000` | **`25_770_825_000_000`** (≈ $25.77M) | `2_942_735_000_000` | 8.8 : 1 |
| 36 mo | `43_200_000_000_000` | `4_223_147_000_000` | **`38_976_853_000_000`** (≈ $38.98M) | `4_093_627_000_000` | **9.5 : 1** |

Every µUSD of accelerated depletion costs the cluster ≈ 9.5 µUSD of net capital — and the
"damage" is the reserve paying for verified work at the uniform rate, while honest liveness is
untouched. To force the Theorem-1 worst case (`M_cap` saturation) the cluster would need
effective units the spread × S_o composition physically denies it (Theorem 2); the schedule
floor stands regardless.

**Honest household P&L through the trough (A-E3-3):** per-unit settlement = `min(u_ref, CET) +
gap = CET` exactly (cap unsaturated); trough income `240 × 55_282 = 13_267_680 MicroUsd`/mo
against the `5_400_000` marginal floor → **+`7_867_680`/mo (+$7.87) at the deepest point**;
the sieging cluster's per-identity position at the same epoch: `≤ −(c_x·240 − knee-capped
receipts)` — Theorem 3's asymmetric winter, exact in the harness tables.

**Recovery leg (months 37–48):** `u_ref` recovers above `CET_gross`; `route_surplus` refills the
reserve toward `RESERVE_CEILING(t)` (restore-never-grow, A-EC6) — asserted: monotone recovery,
conservation exact, and the counter-cyclical property (high-demand epochs replenish what the
winter drew) realized in the integer trajectory.

## 5. Scenario matrix (summary)

| ID | Condition | Expected outcome |
|---|---|---|
| X-0 | 36-mo downturn, no cluster | drain `54_581_688_000_000`; reserve 45.4%; honest attainment ≡ scaled `PPM`; solvency inequality holds |
| X-1 | maximal zero-fee flood at the spread cap | table §4 exactly; zero dilution; attrition 9.5 : 1 |
| X-1b | cap-binding variant (`N_h` ×1.5, slower CET glide) | dilution appears and bottoms at ≥ `930_232 Ppm` (Theorem 2 floor exact); solvency floor unchanged |
| X-2 | fee-bearing flood (X-FLOOD-F) *(E3-A1)* | drain *decreases* vs X-1; honest income rises via `u_ref`; strategy sign pinned negative on both objectives. Surplus-regime variant: reserve-refill-first ⇒ zero burn while besieged; the Deflation Rate Governor caps healthy-state burn velocity; contributor real earnings supply-immune (µUSD peg) |
| X-3 | de-clustered `k = 2` robustness *(E3-A2)* | dilution floor `869_565 Ppm`; burn ≈ 2×; schedule floor unchanged. Lottery freeze-out closed by the Stratified Liveness Lottery — established-honest reserved-lane probability floored by `|Q|`, flood-independent; `k ≥ m` funding residual still the governance-bounded patronage case (§15/§35.2) |
| X-4 | recovery + refill | `route_surplus` conservation; ceiling-bounded restoration; reserve trajectory turns monotone-up |
| X-5 | torture | `u64`/`u128` boundary grid through §33 arithmetic (incl. `reserve = 0` epoch: gap-fill = 0, no panic, settlement continues at `min(u_ref, CET)`); A-PF5 re-verified empirically |

## 6. The assertion register

| ID | Assertion | Expected | Method |
|---|---|---|---|
| **A-E3-1** | Solvency bound: `reserve(t) ≥ reserve(0) − Σ M_cap(τ)` for **every** strategy/budget cell (Theorem 1); strawman floor `27_138_000_000_000` never violated; X-1 realized `41_324_685_400_000`; `reserve ≥ 0` unconditionally with graceful-exhaustion semantics at the `reserve = 0` torture cell | exact trajectories | P, M, **V** (the bound is a 3-line invariant over `compute_epoch_gap_fill`) |
| **A-E3-2** | Burn table: net capital burned exactly `12_730_579_000_000 / 25_770_825_000_000 / 38_976_853_000_000 MicroUsd` at 12/24/36 months (strawman `c_x`); attrition ratio ≥ 7.8 : 1 at every horizon; all sums `u128`-exact | exact integers | P, D |
| **A-E3-3** | Honest liveness: attainment vs scaled target ≡ `1_000_000 Ppm` at strawmen; ≥ `930_232 Ppm` in every cap-binding cell (X-1b); household net cash flow ≥ `+7_867_680 MicroUsd`/mo at the trough; κ ≥ 1% assignment floor never breached | exact | P, D |
| **A-E3-4** | Theorem-2 floor: dilution ≥ `N_h/(N_h + eff_x^max)` across the full (budget × `m` × knee × `k`) sweep; spread-cap algebra `raw_x ≤ N_h/(m−k)` verified per cell | grid | P, **V** |
| **A-E3-5** | Self-funding paradox: X-2 drain < X-1 drain and X-2 honest income > X-1 honest income, epoch-wise — fee-bearing flooding is sign-negative on both siege objectives | sign, epoch-wise | P, D |
| **A-E3-6** | Wash non-attributability continuity: A-EC1/A-EC3/A-EC4 re-asserted inside the E3 loop (no identity-typed value in any sink; round trips strictly negative; farming bounded by merge + `M_cap` + work floor) | invariant | S, P |
| **A-E3-7** | Recovery: `route_surplus` conservation exact; refill ≤ `RESERVE_CEILING(t) − remaining`; reserve monotone-up in months 37–48; `decay_cap` monotonicity untouched throughout | invariant | P, **V** |
| **A-E3-8** | Determinism/totality: `e3stats.json` bit-identical across implementations; X-5 panic-free; E1-A1 conformance vectors inherited | bit-equality; 0 panics | D, P |
| **A-E3-9** *(E3-A1)* | Deflation Rate Governor: `overflow == 0` at every epoch while `reserve_remaining < reserve_ceiling` (zero burn during the siege); per-epoch supply removal `≤ burn_rate_cap_ppm × supply`; `queue` drains to the full cumulative overflow over the horizon (total eventual burn unchanged — anti-wash intact); no identity-typed value enters the queue (A-EC1 preserved); contributor µUSD real earnings invariant to circulating-supply change | invariant, exact | P, S, **V** |
| **A-E3-10** *(E3-A2)* | Stratified Liveness Lottery: an established honest node's reserved-lane selection probability `≥ RESERVED_LIVENESS_BP/BP_FULL × 1/|Q|` at **any** general-pool flood size; `|Q|` is invariant to fresh-identity flooding (dilution requires `SENIORITY_MIN` verified work); the draw is a pure-integer recomputable function of anchored verified-work + beacon (fraud-provable); newcomer onboarding lane unchanged; κ ≥ 1% realized as routed work | invariant, exact | P, M, **V** |

## 7. Calibration outputs — the genesis-schedule constraint surface

1. **The solvency inequality** (the campaign's durable artifact):
   `reserve(0) ≥ 1.25 × Σ_{τ ≤ T_design} M_cap(τ)` with `T_design = 36` months — a closed-form
   pure-integer constraint linking `reserve(0)`, `M_cap(0)`, `decay_ppm`, `m_cap_floor`. E3
   emits the feasible surface; the F5-adjacent economic study picks inside it (§37 rows
   `decay_ppm / m_cap_floor / reserve schedule`).
2. **The dilution-floor coupling:** honest floor `= N_h·PPM/(N_h + eff_x^max)` as a function of
   (`m`, knee, `k`) — the spread rule's `m` is the sharpest lever (`m = 5` lifts the strawman
   floor to `941_176 Ppm`); handed to the §23/§14 calibration owners.
3. **Burn-rate sensitivity:** attrition ratio vs `c_x` ∈ {50k, 100k, 300k} — even at the
   cheapest industrial basis the ratio stays > 4 : 1; ranked against the F5 `C_SITE` rows.
4. **Schedule-shape trade:** faster `decay_ppm` tightens Theorem 1's floor but shrinks the
   funded footprint in late winter — the explicit trade the genesis calibration must sign,
   quantified as (floor % remaining) vs (months of full honest funding).

## 8. Acceptance, findings, exit

- **Green bar:** all A-E3 assertions in both implementations, bit-identical, deterministic CI
  gate; the Theorem-1 invariant and Theorem-2 algebra join the V-marked formal-verification
  targets (TM Part III §8 list).
- **Findings protocol:** E1-A1/A2 discipline — premises verified against sealed sources,
  failures resolved by amendment, never by weakening assertions.
- **Honest boundary, stated:** E3 proves the siege is schedule-bounded and attrition-negative;
  it does **not** claim the reserve is inexhaustible (exhaustion beyond the design shock is
  graceful hibernation, priced by the solvency inequality), and it does **not** close the
  full-de-clustering patronage residual (`k ≥ m`), which remains the governance-bounded
  residual the sealed spec already carries openly (§15, §35.2).
- **Exit → E4:** the governance-hardening interaction under patronage (the `k ≥ m` residual
  meeting §35's bounded-mutation machinery), and multi-shock composition (E1 regional
  hyperinflation *inside* an E3 global winter — the valve drawing on a decaying reserve).

---

*Maintained under the Yellowpaper §4 amendment discipline. E3 alters no invariant: Theorem 1 is
the `min` in `compute_epoch_gap_fill`, Theorem 2 is the spread rule composed with the S_o knee,
Theorem 3 is the Calibration Law's time-pricing meeting sunk household capital — the campaign's
work is to state them as bounds, pin them to floor-exact integer trajectories, and hand the
genesis schedule its solvency inequality. The siege's arithmetic verdict: ≈ $39M burned over
three years buys ≈ $4M of schedule-bounded reserve acceleration, zero honest starvation at
strawmen, and a bounded floor everywhere else — the pool pays the besieger the same
identity-uniform rate as everyone, and outlasts it.*
