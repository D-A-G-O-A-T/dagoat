# GoatCoin (GOAT) — Q2 Hyperinflation Stress Test

### *Track E1: Macroeconomic Simulation & Liveness Proving for the Meta-Index Controller — Phase 2 opening deliverable*

> **Version 1.0 (draft, 2026-07-07), aligned to `GoatCoin_Yellowpaper.md` v1.0 (sealed),
> `GoatCoin_Threat_Model.md` v1.3, and the F5 study design (as amended F5-A1/F5-A2).** This
> document specifies **Q2**, the second adversarial-simulation campaign (successor to the Q1
> anti-capture campaign, §26 Yellowpaper): a deterministic, pure-integer stress test proving that
> the Dynamic-CET settlement layer (Part VII, **[design]** / configuration C3) survives a
> localized sovereign currency collapse — including the exact state-suppression edge case R-C15
> was built to close. Like Q1, this is a closed-loop campaign (simulate → find a hole → fix →
> re-simulate); its findings enter the Yellowpaper as numbered amendments under the §4
> discipline.
>
> **Defensive purpose statement.** This is defensive validation of a settlement mechanism's
> behavior under a macroeconomic shock and under feed-manipulation conditions, conducted so that
> honest household contributors in a collapsing-currency region are not systemically underpaid.
> Per `goatcoin-rs/CONTENT_FILTER_GUIDELINES.md`, the document describes **nodes, feeds, and
> observable conditions, never actors and intents** (a *tariff-freeze condition*, a
> *captured-feed condition*), and every adversarial condition is paired with the mechanism's
> recomputable response.
>
> **Numeric convention.** Every consensus-relevant quantity in the harness is pure-integer per
> Yellowpaper Appendix A: `Ppm` (`u64`, `PPM = 1_000_000` = unity), `Bp` (`u32`,
> `BP_FULL = 10_000` = 100%), `MicroUsd` (`u64`, 1 = 10⁻⁶ USD), all products cast to `u128`
> **before** multiplying, floor division, saturating arithmetic, largest-remainder
> normalization. Every worked number in this document is floor-exact and reproducible from the
> stated inputs — they are the expected values the assertion register (§6) pins.

---

## 0. Scope and configuration

### 0.1 What E1 proves (and what it does not)

The system under test is the **specification**, not shipped code: Part VII is **[design]**
(configuration C3, TM §0), so E1 is the settlement-layer analog of what the D.1 parity oracle is
for the mechanism layer — an executable check that the *math and closure arguments* hold under
the harshest in-scope macro trajectory. Three claims are on trial, one per output assertion
family:

1. **R-C15 detection (A-Q2-1):** the dynamic macro-coherence detector flags a policy-frozen
   residential-electricity feed `state_suppressed` and removes it from the emergency
   corroboration conjunction — without ever false-flagging an honestly-tracking feed.
2. **R-C3 valve liveness and safety (A-Q2-2):** the two-tier emergency valve unlocks to the
   wider `EMERGENCY_SLEW_BP = ±2_500 Bp` (±25%/quarter) band on the surviving free-market
   corroborators, relocks when corroboration lapses, and can never be opened by a single
   captured feed nor by pruning the conjunction below `MIN_CORROBORATING_FEEDS`.
3. **CET tracking (A-Q2-3):** the localized Contributor Earnings Target tracks the
   hyperinflationary reality closely enough that an honest regional contributor's real target
   attainment never enters the systemic-loss regime — and the valve-disabled counterfactual
   *does*, proving the valve is necessary, not decorative.

Out of scope (owned elsewhere): oracle reporter-median capture depth and DA withholding (TM V3,
§19.3–19.4 — E1 takes finalized feed medians as inputs); multi-region contagion dynamics (a
later E-track); the F5-adjacent calibration of the macro constants themselves (E1 *stresses* the
strawmen and maps their coupling constraints, §7 — it does not finalize them).

### 0.2 Harness placement and determinism

Following the Q1 convention (`q1_*.py` porting predicates from the Rust ground truth), the E1
harness is dual-implemented:

- **Normative:** a standalone Rust crate `q2-econ-sim` compiling the Part VII normative snippets
  verbatim (`symmetric_deviation_ppm`, `symmetric_deviation_mar_ppm`, `index_level`,
  `cppi_multiplier`, `rebalance`, `clamp_move`, `compute_epoch_gap_fill`, `route_surplus`) plus
  the §2 valve state machine. Workspace-adjacent, neutrality-gated in CI, **no dependency on or
  from protocol crates** (it is a spec simulator, not protocol code).
- **Mirror:** `q2_hyperinflation_sim.py`, an independent Python port of the same predicates.

Both emit `q2stats.json`; assertion **A-Q2-8** requires the two outputs to be **bit-identical
in every integer field** — the §3.8 discipline applied to the simulator itself. The harness is
fully deterministic: scenario feed series are closed-form integer tables (no RNG); the only
seeded randomness is the reporter-noise sensitivity family (§5.4), seeded from a fixed constant
recorded in `q2stats.json`.

<!-- E1-A1: prose-port hazard. Prose renderings of the deviation formula omit the max(1, sum)
     guard the §30.1 snippet carries; a from-prose port panics on d(0,0). -->
**Verbatim-port mandate (E1-A1).** Every §2.1 function is derived from its Yellowpaper **code
snippet**, never from a prose formula — the prose forms (including this document's §4.1 worked
arithmetic) are non-normative shorthand and some omit the `max(1, sum)` zero-guard that §30.1's
normative `symmetric_deviation_ppm` carries. Before any scenario runs, both implementations must
reproduce the **A-Q2-5b conformance vectors**: `d(0,0) = 0`, `d(X,0) = d(0,X) = 2_000_000` for
all `X > 0` including `u64::MAX`, `d(X,X) = 0`, and symmetry on the boundary corpus.

### 0.3 Constants under test

| Constant | Value | Source | Status |
|---|---|---|---|
| `ROUTINE_SLEW_BP` | 500 (±5%/qtr) | §34 | fixed (routine tier) |
| `EMERGENCY_SLEW_BP` | 2_500 (±25%/qtr) | §31.1 / §37 strawman | **[calibration]** |
| `MACRO_DECOUPLING_PPM` | 400_000 | §31.1 (R-C15) | **[calibration]** |
| `DECOUPLING_EPOCHS` | 2 (quarters) | §31.1 (R-C15) | **[calibration]** |
| `MIN_CORROBORATING_FEEDS` | 2 | §31.1 (R-C15) | **[calibration]** |
| `CORROBORATION_EPOCHS` | 2 (quarters) | §31.1 (R-C3) | **[calibration]** |
| `EMERGENCY_DEVIATION_PPM` | **150_000** | *harness strawman* (unset in §37) | **[calibration]** — E1 sweeps it (§7) |
| `SYMMETRIC_DEVIATION_MAX_PPM` | 2_000_000 | §30.1 | fixed (structural) |
| corroborating-feed set | {electricity, CPI, stablecoin premium} | §31.1 | **[calibration]** |

The harness time base is the **finalized quarter** (the controller's cadence, §30); "epoch" in
the R-C3/R-C15 constants reads as finalization epochs per §31.1's strawman units.

### 0.4 Amendment log — the E1 design record

> Amendments follow the Yellowpaper §4 discipline: numbered entries, inline patch markers at
> touched sites, this log as the index. Both entries below respond to the Core Protocol Security
> Review of v1.0; per the project's verification-before-editing discipline, each
> premise was **checked against the sealed sources before patching**, and the disposition records
> what was confirmed, what was corrected, and what was genuinely closed.

### E1-A1 — Denominator collapse under redenomination × zero-print *(premise corrected; residual closed)*

- **Reported hazard.** An S-4 redenomination (×10⁻⁶ step) coinciding with a liquidity-shock zero
  print drives `cur + prev → 0` in `symmetric_deviation_ppm`, and "the un-patched Yellowpaper
  definition does not wrap the denominator in `max(1, sum)`" — a fatal divide-by-zero panic
  violating A-Q2-5.
- **Premise verification (correction).** The claim is **incorrect against the sealed
  specification**: Yellowpaper §30.1's *normative snippet* carries the guard explicitly
  (`let denom = core::cmp::max(1u128, sum); // zero-guard: only prev==cur==0 hits 1`), the
  doc-comment states totality on all `u64 × u64`, and Threat Model **A-PF1** already asserts it
  as a formal-verification target. There is exactly **one** definition — the R-C2 function — and
  the R-C15 detector and every E1 predicate consume it *by reference* (§2.1), not by
  re-derivation. The only zero-denominator case (`prev == cur == 0`) has a zero numerator →
  `d = 0`; a one-sided zero (`d(X, 0)`, the redenomination × zero-print composite) has a nonzero
  denominator and reads the **defined, clamped** `SYMMETRIC_DEVIATION_MAX_PPM = 2_000_000` —
  no panic exists in the normative form.
- **The genuine residual (closed).** Several *prose* renderings of the formula — the Post-MVP
  Roadmap §6 R-C2 text, and this document's own §4.1 worked arithmetic — show the **unguarded**
  form `2·|cur − prev|·PPM / (cur + prev)`. A harness implementation ported *from prose* (the
  Python mirror is the live risk; a from-scratch Rust re-derivation likewise) would panic exactly
  as the review describes, and A-Q2-8's bit-identity requirement would not catch it — **both**
  mirrors could independently inherit the same prose omission. Closure, three parts:
  1. **Verbatim-port mandate (§0.2 amended):** both harness implementations must derive
     `symmetric_deviation_ppm` (and every §2.1 function) from the §30.1 **code snippet**, never
     from a prose formula; the prose forms are hereby declared *non-normative shorthand*.
  2. **Conformance vector set (A-Q2-5b):** pinned function-level vectors both implementations
     must reproduce before any scenario runs — `d(0,0) = 0` (guard path), `d(X,0) = d(0,X) =
     2_000_000` for all `X > 0` (clamp path, including `X = u64::MAX`: numerator
     `2·(2⁶⁴−1)·10⁶ < 2⁸⁵` fits `u128`), `d(X,X) = 0`, symmetry on a boundary corpus.
  3. **Named composite scenario S-4z (§5.5 amended):** the review's redenomination × zero-print
     event, elevated from the generic boundary grid to a pinned scenario with exact expected
     values — no panic, clamped readings, tier never falsely leaves Routine, conjunction-floor
     lock under transient universal decoupling, recovery on re-coupling.
- **Disposition:** no Yellowpaper change required (the normative function is already total —
  A-PF1); the E1 harness discipline and register are strengthened. Credit where due: the
  composite scenario is a genuinely sharper torture case than the generic grid, and the
  prose-port hazard is real.

### E1-A2 — Attainment overshoot rebound on target retracement *(valid in substance; language precisified, envelope quantified)*

- **Reported hazard.** After the Q4 catch-up and Q5 relock, a continuing decline in `required`
  (labor-anchor drift, §3.1 — and, more strongly, post-stabilization retracement of the off-ramp
  premium) can fall faster than the routine −5%/quarter slew; `applied` then mechanically lags
  **above** `required`, spiking `attainment_ppm > PPM` and breaking the S-1 table's
  "no overshoot by construction" note.
- **Premise verification (confirmed, with one precision).** Valid in substance. Two clarifications:
  (a) **A-Q2-3a survives as written** — it asserts *lower* bounds only; what breaks is the S-1
  table's pinned Q5+ attainment (`= 1_000_000`) under a retracement variant, and the imprecise
  note itself. (b) The note conflated two different properties: **per-move no-overshoot**
  (`clamp_move` never crosses its target in a single move — true by construction, A-Q2-2b
  stands) and **trajectory-level attainment ≤ PPM** (NOT guaranteed when the target itself falls
  faster than the slew — the review's point). The pinned S-1 `required` series plateaus, so the
  canonical run never exhibits the lag; the scenario *family* must.
- **Mechanism disposition — quantify and bound; do not "fix."** Two tempting mechanism patches
  were evaluated and **rejected**, with reasons recorded (the §31.1 stated-openly discipline):
  1. *A downward emergency tier with a relaxed direction rule* — rejected: loosening
     corroboration for downward moves hands a captured feed a −25%/quarter lever against a
     region's earnings, the exact manipulation the routine clamp exists to block.
  2. *An asymmetric routine clamp (fast-fall, slow-rise)* — rejected for the same reason:
     downward movement **reduces household payouts**, so a wide down-slew is an attack surface,
     not a safety feature. Overpayment falls on the emission reserve (bounded by
     `M_cap`/reserve/`route_surplus`); underpayment falls on households. The asymmetry is
     **accessibility-first by design** and is now documented as such.
  The residual — a transient, decaying regional overpay — is bounded, priced, and asserted
  (below), not denied. Thin-pool exposure is second-order: `κ_thin` and `CET_gross` are global
  and untouched (A-Q2-7), and the transient overpay (peak +7.5% in S-1r) cannot bridge the
  structural fresh-capital deficit (composed with Track E2's A-E2 grid, which asserts exactly
  this).
- **Closure, three parts:**
  1. **§4.2 note precisified** (per-move vs trajectory-level, pointer to S-1r).
  2. **Named scenario S-1r (§5.4 amended):** the retracement leg — `required` declines
     `1_620_000 → 1_490_000 → 1_360_000 → 1_300_000` (plateau) over Q5–Q7 as the premium
     retraces and labor-index drift continues. Floor-exact expected trajectory (routine tier,
     −5%/quarter max):

     | q | `required` | `applied` | `attainment_ppm` |
     |---|---|---|---|
     | Q5 | 1_490_000 | 1_539_000 | 1_032_885 |
     | Q6 | 1_360_000 | 1_462_050 | **1_075_036** ← peak overshoot (+7.5%) |
     | Q7 | 1_300_000 | 1_388_947 | 1_068_420 |
     | Q8 | 1_300_000 | 1_319_499 | 1_014_999 |
     | Q9 | 1_300_000 | 1_300_000 | 1_000_000 — converged |

     Per-quarter overshoot growth is analytically bounded by `(BP_FULL − ROUTINE_SLEW_BP) /
     (BP_FULL·(PPM − drop_q)/PPM)` ≈ `0.95/(1 − r_d)` per quarter of sustained drop `r_d`;
     cumulative overpay in S-1r = Σ(applied − required) = **259_496 ppm·quarters** (vs the
     2_252_110 valve-OFF underpay it mirrors — the asymmetry's price is ~11.5% of the harm it
     prevents). The retracement must **not** re-unlock the valve: premium retraces at breach
     magnitude (`d(2_000_000, 1_700_000) = 162_162`, direction down) but CPI still moves *up*
     (+10%/qtr → 95_238, no breach) — same-direction survivors = 1 < 2 → Routine holds
     (asserted).
  3. **New assertion A-Q2-3f (register amended):** trajectory-level overshoot is *bounded and
     decaying* — S-1r peak exactly `1_075_036`, monotone decay post-plateau, parity within 3
     quarters of the `required` plateau, cumulative overpay exactly `259_496` ppm·quarters,
     emission draw within `M_cap`/reserve slack throughout, and tier == Routine at every S-1r
     epoch.
- **Disposition:** assertion-language defect fixed; scenario family and register extended; the
  accessibility-first asymmetry documented as a deliberate, priced property with the rejected
  alternatives on the record. No mechanism change.

---

## 1. Two normative pins discovered in harness construction

Formalizing the §31.1 prose into executable integer predicates exposed two
specification-precision gaps. E1 pins both, pre-registered here as findings **E1-N1** and
**E1-N2** (candidate Yellowpaper amendments; register IDs allocated on acceptance — next free
slot R-C21). A third (**E1-N3**) fell out of the torture grid design. Recording them *before*
running is deliberate: a stress test that quietly resolves ambiguities in whichever direction
passes is not a stress test.

### E1-N1 — The decoupling detector must compare in **local-denomination space**

§31.1 (R-C15) specifies `symmetric_deviation_ppm` "between the feed's index level and the CPI
index level," without pinning the denomination of the feed level. The basket ingests residential
electricity in **µUSD/kWh** (§29), but CPI is inherently a **local-fiat** index. Under
hyperinflation these spaces shear apart mechanically: an *honestly floating* tariff (rising with
inflation) is *flat in µUSD* while fiat CPI multiplies — so a µUSD-space comparison flags every
honest feed in a hyperinflating region as decoupled, and the detector loses all discriminating
power exactly in scope. **The pin:** the detector runs on **local-denomination raw finalized
medians** — `index_level` of the feed's fiat-space value against `index_level` of fiat CPI, both
against the same base epoch. Then the textbook signatures hold exactly:

- frozen tariff: fiat level flat at `1_000_000` while CPI multiplies → deviation grows →
  flagged;
- honest floating tariff: fiat level ≈ CPI level → deviation ≈ 0 → never flagged.

The µUSD conversion continues to govern the feed's *basket contribution* (unchanged); only the
coherence comparison is fiat-space. Deterministic, recomputable, one sentence in the spec —
but load-bearing, as scenario S-0h (§5.1) demonstrates by failing under the un-pinned reading.

### E1-N2 — The global cross-check must not require **neighboring-region suffering**

§31.1 (R-C3) confirms an unlock "against the global-median and neighbouring-region series,"
treating a breach "isolated to one region with no corroboration in its economic neighbourhood"
as suspect. Read literally (*neighbors must also breach*), the cross-check **jams the valve for
every genuinely localized sovereign collapse** — the historically common case is precisely one
country's currency failing while its neighbors hold. E1 implements both readings as
`CROSS_CHECK_MODE` and lets the scenario matrix adjudicate:

- **Mode NB (neighbor-breach):** ≥ 1 neighboring region's corroborating feeds also breach.
- **Mode GD (global-divergence):** the shocked region's surviving corroborators must (a) breach
  **and** (b) each diverge from the *global-median* series of the same component by
  > `MACRO_DECOUPLING_PPM` — i.e., the shock is confirmed to be regional reality, not a global
  data artifact, while requiring nothing of the neighbors' economies. Feed-capture is still
  excluded by the *conjunction across independent components within the region* (forging
  correlated movement across CPI **and** the P2P off-ramp premium — sourced from cross-border
  markets outside a single reporting chain — remains the hard forgery §31.1 relies on).

Scenario S-3 (§5.3) shows Mode NB fails liveness on the canonical scenario while Mode GD passes
liveness *and* every safety scenario. E1's recommendation (subject to the run confirming the
pre-computed expectations): **pin the cross-check as Mode GD** via amendment.

### E1-N3 — Currency **redenomination** has no specified rebase path

A collapsing currency is routinely redenominated (10³–10⁶ old units → 1 new unit). Every
fiat-space raw series then steps by a factor of 10⁻ⁿ in one epoch: `symmetric_deviation_ppm`
clamps at `2_000_000` (total, panic-free — no liveness harm), but *semantically* every feed
decouples from every other unless all reporters rebase in the same finalization window. §31.2's
onboarding machinery sets baselines for *new* regions; nothing specifies an atomic rebase for an
*Active* region. E1's torture grid (§5.5) characterizes the blast radius (worst case: transient
suppression flags on all feeds → conjunction pruned below floor → valve locked *routine*, never
falsely open — safe but sticky) and files the finding: specify a coordinated `base_ref` rebase
transition (a §31.2-style anchored event), amendment candidate.

---

## 2. The system under test, formalized

### 2.1 Function inventory (verbatim from the Yellowpaper)

| Function | Source | Role in E1 |
|---|---|---|
| `symmetric_deviation_ppm(prev, cur)` | §30.1 | per-quarter feed movement; decoupling deviation; breach test |
| `symmetric_deviation_mar_ppm(series, w)` | §30.1 | opex volatility for `rebalance` |
| `index_level(value, base_ref)` | §29 | raw median → `Ppm` level |
| `cppi_multiplier(levels, weights)` | §29 | basket composition |
| `rebalance(ctl)` | §30.2 | quarterly reweight (opex boost; anchors never boosted — R-C14) |
| `clamp_move(prev, target, slew_bp)` | §34 | tier-dependent applied movement |
| `compute_epoch_gap_fill(...)`, `route_surplus(...)` | §33–33.1 | settlement of the localized target; emission exposure bounds |

`clamp_move` is pinned in the harness as:

```rust
/// Applied value moves toward `target`, bounded to ±slew_bp per quarter. u128 cast-before-multiply.
pub fn clamp_move(prev: u64, target: u64, slew_bp: u32) -> u64 {
    let up   = (prev as u128 * (BP_FULL + slew_bp) as u128 / BP_FULL as u128) as u64;
    let down = (prev as u128 * (BP_FULL - slew_bp) as u128 / BP_FULL as u128) as u64;
    target.clamp(down, up)      // never overshoots the target; never exceeds the slew
}
```

### 2.2 The R-C15 detector and R-C3 valve, as executable integer predicates

All series below are **raw finalized medians** (pre-clamp — the clamp governs *application*,
§34; the predicates are recomputable from the published leaves, §31.1). Per E1-N1, coherence
comparisons are fiat-space.

```rust
// ---- R-C15: dynamic macro-coherence -------------------------------------------------
/// Fiat-space levels vs the common base epoch (E1-N1 pin).
fn decoupling_dev(feed_fiat_level: Ppm, cpi_fiat_level: Ppm) -> Ppm {
    symmetric_deviation_ppm(feed_fiat_level, cpi_fiat_level)
}
/// Set: sustained divergence. Clear: immediate on first in-band epoch (§31.1 "the moment it
/// re-couples"). Asymmetric by design; flap risk is bounded because the flag only edits
/// conjunction MEMBERSHIP, and the unlock predicate re-evaluates over a full window anyway.
state_suppressed[k](q) = for all j in (q − DECOUPLING_EPOCHS, q]:
                             decoupling_dev(level_k(j), level_cpi(j)) > MACRO_DECOUPLING_PPM

// ---- R-C3 + R-C15: the two-tier valve ------------------------------------------------
dir_k(q)    = sign(raw_k(q) − raw_k(q−1))                       // integer comparison, no floats
breach_k(q) = symmetric_deviation_ppm(raw_k(q−1), raw_k(q)) >= EMERGENCY_DEVIATION_PPM
held_k(q)   = for all j in (q − CORROBORATION_EPOCHS, q]: breach_k(j) && dir_k(j) == dir_k(q)

survivors(q) = CORROB_SET \ { k : state_suppressed[k](q) }       // dropped from CONJUNCTION only;
                                                                  // basket weight untouched (§31.1)
unlock(q)    = |survivors(q)| >= MIN_CORROBORATING_FEEDS          // floor: pruning can never unlock
            && |{ k in survivors(q) : held_k(q) }| >= MIN_CORROBORATING_FEEDS
            && cross_check(q)                                     // E1-N2: Mode NB vs Mode GD under test

tier(q+1)    = if unlock(q) { Emergency } else { Routine }        // relock is immediate on lapse
applied(q+1) = clamp_move(applied(q), raw_localized_target(q+1),
                          if tier(q+1) == Emergency { EMERGENCY_SLEW_BP } else { ROUTINE_SLEW_BP })
```

Every quantity above is a pure-integer function of anchored feed history: an emergency-tier
posting whose predicate does not re-derive, or whose movement exceeds the active tier's slew, is
**fraud-provable** exactly like a routine posting (§22, B-2). The harness includes a
divergent-poster arm that asserts exactly this (A-Q2-2e).

### 2.3 Settlement coupling

Per region `r`, the harness settles each quarter with the localized target in place of the
global gross (regional settlement per the Part VII pipeline §27):
`gap_fill_r = compute_epoch_gap_fill(n_eff_r, localized_target_r, u_ref_r, m_cap, reserve)` and
contributor payout/unit `= min(u_ref_r, localized_target_r) + gap_fill_r / n_eff_r`, with
`route_surplus` handling the opposite regime. `κ_thin` and the CMI path are upstream and
untouched by the valve — asserted, not assumed (A-Q2-7).

---

## 3. The deterministic unit model

### 3.1 Exchange-rate and feed generators (all integer)

The shock is **30% month-over-month** local-fiat inflation — chosen deliberately because
`1.3³ = 2.197` exactly, so the quarterly factor is the exact integer ratio
`FX_Q_PPM = 2_197_000` and every compounded level is floor-exact:

```
fx_level(q)  = fx_level(q−1) · FX_Q_PPM / PPM          // u128; fiat-per-USD index, base = PPM
             = 1_000_000, 2_197_000, 4_826_809, 10_604_499, …   (2197² = 4_826_809 exactly)
```

Feed generators for the shocked region (fiat-space raw series, base epoch Q0 = `1_000_000`):

| Feed | Condition | Fiat-space level `level(q)` | µUSD-space (basket) behavior |
|---|---|---|---|
| Residential electricity | **tariff-freeze from Q1** (the R-C15 condition) | `1_000_000` flat | µUSD value collapses ∝ `PPM²/fx_level(q)` — a frozen tariff becomes nearly free in hard terms |
| Local CPI | tracks inflation | `fx_level(q)` | anchor; fiat-native |
| P2P stablecoin premium | off-ramp stress | premium multiplier series: `1_030_000 → 1_250_000 → 1_600_000 → 1_950_000 → 2_000_000` (plateau) | denomination-free ratio; the cross-border corroborator (E1-N2) |
| Digital PPP / labor index | scarcity / real labor-index collapse | modeled as slow drifts (±10–20% over the horizon) | complete the basket; not in `CORROB_SET` |
| Neighbor regions × 3, global median | stable | parity ± ≤ 2%/qtr noise band | the cross-check series (E1-N2) |

**The required-target series** (`raw_localized_target`, the tracking objective) is *derived
inside the unit model*, not hand-picked: it is the localized multiplier computed on the
**uncensored** scenario economy (no freeze, no clamps) — the multiplier that would hold a
contributor's real attainment at exactly `PPM`. For S-1 it evaluates to:

```
required(q) = [1_000_000, 1_180_000, 1_380_000, 1_550_000, 1_620_000, 1_620_000, …]  (Ppm)
```

(dominated by the off-ramp premium — earnings realized locally lose the premium haircut — plus
scarcity PPP drift, partially offset by the frozen-tariff opex *windfall* and the real labor-index
anchor pulling down; the composition weights are recorded in `q2stats.json`).

### 3.2 The contributor P&L model (integer µUSD)

Per quarter, for a reference honest household in the shocked region:

```
attainment_ppm(q) = applied(q) · PPM / required(q)               // u128, floor
```

`attainment_ppm = PPM` ⇒ the localized target delivers exactly the §1 real earnings promise
under the shock; the **systemic-loss regime** is pre-registered as
`attainment_ppm < LOSS_FLOOR_PPM = 750_000` (a quarter of real earnings lost to tracking lag —
beyond any plausible opex margin for the §1 reference household). Acceptance bounds in §6.

---

## 4. Scenario S-1 — the canonical collapse + tariff freeze (worked, floor-exact)

Shock at Q1; freeze at Q1; stabilization at Q4 (inflation abates to +10%/qtr; premium plateaus).
Every number below is the harness's expected value, computed by hand from §2–§3 and pinned in
the assertion register.

### 4.1 Detection and valve timeline

| q | CPI fiat level | Elec fiat level | `decoupling_dev(elec, CPI)` | suppressed? | `breach_CPI` (move) | `breach_prem` (move) | tier for q+1 |
|---|---|---|---|---|---|---|---|
| Q0 | 1_000_000 | 1_000_000 | 0 | — | — | — | Routine |
| Q1 | 2_197_000 | 1_000_000 | **748_827** > 400_000 (1st) | not yet (needs 2) | 748_827 ✓ (1st) | 192_982 ✓ (1st) | Routine — elec still in set, `breach_elec = 0` fails the full conjunction |
| Q2 | 4_826_809 | 1_000_000 | **1_313_517** (2nd) | **`state_suppressed` sets** | 748_827 ✓ (2nd) | 245_614 ✓ (2nd) | **Emergency** — survivors {CPI, premium} = 2 ≥ floor, both held 2 epochs, same direction, cross-check GD ✓ |
| Q3 | 10_604_499 | 1_000_000 | 1_655_297 (persists) | suppressed | 748_827 ✓ | 197_183 ✓ | Emergency |
| Q4 | 11_664_949 (+10%) | 1_000_000 | persists | suppressed | **95_238 ✗** (< 150_000) | **25_316 ✗** | **Routine (relock)** — corroboration lapses at Q4 close |

Worked checks (the arithmetic the mirror implementations must reproduce exactly):

- `decoupling_dev(Q1) = 2·|2_197_000 − 1_000_000|·PPM / (2_197_000 + 1_000_000)
  = 2_394_000·10⁶ / 3_197_000 = 748_827` (floor).
- `decoupling_dev(Q2) = 2·3_826_809·10⁶ / 5_826_809 = 1_313_517` (floor).
- CPI per-quarter move is **scale-invariant** under constant-factor growth:
  `d(L, 2.197·L) = 748_827` every shock quarter — a property the harness asserts (it is why a
  constant-rate hyperinflation corroborates *steadily*, not just once).
- Premium moves: `d(1_030_000, 1_250_000) = 2·220_000·10⁶/2_280_000 = 192_982`;
  `d(1_250_000, 1_600_000) = 245_614`; `d(1_600_000, 1_950_000) = 197_183`; plateau
  `d(1_950_000, 2_000_000) = 25_316 < 150_000` — lapse.
- Post-stabilization CPI move: `d(x, 1.1·x) = 2·0.1/2.1 = 95_238 < 150_000` — lapse.

**Key latency result:** valve latency = `max(DECOUPLING_EPOCHS, CORROBORATION_EPOCHS)` =
**2 quarters** from shock onset. The dip this latency causes (Q2 attainment below) is the
honest, quantified cost of anti-manipulation persistence — reported as the calibration tension
`CORROBORATION_EPOCHS` must resolve (§7), never hidden.

### 4.2 Applied-target trajectory and attainment

Valve-ON (emergency tier active for the Q3 and Q4 postings):

| q | `required` | `applied` (valve-ON) | computation | `attainment_ppm` |
|---|---|---|---|---|
| Q1 | 1_180_000 | 1_050_000 | routine: `clamp_move(1_000_000, 1_180_000, 500)` | **889_830** |
| Q2 | 1_380_000 | 1_102_500 | routine (unlock decided at Q2 close) | **798_913** ← trough |
| Q3 | 1_550_000 | 1_378_125 | emergency: `min(1_550_000, 1_102_500·12_500/10_000)` | **889_113** |
| Q4 | 1_620_000 | 1_620_000 | emergency: `1_378_125·1.25 = 1_722_656 → clamped to target` | **1_000_000** — caught up |
| Q5+ | 1_620_000 | 1_620_000 | routine (relocked); target attained. *(E1-A2)* per-move no-overshoot is by construction (`clamp_move` never crosses its target); trajectory-level attainment can exceed `PPM` if `required` later falls faster than the routine slew — that regime is pinned in **S-1r**, bounded by **A-Q2-3f** | 1_000_000 |

Valve-OFF counterfactual (routine ±5% only — the pre-R-C3 hysteresis trap):

```
applied:    1_050_000  1_102_500  1_157_625  1_215_506  1_276_281  1_340_095  …  1_620_000 at Q10
attainment:   889_830    798_913    746_855    750_313    787_827    827_219  …  ≥ 950_000 only at Q9
```

**Headline deltas (pinned in A-Q2-3):**

| Metric | Valve-ON | Valve-OFF |
|---|---|---|
| Minimum attainment | **798_913** (Q2, the latency dip) | **746_855** (Q3) — breaches `LOSS_FLOOR_PPM` |
| Quarters to recovery (≥ 950_000) | **3** (Q4) | **9** (Q9) |
| Quarters below 800_000 | 1 (Q2) | 4 consecutive (Q2–Q5) |
| Cumulative underpayment Σ(required − applied), ppm·quarters | **579_375** | **2_252_110** — **≈ 3.89×** |

The valve-OFF run enters and *stays* in the systemic-loss regime for the duration of the shock —
the quantitative content of "underpaying households exactly when their earnings matter most"
(§31.1). The valve-ON run's single sub-800_000 quarter is the corroboration latency, bounded and
priced.

### 4.3 Settlement-side checks (S-1, valve-ON)

With region share `n_eff_r = 2%` of network effective units and `u_ref_r` held at its pre-shock
level: the emergency-tier target lift raises the per-unit gap by ≤ `+517_500 ppm` of gross at
peak (Q4 applied vs Q0), so regional emission draw stays `< 3.2%` of `M_cap` at the harness's
genesis schedule — **A-Q2-3d** asserts `gap_fill_r ≤ min(M_cap, reserve)` slack at every epoch
and that `decay_cap()` monotonicity is untouched. `route_surplus` conservation
(`to_reserve + burned == surplus`) is asserted over the full run (it should be unreachable in
the shortfall regime — asserted as exactly-zero surplus, a cheap invariant).

---

## 5. The scenario matrix

### 5.1 S-0 — null and honest-tracking controls

- **S-0:** no shock; all feeds parity ± ≤ 2%/qtr noise. Expect: no suppression flag, no unlock,
  applied ≡ routine, attainment ≡ [990_000, 1_010_000]. Any flag or unlock is a
  false-positive failure.
- **S-0h (the E1-N1 witness):** hyperinflation with an **honestly floating** tariff (fiat
  electricity tracks CPI exactly). Expect under the E1-N1 fiat-space pin:
  `decoupling_dev ≡ 0`, no suppression; electricity itself corroborates
  (`breach_elec = 748_827` ✓) so the valve unlocks on the **full three-feed conjunction** at Q2
  with **no pruning needed**. Under the un-pinned µUSD-space reading this scenario false-flags
  the honest feed (`d(455_166, 2_197_000) = 1_313_544` at Q1) — the run that justifies E1-N1.

### 5.2 S-2 — safety under adversarial feed conditions (valve must stay shut)

- **S-2a (single captured feed):** premium series alone driven ×3 while CPI and electricity hold
  parity. Expect: premium breaches but survivors-breaching = 1 < `MIN_CORROBORATING_FEEDS` →
  **locked**; additionally the captured feed *decouples from CPI* → suppressed → pruned from the
  conjunction entirely. Applied path bit-identical to S-0 (the ±5% routine clamp and the
  premium's fixed anchor weight bound the basket drift; R-C14: never weight-boosted).
- **S-2b (pruning condition):** feed conditions engineered so electricity *and* premium both
  flag `state_suppressed`. Survivors = {CPI} = 1 < floor → **unlock is structurally
  impossible** regardless of CPI's breach — the harness proof of "dropping cannot itself open
  the valve" (§31.1). Asserted across every epoch of the run.
- **S-2c (divergent emergency poster):** a posting applies `EMERGENCY_SLEW_BP` movement in a
  quarter where the §2.2 predicate evaluates Routine (and a second variant: movement beyond
  ±2_500 Bp during a genuine unlock). Expect: independent recomputation rejects both — the
  fraud-proof fires (B-2 discipline; A-Q2-2e).

### 5.3 S-3 — the E1-N2 adjudication (isolated sovereign collapse)

S-1 economics with **stable neighbors** (the historically common case):

| Mode | Expected outcome | Verdict |
|---|---|---|
| NB (neighbor-breach) | cross-check fails every epoch → valve never unlocks → attainment trajectory ≡ valve-OFF (min 746_855, 9-quarter recovery) | **fails liveness** in the scenario R-C3 exists for |
| GD (global-divergence) | shocked region's CPI and premium each diverge from global medians by ≫ 400_000 → cross-check passes at Q2 → S-1 timeline reproduced exactly | passes liveness; and in S-2a/S-2b GD adds a second lock (a captured single feed diverges, but the *conjunction* still fails) — safety unchanged |

Plus **S-3g (global-shock control):** all regions shocked identically (a global data artifact or
genuine global event) — under GD the *divergence-from-global-median* term correctly reads ≈ 0,
the emergency tier stays shut regionally, and the global path (CMI/CPPI trend under routine
clamps) carries the adjustment. This is the case the cross-check exists to filter, asserted
explicitly.

### 5.4 S-1 variants — robustness family

- **S-1b (partial freeze):** tariff pass-through at 15%/mo against 30%/mo inflation (fiat elec
  factor 1.520875/qtr). Q1: `d(1_520_875, 2_197_000) = 363_705 < 400_000` — not yet decoupled —
  but `breach_elec = d(1_000_000, 1_520_875) = 413_281 ≥ 150_000` ✓ — the feed **corroborates
  instead**. By Q2 cumulative divergence (`d(2_313_060, 4_826_809) = 704_064`) flags it anyway;
  either way the valve opens on schedule. This is the **complementarity property** (§7): a
  suppression too mild to flag is too mild to withhold corroboration.
- **S-1c (R-C14 damping on/off):** enabling inverse-volatility damping of the `is_liquid`
  premium anchor must not change the unlock timeline by even one epoch (the valve reads raw
  feeds, not weights) — asserted bit-exactly; only the basket composition shifts, within clamps.
- **S-1d (reporter noise):** seeded ±1% integer noise on every raw median; the S-1 timeline
  (flag epoch, unlock epoch, relock epoch) must be invariant, and boundary-oscillating
  suppression flags (set/clear flapping near 400_000) must never flap the *tier* within a
  corroboration window — the window re-evaluation absorbs membership flap.
- **S-1r (retracement leg — E1-A2):** S-1 continued with `required` declining
  `1_620_000 → 1_490_000 → 1_360_000 → 1_300_000` over Q5–Q7 (premium retraces
  `2_000_000 → 1_700_000 → 1_450_000 → 1_350_000`; labor-index drift continues; tariff unfreezes Q6).
  Expected: `applied` descends at the routine −5%/quarter and lags **above** the falling target —
  attainment `1_032_885 → 1_075_036 (peak) → 1_068_420 → 1_014_999 → 1_000_000` (Q9 parity, exact
  table in §0.4/E1-A2). The valve must **not** re-unlock downward (premium breaches down at
  `162_162` but CPI still moves up at `95_238` — same-direction survivors = 1 < 2), and the tariff
  unfreeze must clear `state_suppressed` without tier effect. Cumulative overpay exactly
  `259_496` ppm·quarters — 11.5% of the valve-OFF underpay the mechanism prevents (§4.2).

### 5.5 S-4 — totality and overflow torture (the Appendix-A re-verification)

- **40-quarter compounding:** CPI level reaches `2.197⁴⁰ ≈ 4.6·10¹³ ppm` — still 5½ orders of
  magnitude inside `u64`; every `symmetric_deviation_ppm` intermediate provably < 2⁸⁵ (the AR41
  headroom claim re-verified empirically at every step).
- **Boundary grid:** feeds ∈ {0, 1, 2ᵏ ± 1, `u64::MAX`} × all pairings, through every §2.1
  function — no panic, no wrap, clamps engage (`SYMMETRIC_DEVIATION_MAX_PPM` at the
  collapse/appearance edges; `max(1, ·)` zero-guards).
- **E1-N3 redenomination event:** all fiat series step ×10⁻⁶ at Q6. Same-window coordinated
  rebase ⇒ pairwise coherence preserved (deviations ≈ 0); staggered rebase ⇒ transient universal
  decoupling, conjunction pruned **below floor**, valve locked-routine (safe-but-sticky — never
  falsely open), recovering when series re-couple. Characterized, filed as the E1-N3 amendment
  motivation.
- **S-4z (redenomination × zero-print composite — E1-A1):** the staggered-rebase event
  coinciding with a single-epoch liquidity-shock **zero print** on one feed (raw median = 0 in
  the rebase window — the review's composite). Expected, in **both** implementations: no panic
  (`d(X, 0) = 2_000_000` clamped via the §30.1 guard; `d(0,0) = 0` if the prior epoch also
  printed zero); the zero-print reads as a defined 200% deviation, direction down; it can never
  corroborate an unlock (single epoch — fails `CORROBORATION_EPOCHS`; and the rebase-pruned
  conjunction is below floor regardless); tier == Routine throughout; full recovery on
  re-coupling. This scenario is the runtime witness for the A-Q2-5b conformance vectors.

---

## 6. The assertion register

Method key (TM Part III): P = property-based, D = differential (Rust vs Python mirror),
S = static/structural, M = model checking over the valve state machine.

| ID | Assertion | Expected (S-1 unless noted) | Method |
|---|---|---|---|
| **A-Q2-1a** | R-C15 flags the frozen feed: `state_suppressed[elec]` sets at exactly **Q2 close** (devs 748_827, 1_313_517 — two consecutive > 400_000) and persists through the freeze | exact epochs & integer devs | P, D |
| **A-Q2-1b** | No false flag: S-0 and S-0h produce **zero** suppression flags under the E1-N1 pin (and S-0h demonstrably false-flags under the µUSD-space reading — the pin's witness) | 0 flags / witness reproduced | P, D |
| **A-Q2-1c** | Dropped from conjunction, **not** basket: electricity's basket weight and clamped contribution are unchanged by the flag in every epoch | bit-identical weights vs flag-free run | S, D |
| **A-Q2-2a** | Unlock at exactly the **Q3 posting**, survivors {CPI, premium}, both held `CORROBORATION_EPOCHS`, same direction; not one epoch earlier (Q2-posting must be Routine: elec's `breach = 0` blocks the full conjunction; suppression not yet held) | exact epoch | M, D |
| **A-Q2-2b** | Emergency slew is `±2_500 Bp` and `clamp_move` never crosses its target **per move** (Q4: `1_722_656 → 1_620_000`); trajectory-level lag above a falling target is a distinct, bounded property — A-Q2-3f *(precisified, E1-A2)* | exact applied series (§4.2) | P, D |
| **A-Q2-2c** | **Relock at Q5 posting** — first lapse epoch (Q4 moves 95_238 / 25_316 < 150_000) relocks immediately; no standing-loophole drift afterward | exact epoch | M, D |
| **A-Q2-2d** | Safety: S-2a and S-2b never unlock at any epoch; the floor makes S-2b's unlock **structurally impossible** | 0 unlocks | M, P |
| **A-Q2-2e** | Fraud-provability: both S-2c divergent postings are rejected by independent recomputation of the §2.2 predicate + slew bound | 2/2 rejections | D, M |
| **A-Q2-3a** | Valve-ON attainment: `≥ 750_000` at **every** epoch (min **798_913** at Q2) and `≥ 950_000` within 2 quarters of unlock (Q4 = 1_000_000) | exact trough & recovery | P, D |
| **A-Q2-3b** | Necessity: valve-OFF breaches the loss floor (**746_855** at Q3), stays `< 800_000` for 4 consecutive quarters, recovers only at Q9 | exact counterfactual series | P, D |
| **A-Q2-3c** | Cumulative underpayment ratio OFF/ON = `2_252_110 / 579_375` ≈ **3.89×** | exact integer sums | D |
| **A-Q2-3d** | Settlement bounds: `gap_fill_r ≤ min(M_cap, reserve)` with slack at every epoch; `decay_cap` monotone; `route_surplus` conservation (surplus ≡ 0 in-shock) | invariants over full run | P |
| **A-Q2-3e** | Locality: every non-shocked region's applied series is **bit-identical** to its S-0 run (no contagion through the controller) | bit-equality | D |
| **A-Q2-3f** *(E1-A2)* | Retracement overshoot is **bounded and decaying**: S-1r peak attainment exactly `1_075_036` at Q6, monotone decay after the `required` plateau, parity (`1_000_000`) within 3 quarters of the plateau (Q9), cumulative overpay exactly `259_496` ppm·quarters, emission draw within `M_cap`/reserve slack throughout, and tier == Routine at every S-1r epoch (no downward re-unlock) | exact S-1r series (§0.4) | P, D |
| **A-Q2-4** | Complementarity (no dead zone): over the (inflation-rate × pass-through) sweep grid at the §0.3 strawmen, every cell either corroborates (`breach_elec ≥ 150_000`) or decouples within `DECOUPLING_EPOCHS + 1` — no cell where a suppression both withholds corroboration and evades the flag; emit the phase diagram + the analytic coupling constraint (§7) | full-grid pass + artifact | P, D |
| **A-Q2-5** | Totality/overflow: the §5.5 torture grid runs panic-free; every intermediate within the A-PF1 bounds; redenomination is safe-but-sticky (never falsely open) | 0 panics; characterized | P (fuzz), D |
| **A-Q2-5b** *(E1-A1)* | Conformance vectors reproduced by **both** implementations before any scenario runs: `d(0,0) = 0`, `d(X,0) = d(0,X) = 2_000_000` ∀ `X > 0` (incl. `u64::MAX`), `d(X,X) = 0`, boundary-corpus symmetry — the guard against a from-prose port omitting the §30.1 `max(1, sum)` zero-guard; S-4z is the runtime witness | exact vectors | P, D, **V** |
| **A-Q2-6** | R-C14 invariance: the premium anchor is never weight-boosted in any run; S-1c damping toggle leaves the unlock timeline bit-identical | S, D |
| **A-Q2-7** | Global invariance: `κ_thin` and `CET_gross` (CMI path) identical across all scenarios — the valve moves *local purchasing-power tracking*, never the global gross rate | bit-equality | S, D |
| **A-Q2-8** | Determinism: `q2stats.json` from the Rust normative and Python mirror harnesses are **bit-identical** in every integer field | bit-equality | D |

---

## 7. Calibration outputs — what E1 hands the F5-adjacent macro workstream

E1 does not finalize the macro constants (that is F5-adjacent field data, §37); it maps their
**feasible region and coupling constraints**:

1. **The complementarity inequality.** From the A-Q2-4 sweep: no dead zone exists iff a
   sustained per-quarter pass-through gap large enough to withhold corroboration accumulates to
   the decoupling threshold within the window — approximately, for feed factor `p` and CPI
   factor `g` per quarter: if `2(p−1)/(p+1) < EMERGENCY_DEVIATION_PPM/PPM` then
   `(g/p)^DECOUPLING_EPOCHS` must satisfy `2(r−1)/(r+1) > MACRO_DECOUPLING_PPM/PPM` at
   `r = (g/p)^DECOUPLING_EPOCHS`. The three constants must be chosen **jointly**; E1 emits the
   feasible-region surface so the calibration study picks inside it. (At the strawmen, the
   canonical 30%/mo shock clears the constraint with a wide margin — §5.4 S-1b.)
2. **The latency–manipulation frontier.** Valve latency is
   `max(DECOUPLING_EPOCHS, CORROBORATION_EPOCHS)`; the S-1 trough (798_913 at 2 quarters) scales
   with it. E1 emits attainment-trough vs latency across
   `CORROBORATION_EPOCHS ∈ {1, 2, 3}` × shock-steepness, quantifying what each epoch of
   anti-manipulation persistence costs the shocked region's households — the explicit trade the
   calibration owner must sign, per the §31.1 stated-openly discipline.
3. **`EMERGENCY_DEVIATION_PPM` placement.** The 150_000 strawman sits between routine-clamp
   territory (moves ≤ ~100_000/qtr pass under ±5% tracking without valve help) and the S-1
   corroborator moves (192_982–748_827). The sweep maps false-unlock rate (on the S-0 noise
   family) vs missed-unlock rate (on shock-steepness) as the operating characteristic.
4. **Cross-check pin (E1-N2).** The S-3 adjudication table, feeding the Mode-GD amendment.

## 8. Acceptance criteria, findings protocol, exit

- **Green bar:** all A-Q2 assertions pass in both implementations, bit-identically (A-Q2-8), in
  CI as a deterministic gate (no network, no wall-clock dependence, fixed seeds recorded in the
  artifact).
- **Findings:** any assertion failure, or any behavior contradicting a Yellowpaper claim, is a
  finding — filed against the owning section, resolved by amendment (never by weakening the
  assertion to pass), then re-run. E1-N1/N2/N3 are pre-registered as spec-precision findings
  with their proposed amendments and witnesses; they enter the §4 pipeline with the campaign
  report regardless of the green bar.
- **Artifacts:** `q2stats.json` (all series, all assertion outcomes, integer-exact),
  the A-Q2-4 phase diagram, the §7 frontier tables, and the campaign report cross-referenced by
  assertion ID — the same shape WP-3.5/`livestats.json` gave Q1, so the Iteration-3 analysis
  tooling carries over.
- **Exit → Track E2:** with the valve proven on a single-region shock, the next campaign extends
  to multi-region contagion (correlated shocks, shared-border economies — where Mode GD's
  divergence term is genuinely stressed) and to the oracle layer's reporter-median capture
  interacting with the valve (TM V3 composition) — deliberately out of E1 scope so this
  campaign's claims stay sharp.

---

*Maintained under the Yellowpaper §4 amendment discipline. E1's pre-registered pins (E1-N1
denomination space, E1-N2 cross-check semantics, E1-N3 redenomination rebase) and any run
findings enter as numbered amendments against §31.1/§31.2; the harness constants tagged
**[calibration]** remain strawmen under stress, not finalized values — E1 proves the mechanism
total, live, safe, and necessary at the strawmen, and maps the region within which the F5-adjacent
macro study must place the final constants.*
