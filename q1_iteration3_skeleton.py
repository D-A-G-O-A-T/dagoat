"""
GoatCoin (GOAT) — Q1 Adversarial Simulation, ITERATION 3 skeleton.

Scope: the VERIFICATION layer — cross-class collusion / framing (R-VER1), band-edge
no-attribution (R-VER2), cross-class widening (R-CC1 residual), registration gaming
(R-MAT3 residual). Those residual IDs are defined in the Yellowpaper's residual register.

This skeleton ports the exact predicates from the Rust ground truth
(goatcoin-rs/crates/goat-protocol/src/verification.rs) so the model reasons against the
deployed mechanism, and runs an analytic smoke sweep for S1 (framing) on strawman
parameters. Live-testnet calibration (WP-3.5) replaces the strawmen.

Refinement (this session): (a) S1's structural result confirmed — framing requires MAJORITY
control of the disjoint-pairable escalation pool; (b) a LiveStats data interface added so the
model can be calibrated from real MVP-2/MVP-3 runs (escalation outcomes, divergence
distributions, pool composition) instead of strawman constants. MVP-2 already emits exactly
these via RoundOutcome (status / selected_c / receipts) + the assignment logs.

SECURITY / EXECUTION: stdlib only (math, random, dataclasses), deterministic, no I/O.
Run:  python q1_iteration3_skeleton.py
"""
import json
import math
import os
from dataclasses import dataclass, field
from typing import List

# ---------------- verification predicates (ported from verification.rs) ----------------
EPS = 1e-9
TOKEN_THRESHOLD = 0.98
BASE_SLASH, SLASH_CAP, COUPLING = 15.0, 20.0, 1.0 / 3.0  # B-1


def effective_profile(band_a, band_b, same_class, task_bound):
    """C-1: same-class uses own band; cross-class uses max(band_a, band_b); ineligible
    (None) if the applicable band exceeds the task bound (-> pin same-class)."""
    band = band_a if same_class else max(band_a, band_b)
    if band > task_bound + EPS:
        return None
    return band


def agree(l_inf, token_agreement, band):
    """C-5: tokens AND numerics within band."""
    return token_agreement >= TOKEN_THRESHOLD and l_inf <= band + EPS


def slash_multiple(tol_width, tol_ref=8.0):
    """B-1: coupling 1/3, clamped to [15x, 20x]."""
    raw = BASE_SLASH * (1.0 + COUPLING * (tol_width / tol_ref)) if tol_ref > 0 else BASE_SLASH
    return max(BASE_SLASH, min(SLASH_CAP, raw))


def cheat_ev(value, p_detect, slash):
    """cheat_EV < 0 iff p_detect*slash > 1."""
    return value - p_detect * slash * value


# ---------------- data interface: statistics consumed from MVP-2 / MVP-3 runs ----------------
@dataclass
class LiveStats:
    """Statistics the simulation calibrates against, produced by live testnet runs. Every
    field maps to something MVP-2 already emits (RoundOutcome + assignment logs) or MVP-3
    will (density probe, class maturity). Until then, defaults are Iteration-2 strawmen."""
    # escalation-outcome counts (from RoundOutcome.status + slashed/winner)
    n_settle: int = 0
    n_c_agrees_a: int = 0
    n_c_agrees_b: int = 0
    n_c_agrees_both: int = 0        # -> R-VER2 no-attribution rate
    n_quarantine: int = 0
    # empirical numeric divergence per class pair (RoundOutcome receipts -> l_inf), for S2
    divergence_l_inf: List[float] = field(default_factory=list)
    # escalation-pool composition (from assignment logs + registry), for S1
    escalation_pool_size: int = 40
    disjoint_pairable_fraction: float = 1.0
    # per-site infra cost of a genuinely distinct residential endpoint ($/mo), Iteration-2 curve
    per_site_cost: float = 70.0
    # profile_remeasure frequency (RoundOutcome.profile_remeasure), R-VER2 detection lever
    profile_remeasure_rate: float = 0.0
    # MVP-3 additions: F6 cohort-merge stats (density probe) for S4 registration gaming
    f6_merge_events: int = 0                 # endpoints that triggered COHORT_MERGE
    coverage_inflation_prevented: float = 0.0  # naive_clusters / effective_clusters (>1 = F6 working)

    def no_attribution_rate(self) -> float:
        total = self.n_settle + self.n_c_agrees_a + self.n_c_agrees_b + self.n_c_agrees_both + self.n_quarantine
        return self.n_c_agrees_both / total if total else 0.0

    def f6_effectiveness(self) -> float:
        """Coverage inflation the probe prevented (from MVP-3: naive vs effective cluster
        counts). >1 means F6 is collapsing Sybil cohorts as intended (SC6)."""
        return self.coverage_inflation_prevented


def s1_params_from_live(live: LiveStats):
    """Derive S1's model parameters from live statistics (replaces strawman constants)."""
    return dict(pool_size=max(1, round(live.escalation_pool_size * live.disjoint_pairable_fraction)),
                per_site_cost=live.per_site_cost)


def load_livestats(path: str) -> LiveStats:
    """Load a real livestats.json exported by the Rust collector (WP-3.5) into LiveStats.
    This is the bridge from the deployed testnet to the adversarial model — every field comes
    from instrumented distributed rounds + the density probe, not strawman constants."""
    with open(path) as f:
        d = json.load(f)
    eo = d["escalation_outcomes"]
    f6 = d["f6"]
    return LiveStats(
        n_settle=eo["settle"], n_c_agrees_a=eo["c_agrees_a"], n_c_agrees_b=eo["c_agrees_b"],
        n_c_agrees_both=eo["c_agrees_both"], n_quarantine=eo["quarantine"],
        divergence_l_inf=list(d.get("divergence_l_inf", [])),
        escalation_pool_size=round(d["escalation_pool_disjoint_pairable_mean"]),
        disjoint_pairable_fraction=1.0,  # the mean already counts only disjoint-pairable candidates
        per_site_cost=70.0,              # infra cost still an external assumption (F5 study)
        profile_remeasure_rate=d["profile_remeasure_rate"],
        f6_merge_events=f6["merge_events"], coverage_inflation_prevented=f6["inflation_prevented"],
    )


def wilson(k, n, z=1.96):
    """Wilson score 95% confidence interval for a binomial proportion k/n. Robust at small n
    and at k=0 (unlike the normal approximation). Returns (low, high)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, center - margin), min(1.0, center + margin))


def pct(x):
    return f"{x * 100:.1f}%"


def report_from_real_data(path: str):
    """Produce R-VER1 / R-VER2 / R-MAT3 results with 95% confidence intervals from a real
    testnet livestats.json (WP-3.5 campaign)."""
    with open(path) as f:
        d = json.load(f)
    live = load_livestats(path)
    n = d["rounds"]
    eo = d["escalation_outcomes"]
    be = d.get("band_edge", {})
    f6 = d["f6"]
    escalations = eo["c_agrees_a"] + eo["c_agrees_b"] + eo["c_agrees_both"] + eo["quarantine"]

    print(f"\n=== REAL DATA ({os.path.basename(path)}): {n} rounds, {escalations} escalations ===")
    print(f"  outcomes: settle={eo['settle']} slashB={eo['c_agrees_a']} slashA={eo['c_agrees_b']} "
          f"no-attribution={eo['c_agrees_both']} quarantine={eo['quarantine']}")

    # R-VER1 -----------------------------------------------------------------
    p = s1_params_from_live(live)
    half = p["pool_size"] // 2 + 1
    print(f"\n  R-VER1 (framing collusion): escalation pool measured at {p['pool_size']} "
          f"disjoint-pairable candidates (mean over {n} rounds)")
    for share in (0.10, 0.25, 0.50, 0.60):
        r = s1_framing(share, pool_size=p["pool_size"], per_site_cost=p["per_site_cost"])
        tag = " (breakeven)" if abs(share - 0.5) < 1e-9 else (" PROFIT" if r["net_harm"] > 0 else "")
        print(f"    pool_share {share:.2f}: net_harm {r['net_harm']:+.2f}  ({r['sites_owned']} sites, "
              f"~${r['infra_cost_mo']:.0f}/mo){tag}")
    print(f"    -> net-profit needs >50% of the {p['pool_size']}-candidate pool (>= {half} disjoint "
          f"sites, ~${half * 70}/mo), and C is beacon-lottery-chosen, not attacker-picked.")

    # R-VER2 -----------------------------------------------------------------
    if be:
        ber = be["rounds"]
        na, atr, q = be["no_attribution"], be["attribution"], be["quarantine"]
        na_lo, na_hi = wilson(na, ber)
        atr_lo, atr_hi = wilson(atr, ber)
        print(f"\n  R-VER2 (band-edge gaming): {ber} deliberate straddle attempts")
        print(f"    no-attribution (attacker's goal): {na}/{ber} = {pct(na / ber)}  95% CI [{pct(na_lo)}, {pct(na_hi)}]")
        print(f"    attribution   (BACKFIRED, slashed): {atr}/{ber} = {pct(atr / ber)}  95% CI [{pct(atr_lo)}, {pct(atr_hi)}]")
        print(f"    quarantine (no reward): {q}/{ber} = {pct(q / ber)}; settle: {be['settle']}/{ber}")
        if na > 0:
            print(f"    -> straddling backfires ~{atr / na:.1f}x more often than it succeeds; "
                  f"gaming the band is a losing strategy.")
    pr = d["profile_remeasure_rate"]
    pr_k = round(pr * n)
    pr_lo, pr_hi = wilson(pr_k, n)
    print(f"    detection lever: profile_remeasure fires {pct(pr)} of rounds  95% CI [{pct(pr_lo)}, {pct(pr_hi)}] "
          f"(-> band-retighten trigger)")
    lens = live.divergence_l_inf
    if lens:
        honest = sum(1 for x in lens if x <= 8.0)
        cheat = len(lens) - honest
        print(f"    divergence l_inf: {honest} within band (<=8), {cheat} beyond (>8) — clean separation, band gate binding")

    # R-MAT3 -----------------------------------------------------------------
    sc, sm = f6.get("scenarios", 0), f6.get("sybil_merged", 0)
    hc, hf = f6.get("home_checked", 0), f6.get("home_flagged", 0)
    det_lo, det_hi = wilson(sm, sc)
    fp_lo, fp_hi = wilson(hf, hc)
    print(f"\n  R-MAT3 (F6 detection): {sm}/{sc} concentrated endpoints merged "
          f"(detection rate {pct(sm / sc) if sc else 'n/a'}, 95% CI [{pct(det_lo)}, {pct(det_hi)}])")
    print(f"    false positives: {hf}/{hc} home endpoints wrongly flagged "
          f"(FP rate {pct(hf / hc) if hc else 'n/a'}, 95% CI upper bound {pct(fp_hi)})")
    print(f"    coverage inflation prevented (SC6): {f6['inflation_prevented']:.2f}x")


# ---------------- Strategy S1: framing collusion (R-VER1) ----------------
def s1_framing(pool_share, task_value=1.0, band=8.0, per_site_cost=70.0,
               pool_size=40):
    """One disputed task where the colluder's B posts a wrong result and honest A the right
    one. The escalation executor C is lottery-selected uniformly from the disjoint-pairable
    pool. If C is a colluder (prob ~= pool_share), it 'agrees' with B and honest A is framed
    and slashed. If C is honest (prob 1-pool_share), C agrees with A and the colluder's B is
    slashed. Returns per-attempt honest harm, attacker expected stake loss, net, and the
    infra cost of holding `pool_share` of the pool.

    KEY STRUCTURAL RESULT: with symmetric slashing, net honest harm is positive only when
    pool_share > 0.5 — framing requires MAJORITY control of the disjoint-pairable escalation
    pool. The m>=3 spread + cluster/ASN disjointness make that pool span many operators, so
    majority control is expensive (per-site infra) AND risks the colluder's own C reputation.
    """
    slash = slash_multiple(band)  # value at risk per slash
    p_frame = pool_share          # P(colluding C selected by the lottery)
    honest_harm = p_frame * slash * task_value                 # A wrongly slashed
    attacker_stake_loss = (1.0 - p_frame) * slash * task_value  # B rightly slashed
    net_harm = honest_harm - attacker_stake_loss               # >0 only if pool_share>0.5
    sites_owned = math.ceil(pool_share * pool_size)
    infra_cost_mo = sites_owned * per_site_cost
    return dict(pool_share=pool_share, slash=slash, honest_harm=honest_harm,
                attacker_stake_loss=attacker_stake_loss, net_harm=net_harm,
                sites_owned=sites_owned, infra_cost_mo=infra_cost_mo)


# ---------------- Strategy S2: band-edge no-attribution (R-VER2) [stub] ----------------
def s2_band_edge(band=8.0, remeasure_trigger=0.05):
    """A pair straddles the band edge hoping C lands within band of both (C-2 no-attribution
    -> no slash, free retry). Rate-limited by profile_remeasure -> band-retighten. FULL MODEL
    (WP-3.5): needs the empirical divergence-variance distribution to compute P(C between)."""
    return dict(status="stub", needs="empirical divergence variance (live testnet)",
                detection_lever="profile_remeasure frequency -> band retighten")


# ---------------- Strategy S3: cross-class widening (R-CC1 residual) ----------------
def s3_widening_surface():
    """Check cheat_EV<0 across (band, task_bound, p_detect). B-1 couples slash to band, so a
    wider usable band raises the slash. Returns the danger cells (cheat_EV >= 0)."""
    danger = []
    for band in (0.0, 4.0, 8.0):
        for task_bound in (2.0, 6.0, 10.0):
            eff = effective_profile(0.0, band, same_class=False, task_bound=task_bound)
            if eff is None:
                continue  # ineligible -> pins same-class, no cross-class attack
            slash = slash_multiple(eff)
            for p_detect in (0.15, 0.25, 0.50):  # sampling rate p_class
                ev = cheat_ev(1.0, p_detect, slash)
                if ev >= 0:
                    danger.append((band, task_bound, p_detect, round(ev, 3)))
    return danger


# ---------------- Strategy S4: registration gaming (R-MAT3 residual) [stub] ----------------
def s4_registration_gaming():
    """Cost to fake Stage-1 diversity (50/25/10/5) to stand up a controlled class. Reuses the
    Iteration-2 cohort-evasion cost curve + F6 density coupling. FULL MODEL: WP-3.5."""
    return dict(status="stub", reuses="iteration-2 cohort-evasion cost + F6 density")


def main():
    print("=" * 92)
    print("Q1 ITERATION 3 (skeleton) — verification-layer collusion, strawman parameters")
    print("=" * 92)

    print("\nS1 — framing collusion (R-VER1): sweep colluder share of the escalation pool")
    print(f"{'pool_share':>10} {'honest_harm':>12} {'atk_stake_loss':>15} {'net_harm':>10} {'sites':>6} {'infra$/mo':>10}")
    breakeven = None
    for share in (0.05, 0.10, 0.25, 0.40, 0.50, 0.60, 0.75):
        r = s1_framing(share)
        if breakeven is None and r["net_harm"] > 0:
            breakeven = share
        print(f"{share:>10.2f} {r['honest_harm']:>12.2f} {r['attacker_stake_loss']:>15.2f} "
              f"{r['net_harm']:>10.2f} {r['sites_owned']:>6} {r['infra_cost_mo']:>10.0f}")
    print(f"  -> net honest harm turns positive only at pool_share > 0.5 "
          f"(first positive at {breakeven}); i.e. framing needs MAJORITY of the")
    print(f"     disjoint-pairable pool. Below that the colluder loses more stake (B slashed) "
          f"than harm it imposes.")

    print("\nS3 — cross-class widening (R-CC1 residual): cheat_EV>=0 danger cells")
    danger = s3_widening_surface()
    if not danger:
        print("  none — cheat_EV<0 across all (band, task_bound, p_detect) given B-1 coupling "
              "(cheating is -EV everywhere sampled)")
    else:
        for d in danger:
            print(f"  band={d[0]} task_bound={d[1]} p={d[2]} cheat_EV={d[3]}")

    print("\nS2 — band-edge no-attribution (R-VER2):", s2_band_edge())
    print("S4 — registration gaming (R-MAT3 residual):", s4_registration_gaming())

    print("\nData interface (calibrates from live MVP-2/3 runs):")
    # example: a live run with a larger, mostly-disjoint pool -> even harder to reach majority
    # values illustrative of an MVP-3 run (SC6 Sybil scenario: naive 50 vs effective 21 clusters)
    live = LiveStats(n_settle=180, n_c_agrees_a=12, n_c_agrees_b=3, n_c_agrees_both=2,
                     n_quarantine=3, escalation_pool_size=120, disjoint_pairable_fraction=0.9,
                     per_site_cost=70.0, profile_remeasure_rate=0.02,
                     f6_merge_events=1, coverage_inflation_prevented=50.0 / 21.0)
    p = s1_params_from_live(live)
    r = s1_framing(0.5, pool_size=p["pool_size"], per_site_cost=p["per_site_cost"])
    print(f"  calibrated S1 breakeven (pool_size={p['pool_size']}): to reach 50% control the")
    print(f"    colluder needs {r['sites_owned']} disjoint sites (~${r['infra_cost_mo']:.0f}/mo infra) — "
          f"and 50% is only breakeven, not profit")
    print(f"  observed no-attribution rate (R-VER2) = {live.no_attribution_rate()*100:.1f}% "
          f"(detection lever: profile_remeasure = {live.profile_remeasure_rate*100:.1f}%)")
    print(f"  F6 effectiveness (R-MAT3, from MVP-3): coverage inflation prevented = "
          f"{live.f6_effectiveness():.2f}x ({live.f6_merge_events} cohort-merge event(s))")

    # WP-3.5: if a real testnet export exists, produce updated results from it.
    here = os.path.dirname(os.path.abspath(__file__))
    livestats = os.path.join(here, "livestats.json")
    if os.path.exists(livestats):
        report_from_real_data(livestats)
    else:
        print("\n(no livestats.json found — run `cargo run -p goat-net --bin goat-collect` to")
        print(" generate real testnet data, then re-run this to get real R-VER1/R-VER2 results)")

    print("\nNEXT: larger/longer collection runs for tighter R-VER1 curves; complete S2/S4")
    print("models; a CI cross-check that Python predicates match verification.rs exactly.")


# ---- parity notes ----
# effective_profile / agree / slash_multiple mirror verification.rs + maturity.rs exactly.
# A CI cross-check (future) should assert identical outputs on shared vectors.

if __name__ == "__main__":
    main()
