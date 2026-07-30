"""
GoatCoin (GOAT) - Q1 Adversarial Simulation, iteration 1 (deterministic equilibrium
+ grid-search strategy optimizer). Launch-epoch conditions per Phase 2 Rev E.

Strategies simulated:
  A. Honest whale (data-center, incl. free-power "power giant" variant)
  B. Naive Sybil split (co-located -> clustering merges)
  C. Residential-distributed Sybil (sites, duty-cycling, behavior spoofing,
     cohort evasion, grid-region spread) -- full grid search
  D. Patronage (sponsor real households, fiat-settled/undetectable)
  E. Pioneer farming (analytic bound)
  F. Maturity-ratchet timing attack (analytic EV frontier)
Sensitivity sweeps on s*, gamma, kappa, site cost for the adversary's best strategy.

All dollar figures are $-equivalents of GOAT at launch.
"""
import itertools, math

# ---------------- protocol / market constants (launch) ----------------
D         = 200_000.0      # GCU/day demand
PRICE     = 0.10           # $/GCU
EXEC      = 0.70           # executor fee share
SMALL_CAP = 360_000.0      # honest small fleet capacity GCU/day (50k nodes, 8h)
SMALL_I   = 1.85           # honest idle premium
REF_CAP   = 8.0            # reference node GCU/day (1.0 GCU/h x 8h)
CETG_DAY  = 27.20 / 30     # CET_gross per day
MCAP      = 40_000.0       # emissions hard cap $/day
ELEC_REF  = 7.20           # reference node electricity $/mo

N_GPUS    = 3000           # adversary fleet size

def S_factor(share, sstar, gamma):
    return 1.0 if share <= sstar else (sstar / share) ** gamma

def engine(adv_cap, k_eff, I_adv, kappa=0.05, sstar=0.005, gamma=0.7,
           region_spread=True, extra_small_cap=0.0):
    """One reward epoch at equilibrium. Returns adversary + reference-node flows."""
    small_cap = SMALL_CAP + extra_small_cap
    if adv_cap > 0:
        prop = D * adv_cap / (adv_cap + small_cap)
        adv_asg = min(prop, k_eff * kappa * D, adv_cap)
    else:
        adv_asg = 0.0
    small_asg = D - adv_asg
    util = small_asg / small_cap
    ref_asg = REF_CAP * util
    u_ref = ref_asg * EXEC * PRICE
    M = min(max((D / ref_asg) * (CETG_DAY - u_ref), 0.0), MCAP) if ref_asg > 0 else MCAP
    # emissions weights
    if adv_asg > 0:
        share_pc = (adv_asg / k_eff) / D
        pr = 1.0
        tot_share = adv_asg / D
        if (not region_spread) and I_adv > 1.3 and tot_share > 0.04:
            pr = (0.04 / tot_share) ** 0.7          # P_r, largest-cluster-first (adv IS largest)
        adv_w = adv_asg * I_adv * S_factor(share_pc, sstar, gamma) * pr
    else:
        adv_w = 0.0
    small_w = small_asg * SMALL_I
    M_adv = M * adv_w / (adv_w + small_w) if adv_w + small_w > 0 else 0.0
    adv_rev_day = adv_asg * EXEC * PRICE + M_adv
    ref_net_mo = (u_ref + M * ref_asg * SMALL_I / (adv_w + small_w)) * 30 - ELEC_REF
    total_flow = D * EXEC * PRICE + M
    return dict(adv_asg=adv_asg, M=M, adv_rev_day=adv_rev_day,
                capture=adv_rev_day / total_flow, ref_net=ref_net_mo,
                cet=ref_net_mo / 20.0, util=util)

def idle_premium(duty, spoof, venue):
    qb = {24: 0.15, 12: (0.85 if spoof else 0.50), 8: (0.90 if spoof else 0.55)}[duty]
    if duty > 12:
        qb = min(qb, 0.20)                          # duty-cycle gate
    qn = 0.85 if venue == "res" else 0.10
    return 1.0 + math.sqrt(qb * qn)                 # I_max=2 form

def strategy_pnl(venue, duty, spoof, sites, evasion, region_spread,
                 free_power=False, kappa=0.05, sstar=0.005, gamma=0.7,
                 site_cost=70.0):
    """Monthly P&L + capture for one adversary configuration (3000 GPUs)."""
    if venue == "dc":
        rate, capex_mo, kw, tariff = 4.0, 2000/36, 0.35, (0.0 if free_power else 0.05)
        k_eff, ids, infra_mo = 1, 1, N_GPUS * 5.0
    else:  # residential sites force consumer-class cards (fingerprinting)
        rate, capex_mo, kw, tariff = 1.0, 600/36, 0.20, 0.15
        k_eff = sites if evasion else 1             # cohort detection merges w/o evasion
        ids = sites
        infra_mo = sites * (site_cost + (10.0 if evasion else 0.0))
    cap_day = N_GPUS * rate * duty
    I_adv = idle_premium(duty, spoof, venue)
    r = engine(cap_day, k_eff, I_adv, kappa, sstar, gamma, region_spread)
    rev_mo = r["adv_rev_day"] * 30
    capex = N_GPUS * capex_mo * (1.15 if (venue == "res" and evasion) else 1.0)
    power = N_GPUS * kw * duty * 30 * tariff
    stake = 0.01 * (15 * ids + 1.5 * cap_day)       # lockup cost @12%/yr
    ops = N_GPUS * 2.0 if spoof else 0.0
    ramp = 0.5 * rev_mo / 12                        # 30-day half-rate ramp, amortized 12mo
    cost = capex + power + infra_mo + stake + ops + ramp
    gps = N_GPUS / sites if (venue == "res" and sites) else None
    return dict(rev=rev_mo, cost=cost, profit=rev_mo - cost, capture=r["capture"],
                ref_net=r["ref_net"], cet=r["cet"], I=I_adv, k_eff=k_eff,
                gpus_per_site=gps, per_gpu_h=rev_mo / (N_GPUS * duty * 30))

def fmt(name, s, note=""):
    g = f" g/site={s['gpus_per_site']:.0f}" if s["gpus_per_site"] else ""
    return (f"{name:<44s} capt {s['capture']*100:5.1f}%  rev ${s['rev']/1000:7.1f}k"
            f"  P&L ${s['profit']/1000:+8.1f}k/mo  refCET {s['cet']:.2f}"
            f"  I={s['I']:.2f} k={s['k_eff']}{g} {note}")

print("=" * 118)
print("A/B: DATA-CENTER STRATEGIES (3000 DC-class GPUs, 4 GCU/h)")
print("=" * 118)
print(fmt("A1 honest whale, 24/7", strategy_pnl("dc", 24, False, 0, False, True)))
print(fmt("A2 power giant (FREE power), 24/7", strategy_pnl("dc", 24, False, 0, False, True, free_power=True)))
print(fmt("A3 DC idle-mimicry (12h, spoof)", strategy_pnl("dc", 12, True, 0, False, True)))
print(fmt("B  naive Sybil x80 (co-located->merged)", strategy_pnl("dc", 24, False, 0, False, True), "(k_eff=1: identical to A1)"))

print()
print("=" * 118)
print("C: RESIDENTIAL-DISTRIBUTED SYBIL (3000 consumer GPUs) -- grid search")
print("=" * 118)
results = []
for duty, spoof, sites, evasion, spread in itertools.product(
        (24, 12, 8), (False, True), (25, 50, 100, 200, 375, 500), (False, True), (False, True)):
    s = strategy_pnl("res", duty, spoof, sites, evasion, spread)
    results.append((f"res d{duty} spoof={int(spoof)} sites={sites} ev={int(evasion)} spread={int(spread)}", s))
best_profit = sorted(results, key=lambda x: -x[1]["profit"])[:6]
best_capture = sorted(results, key=lambda x: -x[1]["capture"])[:3]
profitable = [x for x in results if x[1]["profit"] > 0]
print(f"-- profitable configurations: {len(profitable)} of {len(results)}")
print("-- top by PROFIT:")
for n, s in best_profit: print(fmt("  " + n, s))
print("-- top by CAPTURE:")
for n, s in best_capture: print(fmt("  " + n, s))

print()
print("=" * 118)
print("SENSITIVITY (best-capture residential strategy) vs s*, gamma, kappa, site cost")
print("=" * 118)
bn, bs = best_capture[0]
bd = dict(zip(("duty","spoof","sites","evasion","spread"),
              (int(bn.split("d")[1].split()[0]), bool(int(bn.split("spoof=")[1][0])),
               int(bn.split("sites=")[1].split()[0]), bool(int(bn.split("ev=")[1][0])),
               bool(int(bn.split("spread=")[1][0])))))
for sstar in (0.0025, 0.005, 0.01):
    for gamma in (0.5, 0.7, 1.0):
        s = strategy_pnl("res", bd["duty"], bd["spoof"], bd["sites"], bd["evasion"], bd["spread"],
                         sstar=sstar, gamma=gamma)
        print(f"  s*={sstar*100:4.2f}% gamma={gamma:.1f}: capture {s['capture']*100:5.1f}%  P&L ${s['profit']/1000:+7.1f}k/mo")
for kappa in (0.02, 0.05, 0.08):
    s = strategy_pnl("res", bd["duty"], bd["spoof"], bd["sites"], bd["evasion"], bd["spread"], kappa=kappa)
    print(f"  kappa={kappa*100:.0f}%: capture {s['capture']*100:5.1f}%  P&L ${s['profit']/1000:+7.1f}k/mo")
for sc in (40.0, 70.0, 120.0):
    s = strategy_pnl("res", bd["duty"], bd["spoof"], bd["sites"], bd["evasion"], bd["spread"], site_cost=sc)
    print(f"  site=${sc:.0f}/mo: P&L ${s['profit']/1000:+7.1f}k/mo")

print()
print("=" * 118)
print("D: PATRONAGE (sponsor n real households, reference nodes, fiat-settled)")
print("=" * 118)
for n_sp in (10_000, 50_000, 100_000):
    r = engine(0, 0, 1.0, extra_small_cap=n_sp * REF_CAP)
    asg = REF_CAP * r["util"]
    gross_mo = (asg * EXEC * PRICE + r["M"] * asg / D) * 30   # I cancels (all-small)
    influence = n_sp * asg / D
    print(f"  n={n_sp:>7,}: node gross ${gross_mo:5.2f}/mo | patron take cap (vs independence) = $7.20 -> "
          f"P&L <= $0/node | influence {influence*100:4.1f}% of work | "
          f"pure-influence cost ~${(7.20+3)*n_sp*12/1e6:.1f}M/yr | non-sponsored refCET {r['cet']:.2f}")
r = engine(0, 0, 1.0, extra_small_cap=100_000 * REF_CAP)
asg = REF_CAP * r["util"]; gross_mo = (asg * EXEC * PRICE + r["M"] * asg / D) * 30
print(f"  exploitation bound (unaware households, patron takes all net): "
      f"<= ${gross_mo - 7.20:.2f}/node/mo, churn-limited; rig-funded variant payback "
      f"{800/(gross_mo - 7.20 - 5):.0f} mo vs 36 mo depreciation")

print()
print("=" * 118)
print("E: PIONEER FARMING (analytic bound)  |  F: RATCHET CHEAT EV")
print("=" * 118)
node_emis_day = engine(0, 0, 1.0)["M"] * (REF_CAP * engine(0,0,1.0)["util"]) / D
print(f"  E: max pioneer bonus (beta=0.5, pre-decay) = ${0.5*node_emis_day*30:.2f}/node/mo vs residential"
      f" infra >= ${70/6:.2f}/GPU/mo at 6 GPUs/site -> farming never covers infra; genuine owners net gain.")
for slash in (5, 10, 20, 40):
    print(f"  F: slash={slash}x task value -> cheat-EV<0 requires p > {1/(slash+1):.3f}"
          f"  (p_floor=0.10 margin {0.10*(slash+1):.1f}x, p_floor=0.20 margin {0.20*(slash+1):.1f}x)")
