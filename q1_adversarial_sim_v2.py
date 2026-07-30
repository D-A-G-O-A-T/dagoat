"""
GoatCoin (GOAT) - Q1 Adversarial Simulation, ITERATION 2.

Changes vs iteration 1 (q1_adversarial_sim.py):
  F3 fix : p_floor = 0.15, minimum slash multiple = 15x (cap 20x).
  F4 add : q_network now includes a per-endpoint COMPUTE-DENSITY plausibility term.
           A residential last-mile credibly hosts ~1-5 consumer GPUs; beyond that the
           network score degrades sharply (sustained aggregate throughput/bandwidth per
           endpoint is observable). This forces a residential-distributed Sybil toward
           low-density sites -> many more sites -> higher infra + larger cohort surface.
  Grid   : site range extended to include low-density (<=5 GPU/site) configurations.

SECURITY / EXECUTION NOTES (safe to run yourself):
  - Standard library only (math, itertools). No file I/O, no network, no os/subprocess,
    no eval/exec/shell. Deterministic; prints results only. Python 3.8+.

All dollar figures are $-equivalents of GOAT at the launch epoch.
"""
import itertools, math

# ---------------- protocol / market constants (launch) ----------------
D         = 200_000.0      # GCU/day demand
PRICE     = 0.10           # $/GCU
EXEC      = 0.70           # executor fee share
SMALL_CAP = 360_000.0      # honest small fleet capacity GCU/day (50k nodes, 8h)
SMALL_I   = 1.85           # honest idle premium
REF_CAP   = 8.0            # reference node GCU/day
CETG_DAY  = 27.20 / 30     # CET_gross per day
MCAP      = 40_000.0       # emissions hard cap $/day
ELEC_REF  = 7.20           # reference node electricity $/mo
N_GPUS    = 3000           # adversary fleet size

# ---- F3: ratchet safety parameters ----
P_FLOOR   = 0.15
SLASH_MIN = 15            # x task value (cap 20x)

def S_factor(share, sstar, gamma):
    return 1.0 if share <= sstar else (sstar / share) ** gamma

# ---- F4: per-endpoint compute-density plausibility term ----
def q_network(venue, gpus_per_site):
    """Residential last-mile credibly hosts ~1-5 GPUs; degrade sharply beyond."""
    if venue == "dc":
        return 0.10
    d = max(gpus_per_site, 1.0)
    if d <= 5.0:
        return 0.85
    return max(0.10, 0.85 * (5.0 / d) ** 1.5)

def idle_premium(duty, spoof, venue, gpus_per_site=1.0):
    qb = {24: 0.15, 12: (0.85 if spoof else 0.50), 8: (0.90 if spoof else 0.55)}[duty]
    if duty > 12:
        qb = min(qb, 0.20)                       # duty-cycle gate
    qn = q_network(venue, gpus_per_site)
    return 1.0 + math.sqrt(qb * qn)              # I_max = 2 form

def engine(adv_cap, k_eff, I_adv, kappa=0.05, sstar=0.005, gamma=0.7,
           region_spread=True, extra_small_cap=0.0):
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
    if adv_asg > 0:
        share_pc = (adv_asg / k_eff) / D
        pr = 1.0
        tot_share = adv_asg / D
        if (not region_spread) and I_adv > 1.3 and tot_share > 0.04:
            pr = (0.04 / tot_share) ** 0.7
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

def strategy_pnl(venue, duty, spoof, sites, evasion, region_spread,
                 free_power=False, kappa=0.05, sstar=0.005, gamma=0.7,
                 site_cost=70.0):
    if venue == "dc":
        rate, capex_mo, kw, tariff = 4.0, 2000/36, 0.35, (0.0 if free_power else 0.05)
        k_eff, ids, infra_mo, gps = 1, 1, N_GPUS * 5.0, N_GPUS
    else:
        rate, capex_mo, kw, tariff = 1.0, 600/36, 0.20, 0.15
        k_eff = sites if evasion else 1
        ids = sites
        gps = N_GPUS / sites
        # evasion cost grows with the cohort surface (each near-identical site is a
        # correlation point); low-density => many sites => bigger detection surface.
        evasion_pp = (10.0 if evasion else 0.0)
        infra_mo = sites * site_cost + N_GPUS * evasion_pp
    cap_day = N_GPUS * rate * duty
    I_adv = idle_premium(duty, spoof, venue, gps)
    r = engine(cap_day, k_eff, I_adv, kappa, sstar, gamma, region_spread)
    rev_mo = r["adv_rev_day"] * 30
    capex = N_GPUS * capex_mo * (1.15 if (venue == "res" and evasion) else 1.0)
    power = N_GPUS * kw * duty * 30 * tariff
    stake = 0.01 * (15 * ids + 1.5 * cap_day)
    ops = N_GPUS * 2.0 if spoof else 0.0
    ramp = 0.5 * rev_mo / 12
    cost = capex + power + infra_mo + stake + ops + ramp
    return dict(rev=rev_mo, cost=cost, profit=rev_mo - cost, capture=r["capture"],
                ref_net=r["ref_net"], cet=r["cet"], I=I_adv, k_eff=k_eff,
                gpus_per_site=(gps if venue == "res" else None),
                qn=q_network(venue, gps), per_gpu_h=rev_mo / (N_GPUS * duty * 30))

def fmt(name, s, note=""):
    g = f" g/site={s['gpus_per_site']:.0f} qn={s['qn']:.2f}" if s["gpus_per_site"] else ""
    return (f"{name:<46s} capt {s['capture']*100:5.1f}%  rev ${s['rev']/1000:7.1f}k"
            f"  P&L ${s['profit']/1000:+8.1f}k/mo  refCET {s['cet']:.2f}"
            f"  I={s['I']:.2f} k={s['k_eff']}{g} {note}")

print("=" * 122)
print("ITERATION 2  (F3: p_floor=0.15, slash>=15x | F4: density-coupled q_network)")
print("=" * 122)
print("A/B: DATA-CENTER STRATEGIES (3000 DC GPUs, 4 GCU/h)")
print(fmt("A1 honest whale 24/7", strategy_pnl("dc", 24, False, 0, False, True)))
print(fmt("A2 power giant FREE power 24/7", strategy_pnl("dc", 24, False, 0, False, True, free_power=True)))
print(fmt("A3 DC idle-mimicry 12h+spoof", strategy_pnl("dc", 12, True, 0, False, True)))

print()
print("C: RESIDENTIAL-DISTRIBUTED SYBIL -- full grid search (site range incl. low-density)")
print("=" * 122)
sites_range = (25, 50, 100, 200, 375, 600, 1000, 1500)
results = []
for duty, spoof, sites, evasion, spread in itertools.product(
        (24, 12, 8), (False, True), sites_range, (False, True), (False, True)):
    s = strategy_pnl("res", duty, spoof, sites, evasion, spread)
    results.append((f"res d{duty} spoof={int(spoof)} sites={sites} ev={int(evasion)} spread={int(spread)}", s))
profitable = [x for x in results if x[1]["profit"] > 0]
print(f"-- profitable configurations: {len(profitable)} of {len(results)}")
print("-- top by PROFIT:")
for n, s in sorted(results, key=lambda x: -x[1]["profit"])[:6]:
    print(fmt("  " + n, s))
print("-- top by CAPTURE (among profitable, else global):")
pool = profitable if profitable else results
for n, s in sorted(pool, key=lambda x: -x[1]["capture"])[:4]:
    print(fmt("  " + n, s))

print()
print("-- density sweep: hold duty=24, evasion=1, spread=1; vary sites (=> GPUs/site):")
for sites in sites_range:
    s = strategy_pnl("res", 24, False, sites, True, True)
    print(f"   sites={sites:>4} ({N_GPUS//sites:>3} GPU/site, qn={s['qn']:.2f}): "
          f"I={s['I']:.2f} capture {s['capture']*100:4.1f}%  P&L ${s['profit']/1000:+7.1f}k/mo")

print()
print("=" * 122)
print("D: PATRONAGE  |  E: PIONEER  |  F: RATCHET (F3-fixed)")
print("=" * 122)
for n_sp in (10_000, 50_000, 100_000):
    r = engine(0, 0, 1.0, extra_small_cap=n_sp * REF_CAP)
    asg = REF_CAP * r["util"]
    gross_mo = (asg * EXEC * PRICE + r["M"] * asg / D) * 30
    print(f"  D n={n_sp:>7,}: node gross ${gross_mo:5.2f}/mo -> patron P&L <= $0/node; "
          f"pure-influence ~${(7.20+3)*n_sp*12/1e6:.1f}M/yr; non-sponsored refCET {r['cet']:.2f}")
base = engine(0, 0, 1.0)
node_emis_day = base["M"] * (REF_CAP * base["util"]) / D
print(f"  E pioneer: max bonus ${0.5*node_emis_day*30:.2f}/node/mo vs site infra >=${70/6:.2f}/GPU/mo "
      f"(6 GPU/site) -> never covers infra.")
print(f"  F ratchet (F3): p_floor={P_FLOOR}, slash>={SLASH_MIN}x -> cheat-EV<0 needs p>{1/(SLASH_MIN+1):.3f}; "
      f"margin at p_floor = {P_FLOOR*(SLASH_MIN+1):.1f}x (SAFE).  slash=20x -> margin {P_FLOOR*21:.1f}x.")
