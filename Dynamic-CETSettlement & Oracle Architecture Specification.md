# **GoatCoin (GOAT) — Dynamic-CET Settlement & Oracle Architecture Specification**

This document consolidates the micro-architectural specifications for the deferred economic and settlement layers of GoatCoin (goat-settlement). It details the implementation of a **Dynamic Contributor Earnings Target (CET)**, a **Hexa-Index Basket**, an adaptive **Meta-Index Controller**, and a **Validator Quorum Data-Availability (DA) Attestation Crate** designed to eliminate multi-party collusion and data-withholding exploits.

> **Status & scope (2026-07-06).** Forward design for the deferred settlement layer (roadmap item I4, Phase 3) — **not implemented in the `goatcoin-rs` workspace and not part of the Testnet MVP.** Baselines: AI responses 36 (oracle architecture) and 37 (oracle hardening + `goat-settlement` structs). The Validator-Quorum DA scheme (§4) concretizes the mitigation for roadmap risk **R-C1** (off-chain data-withholding). All standing invariants hold: **pure-integer deterministic on-chain math** (fraud-proof recomputation), **Thin-Pool Principle**, **power-source neutrality**, **measured-work-only GCU**, **broad accessibility**, **zero content/license inspection (Core Principle 7)**, and *"if it names a device type, it's wrong."* Strawman constants (`κ_thin`, amortization band, `decay_ppm`, DA thresholds/timeouts, slashing schedule) remain pending the F5 empirical study before any economic go-live.

## **1\. Architectural Axioms & Core Philosophy**

The entire tokenomic design exists to **maximize the efficiency and profitability of global idle compute power** (sunk-cost consumer hardware operating during downtime). To prevent industrial data centers or power-infrastructure giants from capturing the network, the protocol enforces the **Thin-Pool Principle**: the tokenomic ceiling must remain highly profitable for retail home users but structurally unprofitable for entities deploying fresh capital to scale dedicated hardware farms.  
To uphold this philosophy over a multi-year horizon, the protocol abandons a static fiat-pegged reward target. Instead, it transitions to a **Dynamic CET** pegged to live commodity computing rental markets, dynamically localized through a multi-variant purchasing power index.

### **On-Chain Fixed-Point Conventions**

To maintain perfect reproducibility across independent recomputers and enable cryptographic fraud proofs, the settlement layer bans all floating-point math on-chain. The following types and scales are globally enforced:

Rust  
pub const PPM: u64 \= 1\_000\_000;        // Multiplier ratio scale (1\_000\_000 \== 1.0)  
pub const BP\_FULL: u32 \= 10\_000;       // Weight scale (10\_000 bp \== 100%)  
pub type Ppm      \= u64;               // Normalized ratio or index level (base \== 1e6)  
pub type MicroUsd \= u64;               // Asset pricing in millionths of a USD (µUSD)  
pub type Bp       \= u32;               // Weight configuration in basis points  
pub type Epoch    \= u64;

## **2\. Dynamic CET & The Hexa-Index CPPI Basket**

The Dynamic CET establishes a market-clearing computation rate, which is then passed through a regional purchasing power filter to calculate an honest, localized net return on the client application (*Da Goat*).

                             \[Compute Market Index (CMI)\]  
                                          │  
                                          ▼  
              Thin-Pool Gross Rate (median\_CMI × κ\_thin, µUSD/GCU-h)  
                                          │  
                        ┌─────────────────┴─────────────────┐  
                        ▼                                   ▼  
              Opex Cost Components               Real-Value Anchors  
            (Electricity \+ Broadband)       (PPP \+ CPI \+ P2P \+ Labor)  
                        │                                   │  
                        └─────────────────┬─────────────────┘  
                                          ▼  
                            \[Hexa-Index CPPI Multiplier\]  
                                          │  
                                          ▼  
                             Localized Net Target (µUSD)

### **2.1 The Compute Market Index (CMI)**

The CMI tracks the global hourly clearing price of commodity/consumer-tier AI compute (e.g., aggregating live asks from decentralized networks like Akash, Vast.ai, and Spheron spot pools). Crucially, the index filters out enterprise cloud data (such as commercial H100 tiers) to hold the thin-pool cap intact.

**Authoritative on-chain quantity — a per-GCU-hour rate.** The settlement layer works exclusively in a **thin-pool-discounted per-GCU-hour rate**; the discount by the unamendable protocol constant $\\kappa\_{thin} \\in (0,1]$ is applied *before* anything downstream sees the value, so no code path ever handles an un-capped gross:

$$\\text{CET}\_{gross\\\_rate}(\\mu\\text{USD/GCU-h}) \= \\text{median\\\_commodity\\\_rate} \\times \\frac{\\kappa\_{thin\\\_ppm}}{\\text{PPM}}$$

This per-hour rate is what `localized_target_ugcu_h` (§3.2) localizes and what `compute_epoch_gap_fill` (§5) consumes as `cet_gross`.

**Monthly figure is a display projection, not an on-chain gross.** The familiar "8 h/day × 30 days" number exists only for the *Da Goat* client to show a contributor an intuitive monthly estimate. It is derived **from the already-localized, already-κ\_thin-discounted per-hour target**, never from an independent un-capped path:

$$\\text{CET}\_{monthly\\\_display}(\\mu\\text{USD}) \= 240 \\times \\text{localized\\\_target\\\_ugcu\\\_h}(t)$$

Keeping `κ_thin` inside the single authoritative per-hour rate — rather than in a separate monthly formula — removes any risk of a display path and a settlement path disagreeing, and guarantees the thin-pool cap binds every consumer of the value.

### **2.2 The Hexa-Index CPPI Composition**

The Contributor Purchasing-Power Index (CPPI) localizes the gross target using six distinct dimensions, balancing direct operational expenses (Opex) against purchasing-power variables (Anchors):

1. **Residential Electricity ($\\mu\\text{USD/kWh}$):** Tracked via global/regional utility data to automatically shield net contributor margins from local power-grid shocks.  
2. **Broadband Tariff Index:** Captures data-transmission costs and metered-network realities in highly distributed emerging markets.  
3. **Digital PPP / Cost-of-Living:** Anchors global token returns to real-world local digital goods consumption parity (e.g., regional streaming and utility indices).  
4. **Local Inflation (CPI):** Tracks currency debasement so real household income doesn't erode between quarterly oracle rebalances.  
5. **P2P Stablecoin Premium:** Measures the street-level P2P exchange rate divergence (e.g., USDT to local fiat) to capture true off-ramp purchasing power in capital-controlled nations.  
6. **Local Labor Index:** Tracks local statutory minimum-pay equivalents to preserve the financial meaningfulness of the network's passive rewards relative to local human labor.

## **3\. Micro-Architectural Hardening & Oracle Logic**

### **3.1 Overflow-Safe Co-Movement Gate (correlation\_ppm)**

The long-term Meta-Index Controller must evaluate proposed component mutations by computing their on-chain correlation against historical consumer utility baselines. Naive calculation of Pearson correlation variance loops involves calculating a product of sums of squares ($v\_x \\times v\_y$), which scales geometrically to exceed $2^{128}$, triggering fatal arithmetic overflows on-chain.  
The hardened implementation computes integer square roots *individually first*, bounding the final product to a safe, overflow-proof integer threshold:

Rust  
/// Deterministic floor integer square root over u128 (Newton's method).  
pub fn isqrt\_u128(n: u128) \-\> u128 {  
    if n \< 2 { return n; }  
    let mut x: u128 \= 1u128 \<\< ((128 \- n.leading\_zeros() \+ 1\) / 2);  
    loop {  
        let y \= (x \+ n / x) \>\> 1;  
        if y \>= x { return x; }  
        x \= y;  
    }  
}

/// Integer Pearson correlation ×1e6 (PPM), in \[-1\_000\_000, 1\_000\_000\].  
/// Bounded to execute safely without u128 arithmetic overflow under all market parameters.  
pub fn correlation\_ppm(candidate: &\[i128\], utility\_curve: &\[i128\]) \-\> i64 {  
    let n \= candidate.len().min(utility\_curve.len());  
    if n \< 2 { return 0; }  
    let n\_i \= n as i128;

    let (mut sx, mut sy) \= (0i128, 0i128);  
    for i in 0..n {  
        sx \+= candidate\[i\]; sy \+= utility\_curve\[i\];  
    }  
    let (mx, my) \= (sx / n\_i, sy / n\_i);

    let (mut cov, mut vx, mut vy) \= (0i128, 0u128, 0u128);  
    for i in 0..n {  
        let dx \= candidate\[i\] \- mx;  
        let dy \= utility\_curve\[i\] \- my;  
        cov \+= dx \* dy;  
        vx \+= (dx \* dx) as u128;  
        vy \+= (dy \* dy) as u128;  
    }  
    if vx \== 0 || vy \== 0 { return 0; }

    // Hardened denominator: compute roots first to prevent vx \* vy overflow  
    let denom: u128 \= isqrt\_u128(vx).saturating\_mul(isqrt\_u128(vy));  
    if denom \== 0 { return 0; }

    // Apply scaling bit-shift to long-running covariance numerators to preserve ratio accuracy  
    let acov \= cov.unsigned\_abs();  
    let mut s \= 0u32;  
    while (acov \>\> s) \>= (1u128 \<\< 107\) { s \+= 1; }

    let num \= ((acov \>\> s) as i128) \* (PPM as i128);  
    let den \= (denom \>\> s) as i128;  
    if den \== 0 {  
        return if cov \< 0 { \-(PPM as i128) } else { PPM as i128 } as i64;  
    }  
      
    let mag \= num / den;  
    let signed \= if cov \< 0 { \-mag } else { mag };  
    signed.clamp(-(PPM as i128), PPM as i128) as i64  
}

### **3.2 Regional Compute Amortization Normalization**

To prevent import taxes, capital controls, and hardware scarcity from bankrupting contributors in specific sovereign regions, the protocol introduces a tightly bounded, device-agnostic regional amortization modifier. It normalizes target margins without introducing capital subsidies or naming device types.

Rust  
pub fn regional\_amort\_clamped(adj: \&RegionalComputeAdjustment) \-\> Ppm {  
    adj.amortization\_ppm.median.clamp(adj.amort\_min\_ppm, adj.amort\_max\_ppm)  
}

pub fn localized\_target\_ugcu\_h(  
    cmi: \&ComputeMarketIndex,  
    region: \&RegionalComputeAdjustment,  
    cppi: \&CppiOracle,  
) \-\> MicroUsd {  
    // 1\. Derive global thin-pool gross price ceiling  
    let gross \= (cmi.commodity\_rate\_ugcu\_h.median as u128 \* cmi.kappa\_thin\_ppm as u128 / PPM as u128) as u64;

    // 2\. Adjust for regional hardware amortization inequalities  
    let regionalized \= (gross as u128 \* regional\_amort\_clamped(region) as u128 / PPM as u128) as u64;

    // 3\. Compute and apply localized purchasing-power multiplier  
    let levels: \[Ppm; N\_CPPI\] \= core::array::from\_fn(|k| index\_level(cppi.components\[k\].median, cppi.base\_ref\[k\]));  
    let cppi\_ppm \= clamp\_move(cppi.prior\_cppi\_ppm, cppi\_multiplier(\&levels, \&cppi.weights), 500); // 500 bp \= ±5%

    (regionalized as u128 \* cppi\_ppm as u128 / PPM as u128) as u64  
}

### **3.3 Ratio-Return Volatility Model (closes R-C2)**

The adaptive reweight in the `MetaIndexController` was originally specified over the "MAD of
log-returns." A true logarithm has no exact pure-integer form: any fixed-point `log` is an
approximation (lossy near 1.0, table-driven, a needless audit surface) and is undefined at zero —
precisely the failure modes a fraud-provable integer pipeline must exclude. **R-C2 is closed by
replacing log-returns with a deviation-from-parity ratio return in PPM**, which is exact, total
(explicitly handles zeroes), and numerically indistinguishable from |log-return| inside the
protocol's own ±5%/quarter operating envelope (`|ln(1+x) − x| ≤ x²/2`, ≤ 0.125% relative at the
clamp boundary).

**Definition.** For consecutive **finalized** (post-`clamp_move`) component values
`v_{t-1}, v_t`:

$$r_t \\;=\\; \\Big|\\,\\frac{v_t \\cdot \\text{PPM}}{v_{t-1}} \\;-\\; \\text{PPM}\\,\\Big| \\quad \\text{(clamped to } R\\_MAX\\text{)}$$

and per-component trailing volatility is the mean of `r_t` over a configurable window of 4–8
quarters (the "ratio-return MAD"). Deviation is measured **from parity (zero return), not from
the window's own mean**: the controller buffers *movement* in a contributor's cost basis — a
sustained tariff climb must register as pressure even though its dispersion around its own trend
is near zero. This is a deliberate semantic improvement over classical MAD-about-the-mean.

Rust  
/// Per-tick ratio-return clamp (PPM). Defense-in-depth: finalized series are already  
/// ±5%/quarter-clamped (r\_t ≤ 50\_000 structurally); this bounds any raw/unclamped path.  
pub const RATIO\_RETURN\_MAX\_PPM: Ppm \= 500\_000;   // ±50% per tick, hard cap  
pub const VOL\_WINDOW\_MIN\_SAMPLES: usize \= 2;     // fewer valid returns \=\> no boost (safe default)  
pub const VOL\_WINDOW\_DEFAULT\_QUARTERS: usize \= 4;  
pub const VOL\_WINDOW\_MAX\_QUARTERS: usize \= 8;    // constitution-band upper bound

/// r\_t \= |v\_t·PPM/v\_{t-1} − PPM|, clamped. None if either value is zero (a zero in a cost/index  
/// feed is a data fault, not a price: the pair is EXCLUDED rather than mapped to a fake return).  
pub fn ratio\_return\_ppm(prev: u64, cur: u64) \-\> Option\<Ppm\> {  
    if prev \== 0 || cur \== 0 { return None; }  
    let ratio \= (cur as u128).saturating\_mul(PPM as u128) / (prev as u128); // ≤2^64·2^20 \<\< 2^128  
    let dev \= ratio.abs\_diff(PPM as u128);  
    Some(dev.min(RATIO\_RETURN\_MAX\_PPM as u128) as Ppm)  
}

/// Trailing ratio-return MAD over the finalized series (window ≤ VOL\_WINDOW\_MAX\_QUARTERS \+ 1  
/// values). Floor division \=\> deterministic. None if \< VOL\_WINDOW\_MIN\_SAMPLES valid returns —  
/// the caller treats None as ZERO boost (a silent/dead feed must never gain weight by starving  
/// its own history; liveness is escalated to the mutation state machine instead).  
pub fn ratio\_return\_mad\_ppm(finalized: &\[u64\]) \-\> Option\<Ppm\> {  
    let (mut sum, mut n): (u128, u128) \= (0, 0);  
    for w in finalized.windows(2) {  
        if let Some(r) \= ratio\_return\_ppm(w\[0\], w\[1\]) { sum \+= r as u128; n \+= 1; }  
    }  
    if (n as usize) \< VOL\_WINDOW\_MIN\_SAMPLES { return None; }  
    Some((sum / n) as Ppm)  
}

**Overflow & determinism.** The only wide product is `cur·PPM` (`< 2^84`, fits `u128` with ~44
bits of headroom); the window sum is bounded by `8 · R_MAX < 2^23`. All divisions are integer
floor; no float, no table, no library — every recomputer reproduces the value bit-identically,
so a mis-posted volatility (and therefore a mis-posted weight vector) is a fraud proof.

**Integration into `rebalance()`.** The controller's `trailing_vol_ppm[k]` is now *derived state*
— recomputed each quarter from the per-component ring buffer of finalized medians — rather than
an externally supplied figure:

Rust  
/// Fixed-capacity ring of the last (VOL\_WINDOW\_MAX\_QUARTERS \+ 1\) finalized component values.  
\#\[derive(Clone, Debug)\]  
pub struct FeedHistory {  
    pub values: \[u64; VOL\_WINDOW\_MAX\_QUARTERS \+ 1\],  
    pub len: u32, // valid entries (oldest evicted first once full)  
}

// MetaIndexController changes (diff):  
//   \-  pub trailing\_vol\_ppm: \[Ppm; N\_CPPI\],   // integer MAD of log-returns over the window  
//   \+  pub history:          \[FeedHistory; N\_CPPI\], // finalized medians (post-clamp), per component  
//   \+  pub vol\_window\_quarters: u32,           // 4..=8, constitution-band  
//   (rebalance() computes σ\_k \= ratio\_return\_mad\_ppm(\&history\[k\]).unwrap\_or(0) inline;  
//    the boost formula base·(PPM \+ min(λ·σ\_k/PPM, boost\_cap))/PPM, the \[w\_min,w\_max\] clamp,  
//    and largest-remainder renormalization to 10\_000 bp are UNCHANGED.)

**Compatibility with the ±5%/quarter clamp.** Volatility is computed over the *finalized* series,
whose per-quarter moves are already bounded to ±5% by `clamp_move`; therefore `r_t ≤ 50_000` PPM
structurally, `σ_k ≤ 50_000` PPM, and λ is calibrated so that a *sustained* 5%/quarter cost regime
approaches `boost_cap` while quiet regimes contribute ~0. A manipulated single tick is triple-
bounded: the feed's own challenge window, the ±5% clamp on the value entering the history, and the
4–8-quarter averaging. The weight output path (clamp to `[w_min, w_max]`, quarterly cadence,
largest-remainder renormalization) is unchanged.

**Edge cases (specified, not incidental):**

To achieve maximum state minimization, raw submissions from hundreds of oracle reporters are cached entirely off-chain in content-addressed storage. The ledger anchors only a dense, 32-byte Merkle root structure.

### **4.1 Data-Availability Withholding Guardrail**

To prevent an adversarial oracle reporter from anchoring a corrupted manifest and then deliberately withholding the underlying leaf data from the P2P network to run out the 7-day challenge window, the protocol decouples the state transitions. The challenge window **does not begin** when a manifest is posted. It activates only when a QuorumCertificate is anchored, proving independent validators have successfully fetched and replicated the underlying data.

Rust  
/// The dense on-chain footprint for a single region-epoch oracle posting.  
\#\[derive(Clone, Debug)\]  
pub struct FeedManifest {  
    pub feed\_id: u16,  
    pub region\_id: u32,  
    pub epoch: Epoch,  
    pub submissions\_root: \[u8; 32\], // Merkle root over sorted reporter data  
    pub submissions\_cid: \[u8; 32\],  // IPFS/Content Address of canonical leaf blob  
    pub n\_leaves: u32,  
    pub posted\_median: u64,  
    pub prior\_accepted: u64,  
    pub proposed: u64,  
}

\#\[derive(Clone, Debug)\]  
pub struct DaAttestation {  
    pub validator\_id: String,  
    pub signature\_ml\_dsa: Vec\<u8\>,  // Cryptographic signature confirming data possession  
}

\#\[derive(Clone, Debug)\]  
pub struct QuorumCertificate {  
    pub epoch: Epoch,  
    pub region\_id: u32,  
    pub submissions\_cid: \[u8; 32\],  
    pub attestations: Vec\<DaAttestation\>,  
}

### **4.2 Deterministic Quorum Verification & Slashing**

Rust  
pub const DA\_SIGNATURE\_DOMAIN: &\[u8\] \= b"GDA\\x01";

pub fn verify\_da\_quorum(cert: \&QuorumCertificate, registry: \&ValidatorRegistry) \-\> Result\<(), DaError\> {  
    // Enforce 2/3 deterministic BFT majority threshold via pure integer math  
    let total\_validators \= registry.active\_count() as u64;  
    let required\_quorum \= ((total\_validators.saturating\_mul(2)) / 3).saturating\_add(1);  
      
    if (cert.attestations.len() as u64) \< required\_quorum {  
        return Err(DaError::InsufficientQuorum);  
    }

    let mut seen\_validators \= HashSet::with\_capacity(cert.attestations.len());  
    let mut msg \= Vec::with\_capacity(3 \+ 8 \+ 4 \+ 32);  
    msg.extend\_from\_slice(DA\_SIGNATURE\_DOMAIN);  
    msg.extend\_from\_slice(\&cert.epoch.to\_be\_bytes());  
    msg.extend\_from\_slice(\&cert.region\_id.to\_be\_bytes());  
    msg.extend\_from\_slice(\&cert.submissions\_cid);

    for attestation in \&cert.attestations {  
        if \!seen\_validators.insert(\&attestation.validator\_id) {  
            return Err(DaError::DuplicateValidator);  
        }  
        let pubkey \= registry.get\_ml\_dsa\_pubkey(\&attestation.validator\_id).ok\_or(DaError::UnknownValidator)?;  
        if \!pqsign::verify(\&pubkey, \&msg, \&attestation.signature\_ml\_dsa) {  
            return Err(DaError::InvalidSignature);  
        }  
    }  
    Ok(())  
}

If a reporter fails to broadcast their raw leaves to the network within a hard timeout boundary (DA\_TIMEOUT\_EPOCHS \= 24), the validators will refuse to provide attestations. The ledger maintenance engine automatically identifies the timeout, intercepts the state transition, deletes the reporter's reputation score, and **burns 100% of their locked staking bond** directly out of total supply.

## **5\. goat-settlement Emission Allocation Controller**

The Emission Controller executes the core gap-fill distribution strategy. It mints only the precise token volume required to bridge the difference between organic usage channel revenue ($u\_{ref}$) and the sliding CET\_gross target floor, multiplied across the effective network load ($N\_{eff}$).

Rust  
pub struct EmissionController {  
    pub epoch: Epoch,  
    pub reserve\_remaining: u64,  
    pub m\_cap\_current: u64,       // Maximum token capacity allowable per epoch  
    pub m\_cap\_floor: u64,         // Long-run tail emission constant  
    pub decay\_ppm: Ppm,           // Fixed disinflationary step multiplier  
}

impl EmissionController {  
    pub fn decay\_cap(\&mut self) {  
        let decayed \= (self.m\_cap\_current as u128 \* self.decay\_ppm as u128 / PPM as u128) as u64;  
        self.m\_cap\_current \= decayed.max(self.m\_cap\_floor);  
    }  
}

/// Pure gap-fill calculation loop. Entirely saturating; immune to economic shock overflows.  
pub fn compute\_epoch\_gap\_fill(  
    n\_eff: u64,        // Effective work hours (already clustering/F6 discounted upstream)  
    cet\_gross: u64,    // Localized dynamic gross target (µUSD/hour)  
    u\_ref: u64,        // Realized market usage fees collected per ref-hour  
    m\_cap: u64,  
    reserve\_remaining: u64,  
) \-\> u64 {  
    // If organic usage channel fees meet or outrun market targets, emissions contract to 0  
    let gap\_per\_unit \= cet\_gross.saturating\_sub(u\_ref);  
      
    let raw \= (n\_eff as u128).saturating\_mul(gap\_per\_unit as u128);  
    let capped \= raw.min(m\_cap as u128) as u64;  
      
    capped.min(reserve\_remaining)  
}  
